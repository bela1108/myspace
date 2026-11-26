from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from django.apps import apps
from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.db import DEFAULT_DB_ALIAS, connections, models
from django.utils.encoding import smart_str
from django.utils.module_loading import import_string

from auditlog.models import DEFAULT_OBJECT_REPR, _get_manager_from_settings


NO_SNAPSHOT = object()


def normalize_relation_fields(value: Any) -> dict[str, dict[str, Any]]:
    """Normalize the different accepted relation snapshot declarations.

    The canonical form is a mapping of field name to a specification.  A spec may
    contain ``fields`` (the only target fields allowed to be persisted),
    ``display`` (a field name or a dotted-path callable), and ``mask_fields``.
    ``True`` opts every forward relation into a reference-only snapshot.
    """

    if value in (None, False):
        return {}
    if value is True:
        return {"__all__": {"fields": [], "display": None, "mask_fields": []}}
    if isinstance(value, str):
        value = [value]

    if isinstance(value, (list, tuple, set, frozenset)):
        value = {field_name: True for field_name in value}

    if not isinstance(value, Mapping):
        raise TypeError(
            "Relation snapshots must be a mapping, an iterable of field names, "
            "or True."
        )

    normalized = {}
    for field_name, spec in value.items():
        if field_name == "__all__":
            normalized[field_name] = _normalize_spec(spec)
            continue
        normalized[str(field_name)] = _normalize_spec(spec)
    return normalized


def _normalize_spec(spec: Any) -> dict[str, Any]:
    if spec in (None, True):
        return {"fields": [], "display": None, "mask_fields": []}
    if spec is False:
        return {"enabled": False, "fields": [], "display": None, "mask_fields": []}
    if isinstance(spec, str):
        spec = [spec]
    if isinstance(spec, (list, tuple, set, frozenset)):
        return {
            "fields": [str(field) for field in spec],
            "display": None,
            "mask_fields": [],
        }
    if not isinstance(spec, Mapping):
        raise TypeError(
            "A relation snapshot specification must be a field name iterable "
            "or a mapping."
        )

    fields = spec.get(
        "fields",
        spec.get("allow_fields", spec.get("allowed_fields", spec.get("display_fields", []))),
    )
    if fields is None:
        fields = []
    elif isinstance(fields, str):
        fields = [fields]
    mask_fields = spec.get("mask_fields", [])
    if isinstance(mask_fields, str):
        mask_fields = [mask_fields]

    display = spec.get("display", spec.get("display_field"))
    if display is None and spec.get("use_object_repr") is False:
        display = False

    return {
        "fields": [str(field) for field in fields],
        "display": display,
        "mask_fields": [str(field) for field in mask_fields],
        "mask_callable": spec.get("mask_callable"),
    }


def _relation_config_for_model(model: models.Model) -> dict[str, dict[str, Any]]:
    from auditlog.registry import auditlog

    if not auditlog.contains(model):
        return {}
    config = auditlog.get_relation_fields(model)
    if "__all__" in config:
        all_spec = config["__all__"]
        return {
            field.name: all_spec
            for field in model._meta.get_fields()
            if _is_forward_relation(field)
        }
    return config


def _is_forward_relation(field: Any) -> bool:
    return bool(
        getattr(field, "is_relation", False)
        and not getattr(field, "many_to_many", False)
        and (getattr(field, "many_to_one", False) or getattr(field, "one_to_one", False))
    )


def build_relation_snapshots(model, old, new, changes) -> dict[str, Any] | None:
    """Capture the related objects referenced by changed foreign keys."""

    if not changes:
        return None
    if isinstance(changes, str):
        try:
            changes = json.loads(changes)
        except (TypeError, ValueError):
            return None

    config = _relation_config_for_model(model)
    if not config:
        return None

    owner = new if new is not None else old
    alias = get_db_alias(owner)
    snapshots: dict[str, Any] = {}

    for field_name, change in changes.items():
        if not isinstance(change, (list, tuple)) or len(change) != 2:
            continue
        spec = config.get(field_name)
        if not spec or spec.get("enabled") is False:
            continue
        try:
            field = model._meta.get_field(field_name)
        except FieldDoesNotExist:
            continue
        if not _is_forward_relation(field):
            continue

        old_snapshot = _snapshot_for_side(
            field=field,
            owner=old,
            raw_value=_side_value(field, old, change[0]),
            alias=get_db_alias(old) if old is not None else alias,
            spec=spec,
        )
        new_snapshot = _snapshot_for_side(
            field=field,
            owner=new,
            raw_value=_side_value(field, new, change[1]),
            alias=get_db_alias(new) if new is not None else alias,
            spec=spec,
        )
        snapshots[field_name] = {"old": old_snapshot, "new": new_snapshot}

    return snapshots or None


def _side_value(field, owner, fallback):
    """Use the real FK value, even when the recorded change is masked."""

    if owner is not None:
        value = getattr(owner, field.attname, None)
        if value is not None:
            return value
    return fallback


def _snapshot_for_side(field, owner, raw_value, alias, spec):
    if raw_value is None or str(raw_value) == "None":
        return None

    pk = smart_str(raw_value)
    related_model = field.related_model
    target = _get_related_object(field, owner, pk, alias)
    snapshot = {
        "model": related_model._meta.label_lower,
        "pk": pk,
        "db": alias or DEFAULT_DB_ALIAS,
        "target_missing": target is None,
    }

    if target is None:
        snapshot["display"] = None
        snapshot["object_repr"] = None
        snapshot["fields"] = {}
        snapshot["masked_fields"] = []
        return snapshot

    target_config = _target_model_config(related_model)
    mask_fields = set(spec.get("mask_fields") or [])
    mask_fields.update(target_config.get("mask_fields", []))
    mask_callable = spec.get("mask_callable") or target_config.get("mask_callable")

    display = _snapshot_display(target, spec, mask_fields, mask_callable)
    snapshot["display"] = display
    snapshot["object_repr"] = display

    fields = {}
    masked_fields = []
    for field_name in spec.get("fields") or []:
        if field_name in mask_fields:
            value = _mask_target_value(
                target, field_name, mask_callable
            )
            masked_fields.append(field_name)
        else:
            value = _target_value(target, field_name)
        if value is not NO_SNAPSHOT:
            fields[field_name] = _json_safe(value)
    snapshot["fields"] = fields
    snapshot["masked_fields"] = masked_fields
    return snapshot


def _target_model_config(related_model) -> dict[str, Any]:
    from auditlog.registry import auditlog

    if not auditlog.contains(related_model):
        return {}
    return auditlog.get_model_fields(related_model)


def _get_related_object(field, owner, pk, alias):
    if owner is not None and getattr(owner, field.attname, None) is not None:
        try:
            cached = field.get_cached_value(owner)
        except (AttributeError, KeyError):
            cached = None
        if cached is not None and smart_str(getattr(cached, "pk", None)) == pk:
            return cached

    try:
        manager = _get_manager_from_settings(field.related_model)
        return manager.using(alias or DEFAULT_DB_ALIAS).filter(pk=pk).first()
    except Exception:
        # A missing/deleted target or an unavailable database must leave a
        # traceable reference, not abort the business transaction.
        return None


def _target_value(target, field_name):
    try:
        return getattr(target, field_name)
    except (AttributeError, ObjectDoesNotExist, FieldDoesNotExist):
        return NO_SNAPSHOT


def _mask_target_value(target, field_name, mask_callable):
    from auditlog.diff import get_mask_function

    value = _target_value(target, field_name)
    if value is NO_SNAPSHOT:
        return value
    return get_mask_function(mask_callable)(smart_str(value))


def _snapshot_display(target, spec, mask_fields, mask_callable):
    display = spec.get("display")
    if display is False:
        return None
    if callable(display):
        try:
            return smart_str(display(target))
        except Exception:
            return DEFAULT_OBJECT_REPR
    if isinstance(display, str):
        if "." in display and not hasattr(target, display):
            try:
                return smart_str(import_string(display)(target))
            except Exception:
                pass
        value = _target_value(target, display)
        if value is not NO_SNAPSHOT:
            if display in mask_fields:
                from auditlog.diff import get_mask_function

                return get_mask_function(mask_callable)(smart_str(value))
            return smart_str(value)

    # When no explicit display is configured, only use a field the caller
    # explicitly allowed.  This avoids leaking a masked value through
    # ``__str__``.
    for field_name in spec.get("fields") or []:
        value = _target_value(target, field_name)
        if value is NO_SNAPSHOT:
            continue
        if field_name in mask_fields:
            from auditlog.diff import get_mask_function

            return get_mask_function(mask_callable)(smart_str(value))
        return smart_str(value)

    try:
        display = smart_str(target)
    except Exception:
        return DEFAULT_OBJECT_REPR
    if mask_fields:
        from auditlog.diff import get_mask_function

        return get_mask_function(mask_callable)(display)
    return display


def _json_safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {smart_str(key): _json_safe(item) for key, item in value.items()}
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return smart_str(value)
    return value


def get_db_alias(instance) -> str:
    if instance is None:
        return DEFAULT_DB_ALIAS
    alias = getattr(getattr(instance, "_state", None), "db", None) or DEFAULT_DB_ALIAS
    if alias not in connections.settings:
        return DEFAULT_DB_ALIAS
    return alias


def get_snapshot_entry(log_entry, field_name, index: int):
    snapshots = log_entry.relation_snapshots or {}
    entry = snapshots.get(field_name, NO_SNAPSHOT)
    if entry is NO_SNAPSHOT:
        return NO_SNAPSHOT
    if isinstance(entry, (list, tuple)):
        return entry[index] if index < len(entry) else NO_SNAPSHOT
    if isinstance(entry, Mapping):
        if index == 0 and "old" in entry:
            return entry["old"]
        if index == 1 and "new" in entry:
            return entry["new"]
        if index in entry:
            return entry[index]
    return NO_SNAPSHOT


def snapshot_display(snapshot) -> str | None:
    if not isinstance(snapshot, Mapping):
        return None
    display = snapshot.get("display")
    if display not in (None, ""):
        return smart_str(display)
    object_repr = snapshot.get("object_repr")
    if object_repr not in (None, ""):
        return smart_str(object_repr)
    return None


def snapshot_reference(snapshot) -> str:
    if not isinstance(snapshot, Mapping):
        return "unknown object"
    model_label = snapshot.get("model") or "unknown model"
    try:
        model = apps.get_model(model_label)
    except (LookupError, ValueError):
        model = None
    model_name = model.__name__ if model is not None else model_label
    return f"{model_name} ({snapshot.get('pk', '?')})"


def relation_was_configured(model, field_name: str) -> bool:
    return field_name in _relation_config_for_model(model)


def get_snapshot_current_state(snapshot) -> str:
    """Return ``present``, ``missing`` or ``unknown`` for the referenced object."""

    if not isinstance(snapshot, Mapping):
        return "unknown"
    try:
        model = apps.get_model(snapshot["model"])
    except (KeyError, LookupError, ValueError):
        return "unknown"
    try:
        manager = _get_manager_from_settings(model)
        obj = (
            manager.using(snapshot.get("db") or DEFAULT_DB_ALIAS)
            .filter(pk=snapshot.get("pk"))
            .first()
        )
    except Exception:
        return "unknown"
    return "present" if obj is not None else "missing"
