from datetime import date, datetime, time
from functools import wraps
from weakref import WeakKeyDictionary

from django.conf import settings
from django.core.exceptions import FieldDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models

from auditlog import get_logentry_model
from auditlog.context import auditlog_disabled
from auditlog.diff import model_instance_diff
from auditlog.models import _get_manager_from_settings
from auditlog.signals import post_log, pre_log

# Snapshots of through rows before they are removed. Through rows are gone by
# the time ``post_remove``/``post_clear`` fires, so the snapshot taken on the
# matching ``pre_*`` signal is consumed afterwards. This preserves evidence
# such as the validity period stored on a removed edge.
_m2m_clear_snapshots: WeakKeyDictionary = WeakKeyDictionary()
_m2m_remove_snapshots: WeakKeyDictionary = WeakKeyDictionary()


def _get_m2m_field(through_model, field_name):
    """Return the ManyToManyField on the owner side registered as ``field_name``.

    A single through model may back several many-to-many relations, so the
    field name is used to tell them apart.
    """
    owner_model = None
    for candidate in through_model._meta.get_fields():
        if not isinstance(candidate, models.ForeignKey):
            continue
        related_model = candidate.related_model
        try:
            field = related_model._meta.get_field(field_name)
        except FieldDoesNotExist:
            continue
        field_through = getattr(field, "through", None) or getattr(
            field.remote_field, "through", None
        )
        if isinstance(field, models.ManyToManyField) and field_through is through_model:
            owner_model = related_model
            return field
    return owner_model


def _get_relation_sides(field, reverse):
    """Return ``(through_source_field, through_target_field)`` for a signal.

    ``m2m_changed`` is emitted from both ends of a relation. Forward and
    reverse operations on the same edge therefore resolve to the same pair of
    through columns, only in opposite order.
    """
    if reverse:
        return field.m2m_reverse_field_name(), field.m2m_field_name()
    return field.m2m_field_name(), field.m2m_reverse_field_name()


def _get_through_model(field):
    """Return the through model of a many-to-many field across Django versions."""
    return getattr(field, "through", None) or field.remote_field.through


def _json_safe(value):
    """Coerce through column values into types that can be stored as JSON."""
    if isinstance(value, (datetime, date, time)):
        return DjangoJSONEncoder().default(value)
    if isinstance(value, models.Model):
        return value.pk
    return value


def _snapshot_through_fields(through_row, source_field_name, target_field_name):
    """Snapshot the user-defined columns (e.g. validity period) of an edge."""
    relation_columns = {source_field_name, target_field_name}
    snapshot = {}
    pk_name = through_row._meta.pk.name
    for field in through_row._meta.local_concrete_fields:
        if field.name in relation_columns:
            continue
        if field.name == pk_name:
            continue
        if isinstance(field, models.ForeignKey):
            continue
        snapshot[field.name] = _json_safe(getattr(through_row, field.attname))
    return snapshot


def _build_edges(
    through_rows, field, reverse, source_field_name, target_field_name
):
    """Build direction-aware evidence for each through row behind a change."""
    through_model = _get_through_model(field)
    if reverse:
        source_model = field.related_model
        target_model = field.model
    else:
        source_model = field.model
        target_model = field.related_model
    edges = []
    for through_row in through_rows:
        edges.append(
            {
                "through_model": through_model._meta.label,
                "through_pk": through_row.pk,
                "source_model": source_model._meta.label,
                "source_pk": getattr(through_row, f"{source_field_name}_id"),
                "target_model": target_model._meta.label,
                "target_pk": getattr(through_row, f"{target_field_name}_id"),
                "direction": "reverse" if reverse else "forward",
                "fields": _snapshot_through_fields(
                    through_row, source_field_name, target_field_name
                ),
            }
        )
    return edges


def _get_through_rows(
    action, kwargs, field, reverse, source_field_name, target_field_name
):
    """Return the through rows affected by an m2m signal."""
    instance = kwargs["instance"]
    through_model = _get_through_model(field)

    if action == "pre_clear":
        return list(
            through_model._default_manager.filter(
                **{f"{source_field_name}_id": instance.pk}
            ).order_by(through_model._meta.pk.name)
        )

    if action == "post_clear":
        return list(
            _m2m_clear_snapshots.get(instance, {}).pop((field.name, reverse), [])
        )

    if action == "post_remove":
        return list(
            _m2m_remove_snapshots.get(instance, {}).pop((field.name, reverse), [])
        )

    return list(
        through_model._default_manager.filter(
            **{
                f"{source_field_name}_id": instance.pk,
                f"{target_field_name}_id__in": kwargs["pk_set"],
            }
        ).order_by(through_model._meta.pk.name)
    )


def _get_changed_targets(action, kwargs, through_rows, target_field_name):
    """Return the target objects referenced by the changed through rows."""
    # kwargs["model"] is the model whose primary keys are carried by
    # pk_set; for reverse operations it differs from field.related_model.
    manager = _get_manager_from_settings(kwargs["model"])

    if action == "post_clear":
        target_pks = [
            getattr(row, f"{target_field_name}_id") for row in through_rows
        ]
    else:
        target_pks = list(kwargs["pk_set"])

    if not target_pks:
        return manager.none()
    return manager.filter(pk__in=target_pks).order_by(manager.model._meta.pk.name)


def check_disable(signal_handler):
    """
    Decorator that passes along disabled in kwargs if any of the following is true:
    - 'auditlog_disabled' from threadlocal is true
    - raw = True and AUDITLOG_DISABLE_ON_RAW_SAVE is True
    """

    @wraps(signal_handler)
    def wrapper(*args, **kwargs):
        try:
            auditlog_disabled_value = auditlog_disabled.get()
        except LookupError:
            auditlog_disabled_value = False
        if not auditlog_disabled_value and not (
            kwargs.get("raw") and settings.AUDITLOG_DISABLE_ON_RAW_SAVE
        ):
            signal_handler(*args, **kwargs)

    return wrapper


@check_disable
def log_create(sender, instance, created, **kwargs):
    """
    Signal receiver that creates a log entry when a model instance is first saved to the database.

    Direct use is discouraged, connect your model through :py:func:`auditlog.registry.register` instead.
    """
    if created:
        _create_log_entry(
            action=get_logentry_model().Action.CREATE,
            instance=instance,
            sender=sender,
            diff_old=None,
            diff_new=instance,
            use_json_for_changes=settings.AUDITLOG_STORE_JSON_CHANGES,
        )


@check_disable
def log_update(sender, instance, **kwargs):
    """
    Signal receiver that creates a log entry when a model instance is changed and saved to the database.

    Direct use is discouraged, connect your model through :py:func:`auditlog.registry.register` instead.
    """
    if not instance._state.adding and instance.pk is not None:
        update_fields = kwargs.get("update_fields", None)
        old = _get_manager_from_settings(sender).filter(pk=instance.pk).first()
        _create_log_entry(
            action=get_logentry_model().Action.UPDATE,
            instance=instance,
            sender=sender,
            diff_old=old,
            diff_new=instance,
            fields_to_check=update_fields,
            use_json_for_changes=settings.AUDITLOG_STORE_JSON_CHANGES,
        )


@check_disable
def log_delete(sender, instance, **kwargs):
    """
    Signal receiver that creates a log entry when a model instance is deleted from the database.

    Direct use is discouraged, connect your model through :py:func:`auditlog.registry.register` instead.
    """
    if instance.pk is not None:
        _create_log_entry(
            action=get_logentry_model().Action.DELETE,
            instance=instance,
            sender=sender,
            diff_old=instance,
            diff_new=None,
            use_json_for_changes=settings.AUDITLOG_STORE_JSON_CHANGES,
        )


def log_access(sender, instance, **kwargs):
    """
    Signal receiver that creates a log entry when a model instance is accessed in a AccessLogDetailView.

    Direct use is discouraged, connect your model through :py:func:`auditlog.registry.register` instead.
    """
    if instance.pk is not None:
        _create_log_entry(
            action=get_logentry_model().Action.ACCESS,
            instance=instance,
            sender=sender,
            diff_old=None,
            diff_new=None,
            force_log=True,
            use_json_for_changes=settings.AUDITLOG_STORE_JSON_CHANGES,
        )


def _create_log_entry(
    action,
    instance,
    sender,
    diff_old,
    diff_new,
    fields_to_check=None,
    force_log=False,
    use_json_for_changes=False,
):
    pre_log_results = pre_log.send(
        sender,
        instance=instance,
        action=action,
    )

    if any(item[1] is False for item in pre_log_results):
        return
    LogEntry = get_logentry_model()

    error = None
    log_entry = None
    changes = None
    try:
        changes = model_instance_diff(
            diff_old,
            diff_new,
            fields_to_check=fields_to_check,
            use_json_for_changes=use_json_for_changes,
        )

        if force_log or changes:
            log_entry = LogEntry.objects.log_create(
                instance,
                action=action,
                changes=changes,
                force_log=force_log,
            )
    except BaseException as e:
        error = e
    finally:
        if log_entry or error:
            post_log.send(
                sender,
                instance=instance,
                instance_old=diff_old,
                action=action,
                error=error,
                pre_log_results=pre_log_results,
                changes=changes,
                log_entry=log_entry,
                log_created=log_entry is not None,
                use_json_for_changes=settings.AUDITLOG_STORE_JSON_CHANGES,
            )
        if error:
            raise error


def make_log_m2m_changes(field_name):
    """Return a handler for m2m_changed with field_name enclosed."""

    @check_disable
    def log_m2m_changes(signal, action=None, **kwargs):
        """Handle m2m_changed and call LogEntry.objects.log_m2m_changes as needed."""
        if action not in [
            "pre_clear",
            "pre_remove",
            "post_add",
            "post_clear",
            "post_remove",
        ]:
            return
        LogEntry = get_logentry_model()
        field = _get_m2m_field(kwargs["sender"], field_name)
        if field is None:
            return

        reverse = bool(kwargs["reverse"])
        source_field_name, target_field_name = _get_relation_sides(field, reverse)
        instance = kwargs["instance"]

        if action in ("pre_clear", "pre_remove"):
            through_rows = _get_through_rows(
                action, kwargs, field, reverse, source_field_name, target_field_name
            )
            snapshots = (
                _m2m_clear_snapshots if action == "pre_clear" else _m2m_remove_snapshots
            )
            snapshots.setdefault(instance, {})[(field_name, reverse)] = through_rows
            return

        through_rows = _get_through_rows(
            action, kwargs, field, reverse, source_field_name, target_field_name
        )

        # Operations on an empty relation remove no edges and therefore have
        # nothing to audit. This also avoids treating every existing object as
        # removed simply because ``pk_set`` is unavailable on ``post_clear``.
        if action in ("post_clear", "post_remove") and not through_rows:
            return

        changed_queryset = _get_changed_targets(
            action, kwargs, through_rows, target_field_name
        )
        operation = "add" if action == "post_add" else "delete"

        edges = _build_edges(
            through_rows, field, reverse, source_field_name, target_field_name
        )

        LogEntry.objects.log_m2m_changes(
            changed_queryset,
            instance,
            operation,
            field_name,
            edges=edges,
            reverse=reverse,
        )

    return log_m2m_changes
