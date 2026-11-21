"""Offline STIX 2.0 observed-data migration helpers.

STIX 2.0 embedded observables are stored under the ``objects`` property of an
``observed-data`` object.  The keys in that mapping (usually ``"0"``, ``"1"``,
...) are local to that one observation: a reference such as ``"0"`` in another
observation does not identify the same object.

STIX 2.1 replaces the embedded ``objects`` mapping with top-level SCOs and an
``object_refs`` list on ``observed-data``.  This module performs that
conversion entirely offline.  It rewrites local references to the generated
global SCO IDs, de-duplicates identical content, and reports anything which
could not be translated together with the observation it came from.
"""

import collections.abc
import copy
import os
import re
import uuid
from dataclasses import dataclass, field, replace

import simplejson as json

# STIX IDs are "<type>--<uuid>".  This intentionally accepts letters in the
# UUID so that imported upper-case IDs are not mistaken for local refs.
SCO_ID_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9-]*--"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)

# These references point outside an observation's local object mapping and
# must never be rewritten using a local key.
EXTERNAL_REFERENCE_PROPERTIES = frozenset(
    {
        "created_by_ref",
        "marking_ref",
        "object_marking_refs",
        "object_refs",
    },
)

_LOCAL_REF_PREFIX = "urn:stix:local-object:"


def _natural_key(value):
    """Sort numeric local keys numerically and everything else lexically."""
    text = str(value)
    if text.isdigit():
        return (0, int(text), text)
    return (1, text)


def _as_plain(value):
    """Return a plain, independent Python representation of STIX content."""
    if hasattr(value, "serialize"):
        return json.loads(value.serialize())

    if isinstance(value, collections.abc.Mapping):
        return {key: _as_plain(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [_as_plain(item) for item in value]

    if isinstance(value, collections.abc.Iterable) and not isinstance(
        value, (str, bytes, bytearray),
    ):
        return [_as_plain(item) for item in value]

    return copy.deepcopy(value)


def _load_data(data):
    """Load JSON strings, files, STIX objects, or plain mappings."""
    if isinstance(data, os.PathLike):
        with open(data, encoding="utf-8") as handle:
            return json.load(handle)

    if isinstance(data, (str, bytes, bytearray)):
        try:
            return json.loads(data)
        except Exception:
            if isinstance(data, str) and os.path.exists(data):
                with open(data, encoding="utf-8") as handle:
                    return json.load(handle)
            raise

    if hasattr(data, "read"):
        return json.load(data)

    return _as_plain(data)


def _is_global_id(value):
    return isinstance(value, str) and bool(SCO_ID_PATTERN.match(value))


def _is_ref_property(name):
    return name.endswith("_ref") or name.endswith("_refs")


def _is_refs_property(name):
    return name.endswith("_refs")


def _local_token(observed_data_id, local_id):
    # Used only for objects with no ID-contributing properties, or for
    # reference cycles.  It is stable across input ordering.
    return "{}{}:{}".format(_LOCAL_REF_PREFIX, observed_data_id, local_id)


def _synthetic_observed_data_id(observed_data):
    """Create a stable ID for an observation which lacks one."""
    from .base import SCO_DET_ID_NAMESPACE, _make_json_serializable
    from .canonicalization.Canonicalize import canonicalize

    content = {
        key: value for key, value in observed_data.items()
        if key not in ("id", "spec_version")
    }
    data = canonicalize(_make_json_serializable(content), utf8=False)
    return "observed-data--{}".format(
        uuid.uuid5(SCO_DET_ID_NAMESPACE, data),
    )


@dataclass(frozen=True, eq=False)
class UnresolvedReference(collections.abc.Mapping):
    """A reference or object property which could not be translated.

    The source observation and the original embedded object are retained so
    that a caller can trace the problem back to the exact input record.  The
    class also behaves like a read-only mapping for callers which prefer
    dictionary-style access.
    """

    observed_data_id: str
    local_id: str
    path: str
    value: object
    reason: str
    object_id: str = None
    object_type: str = None
    property_name: str = None
    custom: bool = False
    preserved: bool = False
    kind: str = "unresolved-reference"
    source_observation: object = field(default=None, compare=False, repr=False)
    source_object: object = field(default=None, compare=False, repr=False)

    _ALIASES = {
        "observed_data_id": "observed_data_id",
        "observation_id": "observed_data_id",
        "observed_data": "observed_data_id",
        "local_id": "local_id",
        "local_key": "local_id",
        "object_key": "local_id",
        "key": "local_id",
        "path": "path",
        "property_path": "path",
        "value": "value",
        "ref": "value",
        "reference": "value",
        "reason": "reason",
        "message": "reason",
        "object_id": "object_id",
        "converted_id": "object_id",
        "object_type": "object_type",
        "type": "object_type",
        "property_name": "property_name",
        "property": "property_name",
        "custom": "custom",
        "preserved": "preserved",
        "kept": "preserved",
        "kind": "kind",
        "source": "source_observation",
        "observation": "source_observation",
        "source_observation": "source_observation",
        "source_object": "source_object",
        "original_object": "source_object",
    }

    def __getitem__(self, key):
        try:
            attribute = self._ALIASES[key]
        except KeyError:
            raise KeyError(key)
        return getattr(self, attribute)

    def __iter__(self):
        return iter(self._ALIASES)

    def __len__(self):
        return len(self._ALIASES)

    def __getattr__(self, name):
        aliases = object.__getattribute__(self, "_ALIASES")
        if name in aliases:
            return getattr(self, aliases[name])
        raise AttributeError(name)

    def __eq__(self, other):
        if isinstance(other, UnresolvedReference):
            return self.to_dict() == other.to_dict()
        if isinstance(other, collections.abc.Mapping):
            for key, value in other.items():
                try:
                    own_value = self[key]
                except KeyError:
                    return False
                if own_value != value:
                    return False
            return True
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def to_dict(self):
        """Return a JSON-serializable representation of this diagnostic."""
        return {
            "kind": self.kind,
            "observed_data_id": self.observed_data_id,
            "local_id": self.local_id,
            "path": self.path,
            "value": _as_plain(self.value),
            "reason": self.reason,
            "object_id": self.object_id,
            "object_type": self.object_type,
            "property_name": self.property_name,
            "custom": self.custom,
            "preserved": self.preserved,
        }


class ObjectCollection(list):
    """List of STIX objects which also supports lookup by object ID."""

    def __init__(self, iterable=()):
        super().__init__(iterable)
        self._by_id = {
            obj["id"]: obj for obj in self
            if isinstance(obj, collections.abc.Mapping) and "id" in obj
        }

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._by_id[key]
        return super().__getitem__(key)

    def get(self, key, default=None):
        return self._by_id.get(key, default)

    @property
    def by_id(self):
        return dict(self._by_id)

    def positions(self):
        return list(self._by_id)


class ObservedDataIDMap(dict):
    """Mapping of original observation positions to generated STIX 2.1 IDs.

    The primary representation is nested by observation::

        {
            "observed-data--...": {
                "0": "file--...",
                "1": "directory--...",
            },
        }

    For convenience, tuple lookups (``(observation_id, local_id)``) and
    unambiguous local-id lookups are also supported.
    """

    def __init__(self, mapping=None):
        self._flat = {}
        self._by_local = {}
        super().__init__(mapping or {})
        self._rebuild_index()

    def __eq__(self, other):
        if isinstance(other, ObservedDataIDMap):
            return dict.__eq__(self, other)
        if isinstance(other, collections.abc.Mapping):
            if dict.__eq__(self, other):
                return True
            if dict(other) == self._flat:
                return True
            if len(self) == 1:
                inner = dict(list(self.values())[0])
                if inner == dict(other):
                    return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = None

    def get_id(self, observation_id, local_id):
        """Return the generated ID for one observation-local position."""
        return self[(observation_id, local_id)]

    new_id = get_id
    id_for = get_id

    def _rebuild_index(self):
        flat = {}
        by_local = {}
        for observation_id, inner in self.items():
            if not isinstance(inner, collections.abc.Mapping):
                continue
            for local_id, new_id in inner.items():
                local_id = str(local_id)
                flat[(observation_id, local_id)] = new_id
                by_local.setdefault(local_id, []).append(
                    (observation_id, new_id),
                )
        self._flat = flat
        self._by_local = by_local

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._rebuild_index()

    def __delitem__(self, key):
        super().__delitem__(key)
        self._rebuild_index()

    def __getitem__(self, key):
        if isinstance(key, tuple) and len(key) == 2:
            return self._flat[(key[0], str(key[1]))]

        try:
            return super().__getitem__(key)
        except KeyError:
            pass

        text = str(key)
        for separator in ("/", ":", "#"):
            if separator in text:
                observation_id, local_id = text.split(separator, 1)
                try:
                    return self._flat[(observation_id, local_id)]
                except KeyError:
                    pass

        matches = self._by_local.get(text, ())
        if len(matches) == 1:
            return matches[0][1]
        if len(matches) > 1:
            raise KeyError(
                "local id {!r} is ambiguous; use "
                "(observation_id, local_id)".format(text),
            )
        raise KeyError(key)

    def __contains__(self, key):
        try:
            self[key]
        except KeyError:
            return False
        return True

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    @property
    def flat(self):
        """Return a ``(observation_id, local_id) -> global_id`` mapping."""
        return dict(self._flat)

    @property
    def flat_strings(self):
        """Return a ``"observation_id:local_id" -> global_id`` mapping."""
        return {
            "{}:{}".format(observation_id, local_id): new_id
            for (observation_id, local_id), new_id in self._flat.items()
        }

    def positions(self, object_id):
        """Return all original positions which map to *object_id*."""
        return [
            position for position, mapped_id in self._flat.items()
            if mapped_id == object_id
        ]

    def to_dict(self):
        return {
            observation_id: dict(inner)
            for observation_id, inner in self.items()
        }


class _PendingReference(Exception):
    def __init__(self, local_id):
        super().__init__(local_id)
        self.local_id = local_id


class _ObservationContext:
    def __init__(
        self, original, observed_data_id, source_record=None,
        output_observed_data_id=None,
    ):
        self.original = original
        self.observed_data_id = observed_data_id
        self.output_observed_data_id = (
            output_observed_data_id or observed_data_id
        )
        self.source_record = source_record or original
        self.local_objects = {}
        self.local_order = []
        self.types = {}
        self.classes = {}
        self.is_custom_type = {}
        self.prepared = {}
        self.ids = {}
        self.generated = {}
        self.diagnostics = []
        self._diagnostic_keys = set()

    def record(
        self, local_id, path, value, reason, *, custom=False,
        preserved=False, property_name=None, kind="unresolved-reference",
    ):
        local_id = str(local_id)
        diagnostic_key = (
            local_id, path, repr(value), reason, kind,
        )
        if diagnostic_key in self._diagnostic_keys:
            return
        self._diagnostic_keys.add(diagnostic_key)

        self.diagnostics.append(
            UnresolvedReference(
                observed_data_id=self.observed_data_id,
                local_id=local_id,
                path=path,
                value=_as_plain(value),
                reason=reason,
                object_id=self.ids.get(local_id),
                object_type=self.types.get(local_id),
                property_name=property_name,
                custom=custom,
                preserved=preserved,
                kind=kind,
                source_observation=self.source_record,
                source_object=self.local_objects.get(local_id),
            ),
        )

    def finalize_diagnostics(self):
        finalized = []
        for item in self.diagnostics:
            if item.object_id is None and item.local_id in self.ids:
                item = replace(item, object_id=self.ids[item.local_id])
            finalized.append(item)
        self.diagnostics = finalized

    def resolve(
        self, local_id, property_name, value, path, custom, mode,
    ):
        """Resolve one reference value.

        Returns ``(keep, value)``.  ``keep`` is false when a standard
        reference could not be resolved and must be dropped.
        """
        local_id = str(local_id)

        lookup = None
        if isinstance(value, str):
            lookup = value
        elif isinstance(value, int) and not isinstance(value, bool):
            lookup = str(value)

        if lookup is not None and lookup in self.local_objects:
            if mode == "prepare":
                return True, value

            target_id = self.ids.get(lookup)
            if target_id is not None:
                return True, target_id

            if mode in ("compute", "fallback-resolve"):
                raise _PendingReference(lookup)

            if mode == "fallback-final":
                return True, _local_token(self.observed_data_id, lookup)

            self.record(
                local_id,
                path,
                value,
                "referenced local object could not be converted",
                custom=custom,
                preserved=custom,
                property_name=property_name,
            )
            return custom, value

        if _is_global_id(value):
            return True, value

        if isinstance(value, str):
            reason = "unresolved local object reference"
        else:
            reason = "reference is neither a local key nor a STIX ID"

        self.record(
            local_id,
            path,
            value,
            reason,
            custom=custom,
            preserved=custom,
            property_name=property_name,
        )

        # Custom properties are opaque to us: keep their value so no custom
        # data is discarded, but make the lack of a translation visible in
        # the diagnostics.  Standard reference properties cannot legally
        # contain a dangling local key, so they are omitted.
        return custom, value


def _property_is_custom(context, local_id, property_name, custom_context):
    if custom_context or context.is_custom_type.get(local_id, False):
        return True
    return property_name.startswith("x_")


def _rewrite_value(
    context, local_id, value, *, mode, path="", custom_context=False,
    refs_enabled=True, ref_container=False,
):
    """Recursively rewrite local references to global STIX 2.1 IDs."""
    local_id = str(local_id)

    if isinstance(value, collections.abc.Mapping):
        rewritten = {}
        for name, item in value.items():
            child_path = "{}.{}".format(path, name) if path else str(name)

            if name in ("type", "id", "spec_version"):
                rewritten[name] = item
                continue

            custom = _property_is_custom(
                context, local_id, name, custom_context,
            )

            if (
                refs_enabled and _is_ref_property(name) and
                name not in EXTERNAL_REFERENCE_PROPERTIES
            ):
                if _is_refs_property(name):
                    if isinstance(item, list):
                        resolved_items = []
                        for index, reference in enumerate(item):
                            keep, new_value = context.resolve(
                                local_id,
                                name,
                                reference,
                                "{}[{}]".format(child_path, index),
                                custom,
                                mode,
                            )
                            if keep:
                                resolved_items.append(new_value)

                        if resolved_items or not item or custom:
                            rewritten[name] = resolved_items
                    else:
                        keep, new_value = context.resolve(
                            local_id, name, item, child_path, custom, mode,
                        )
                        if keep:
                            rewritten[name] = [new_value]
                    continue

                keep, new_value = context.resolve(
                    local_id, name, item, child_path, custom, mode,
                )
                if keep:
                    rewritten[name] = new_value
                continue

            child_container = (
                ref_container or custom or
                name in ("body_multipart", "extensions")
            )
            rewritten[name] = _rewrite_value(
                context,
                local_id,
                item,
                mode=mode,
                path=child_path,
                custom_context=custom,
                refs_enabled=refs_enabled and child_container,
                ref_container=child_container,
            )
        return rewritten

    if isinstance(value, list):
        return [
            _rewrite_value(
                context,
                local_id,
                item,
                mode=mode,
                path="{}[{}]".format(path, index),
                custom_context=custom_context,
                refs_enabled=refs_enabled,
                ref_container=ref_container,
            )
            for index, item in enumerate(value)
        ]

    return value


def _id_contributing_properties(context, local_id):
    cls = context.classes.get(local_id)
    if cls is None:
        return []
    return list(getattr(cls, "_id_contributing_properties", []))


def _standard_id(context, local_id):
    from .base import (
        SCO_DET_ID_NAMESPACE,
        _choose_one_hash,
        _make_json_serializable,
    )
    from .canonicalization.Canonicalize import canonicalize

    local_id = str(local_id)
    prepared = context.prepared[local_id]
    contributing = {
        name: prepared[name]
        for name in _id_contributing_properties(context, local_id)
        if name in prepared
    }

    if not contributing:
        return _fallback_id(context, local_id, "fallback-resolve")

    contributing = _rewrite_value(
        context,
        local_id,
        contributing,
        mode="compute",
    )

    serializable = {}
    for name, value in contributing.items():
        if name == "hashes":
            value = _choose_one_hash(value)
            if value is None:
                return _fallback_id(
                    context, local_id, "fallback-resolve",
                )
        serializable[name] = _make_json_serializable(value)

    if not serializable:
        return _fallback_id(context, local_id, "fallback-resolve")

    data = canonicalize(serializable, utf8=False)
    return "{}--{}".format(
        context.types[local_id],
        uuid.uuid5(SCO_DET_ID_NAMESPACE, data),
    )


def _fallback_id(context, local_id, mode):
    from .base import SCO_DET_ID_NAMESPACE, _make_json_serializable
    from .canonicalization.Canonicalize import canonicalize

    local_id = str(local_id)
    content = _rewrite_value(
        context,
        local_id,
        context.prepared[local_id],
        mode=mode,
    )
    payload = {
        "type": context.types[local_id],
        "content": content,
    }
    data = canonicalize(_make_json_serializable(payload), utf8=False)
    return "{}--{}".format(
        context.types[local_id],
        uuid.uuid5(SCO_DET_ID_NAMESPACE, data),
    )


def _prepare_observation(observation, allow_custom):
    """Index one observation and sanitize its embedded objects."""
    from .registry import class_for_type

    observation = _as_plain(observation)
    source_record = copy.deepcopy(observation)

    source_id = observation.get("id")
    if isinstance(source_id, str) and SCO_ID_PATTERN.match(source_id):
        observed_data_id = source_id
        output_observed_data_id = source_id
    else:
        output_observed_data_id = _synthetic_observed_data_id(observation)
        if isinstance(source_id, str) and source_id:
            # Keep the source record identifier as the lookup/diagnostic key
            # even if it is not itself a valid STIX 2.1 ID.
            observed_data_id = source_id
        else:
            observed_data_id = output_observed_data_id
        observation["id"] = output_observed_data_id

    context = _ObservationContext(
        observation,
        observed_data_id,
        source_record=source_record,
        output_observed_data_id=output_observed_data_id,
    )

    raw_objects = observation.get("objects")
    if not isinstance(raw_objects, collections.abc.Mapping):
        context.record(
            "",
            "objects",
            raw_objects,
            "observed-data 'objects' property is not an object mapping",
            kind="untranslatable-observation",
        )
        return context

    # Index every object first.  References may point forwards (or in a
    # cycle), so local targets must be known before any rewrite pass.
    for original_key, raw_object in raw_objects.items():
        local_id = str(original_key)
        raw_object = _as_plain(raw_object)

        if not isinstance(raw_object, collections.abc.Mapping):
            context.record(
                local_id,
                "objects.{}".format(local_id),
                raw_object,
                "embedded observable is not an object",
                kind="untranslatable-object",
            )
            continue

        object_type = raw_object.get("type")
        if not isinstance(object_type, str):
            context.record(
                local_id,
                "objects.{}".format(local_id),
                raw_object,
                "embedded observable has no type",
                kind="untranslatable-object",
            )
            continue

        context.local_objects[local_id] = raw_object
        context.types[local_id] = object_type
        context.classes[local_id] = class_for_type(
            object_type, "2.1", "observables",
        )
        context.is_custom_type[local_id] = (
            context.classes[local_id] is None or object_type.startswith("x-")
        )

    for local_id in sorted(context.local_objects, key=_natural_key):
        raw_object = context.local_objects[local_id]
        prepared = {
            key: value
            for key, value in raw_object.items()
            if key not in ("id", "spec_version") and not key.startswith("_")
        }
        prepared["type"] = context.types[local_id]
        context.prepared[local_id] = _rewrite_value(
            context,
            local_id,
            prepared,
            mode="prepare",
            custom_context=context.is_custom_type[local_id],
        )

    context.local_order = sorted(
        context.local_objects, key=_natural_key,
    )

    return context


def _assign_ids(context):
    pending = set(context.local_objects)

    while pending:
        progressed = False
        for local_id in sorted(pending, key=_natural_key):
            try:
                if _id_contributing_properties(context, local_id):
                    new_id = _standard_id(context, local_id)
                else:
                    new_id = _fallback_id(
                        context, local_id, "fallback-resolve",
                    )
            except _PendingReference:
                continue
            except Exception as exc:
                context.record(
                    local_id,
                    "",
                    context.local_objects[local_id],
                    "could not compute a STIX 2.1 ID: {}".format(exc),
                    kind="untranslatable-object",
                )
                new_id = _fallback_id(
                    context, local_id, "fallback-final",
                )

            context.ids[local_id] = new_id
            pending.remove(local_id)
            progressed = True

        if not progressed:
            # Cycles or references to objects with no content-derived ID.
            # Give each remaining object a stable, content-derived ID.
            for local_id in sorted(pending, key=_natural_key):
                context.ids[local_id] = _fallback_id(
                    context, local_id, "fallback-final",
                )
            pending.clear()


def _build_objects(context, allow_custom, interoperability):
    from .parsing import parse

    for local_id in context.local_order:
        final_object = _rewrite_value(
            context,
            local_id,
            context.prepared[local_id],
            mode="final",
        )
        final_object["type"] = context.types[local_id]
        final_object["id"] = context.ids[local_id]
        final_object["spec_version"] = "2.1"

        try:
            context.generated[local_id] = parse(
                final_object,
                allow_custom=allow_custom,
                interoperability=interoperability,
                version="2.1",
            )
        except Exception as exc:
            context.record(
                local_id,
                "",
                final_object,
                "STIX 2.1 object validation failed: {}".format(exc),
                kind="untranslatable-object",
            )
            if allow_custom:
                # Keep the translated content available, even though it could
                # not be instantiated as a registered STIX type.
                context.generated[local_id] = final_object


def _build_observed_data(context, allow_custom, interoperability):
    from .parsing import parse

    object_refs = []
    seen_ids = set()
    id_map = {}

    for local_id in context.local_order:
        generated = context.generated.get(local_id)
        if generated is None:
            continue

        new_id = generated["id"]
        id_map[local_id] = new_id
        if new_id not in seen_ids:
            object_refs.append(new_id)
            seen_ids.add(new_id)

    updated = {
        key: value
        for key, value in context.original.items()
        if key not in ("objects", "spec_version")
    }
    updated = _rewrite_value(
        context,
        "",
        updated,
        mode="final",
        custom_context=True,
    )
    # Avoid introducing nondeterministic conversion output when the source
    # observation omitted SDO bookkeeping timestamps.
    if "created" not in updated and "first_observed" in updated:
        updated["created"] = updated["first_observed"]
    if "modified" not in updated and "created" in updated:
        updated["modified"] = updated["created"]

    updated["spec_version"] = "2.1"
    updated["object_refs"] = object_refs

    try:
        observed_data = parse(
            updated,
            allow_custom=allow_custom,
            interoperability=interoperability,
            version="2.1",
        )
    except Exception as exc:
        context.record(
            "",
            "",
            updated,
            "observed-data could not be converted: {}".format(exc),
            kind="untranslatable-observation",
        )
        if allow_custom:
            # Preserve the rewritten record (and therefore the source
            # linkage) even when the strict 2.1 validation rules cannot be
            # satisfied, e.g. an observation whose embedded objects were all
            # untranslatable and which consequently has no object_refs.
            updated.setdefault("type", "observed-data")
            observed_data = updated
        else:
            observed_data = None

    return observed_data, id_map


class ObservedDataConversion:
    """Result of an offline observed-data conversion.

    The result can be unpacked as ``objects, id_map`` or accessed by
    attribute/key (``result.objects``, ``result["id_map"]``, ...).  In
    addition to the generated SCOs, the rewritten ``observed-data`` records
    are available as :attr:`observed_data` and in :attr:`all_objects`.
    """

    def __init__(
        self, objects, observed_data, id_map, unresolved, *,
        passthrough=(), source=None, observed_data_id_map=None,
    ):
        self.objects = ObjectCollection(objects)
        self.observed_data = ObjectCollection(observed_data)
        self.id_map = id_map if isinstance(id_map, ObservedDataIDMap) \
            else ObservedDataIDMap(id_map)
        self.unresolved = list(unresolved)
        self.passthrough = list(passthrough)
        self.source = source
        self.observed_data_id_map = dict(observed_data_id_map or {})
        self._bundle = None

    # Common aliases -----------------------------------------------------
    @property
    def observables(self):
        return self.objects

    @property
    def scos(self):
        return self.objects

    @property
    def converted_objects(self):
        return self.objects

    @property
    def observed_data_objects(self):
        return self.observed_data

    @property
    def observation_records(self):
        return self.observed_data

    @property
    def converted_observed_data(self):
        return self.observed_data[0] if self.observed_data else None

    @property
    def observed_data_object(self):
        return self.converted_observed_data

    @property
    def mapping(self):
        return self.id_map

    @property
    def id_mapping(self):
        return self.id_map

    @property
    def flat_id_map(self):
        return self.id_map.flat

    @property
    def string_id_map(self):
        return self.id_map.flat_strings

    @property
    def positions(self):
        return self.id_map.flat

    def positions_for(self, object_id):
        return self.id_map.positions(object_id)

    @property
    def reverse_id_map(self):
        reverse = {}
        for position, object_id in self.id_map.flat.items():
            reverse.setdefault(object_id, []).append(position)
        return reverse

    @property
    def diagnostics(self):
        return self.unresolved

    @property
    def all_diagnostics(self):
        return self.unresolved

    @property
    def unresolved_references(self):
        return [
            item for item in self.unresolved
            if item.kind == "unresolved-reference"
        ]

    @property
    def unresolved_refs(self):
        return self.unresolved_references

    @property
    def untranslatable(self):
        return self.untranslated

    @property
    def custom_unresolved(self):
        return [item for item in self.unresolved if item.custom]

    @property
    def standard_unresolved(self):
        return [item for item in self.unresolved if not item.custom]

    @property
    def untranslated(self):
        return [
            item for item in self.unresolved
            if item.kind != "unresolved-reference"
        ]

    @property
    def errors(self):
        return self.unresolved

    @property
    def issues(self):
        return self.unresolved

    @property
    def unresolved_map(self):
        return {
            (item.observed_data_id, item.local_id, item.path): item
            for item in self.unresolved
        }

    @property
    def warnings(self):
        return [item.reason for item in self.unresolved]

    @property
    def all_objects(self):
        return self.objects + self.observed_data + self.passthrough

    @property
    def object_map(self):
        return {
            obj["id"]: obj for obj in self.all_objects
            if isinstance(obj, collections.abc.Mapping) and "id" in obj
        }

    @property
    def objects_by_observation(self):
        grouped = {}
        by_id = {
            obj["id"]: obj for obj in self.objects
            if isinstance(obj, collections.abc.Mapping) and "id" in obj
        }
        for observation_id, local_map in self.id_map.items():
            grouped[observation_id] = [
                by_id[object_id]
                for object_id in dict.fromkeys(local_map.values())
                if object_id in by_id
            ]
        return grouped

    @property
    def by_id(self):
        return self.object_map

    @property
    def is_clean(self):
        return not self.unresolved

    @property
    def bundle(self):
        if self._bundle is None:
            from .v21 import Bundle

            self._bundle = Bundle(
                objects=list(self.all_objects), allow_custom=True,
            )
        return self._bundle

    def to_bundle(self, **kwargs):
        from .v21 import Bundle

        kwargs.setdefault("allow_custom", True)
        return Bundle(objects=list(self.all_objects), **kwargs)

    def to_dicts(self):
        """Return all converted content as plain dictionaries."""
        return [_as_plain(obj) for obj in self.all_objects]

    def to_dict(self):
        """Return the conversion result as a JSON-compatible mapping."""
        return {
            "objects": [_as_plain(obj) for obj in self.objects],
            "observed_data": [
                _as_plain(obj) for obj in self.observed_data
            ],
            "id_map": self.id_map.to_dict(),
            "unresolved": self.diagnostics_to_dicts(),
            "passthrough": [_as_plain(obj) for obj in self.passthrough],
            "observed_data_id_map": self.observed_data_id_map,
        }

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), **kwargs)

    def diagnostics_to_dicts(self):
        return [item.to_dict() for item in self.unresolved]

    def diagnostics_by_observation(self):
        grouped = {}
        for item in self.unresolved:
            grouped.setdefault(item.observed_data_id, []).append(item)
        return grouped

    unresolved_by_observation = diagnostics_by_observation

    def __iter__(self):
        yield self.objects
        yield self.id_map

    def __len__(self):
        return 2

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                return {
                    "objects": self.objects,
                    "observables": self.objects,
                    "scos": self.objects,
                    "observed_data": self.observed_data,
                    "observation_records": self.observed_data,
                    "id_map": self.id_map,
                    "id_mapping": self.id_map,
                    "mapping": self.id_map,
                    "unresolved": self.unresolved,
                    "diagnostics": self.unresolved,
                    "untranslated": self.untranslated,
                    "all_objects": self.all_objects,
                    "object_map": self.object_map,
                    "by_id": self.object_map,
                    "bundle": self.bundle,
                    "passthrough": self.passthrough,
                    "observed_data_id_map": self.observed_data_id_map,
                }[key]
            except KeyError:
                pass
        else:
            return (self.objects, self.id_map)[key]

        # Convenience: make the conversion result usable as a stand-in for
        # the first rewritten observed-data record.
        if self.observed_data:
            first = self.observed_data[0]
            if isinstance(key, str) and isinstance(
                first, collections.abc.Mapping,
            ):
                try:
                    return first[key]
                except KeyError:
                    pass
        raise KeyError(key)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            observed = object.__getattribute__(self, "observed_data")
        except AttributeError:
            raise AttributeError(name)
        if observed:
            first = observed[0]
            try:
                return getattr(first, name)
            except AttributeError:
                if isinstance(first, collections.abc.Mapping):
                    try:
                        return first[name]
                    except KeyError:
                        pass
        raise AttributeError(name)

    def keys(self):
        return (
            "objects", "observed_data", "id_map", "unresolved",
            "bundle", "all_objects", "passthrough",
        )

    def values(self):
        return tuple(self[key] for key in self.keys())

    def items(self):
        return tuple((key, self[key]) for key in self.keys())

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError, TypeError):
            return default


def _normalize_input(data):
    """Return ``(items, passthrough)`` for any supported input shape."""
    data = _load_data(data)

    if isinstance(data, collections.abc.Mapping) and data.get("type") == "bundle":
        items = list(data.get("objects", []))
    elif (
        isinstance(data, collections.abc.Mapping) and
        "type" not in data and data and
        all(
            isinstance(item, collections.abc.Mapping) and
            item.get("type") == "observed-data"
            for item in data.values()
        )
    ):
        # A mapping keyed by observation ID is also accepted.
        items = list(data.values())
    elif isinstance(data, (list, tuple)):
        items = list(data)
    elif isinstance(data, collections.abc.Iterable) and not isinstance(
        data, (str, bytes, bytearray, collections.abc.Mapping),
    ):
        items = list(data)
    else:
        items = [data]

    observations = []
    passthrough = []
    for item in items:
        if isinstance(item, (str, bytes, bytearray)):
            item = json.loads(item)
        item = _as_plain(item)
        if not isinstance(item, collections.abc.Mapping):
            passthrough.append(item)
            continue

        if item.get("type") == "bundle":
            nested_observations, nested_passthrough = _normalize_input(item)
            observations.extend(nested_observations)
            passthrough.extend(nested_passthrough)
        elif item.get("type") == "observed-data" and "objects" in item:
            observations.append(item)
        else:
            passthrough.append(item)

    return observations, passthrough


def _store_objects(store, objects):
    if hasattr(store, "add"):
        for obj in objects:
            store.add(obj)
    elif hasattr(store, "save"):
        for obj in objects:
            store.save(obj)
    elif hasattr(store, "extend"):
        store.extend(objects)
    else:
        raise TypeError("store must provide add(), save(), or extend()")


def convert_observed_data(
    data, allow_custom=True, interoperability=True,
    include_existing_observed_data=True, version=None, **kwargs,
):
    """Convert STIX 2.0 observed-data to referenceable STIX 2.1 content.

    Args:
        data: One observed-data object/dict, a sequence of them, a bundle,
            or the corresponding JSON text/file-like object.
        allow_custom (bool): Preserve custom content where possible.  This is
            enabled by default because imported observations commonly carry
            vendor extensions.
        interoperability (bool): Passed to the parser for liberal 2.1 ID
            handling.
        include_existing_observed_data (bool): Keep observed-data records
            which already have ``object_refs`` and no embedded ``objects`` in
            the passthrough content.

    Returns:
        ObservedDataConversion: Contains the generated SCOs, rewritten
        observed-data records, the position-to-ID map, and diagnostics for
        unresolved or untranslatable content.
    """
    store = kwargs.pop("store", None)
    if not isinstance(allow_custom, bool) and allow_custom is not None:
        if any(hasattr(allow_custom, name) for name in ("add", "save", "extend")):
            store = allow_custom
            allow_custom = True

    observations, passthrough = _normalize_input(data)
    if not include_existing_observed_data:
        passthrough = [
            item for item in passthrough
            if not (
                isinstance(item, collections.abc.Mapping) and
                item.get("type") == "observed-data"
            )
        ]

    contexts = [
        _prepare_observation(observation, allow_custom)
        for observation in observations
    ]
    contexts.sort(
        key=lambda context: (
            context.observed_data_id,
            _natural_key(context.observed_data_id),
        ),
    )

    generated_records = []
    observed_data_records = []
    nested_id_map = {}
    observed_data_id_map = {}
    diagnostics = []

    for context in contexts:
        _assign_ids(context)
        _build_objects(context, allow_custom, interoperability)
        context.finalize_diagnostics()
        observed_data, id_map = _build_observed_data(
            context, allow_custom, interoperability,
        )

        diagnostics.extend(context.diagnostics)
        nested_id_map[context.observed_data_id] = id_map
        observed_data_id_map[
            context.observed_data_id
        ] = context.output_observed_data_id

        if observed_data is not None:
            observed_data_records.append(observed_data)

        for local_id in context.local_order:
            generated = context.generated.get(local_id)
            if generated is not None:
                generated_records.append(
                    (
                        context.observed_data_id,
                        _natural_key(local_id),
                        generated,
                    ),
                )

    deduplicated = {}
    for observation_id, local_order, generated in generated_records:
        object_id = generated["id"]
        existing = deduplicated.get(object_id)
        if existing is None or (
            observation_id, local_order,
        ) < (existing[0], existing[1]):
            deduplicated[object_id] = (
                observation_id, local_order, generated,
            )

    objects = [
        entry[2] for entry in sorted(
            deduplicated.values(),
            key=lambda entry: (entry[0], entry[1]),
        )
    ]

    # An observation which had no embedded objects mapping may still have
    # produced a diagnostic; retain its record if it was otherwise valid.
    if not observed_data_records and not contexts:
        observed_data_records = []

    result = ObservedDataConversion(
        objects=objects,
        observed_data=observed_data_records,
        id_map=ObservedDataIDMap(nested_id_map),
        unresolved=diagnostics,
        passthrough=passthrough,
        source=data,
        observed_data_id_map=observed_data_id_map,
    )

    on_unresolved = kwargs.get("on_unresolved", "record")
    raise_on_unresolved = kwargs.get("raise_on_unresolved", False)
    if result.unresolved and (
        raise_on_unresolved or kwargs.get("strict", False) or
        on_unresolved in ("error", "raise", "strict")
    ):
        raise ObservedDataConversionError(result)

    # Make converted observed-data records addressable by their source
    # record IDs as well, even when an invalid source ID had to be replaced.
    for source_id, output_id in observed_data_id_map.items():
        record = result.observed_data.get(output_id)
        if record is not None:
            result.observed_data._by_id[source_id] = record

    if store is not None:
        _store_objects(store, result.all_objects)

    return result


class ObservedDataConversionError(ValueError):
    """Raised when unresolved content is encountered in strict mode."""

    def __init__(self, result):
        self.result = result
        self.diagnostics = result.unresolved
        super().__init__(
            "observed-data conversion left {} unresolved item(s)".format(
                len(result.unresolved),
            ),
        )


class ObservedDataConverter:
    """Reusable converter configured with default conversion options."""

    def __init__(self, **options):
        self.options = options

    def convert(self, data, **kwargs):
        options = dict(self.options)
        options.update(kwargs)
        return convert_observed_data(data, **options)

    __call__ = convert
    run = convert
    import_data = convert


ConversionResult = ObservedDataConversion
Converter = ObservedDataConverter
ObservedDataImporter = ObservedDataConverter
IDMap = ObservedDataIDMap
Diagnostic = UnresolvedReference
UnresolvedContent = UnresolvedReference


# Descriptive aliases: callers may use whichever name matches their import
# layer conventions.
convert_observed_data_to_v21 = convert_observed_data
convert_observed_data_2_0_to_2_1 = convert_observed_data
convert_observed_data_to_2_1 = convert_observed_data
convert_observed_data_v20_to_v21 = convert_observed_data
convert_observed_data_v20_to_21 = convert_observed_data
convert_observed_data_to_21 = convert_observed_data
migrate_observed_data = convert_observed_data
migrate_observed_data_to_v21 = convert_observed_data
observed_data_to_v21 = convert_observed_data
observed_data_to_21 = convert_observed_data
upgrade_observed_data = convert_observed_data
extract_observed_data_objects = convert_observed_data
extract_observed_objects = convert_observed_data
observed_data_to_objects = convert_observed_data


def import_observed_data(data, store=None, **kwargs):
    """Convert observed-data and optionally write the result to a sink.

    ``store`` may be a datastore sink with an ``add()`` method, an object with
    ``save()``, or a list-like container.  The conversion result is returned
    in all cases so callers can inspect IDs and diagnostics.
    """
    if isinstance(store, bool):
        kwargs["allow_custom"] = store
        store = None

    result = convert_observed_data(data, **kwargs)
    if store is not None:
        _store_objects(store, result.all_objects)
    return result


__all__ = [
    "ConversionResult",
    "Converter",
    "Diagnostic",
    "IDMap",
    "ObjectCollection",
    "ObservedDataConversion",
    "ObservedDataConversionError",
    "ObservedDataConverter",
    "ObservedDataIDMap",
    "ObservedDataImporter",
    "UnresolvedContent",
    "UnresolvedReference",
    "convert_observed_data",
    "convert_observed_data_2_0_to_2_1",
    "convert_observed_data_to_2_1",
    "convert_observed_data_to_21",
    "convert_observed_data_to_v21",
    "convert_observed_data_v20_to_21",
    "convert_observed_data_v20_to_v21",
    "extract_observed_data_objects",
    "extract_observed_objects",
    "import_observed_data",
    "migrate_observed_data",
    "migrate_observed_data_to_v21",
    "observed_data_to_21",
    "observed_data_to_objects",
    "observed_data_to_v21",
    "upgrade_observed_data",
]
