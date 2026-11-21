"""Caller-aware STIX Bundle export.

The functions in this module implement a fail-closed export filter for STIX
Bundles.  A caller supplies the marking definitions they are allowed to
receive; objects marked with anything else are withheld, and granular
markings can cause optional properties (including list elements) to be
removed.  The included export report deliberately contains no identifiers of
objects which were withheld.

The public entry point is :func:`export_bundle`.  It returns an
``ExportedBundle``: a normal :class:`stix2.Bundle` with an additional
``report`` attribute.  For convenience it can also be unpacked as
``bundle, report = export_bundle(...)``.
"""

import copy
import re
from collections import OrderedDict, abc

import simplejson

from .base import _STIXBase
from .exceptions import (
    AtLeastOnePropertyError, MissingPropertiesError, PropertyPresenceError,
)
from .parsing import parse
from .registry import class_for_type
from .utils import detect_spec_version
from .v20.bundle import Bundle as _Bundle20
from .v21.bundle import Bundle as _Bundle21

__all__ = [
    "ExportedBundle",
    "ExportReport",
    "MarkingPolicy",
    "export_bundle",
    "export_bundle_for_caller",
    "export_bundle_by_markings",
    "export_bundle_for_markings",
    "export_bundle_with_report",
    "export_for_caller",
    "filter_bundle",
    "filter_bundle_by_markings",
    "redact_bundle",
    "sanitize_bundle",
]


# Canonical TLP marking definitions.  Both STIX 2.0 and 2.1 use these IDs.
_TLP_MARKINGS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": ("white", 0, "TLP:WHITE"),
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": ("green", 1, "TLP:GREEN"),
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": ("amber", 2, "TLP:AMBER"),
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": ("red", 3, "TLP:RED"),
}

_TLP_ALIASES = {}
_TLP_LEVELS = {}
for _marking_id, (_color, _level, _name) in _TLP_MARKINGS.items():
    for _alias in (
        _marking_id, _color, _name, _name.lower(), _name.replace("TLP:", "").lower(),
    ):
        _TLP_ALIASES[_alias] = _marking_id
    _TLP_LEVELS[_marking_id] = _level
_TLP_ALIASES["clear"] = _TLP_ALIASES["white"]
_TLP_ALIASES["TLP:CLEAR"] = _TLP_ALIASES["white"]


_REMOVE = object()


class ExportReport(dict):
    """Dictionary-like report describing what an export withheld.

    Report entries never contain the identifier of a withheld object.  They
    identify entries by their position in the input bundle and by object type
    so that an analyst can correlate them without leaking restricted IDs.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class MarkingPolicy:
    """The set of marking definitions (and languages) a caller may receive.

    ``allowed_markings`` may contain marking definition IDs, marking
    definition objects, or TLP names/colors.  TLP markings are treated as a
    clearance hierarchy by default (if a caller can receive TLP:AMBER they can
    also receive TLP:WHITE and TLP:GREEN).  Set ``tlp_hierarchy=False`` for
    exact-ID matching.
    """

    def __init__(
        self, allowed_markings=None, *, tlp_hierarchy=None,
        allowed_languages=None, include_unmarked=True,
    ):
        self.allowed_ids = set()
        self.tlp_levels = set()
        self.allow_all = False
        self.allowed_languages = (
            None if allowed_languages is None else set(_as_list(allowed_languages))
        )
        self.include_unmarked = bool(include_unmarked)

        self._add_markings(allowed_markings)

        if tlp_hierarchy is None:
            tlp_hierarchy = bool(self.tlp_levels)
        self.tlp_hierarchy = bool(tlp_hierarchy)
        self.tlp_clearance = max(self.tlp_levels) if self.tlp_levels else None

    def _add_markings(self, markings):
        if markings is None or markings is False:
            return
        if markings is True:
            self.allow_all = True
            return

        if isinstance(markings, str):
            markings = [markings]
        elif isinstance(markings, abc.Mapping):
            if _looks_like_marking_definition(markings):
                markings = [markings]
            else:
                markings = [key for key, value in markings.items() if value]

        for marking in markings:
            self._add_marking(marking)

    def _add_marking(self, marking):
        if marking is True or marking in ("*", "all", "ALL"):
            self.allow_all = True
            return

        marking_id = _marking_id(marking)
        if marking_id in ("*", "all", "ALL"):
            self.allow_all = True
            return
        if marking_id is None:
            return

        tlp_id = _TLP_ALIASES.get(marking_id)
        if tlp_id is not None:
            self.allowed_ids.add(tlp_id)
            self.tlp_levels.add(_TLP_LEVELS[tlp_id])
            return

        tlp_info = _tlp_info(marking)
        if tlp_info is not None:
            tlp_id, level = tlp_info
            self.allowed_ids.add(tlp_id)
            self.tlp_levels.add(level)
            return

        self.allowed_ids.add(marking_id)

    def allows_marking(self, marking):
        if marking is None:
            return True
        if self.allow_all:
            return True

        marking_id = _marking_id(marking)
        if marking_id in self.allowed_ids:
            return True

        if self.tlp_hierarchy and marking_id in _TLP_LEVELS:
            return (
                self.tlp_clearance is not None
                and _TLP_LEVELS[marking_id] <= self.tlp_clearance
            )

        return False

    def allows_language(self, language):
        if language is None or self.allowed_languages is None:
            return True
        return language in self.allowed_languages

    def __contains__(self, marking):
        return self.allows_marking(marking)


class _ExportedBundleMixin:
    """Bundle behaviour plus export report access and tuple-like unpacking."""

    @property
    def bundle(self):
        return self

    @property
    def report(self):
        return self._export_report

    @property
    def export_report(self):
        return self._export_report

    @property
    def diagnostics(self):
        return self._export_report.get("diagnostics", [])

    @property
    def excluded(self):
        return self._export_report.get("excluded", [])

    @property
    def redacted(self):
        return self._export_report.get("redacted", [])

    @property
    def relationships(self):
        return self._export_report.get("relationships", [])

    @property
    def exported(self):
        return self._export_report.get("exported", [])

    def keys(self):
        return self._inner.keys()

    def items(self):
        return self._inner.items()

    def values(self):
        return self._inner.values()

    def __iter__(self):
        yield self
        yield self._export_report

    def __repr__(self):
        return "ExportedBundle(%s)" % dict(self)


class ExportedBundle(_ExportedBundleMixin, _Bundle21):
    """A STIX 2.1 Bundle carrying an :class:`ExportReport`."""

    def __init__(self, *args, report=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._export_report = report if report is not None else ExportReport()


class _ExportedBundle20(_ExportedBundleMixin, _Bundle20):
    def __init__(self, *args, report=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._export_report = report if report is not None else ExportReport()


def export_bundle(
    bundle, allowed_markings=None, *, permissions=None, caller_permissions=None,
    allowed=None, allowed_marking_refs=None, marking_permissions=None,
    allowed_marking_ids=None, caller_markings=None, permitted_markings=None,
    tlp_hierarchy=None, allowed_languages=None, include_unmarked=True,
    **kwargs,
):
    """Export a Bundle containing only content the caller may receive.

    Args:
        bundle: A :class:`stix2.Bundle`, a bundle dictionary, JSON string, or
            file-like object containing one.
        allowed_markings: Marking definition IDs, marking definition objects,
            or TLP labels the caller is permitted to receive.  May also be a
            :class:`MarkingPolicy`.
        permissions, caller_permissions, allowed, allowed_marking_refs,
        marking_permissions, allowed_marking_ids, caller_markings,
        permitted_markings: Aliases for ``allowed_markings``.
        tlp_hierarchy (bool): Treat TLP markings as a clearance hierarchy.
            Defaults to ``True`` when TLP markings are supplied.
        allowed_languages: Optional iterable of language codes a caller may
            receive.  By default language granular markings do not restrict
            content.
        include_unmarked (bool): Include objects with no object-level marking.

    Returns:
        ExportedBundle: The filtered bundle.  Its ``report`` attribute (also
        available via unpacking as ``bundle, report = export_bundle(...)``)
        describes withheld content without disclosing withheld object IDs.

    Notes:
        Object-level markings are evaluated before granular markings.  A
        disallowed object-level marking withholds the entire object.  A
        disallowed granular marking removes the selected value (or list
        element); if that value is required, the whole object is withheld.
        Relationships whose endpoints are not exported are withheld and
        reported with a non-identifying reason.
    """
    permission_sources = [
        value for value in (
            allowed_markings, permissions, caller_permissions, allowed,
            allowed_marking_refs, marking_permissions, allowed_marking_ids,
            caller_markings, permitted_markings,
        ) if value is not None
    ]
    if len(permission_sources) > 1:
        raise TypeError("specify marking permissions only once")

    if not kwargs:
        pass
    else:
        unexpected = sorted(kwargs)
        raise TypeError(
            "unexpected keyword argument(s): %s" % ", ".join(unexpected),
        )

    policy = permission_sources[0] if permission_sources else allowed_markings
    if not isinstance(policy, MarkingPolicy):
        policy = MarkingPolicy(
            policy,
            tlp_hierarchy=tlp_hierarchy,
            allowed_languages=allowed_languages,
            include_unmarked=include_unmarked,
        )
    elif allowed_languages is not None or tlp_hierarchy is not None or not include_unmarked:
        policy = MarkingPolicy(
            policy.allowed_ids | set(_TLP_ALIASES[c] for level in policy.tlp_levels
                                     for c, l, _ in _TLP_MARKINGS.values() if l == level),
            tlp_hierarchy=policy.tlp_hierarchy if tlp_hierarchy is None else tlp_hierarchy,
            allowed_languages=policy.allowed_languages if allowed_languages is None else allowed_languages,
            include_unmarked=include_unmarked,
        )
        if policy.allow_all:
            policy.allow_all = True

    plain_bundle = _load_bundle(bundle)
    version = _bundle_version(plain_bundle)
    original_objects = plain_bundle.get("objects") or []

    original_ids = set()
    for obj in original_objects:
        if isinstance(obj, abc.Mapping) and obj.get("id"):
            original_ids.add(obj["id"])

    records = []
    candidates = OrderedDict()
    excluded = {}

    for position, obj in enumerate(original_objects):
        if not isinstance(obj, abc.Mapping):
            excluded[position] = {
                "type": None,
                "position": position,
                "reason": "object_not_exportable",
                "message": "The object is not a STIX object.",
            }
            continue

        record = {
            "position": position,
            "original": obj,
            "type": obj.get("type"),
            "id": obj.get("id"),
            "policy": policy,
            "required": _required_properties(obj, version),
            "restrictions": _granular_restrictions(obj, policy),
        }
        records.append(record)

        if not record["id"]:
            excluded[position] = _excluded_entry(
                record, "object_not_exportable",
                "The object has no identifier and cannot be exported.",
            )
            continue

        if not _object_marking_allowed(obj, policy):
            excluded[position] = _excluded_entry(
                record, "object_marking_not_permitted",
                "The object is marked with a marking the caller is not permitted to receive.",
            )
            continue

        candidates[position] = record

    dropped_positions = set()
    while True:
        available_ids = {
            record["id"] for position, record in candidates.items()
            if position not in dropped_positions
        }
        new_drops = []
        redactions = {}

        for position, record in candidates.items():
            if position in dropped_positions:
                continue
            try:
                outcome = _redact_object(
                    record, available_ids, original_ids, version,
                )
            except Exception:
                outcome = _failure(
                    "object_not_exportable",
                    "The object could not be safely redacted.",
                    record,
                )
            if outcome["ok"]:
                redactions[position] = outcome
            else:
                new_drops.append((position, outcome))

        if not new_drops:
            break

        for position, outcome in new_drops:
            dropped_positions.add(position)
            excluded[position] = _excluded_entry(
                candidates[position], outcome["reason"], outcome["message"],
                endpoint=outcome.get("endpoint"),
                property_name=outcome.get("property"),
            )

    exported = []
    redacted_entries = []
    for position, record in candidates.items():
        if position in dropped_positions:
            continue
        outcome = redactions.get(position)
        if outcome is None:
            try:
                outcome = _redact_object(record, {
                    other["id"] for other in records
                    if other["position"] not in excluded
                    and other["position"] not in dropped_positions
                }, original_ids, version)
            except Exception:
                continue
        if not outcome["ok"]:
            continue
        exported.append((position, outcome["object"]))

        removed_selectors = outcome.get("removed_selectors", [])
        removed_refs = outcome.get("removed_refs", [])
        if removed_selectors or removed_refs:
            reason = (
                "granular_marking_not_permitted"
                if removed_selectors else "referenced_object_not_available"
            )
            entry = {
                "type": record["type"],
                "id": record["id"],
                "position": position,
                "action": "redacted",
                "reason": reason,
                "reason_code": reason,
            }
            if removed_selectors:
                entry["selectors"] = sorted(removed_selectors)
            if removed_refs:
                entry["properties"] = sorted(removed_refs)
                entry["message"] = (
                    "References to objects which are not available to the caller were removed."
                )
            redacted_entries.append(entry)
            record["has_redactions"] = True

    exported_ids = [
        obj.get("id") for _, obj in exported
        if isinstance(obj, abc.Mapping) and obj.get("id")
    ]

    output_bundle = _build_bundle(
        plain_bundle, [obj for _, obj in exported], version,
    )
    report = _build_report(
        output_bundle, len(original_objects), exported_ids,
        excluded, redacted_entries,
    )
    return _wrap_bundle(output_bundle, report, version)


def filter_bundle(bundle, allowed_markings=None, **kwargs):
    """Alias for :func:`export_bundle`."""
    return export_bundle(bundle, allowed_markings, **kwargs)


def redact_bundle(bundle, allowed_markings=None, **kwargs):
    """Alias for :func:`export_bundle`."""
    return export_bundle(bundle, allowed_markings, **kwargs)


def export_bundle_for_caller(bundle, allowed_markings=None, **kwargs):
    """Alias for :func:`export_bundle`."""
    return export_bundle(bundle, allowed_markings, **kwargs)


def export_for_caller(bundle, allowed_markings=None, **kwargs):
    """Alias for :func:`export_bundle`."""
    return export_bundle(bundle, allowed_markings, **kwargs)


def export_bundle_for_markings(bundle, allowed_markings=None, **kwargs):
    return export_bundle(bundle, allowed_markings, **kwargs)


def export_bundle_by_markings(bundle, allowed_markings=None, **kwargs):
    return export_bundle(bundle, allowed_markings, **kwargs)


def filter_bundle_by_markings(bundle, allowed_markings=None, **kwargs):
    return export_bundle(bundle, allowed_markings, **kwargs)


def sanitize_bundle(bundle, allowed_markings=None, **kwargs):
    return export_bundle(bundle, allowed_markings, **kwargs)


def export_bundle_with_report(bundle, allowed_markings=None, **kwargs):
    result = export_bundle(bundle, allowed_markings, **kwargs)
    return result.bundle, result.report


def _as_list(value):
    if isinstance(value, str):
        return [value]
    return list(value)


def _to_plain(value):
    if isinstance(value, _STIXBase):
        return {key: _to_plain(child) for key, child in value.items()}
    if isinstance(value, abc.Mapping):
        return {key: _to_plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_plain(child) for child in value]
    return copy.deepcopy(value)


def _load_bundle(bundle):
    if isinstance(bundle, (bytes, bytearray)):
        bundle = bundle.decode("utf-8")

    if isinstance(bundle, str):
        data = simplejson.loads(bundle)
    elif hasattr(bundle, "read"):
        data = simplejson.load(bundle)
    else:
        data = bundle

    data = _to_plain(data)
    if isinstance(data, list):
        data = {"type": "bundle", "objects": data}

    if not isinstance(data, abc.Mapping) or data.get("type") != "bundle":
        raise ValueError("bundle must be a STIX Bundle")

    data = dict(data)
    data.setdefault("objects", [])
    return data


def _bundle_version(bundle):
    if bundle.get("spec_version") == "2.0":
        return "2.0"
    try:
        return detect_spec_version(bundle)
    except Exception:
        return "2.1"


def _looks_like_marking_definition(value):
    return (
        isinstance(value, abc.Mapping)
        and value.get("type") == "marking-definition"
    )


def _marking_id(marking):
    if marking is None:
        return None
    if isinstance(marking, str):
        return marking
    if isinstance(marking, abc.Mapping):
        return marking.get("id")
    return getattr(marking, "id", None)


def _tlp_info(marking):
    """Return ``(canonical_id, level)`` for a TLP MarkingDefinition."""
    if isinstance(marking, abc.Mapping):
        marking_id = marking.get("id")
        name = marking.get("name") or ""
        definition = marking.get("definition") or {}
        color = definition.get("tlp") if isinstance(definition, abc.Mapping) else None
    else:
        marking_id = getattr(marking, "id", None)
        name = getattr(marking, "name", "") or ""
        definition = getattr(marking, "definition", None)
        color = getattr(definition, "tlp", None) if definition is not None else None

    if not color:
        match = re.search(r"TLP\s*:\s*(white|clear|green|amber|red)", name, re.I)
        if match:
            color = match.group(1)
    if not color:
        return None

    color = str(color).lower()
    if color == "clear":
        color = "white"
    for tlp_id, (known_color, level, _) in _TLP_MARKINGS.items():
        if known_color == color:
            return marking_id or tlp_id, level
    return None


def _required_properties(obj, version):
    obj_type = obj.get("type")
    if not obj_type:
        return set()
    cls = class_for_type(obj_type, version, "objects")
    if cls is None:
        return set()
    return {
        name for name, prop in cls._properties.items()
        if getattr(prop, "required", False)
    }


def _object_marking_allowed(obj, policy):
    # Marking definitions are metadata needed to interpret references made by
    # the remaining objects; they are not themselves subject to their own
    # marking definitions.
    if obj.get("type") == "marking-definition":
        return True

    markings = obj.get("object_marking_refs") or []
    if not markings:
        return policy.include_unmarked
    return all(policy.allows_marking(marking) for marking in markings)


def _granular_restrictions(obj, policy):
    restrictions = []
    for granular in obj.get("granular_markings") or []:
        if not isinstance(granular, abc.Mapping):
            continue

        marking_ref = granular.get("marking_ref")
        language = granular.get("lang")
        allowed = True
        if marking_ref is not None:
            allowed = policy.allows_marking(marking_ref)
        if language is not None:
            allowed = allowed and policy.allows_language(language)

        if allowed:
            continue

        for selector in granular.get("selectors") or []:
            tokens = _parse_selector(selector)
            if tokens:
                restrictions.append(tokens)
    return restrictions


_SELECTOR_PART = re.compile(r"^\[(\d+)\]$")
_SELECTOR_INLINE_INDEX = re.compile(r"^(.*?)((?:\[\d+\])+)$")


def _parse_selector(selector):
    if not isinstance(selector, str) or not selector:
        return None

    tokens = []
    for part in selector.split("."):
        if not part:
            return None
        match = _SELECTOR_PART.match(part)
        if match:
            tokens.append(int(match.group(1)))
            continue

        # Also accept the common non-spec form "foo[0]" for robustness.
        inline = _SELECTOR_INLINE_INDEX.match(part)
        if inline and inline.group(1):
            tokens.append(inline.group(1))
            tokens.extend(
                int(index) for index in re.findall(r"\[(\d+)\]", inline.group(2))
            )
            continue

        tokens.append(part)

    return tuple(tokens)


def _format_selector(tokens):
    return ".".join(
        "[%d]" % token if isinstance(token, int) else token
        for token in tokens
    )


def _is_restricted(path, restrictions):
    for restriction in restrictions:
        if path[:len(restriction)] == restriction:
            return True
    return False


def _is_empty_container(value):
    return (isinstance(value, list) and not value) or (
        isinstance(value, abc.Mapping) and not value
    )


def _walk_restrictions(
    node, original_path, new_path, restrictions, path_map,
):
    if _is_restricted(original_path, restrictions):
        return _REMOVE

    if isinstance(node, abc.Mapping):
        result = {}
        for key, value in node.items():
            original_child = original_path + (key,)
            new_child = new_path + (key,)
            walked = _walk_restrictions(
                value, original_child, new_child, restrictions, path_map,
            )
            if walked is _REMOVE or _is_empty_container(walked):
                continue
            result[key] = walked
            path_map[original_child] = new_child
        return result

    if isinstance(node, list):
        result = []
        for index, value in enumerate(node):
            original_child = original_path + (index,)
            new_child = new_path + (len(result),)
            walked = _walk_restrictions(
                value, original_child, new_child, restrictions, path_map,
            )
            if walked is _REMOVE or _is_empty_container(walked):
                continue
            result.append(walked)
            path_map[original_child] = new_child
        return result

    return copy.deepcopy(node)


def _get_at_path(value, path):
    current = value
    for token in path:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                return _REMOVE
            current = current[token]
        else:
            if not isinstance(current, abc.Mapping) or token not in current:
                return _REMOVE
            current = current[token]
    return current


def _scrub_references(
    node, original_path, new_path, available_ids, original_ids,
    required_names, path_map, removed_refs, top_level=True,
):
    if isinstance(node, abc.Mapping):
        result = {}
        required_missing = None

        for key, value in node.items():
            if key in ("granular_markings", "object_marking_refs"):
                result[key] = copy.deepcopy(value)
                path_map[original_path + (key,)] = new_path + (key,)
                continue

            child_original = original_path + (key,)
            child_new = new_path + (key,)
            is_required = top_level and key in required_names

            if key.endswith("_ref") and isinstance(value, str):
                if _is_unavailable_ref(value, available_ids, original_ids):
                    if is_required:
                        required_missing = key
                    else:
                        removed_refs.add(_format_selector(child_original))
                    continue
                result[key] = value
                path_map[child_original] = child_new
                continue

            if key.endswith("_refs") and isinstance(value, list):
                kept = []
                for index, ref in enumerate(value):
                    item_original = child_original + (index,)
                    item_new = child_new + (len(kept),)
                    if isinstance(ref, str) and _is_unavailable_ref(
                        ref, available_ids, original_ids,
                    ):
                        removed_refs.add(_format_selector(item_original))
                        continue
                    kept.append(copy.deepcopy(ref))
                    path_map[item_original] = item_new

                if not kept:
                    if is_required:
                        required_missing = key
                    else:
                        removed_refs.add(_format_selector(child_original))
                    continue

                result[key] = kept
                path_map[child_original] = child_new
                continue

            scrubbed = _scrub_references(
                value, child_original, child_new, available_ids,
                original_ids, set(), path_map, removed_refs,
                top_level=False,
            )
            if scrubbed is _REMOVE or _is_empty_container(scrubbed):
                if is_required:
                    required_missing = key
                continue
            result[key] = scrubbed
            path_map[child_original] = child_new

        if required_missing is not None:
            return _RefScrubFailure(required_missing)
        return result

    if isinstance(node, list):
        result = []
        for index, value in enumerate(node):
            item_original = original_path + (index,)
            item_new = new_path + (len(result),)
            scrubbed = _scrub_references(
                value, item_original, item_new, available_ids,
                original_ids, set(), path_map, removed_refs,
                top_level=False,
            )
            if scrubbed is _REMOVE or _is_empty_container(scrubbed):
                continue
            result.append(scrubbed)
            path_map[item_original] = item_new
        return result

    return copy.deepcopy(node)


class _RefScrubFailure:
    def __init__(self, property_name):
        self.property_name = property_name


def _is_unavailable_ref(ref, available_ids, original_ids):
    return ref in original_ids and ref not in available_ids


def _compose_path(original_path, restriction_map, ref_map):
    intermediate = restriction_map.get(original_path)
    if intermediate is None:
        return None
    return ref_map.get(intermediate)


def _rewrite_granular_markings(
    original_obj, output_obj, restriction_map, ref_map, policy,
):
    rewritten = []
    removed_selectors = set()

    for granular in original_obj.get("granular_markings") or []:
        if not isinstance(granular, abc.Mapping):
            continue

        marking_ref = granular.get("marking_ref")
        language = granular.get("lang")
        allowed = True
        if marking_ref is not None:
            allowed = policy.allows_marking(marking_ref)
        if language is not None:
            allowed = allowed and policy.allows_language(language)

        selectors = []
        for selector in granular.get("selectors") or []:
            tokens = _parse_selector(selector)
            if not tokens:
                continue

            if not allowed:
                removed_selectors.add(selector)
                continue

            mapped = _compose_path(tokens, restriction_map, ref_map)
            if mapped is None or _get_at_path(output_obj, mapped) is _REMOVE:
                removed_selectors.add(selector)
                continue
            selectors.append(_format_selector(mapped))

        if allowed and selectors:
            entry = copy.deepcopy(dict(granular))
            entry["selectors"] = sorted(set(selectors))
            rewritten.append(entry)

    return rewritten, removed_selectors


def _redact_object(record, available_ids, original_ids, version):
    original = record["original"]
    restrictions = record["restrictions"]

    restriction_map = {}
    redacted = _walk_restrictions(
        original, (), (), restrictions, restriction_map,
    )

    if redacted is _REMOVE or _is_empty_container(redacted):
        return _failure(
            "required_property_not_permitted" if restrictions
            else "object_not_exportable",
            "Required content could not be disclosed, so the object was withheld.",
            record,
        )

    required = set(record["required"])
    for identity_property in ("type", "id", "spec_version"):
        if identity_property in original:
            required.add(identity_property)

    missing_required = required - set(redacted)
    if missing_required:
        return _failure(
            "required_property_not_permitted" if restrictions
            else "required_property_missing",
            "A required property could not be disclosed, so the object was withheld.",
            record,
            property_name=sorted(missing_required)[0],
        )

    ref_map = {}
    removed_refs = set()
    scrubbed = _scrub_references(
        redacted, (), (), available_ids, original_ids,
        required, ref_map, removed_refs, top_level=True,
    )
    if isinstance(scrubbed, _RefScrubFailure):
        missing_property = scrubbed.property_name
        relation_endpoint = (
            record["type"] == "relationship"
            and missing_property in ("source_ref", "target_ref")
        ) or (
            record["type"] == "sighting"
            and missing_property == "sighting_of_ref"
        ) or (
            record["type"] == "language-content"
            and missing_property == "object_ref"
        )
        reason = (
            "relationship_endpoint_not_available"
            if relation_endpoint
            else "required_reference_not_available"
        )
        return _failure(
            reason,
            "A required relationship endpoint or referenced object is not available to the caller.",
            record,
            endpoint=missing_property
            if reason == "relationship_endpoint_not_available" else None,
            property_name=missing_property,
        )

    if _is_empty_container(scrubbed):
        return _failure(
            "object_not_exportable",
            "No disclosable content remained in the object.",
            record,
        )

    rewritten, removed_selectors = _rewrite_granular_markings(
        original, scrubbed, restriction_map, ref_map, record["policy"],
    )
    if original.get("granular_markings"):
        if rewritten:
            scrubbed["granular_markings"] = rewritten
        else:
            scrubbed.pop("granular_markings", None)

    try:
        parsed = parse(scrubbed, allow_custom=True, version=version)
    except (MissingPropertiesError, AtLeastOnePropertyError):
        return _failure(
            "required_property_not_permitted" if restrictions
            else "required_property_missing",
            "A required property could not be preserved, so the object was withheld.",
            record,
        )
    except PropertyPresenceError:
        return _failure(
            "object_not_exportable",
            "The redacted object could not be represented as valid STIX.",
            record,
        )
    except Exception as exc:
        if _caused_by_required_property_error(exc):
            return _failure(
                "required_property_not_permitted" if restrictions
                else "required_property_missing",
                "A required property could not be preserved, so the object was withheld.",
                record,
            )
        return _failure(
            "object_not_exportable",
            "The redacted object could not be represented as valid STIX.",
            record,
        )

    return {
        "ok": True,
        "object": parsed,
        "removed_selectors": removed_selectors,
        "removed_refs": removed_refs,
    }


def _failure(reason, message, record, endpoint=None, property_name=None):
    outcome = {
        "ok": False,
        "reason": reason,
        "message": message,
    }
    if endpoint:
        outcome["endpoint"] = endpoint
    if property_name:
        outcome["property"] = property_name
    return outcome


def _caused_by_required_property_error(exc):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, (MissingPropertiesError, AtLeastOnePropertyError)):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _excluded_entry(
    record, reason, message, endpoint=None, property_name=None,
):
    entry = {
        "type": record["type"],
        "position": record["position"],
        "reason": reason,
        "reason_code": reason,
        "message": message,
        "disclosure_reason": message,
    }
    if endpoint:
        entry["endpoint"] = endpoint
    if property_name:
        entry["property"] = property_name
    return entry


def _build_bundle(original_bundle, objects, version):
    bundle = {}
    if "id" in original_bundle:
        bundle["id"] = original_bundle["id"]
    else:
        bundle["id"] = "bundle--00000000-0000-4000-8000-000000000000"
    bundle["type"] = "bundle"
    if version == "2.0":
        bundle["spec_version"] = "2.0"
    if objects:
        bundle["objects"] = objects
        return parse(bundle, allow_custom=True)
    # detect_spec_version() cannot infer a version from an empty objects
    # list, so build the (valid) empty bundle directly.
    bundle_cls = _Bundle20 if version == "2.0" else _Bundle21
    return bundle_cls(allow_custom=True, **bundle)


def _wrap_bundle(bundle, report, version):
    values = dict(bundle)
    if version == "2.0":
        return _ExportedBundle20(report=report, allow_custom=True, **values)
    return ExportedBundle(report=report, allow_custom=True, **values)


def _build_report(bundle, input_count, exported_ids, excluded, redacted):
    excluded_entries = [
        excluded[position] for position in sorted(excluded)
    ]
    diagnostics = []
    diagnostics.extend(excluded_entries)
    diagnostics.extend(redacted)
    relationships = [
        entry for entry in excluded_entries
        if entry.get("type") == "relationship"
        or entry.get("reason") == "relationship_endpoint_not_available"
    ]

    return ExportReport(
        {
            "bundle_id": bundle.get("id"),
            "input_count": input_count,
            "exported": list(exported_ids),
            "exported_count": len(exported_ids),
            "excluded": excluded_entries,
            "excluded_count": len(excluded_entries),
            "excluded_reasons": [entry.get("reason") for entry in excluded_entries],
            "redacted": redacted,
            "redacted_count": len(redacted),
            "redacted_reasons": [entry.get("reason") for entry in redacted],
            "diagnostics": diagnostics,
            "withheld": excluded_entries,
            "dropped_objects": excluded_entries,
            "redactions": redacted,
            "relationships": relationships,
            "dropped_relationships": relationships,
        },
    )
