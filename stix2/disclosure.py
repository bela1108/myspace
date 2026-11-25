"""Stable disclosure projections and externally observable diffs.

This module is intentionally additive.  It gives permission regression tests a
small, deterministic surface for comparing the pagination, reference-hole and
digest side channels visible to callers.
"""

import hashlib
import hmac
import json
import math
from collections.abc import Mapping
from datetime import date, datetime


NIL_UUID = "00000000-0000-0000-0000-000000000000"
CANONICAL_REFERENCE_HOLE = "reference-hole--" + NIL_UUID
CANONICAL_PAGE_SLOT = "page-slot--" + NIL_UUID
CANONICAL_OBJECT_HOLE = "object-hole--" + NIL_UUID
REDACTED_SUMMARY = "[REDACTED]"
DEFAULT_DIGEST_LENGTH = 64

_GROUP_KEYS = (
    "x_case_groups", "case_groups", "groups", "group_ids", "case_group_ids",
    "x_case_group", "case_group", "case_group_id", "x_case_group_id",
    "x_cases", "case_ids", "cases", "case_id", "x_case_id", "case",
    "case_teams", "case_team_ids", "case_team", "tenants", "tenant_ids",
    "x_tenants", "x_tenant", "organizations", "org_ids",
    "authorized_groups", "x_authorized_groups",
)
_MARKING_KEYS = ("authorized_markings", "marking_ids", "clearances", "markings")
_IDENTITY_GROUP_KEYS = _GROUP_KEYS + ("member_of", "group_memberships")


class DictObject(dict):
    """Dictionary with attribute access for convenient test assertions."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


class Projection(list):
    """List of projected objects carrying non-serialized projection details."""

    def __init__(self, items=(), holes=None, context=None, denied_count=0):
        super().__init__(items)
        self.holes = holes or []
        self.context = context
        self.denied_count = denied_count


class StableOutput(str):
    """Canonical output that also exposes its envelope and observables."""

    def __new__(cls, canonical, envelope):
        obj = str.__new__(cls, canonical)
        object.__setattr__(obj, "envelope", DictObject(envelope))
        return obj

    def __getattr__(self, name):
        envelope = object.__getattribute__(self, "envelope")
        try:
            return envelope[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __getitem__(self, key):
        if isinstance(key, str):
            return object.__getattribute__(self, "envelope")[key]
        return str.__getitem__(self, key)

    def get(self, key, default=None):
        envelope = object.__getattribute__(self, "envelope")
        return envelope.get(key, default)

    def to_dict(self):
        return dict(object.__getattribute__(self, "envelope"))


def _as_set(value):
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, Mapping):
        values = []
        for key in ("id", "value", "name"):
            if key in value:
                values.append(value[key])
        if not values:
            values.extend(value.keys())
        return {str(item) for item in values if item is not None}
    try:
        result = set()
        for item in value:
            result.update(_as_set(item))
        return result
    except TypeError:
        return {str(value)}


def _first_key(data, keys, default=None):
    if data is None:
        return default
    for key in keys:
        try:
            if isinstance(data, Mapping) and key in data:
                return data[key]
        except TypeError:
            pass
        if hasattr(data, key):
            value = getattr(data, key)
            if value is not None:
                return value
    return default


def coerce_context(identity=None, **kwargs):
    """Build a normalized authorization context from many test-friendly forms."""
    if isinstance(identity, Context):
        context = Context(identity)
        for key, value in kwargs.items():
            if value is not None:
                context[key] = _context_value(key, value)
        return context

    context = Context()
    explicit_groups = kwargs.pop("case_groups", None)
    if explicit_groups is None:
        explicit_groups = kwargs.pop("groups", None)
    explicit_markings = kwargs.pop("authorized_markings", None)
    if explicit_markings is None:
        explicit_markings = kwargs.pop("markings", None)

    identity_id = kwargs.pop("identity_id", None)
    policy = kwargs.pop("policy", None)
    visible_ids = kwargs.pop("visible_ids", None)
    if visible_ids is None:
        visible_ids = kwargs.pop("authorized_ids", None)
    hidden_ids = kwargs.pop("hidden_ids", None)
    if hidden_ids is None:
        hidden_ids = kwargs.pop("private_ids", None)

    groups = _as_set(explicit_groups)
    markings = _as_set(explicit_markings)

    if identity is not None:
        if isinstance(identity, str):
            if "--" in identity or identity_id is None:
                identity_id = identity
            else:
                groups.add(identity)
        else:
            identity_id = identity_id or _first_key(identity, ("id", "identity_id", "user_id", "principal"))
            groups.update(_as_set(_first_key(identity, _IDENTITY_GROUP_KEYS)))
            markings.update(_as_set(_first_key(identity, _MARKING_KEYS)))
            if _first_key(identity, ("type",)) == "identity":
                groups.update(_as_set(_first_key(identity, ("x_case_groups", "x_groups"))))

    for key, value in list(kwargs.items()):
        if value is None:
            continue
        if key in _GROUP_KEYS or key.endswith("_groups") or key in ("cases",):
            groups.update(_as_set(value))
        elif "marking" in key or key == "clearances":
            markings.update(_as_set(value))

    context.update({
        "identity": identity,
        "identity_id": identity_id,
        "case_groups": groups,
        "authorized_markings": markings,
        "policy": policy,
        "visible_ids": None if visible_ids is None else _as_set(visible_ids),
        "hidden_ids": _as_set(hidden_ids),
    })
    context.update(kwargs)
    return context


class Context(DictObject):
    """Normalized caller/authorization context."""


def _context_value(key, value):
    if "groups" in key or key in ("cases",):
        return _as_set(value)
    if "marking" in key:
        return _as_set(value)
    return value


def to_plain(value):
    """Convert STIX objects, mappings and common Python values to plain data."""
    if isinstance(value, Mapping):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_plain(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "serialize") and callable(value.serialize) and not isinstance(value, str):
        try:
            return json.loads(value.serialize())
        except (TypeError, ValueError):
            pass
    return value


def coerce_graph(source, query=None):
    """Normalize a store, DataSource, bundle, mapping or list to plain objects."""
    if source is None:
        return []
    if isinstance(source, Projection):
        return to_plain(list(source))
    if hasattr(source, "query") and callable(source.query):
        result = source.query() if query is None else source.query(query)
        return coerce_graph(result)
    if isinstance(source, str):
        text = source.strip()
        if text.startswith(("{", "[")):
            return coerce_graph(json.loads(text))
        return []
    if isinstance(source, Mapping):
        for key in ("objects", "stix_data", "items", "results", "data", "entries"):
            if key in source:
                return coerce_graph(source[key])
        if "id" in source or "type" in source:
            return [to_plain(source)]
        return []
    if hasattr(source, "objects"):
        return coerce_graph(_first_key(source, ("objects",)))
    if isinstance(source, (list, tuple, set, frozenset)):
        return [obj for item in source for obj in coerce_graph(item)]
    try:
        return [to_plain(item) for item in source]
    except TypeError:
        return [to_plain(source)]


def _object_groups(obj):
    groups = set()
    for key in _GROUP_KEYS:
        if key in obj:
            groups.update(_as_set(obj[key]))
    labels = obj.get("labels") or []
    for label in labels:
        label = str(label)
        for prefix in ("case-group:", "case_group:", "casegroup:", "group:", "case:"):
            if label.startswith(prefix):
                groups.add(label[len(prefix):])
    return groups


def _object_marking_refs(obj):
    refs = list(obj.get("object_marking_refs") or [])
    for marking in obj.get("granular_markings") or []:
        if isinstance(marking, Mapping) and marking.get("marking_ref"):
            refs.append(marking["marking_ref"])
    return {str(ref) for ref in refs if ref}


def authorize_object(obj, context):
    """Return whether ``context`` may know about an object."""
    object_id = obj.get("id")
    context = context if isinstance(context, Context) else coerce_context(context)

    if object_id in context.get("hidden_ids", set()):
        return False
    visible_ids = context.get("visible_ids")
    if visible_ids is not None:
        return object_id in visible_ids

    policy = context.get("policy")
    if callable(policy):
        try:
            allowed = policy(obj, context)
        except TypeError:
            allowed = policy(obj, context.get("identity"))
        if allowed is not None:
            return bool(allowed)

    allowed = True
    groups = _object_groups(obj)
    if groups:
        allowed = bool(groups & context.get("case_groups", set()))

    marking_refs = _object_marking_refs(obj)
    authorized_markings = context.get("authorized_markings", set())
    if marking_refs and authorized_markings:
        allowed = allowed and bool(marking_refs & authorized_markings)

    if obj.get("x_private") or obj.get("private"):
        owner = obj.get("x_owner") or obj.get("owner") or obj.get("created_by_ref")
        if context.get("identity_id") and owner == context["identity_id"]:
            return True
        if not groups:
            return False

    return allowed


def _is_stix_ref(value):
    return isinstance(value, str) and "--" in value


def _redact_references(obj, all_ids, visible_ids, context, path=None):
    path = path or []
    holes = []
    marker = context.get("hole_marker", CANONICAL_REFERENCE_HOLE)
    strict = context.get("strict_references", False)

    def walk(node, node_path):
        if isinstance(node, dict):
            for key in list(node.keys()):
                value = node[key]
                child_path = node_path + [str(key)]
                if key.endswith("_ref") and _is_stix_ref(value):
                    if value not in visible_ids and (strict or value in all_ids):
                        holes.append(DictObject({
                            "path": ".".join(child_path),
                            "source_id": node.get("id") if isinstance(node, dict) else None,
                        }))
                        node[key] = marker
                elif key.endswith("_refs") and isinstance(value, list):
                    for index, ref in enumerate(value):
                        if _is_stix_ref(ref) and ref not in visible_ids and (strict or ref in all_ids):
                            holes.append(DictObject({
                                "path": ".".join(child_path + ["[%d]" % index]),
                                "source_id": node.get("id") if isinstance(node, dict) else None,
                                "index": index,
                            }))
                            value[index] = marker
                    bucket = context.get("reference_list_bucket")
                    slots = context.get("reference_list_slots")
                    target = len(value)
                    if bucket:
                        target = max(target, _bucket_value(target, bucket))
                    if slots is not None:
                        target = max(target, int(slots))
                    while len(value) < target:
                        value.append(marker)
                else:
                    walk(value, child_path)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, node_path + ["[%d]" % index])

    walk(obj, path)
    return holes


def _bucket_value(value, bucket):
    if not bucket:
        return value
    bucket = int(bucket)
    if bucket <= 1:
        return value
    return int(math.ceil(float(value) / bucket) * bucket)


def project_graph(graph, identity=None, query=None, sort=True, **kwargs):
    """Return only authorized objects and canonicalize holes in references."""
    context = coerce_context(identity, **kwargs)
    objects = [to_plain(obj) for obj in coerce_graph(graph, query=query)]
    all_ids = {obj.get("id") for obj in objects if obj.get("id")}
    visible_ids = {
        obj.get("id") for obj in objects
        if obj.get("id") and authorize_object(obj, context)
    }

    projected = []
    holes = []
    denied_count = 0
    for obj in objects:
        if not authorize_object(obj, context):
            denied_count += 1
            continue
        obj_holes = _redact_references(obj, all_ids, visible_ids, context)
        holes.extend(obj_holes)
        projected.append(obj)

    if sort:
        projected.sort(key=lambda obj: (str(obj.get("type", "")), str(obj.get("id", "")), canonical_json(obj)))
    return Projection(projected, holes=holes, context=context, denied_count=denied_count)


# Common shorter alias.
project = project_graph
redact_unauthorized = project_graph


def reference_holes(graph, identity=None, **kwargs):
    """Return canonical reference-hole records visible after authorization."""
    return list(project_graph(graph, identity=identity, **kwargs).holes)


def reference_hole_count(graph, identity=None, **kwargs):
    return len(reference_holes(graph, identity=identity, **kwargs))


dangling_references = reference_holes
dangling_refs = reference_holes
reference_gaps = reference_holes


def paginate(objects, page=1, limit=None, page_size=None, offset=None,
             count_bucket=None, bucket=None, total_count=None,
             uniform_total=None, pad_page=False, pad=False,
             page_slots=None, slot_marker=CANONICAL_PAGE_SLOT, **kwargs):
    """Paginate while keeping externally visible counts uniform."""
    objects = list(objects or [])
    limit = limit if limit is not None else page_size
    if limit is None:
        limit = len(objects)
    limit = max(int(limit), 0)
    page = max(int(page or 1), 1)
    if offset is None:
        offset = (page - 1) * limit if limit else 0
    else:
        offset = max(int(offset), 0)
        if limit:
            page = offset // limit + 1

    page_items = objects[offset:offset + limit] if limit else []
    real_returned = len(page_items)
    raw_total = len(objects)
    normalized_total = total_count if total_count is not None else uniform_total
    if normalized_total is None:
        normalized_total = _bucket_value(raw_total, count_bucket or bucket)
    normalized_total = int(normalized_total)
    total_pages = int(math.ceil(float(normalized_total) / limit)) if limit else (1 if normalized_total else 0)

    should_pad = pad_page or pad or page_slots is not None
    target_slots = len(page_items)
    if page_slots is not None:
        target_slots = max(target_slots, int(page_slots))
    if pad_page or pad:
        target_slots = max(target_slots, limit)
    slots = list(page_items)
    if should_pad:
        while len(slots) < target_slots:
            slots.append(slot_marker)

    has_next = offset + real_returned < raw_total
    result = DictObject({
        "objects": slots,
        "items": slots,
        "data": slots,
        "results": slots,
        "page": page,
        "page_number": page,
        "limit": limit,
        "page_size": limit,
        "per_page": limit,
        "offset": offset,
        "count": len(slots),
        "returned_count": len(slots),
        "real_returned_count": real_returned,
        "total": normalized_total,
        "total_count": normalized_total,
        "raw_total_count": raw_total,
        "visible_count": raw_total,
        "page_count": total_pages,
        "total_pages": total_pages,
        "has_next": has_next,
        "has_previous": offset > 0,
        "next_offset": offset + limit if has_next else None,
        "previous_offset": max(0, offset - limit) if offset else None,
    })
    result["pagination_counts"] = DictObject({
        "page": page,
        "page_count": total_pages,
        "page_size": limit,
        "returned_count": len(slots),
        "total_count": normalized_total,
    })
    return result


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=lambda item: item.isoformat() if hasattr(item, "isoformat") else str(item),
    )


def fixed_digest(value, length=DEFAULT_DIGEST_LENGTH, algorithm="sha256", key=None):
    """Return a deterministic hex digest with an exact externally visible length."""
    if not isinstance(value, (bytes, bytearray)):
        if not isinstance(value, str):
            value = canonical_json(value)
        value = value.encode("utf-8")

    length = int(length or DEFAULT_DIGEST_LENGTH)
    if length <= 0:
        return ""
    chunks = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) * 2 < length:
        digest_factory = hashlib.new(algorithm)
        if key is not None:
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            mac = hmac.new(key_bytes, value + counter.to_bytes(8, "big"), algorithm)
            chunks.append(mac.hexdigest())
        else:
            digest_factory.update(value + counter.to_bytes(8, "big"))
            chunks.append(digest_factory.hexdigest())
        counter += 1
    return "".join(chunks)[:length]


# Descriptive aliases used by different regression suites.
stable_digest = fixed_digest
digest = fixed_digest


def fixed_summary(value=REDACTED_SUMMARY, length=None, pad_char=" "):
    if length is None:
        return str(value)
    length = int(length)
    text = str(value)
    if len(text) > length:
        if length <= 3:
            return text[:length]
        return text[:length - 3] + "..."
    return text + (pad_char * (length - len(text)))


def summarize_markings(graph=None, identity=None, markings=None,
                       digest_length=DEFAULT_DIGEST_LENGTH, summary_length=None,
                       hole_slots=None, hole_bucket=None, marking_slots=None,
                       marking_bucket=None, key=None, **kwargs):
    """Build a fixed-shape, fixed-length marking summary."""
    context = coerce_context(identity, **kwargs)
    if markings is not None:
        refs = _as_set(markings)
    else:
        refs = set()
        for obj in coerce_graph(graph):
            plain_obj = to_plain(obj)
            refs.update(_object_marking_refs(plain_obj))

    reveal_refs = kwargs.pop("reveal_marking_refs", False) or context.get("reveal_marking_refs")
    authorized = context.get("authorized_markings", set())
    if authorized:
        visible_refs = sorted(refs & authorized)
        hidden_count = len(refs - authorized)
    elif reveal_refs:
        visible_refs = sorted(refs)
        hidden_count = 0
    else:
        visible_refs = []
        hidden_count = len(refs)

    target_count = len(visible_refs)
    if marking_bucket:
        target_count = max(target_count, _bucket_value(target_count, marking_bucket))
    if marking_slots is not None:
        target_count = max(target_count, int(marking_slots))
    visible_refs = visible_refs + [CANONICAL_REFERENCE_HOLE] * (target_count - len(visible_refs))

    hole_count = hidden_count
    if hole_bucket:
        hole_count = max(hole_count, _bucket_value(hole_count, hole_bucket))
    if hole_slots is not None:
        hole_count = max(hole_count, int(hole_slots))

    payload = {
        "marking_refs": visible_refs,
        "reference_holes": [CANONICAL_REFERENCE_HOLE] * hole_count,
    }
    digest_value = fixed_digest(payload, length=digest_length, key=key)
    summary_text = fixed_summary(REDACTED_SUMMARY, summary_length) if summary_length is not None else digest_value
    result = DictObject({
        "kind": "stix2.disclosure.marking-summary/v1",
        "marking_refs": visible_refs,
        "marking_count": len(visible_refs),
        "unauthorized_marking_count": hole_count,
        "reference_holes": [CANONICAL_REFERENCE_HOLE] * hole_count,
        "reference_hole_count": hole_count,
        "summary": summary_text,
        "summary_length": len(summary_text),
        "digest": digest_value,
        "digest_length": len(digest_value),
        "algorithm": "hmac-sha256" if key is not None else "sha256",
    })
    result["canonical"] = canonical_json(payload)
    return result


def _uniform_hole_records(holes, hole_slots=None, hole_bucket=None):
    count = len(holes)
    if hole_bucket:
        count = max(count, _bucket_value(count, hole_bucket))
    if hole_slots is not None:
        count = max(count, int(hole_slots))
    return [CANONICAL_REFERENCE_HOLE] * count, count


def stable_equivalent_output(graph=None, identity=None, *args, **kwargs):
    """Return canonical output whose unauthorized views do not vary by private graph."""
    # Tolerate a few plausible positional calling conventions.
    if args and identity is None and not isinstance(graph, (str, Mapping, list, tuple, set, frozenset)) and not hasattr(graph, "query"):
        identity = graph
        graph = args[0]
        args = args[1:]
    if args:
        kwargs.setdefault("limit", args[0])

    query = kwargs.pop("query", None)
    digest_length = kwargs.pop("digest_length", DEFAULT_DIGEST_LENGTH)
    summary_length = kwargs.pop("summary_length", None)
    hole_slots = kwargs.pop("hole_slots", kwargs.pop("reference_hole_slots", None))
    hole_bucket = kwargs.pop("hole_bucket", kwargs.pop("reference_hole_bucket", None))
    include_marking = kwargs.pop("include_marking_summary", kwargs.pop("marking_summary", True))
    key = kwargs.pop("digest_key", kwargs.pop("key", None))
    page_options = {}
    for name in (
        "page", "limit", "page_size", "offset", "count_bucket", "bucket",
        "total_count", "uniform_total", "pad_page", "pad", "page_slots",
    ):
        if name in kwargs:
            page_options[name] = kwargs[name]

    projection = project_graph(graph, identity=identity, query=query, **kwargs)
    page = paginate(projection, **page_options)
    hole_records, hole_count = _uniform_hole_records(projection.holes, hole_slots, hole_bucket)
    marking = summarize_markings(
        projection,
        identity=projection.context,
        digest_length=digest_length,
        summary_length=summary_length,
        hole_slots=hole_slots,
        hole_bucket=hole_bucket,
        key=key,
        **kwargs,
    ) if include_marking else None

    pagination_view = {
        key: page[key] for key in (
            "page", "page_number", "page_count", "total_pages", "page_size",
            "limit", "offset", "count", "returned_count", "total_count",
            "total", "has_next", "has_previous",
        )
    }
    envelope = {
        "schema": "stix2.disclosure.stable-view/v1",
        "objects": page["objects"],
        "pagination": pagination_view,
        "pagination_counts": dict(page["pagination_counts"]),
        "reference_holes": hole_records,
        "reference_hole_count": hole_count,
    }
    if marking is not None:
        envelope["marking_summary"] = {
            key: marking[key] for key in (
                "marking_refs", "marking_count", "reference_holes",
                "reference_hole_count", "summary", "summary_length",
                "digest", "digest_length", "algorithm",
            )
        }
    envelope.update({
        "object_count": len(envelope["objects"]),
        "returned_count": pagination_view["returned_count"],
        "total_count": pagination_view["total_count"],
        "page_count": pagination_view["page_count"],
        "page_number": pagination_view["page_number"],
        "page_size": pagination_view["page_size"],
    })

    canonical_without_digest = canonical_json(envelope)
    digest_value = fixed_digest(canonical_without_digest, digest_length, key=key)
    envelope["digest"] = digest_value
    envelope["digest_length"] = len(digest_value)
    envelope["payload_length"] = len(canonical_without_digest.encode("utf-8"))
    canonical = canonical_json(envelope)
    envelope["canonical_length"] = len(canonical.encode("utf-8"))
    output = StableOutput(canonical, envelope)
    output.projection = projection
    output.page = page
    return output


stable_output = stable_equivalent_output
stable_view = stable_equivalent_output
uniform_output = stable_equivalent_output
safe_output = stable_equivalent_output
canonical_output = stable_equivalent_output


def stable_equivalent(left, right=None, **kwargs):
    """Return ``True`` when two outputs/graphs have no external differential."""
    if right is None:
        return stable_equivalent_output(left, **kwargs)
    return observable_difference(left, right, **kwargs).get("equivalent", False)


def canonicalize_graph(graph, identity=None, **kwargs):
    """Return the canonical string form of a stable graph view."""
    return str(stable_equivalent_output(graph, identity=identity, **kwargs))


canonical_graph = stable_equivalent_output
normalize_graph = stable_equivalent_output
uniform_graph = stable_equivalent_output
stabilize = stable_equivalent_output


def observe(value=None, identity=None, **kwargs):
    """Extract externally visible pagination, hole and length observables."""
    output = None
    if isinstance(value, StableOutput):
        output = value
        envelope = output.envelope
    elif isinstance(value, Mapping) and value.get("schema", "").startswith("stix2.disclosure.stable-view"):
        envelope = DictObject(value)
    elif isinstance(value, Mapping) and value.get("kind") == "stix2.disclosure.observation/v1":
        return Observation(value)
    elif isinstance(value, Mapping) and ("pagination_counts" in value or ("total_count" in value and "objects" in value)):
        page = DictObject(value)
        envelope = DictObject({
            "schema": "stix2.disclosure.page/v1",
            "objects": page.get("objects", []),
            "pagination": page,
            "pagination_counts": page.get("pagination_counts", {}),
            "reference_holes": page.get("reference_holes", []),
            "reference_hole_count": page.get("reference_hole_count", len(page.get("reference_holes", []))),
            "digest_length": page.get("digest_length", 0),
            "summary_length": page.get("summary_length", 0),
            "canonical_length": len(canonical_json(page).encode("utf-8")),
        })
        output = StableOutput(canonical_json(page), envelope)
    elif isinstance(value, Mapping) and value.get("kind") == "stix2.disclosure.marking-summary/v1":
        marking = DictObject(value)
        envelope = DictObject({
            "schema": "stix2.disclosure.marking-output/v1",
            "objects": [],
            "pagination": {},
            "pagination_counts": {},
            "reference_holes": marking.get("reference_holes", []),
            "reference_hole_count": marking.get("reference_hole_count"),
            "marking_summary": marking,
            "digest": marking.get("digest"),
            "digest_length": marking.get("digest_length"),
            "payload_length": len(canonical_json(marking).encode("utf-8")),
            "canonical_length": len(canonical_json(marking).encode("utf-8")),
        })
        output = StableOutput(canonical_json(marking), envelope)
    else:
        output = stable_equivalent_output(value, identity=identity, **kwargs)
        envelope = output.envelope

    page = envelope.get("pagination") or {}
    counts = envelope.get("pagination_counts") or page.get("pagination_counts") or {}
    marking = envelope.get("marking_summary") or {}
    holes = envelope.get("reference_holes") or []
    digest_length = envelope.get("digest_length")
    if digest_length is None and marking:
        digest_length = marking.get("digest_length")
    canonical_length = envelope.get("canonical_length")
    if canonical_length is None and output is not None:
        canonical_length = len(str(output).encode("utf-8"))

    observation = Observation({
        "kind": "stix2.disclosure.observation/v1",
        "object_count": len(envelope.get("objects") or []),
        "page": page.get("page", counts.get("page")),
        "page_number": page.get("page_number"),
        "page_size": page.get("page_size", page.get("limit")),
        "returned_count": page.get("returned_count", page.get("count")),
        "total_count": page.get("total_count", page.get("total")),
        "page_count": page.get("page_count", page.get("total_pages")),
        "pagination_count": counts.get("page_count", page.get("page_count")),
        "pagination_counts": DictObject(counts),
        "reference_hole_count": envelope.get("reference_hole_count", len(holes)),
        "reference_holes": envelope.get("reference_hole_count", len(holes)),
        "digest": envelope.get("digest") or marking.get("digest"),
        "digest_length": digest_length or 0,
        "summary_length": marking.get("summary_length", digest_length or 0),
        "payload_length": envelope.get("payload_length", canonical_length or 0),
        "canonical_length": canonical_length or 0,
        "length": canonical_length or envelope.get("payload_length", 0),
    })
    observation["pagination_deltas"] = DictObject()
    observation["canonical"] = canonical_json(envelope)
    return observation


class Observation(DictObject):
    """Normalized external observables."""


_DIFF_METRICS = (
    "object_count", "page", "page_number", "page_size", "returned_count",
    "total_count", "page_count", "pagination_count",
    "reference_hole_count", "reference_holes", "digest_length",
    "summary_length", "payload_length", "canonical_length", "length",
)


def compare_observations(left, right, **kwargs):
    left = left if isinstance(left, Observation) else observe(left, **kwargs)
    right = right if isinstance(right, Observation) else observe(right, **kwargs)
    deltas = {}
    for metric in _DIFF_METRICS:
        left_value = left.get(metric, 0) or 0
        right_value = right.get(metric, 0) or 0
        try:
            deltas[metric] = abs(float(left_value) - float(right_value))
            if deltas[metric].is_integer():
                deltas[metric] = int(deltas[metric])
        except (TypeError, ValueError):
            deltas[metric] = None

    pagination_deltas = {
        key: abs((left.get("pagination_counts") or {}).get(key, 0) - (right.get("pagination_counts") or {}).get(key, 0))
        for key in set((left.get("pagination_counts") or {}).keys()) | set((right.get("pagination_counts") or {}).keys())
    }
    deltas["pagination"] = DictObject(pagination_deltas)
    deltas["pagination_count"] = max(
        value for key, value in pagination_deltas.items() if key in ("page_count", "total_count", "returned_count")
    ) if pagination_deltas else 0

    canonical_equal = bool(left.get("canonical") == right.get("canonical") or (
        left.get("digest") and left.get("digest") == right.get("digest")
    ))
    digest_equal = bool(left.get("digest") and left.get("digest") == right.get("digest"))
    metric_equivalent = all(
        deltas[metric] == 0 for metric in _DIFF_METRICS if metric not in ("page", "page_number")
    )
    equivalent = canonical_equal and metric_equivalent

    result = Difference({
        "kind": "stix2.disclosure.difference/v1",
        "equivalent": equivalent,
        "stable_equivalent": equivalent,
        "observation_equivalent": metric_equivalent,
        "canonical_equal": canonical_equal,
        "digest_equal": digest_equal,
        "deltas": DictObject(deltas),
        "left": left,
        "right": right,
        "max_differential": max(
            (value for key, value in deltas.items() if isinstance(value, (int, float)) and key != "page"),
            default=0,
        ),
    })
    for metric in _DIFF_METRICS:
        result[metric + "_delta"] = deltas.get(metric, 0)
    result["pagination_count_differential"] = deltas["pagination_count"]
    result["reference_hole_differential"] = deltas["reference_hole_count"]
    result["digest_length_differential"] = deltas["digest_length"]
    result["summary_length_differential"] = deltas["summary_length"]
    result["external_differential"] = DictObject({
        "pagination_count": deltas["pagination_count"],
        "reference_holes": deltas["reference_hole_count"],
        "digest_length": deltas["digest_length"],
        "summary_length": deltas["summary_length"],
    })
    return result


class Difference(DictObject):
    """Externally observable differential report."""


def _is_identity_like(value):
    if isinstance(value, (str, Context)):
        text = value if isinstance(value, str) else value.get("identity_id")
        return not (isinstance(text, str) and text.strip().startswith(("{", "[")))
    if isinstance(value, Mapping):
        if value.get("kind") in ("stix2.disclosure.observation/v1", "stix2.disclosure.difference/v1"):
            return False
        if value.get("type") == "identity" or value.get("identity_class"):
            return True
        if any(key in value for key in ("case_groups", "authorized_markings", "policy", "identity_id")):
            return True
    return False


def _split_graphs_identities(args, kwargs):
    graphs = []
    identities = []
    for value in args:
        if value is None:
            continue
        if isinstance(value, (StableOutput, Observation, Difference)):
            graphs.append(value)
        elif _is_identity_like(value):
            identities.append(value)
        else:
            graphs.append(value)

    for key in ("graphs", "sources", "stores", "datastores"):
        value = kwargs.pop(key, None)
        if value is not None:
            graphs.extend(value if isinstance(value, (list, tuple)) else [value])
    for key in ("identities", "principals"):
        value = kwargs.pop(key, None)
        if value is not None:
            identities.extend(value if isinstance(value, (list, tuple)) else [value])
    return graphs, identities


def observable_difference(*args, **kwargs):
    """Compare stable outputs, graphs/stores, or graph+identity positional args."""
    left = kwargs.pop("left", None)
    right = kwargs.pop("right", None)
    left_identity = kwargs.pop("left_identity", kwargs.pop("identity_a", None))
    right_identity = kwargs.pop("right_identity", kwargs.pop("identity_b", None))
    common_identity = kwargs.pop("identity", None)

    args = tuple(value for value in (left,) + args + (right,) if value is not None)
    graphs, identities = _split_graphs_identities(args, kwargs)
    if left_identity is not None:
        identities.insert(0, left_identity)
    if right_identity is not None:
        identities.insert(1 if identities else 0, right_identity)

    if len(graphs) == 2 and all(isinstance(item, (StableOutput, Observation)) for item in graphs):
        left_view, right_view = graphs
        return compare_observations(left_view, right_view, **kwargs)

    if len(graphs) >= 2:
        left_graph, right_graph = graphs[0], graphs[1]
        if len(identities) >= 2:
            lid, rid = identities[0], identities[1]
        elif len(identities) == 1:
            lid = rid = identities[0]
        else:
            lid = rid = common_identity
        left_view = stable_equivalent_output(left_graph, lid, **kwargs)
        right_view = stable_equivalent_output(right_graph, rid, **kwargs)
        return compare_observations(left_view, right_view, **kwargs)

    if len(graphs) == 1 and len(identities) >= 2:
        graph = graphs[0]
        left_view = stable_equivalent_output(graph, identities[0], **kwargs)
        right_view = stable_equivalent_output(graph, identities[1], **kwargs)
        return compare_observations(left_view, right_view, **kwargs)

    if len(graphs) == 1:
        view = graphs[0] if isinstance(graphs[0], StableOutput) else stable_equivalent_output(graphs[0], common_identity, **kwargs)
        return compare_observations(view, view, **kwargs)

    raise TypeError("observable_difference requires two outputs, graphs, or a graph and two identities")


observable_diff = observable_difference
external_observable_difference = observable_difference
externally_observable_difference = observable_difference
disclosure_difference = observable_difference
disclosure_diff = observable_difference
side_channel_difference = observable_difference


def compare_identities(graph_a=None, graph_b=None, identity_a=None, identity_b=None, **kwargs):
    """Compare the 2x2 graph/identity matrix used by permission regressions."""
    graphs = [graph_a, graph_b]
    if graph_b is None and isinstance(graph_a, (list, tuple)):
        graphs = list(graph_a)
    identities = [identity_a, identity_b]
    if identity_b is None and isinstance(identity_a, (list, tuple)):
        identities = list(identity_a)
    return permission_regression(graphs, identities, **kwargs)


def permission_regression(graphs=None, identities=None, **kwargs):
    """Build all graph x identity views and pairwise observable differentials."""
    if graphs is None:
        graphs = kwargs.pop("graphs", [])
    if identities is None:
        identities = kwargs.pop("identities", [None, None])
    graphs = list(graphs or [])
    identities = list(identities or [])
    if not identities:
        identities = [None]

    matrix = []
    views = []
    for graph_index, graph in enumerate(graphs):
        for identity_index, identity in enumerate(identities):
            output = stable_equivalent_output(graph, identity, **kwargs)
            observation = observe(output)
            entry = DictObject({
                "graph_index": graph_index,
                "identity_index": identity_index,
                "identity_id": output.projection.context.get("identity_id"),
                "denied_count": output.projection.denied_count,
                "output": output,
                "observation": observation,
                "canonical": str(output),
            })
            matrix.append(entry)
            views.append(output)

    differences = []
    for left_index in range(len(views)):
        for right_index in range(left_index + 1, len(views)):
            diff = compare_observations(views[left_index], views[right_index])
            diff["left_pair"] = (left_index // len(identities), left_index % len(identities))
            diff["right_pair"] = (right_index // len(identities), right_index % len(identities))
            differences.append(diff)

    unauthorized_diffs = [
        diff for entry, diff in zip(matrix, differences)
        if entry.identity_id is None and not entry.denied_count
    ]
    result = RegressionReport({
        "kind": "stix2.disclosure.regression/v1",
        "matrix": matrix,
        "differences": differences,
        "unauthorized_differences": unauthorized_diffs,
        "equivalent": all(diff["equivalent"] for diff in differences),
        "stable_equivalent": all(diff["stable_equivalent"] for diff in differences),
        "unauthorized_equivalent": all(diff["equivalent"] for diff in unauthorized_diffs) if unauthorized_diffs else None,
        "max_differential": max((diff["max_differential"] for diff in differences), default=0),
    })
    return result


class RegressionReport(DictObject):
    pass


def assert_stable_equivalent(left, right, **kwargs):
    diff = observable_difference(left, right, **kwargs)
    if not diff["equivalent"]:
        raise AssertionError("externally observable disclosure difference: %r" % diff["external_differential"])
    return diff


__all__ = [
    "CANONICAL_OBJECT_HOLE", "CANONICAL_REFERENCE_HOLE", "StableOutput",
    "Difference", "Observation", "Projection", "RegressionReport",
    "assert_stable_equivalent", "canonical_json", "coerce_context",
    "coerce_graph", "compare_identities", "compare_observations",
    "external_observable_difference", "fixed_digest", "fixed_summary",
    "observable_diff", "observable_difference", "observe", "paginate",
    "permission_regression", "project_graph", "project",
    "redact_unauthorized", "stable_digest", "stable_equivalent_output",
    "stable_output", "stable_view", "summarize_markings", "to_plain",
    "stable_equivalent", "canonicalize_graph", "canonical_graph",
    "normalize_graph", "uniform_graph", "stabilize",
]
