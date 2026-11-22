"""Core local source-independence checks over STIX 2 content.

The checker reconstructs "who actually collected this" from three kinds of
local evidence:

* ``observed-data`` objects (the observations themselves);
* citations declared by an observation, such as a custom ``citation_refs``
  list or an ``external_references`` entry whose ``external_id`` is a STIX
  identifier; and
* collection relationships registered by the caller, either as STIX
  ``relationship`` SROs or as an explicit ``collection_relations`` argument.

Observations connected directly or transitively -- including mutual citation
cycles -- are one independent source.  A citation whose target is not part of
the visible graph is a reference gap.

Two views are provided.  The custodian view sees every observation and returns
the exact local component count.  The public view removes observations carrying
a restricted marking, and must not reveal their identifiers, names, or even
whether they exist.  Consequently every unresolved public citation is presented
in exactly the same form, whether its target is restricted or simply missing.
The public result gives a lower bound rather than an exact count.
"""

import json
import re
from collections import defaultdict

from stix2.datastore import DataSource
from stix2.datastore.memory import MemorySource

PUBLIC_VIEW = "public"
CUSTODIAN_VIEW = "custodian"

_VIEW_ALIASES = {
    "public": PUBLIC_VIEW,
    "custodian": CUSTODIAN_VIEW,
    "custody": CUSTODIAN_VIEW,
}

OBSERVED_DATA_TYPE = "observed-data"
RELATIONSHIP_TYPE = "relationship"
MARKING_DEFINITION_TYPE = "marking-definition"
REPORT_TYPE = "report"

DEFAULT_SOURCE_TYPES = (OBSERVED_DATA_TYPE,)
DEFAULT_COLLECTION_RELATIONSHIP_TYPES = frozenset((
    "derived-from",
    "based-on",
))
DEFAULT_CITATION_PROPERTIES = (
    "citation_refs",
    "self_reported_refs",
    "reported_refs",
    "source_refs",
    "derived_from_refs",
    "cites",
    "citations",
)
DEFAULT_RESTRICTED_MARKING_NAME_PATTERNS = (
    "CUSTODIAN",
    "CUSTODY",
    "保管",
)

SELF_CITATION = "self-citation"
COLLECTION_RELATIONSHIP = "collection-relationship"
CALLER_RELATION = "caller-relation"

GAP_UNRESOLVED = "unresolved"
GAP_RESTRICTED = "restricted"

_STIX_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*--\S+$")


class ProvenanceEdge:
    """A resolved provenance link between two observations.

    Attributes:
        source_ref (str): STIX ID of the citing or derived observation.
        target_ref (str): STIX ID of the cited or upstream observation.
        kind (str): ``SELF_CITATION``, ``COLLECTION_RELATIONSHIP`` or
            ``CALLER_RELATION``.
        detail (str): The property name or relationship type carrying the
            link.
    """

    __slots__ = ("source_ref", "target_ref", "kind", "detail")

    def __init__(self, source_ref, target_ref, kind, detail):
        self.source_ref = source_ref
        self.target_ref = target_ref
        self.kind = kind
        self.detail = detail

    def __eq__(self, other):
        if not isinstance(other, ProvenanceEdge):
            return NotImplemented
        return (
            self.source_ref == other.source_ref
            and self.target_ref == other.target_ref
            and self.kind == other.kind
            and self.detail == other.detail
        )

    def __hash__(self):
        return hash((self.source_ref, self.target_ref, self.kind, self.detail))

    def __repr__(self):
        return (
            "ProvenanceEdge(source_ref={!r}, target_ref={!r}, kind={!r}, "
            "detail={!r})"
        ).format(
            self.source_ref, self.target_ref, self.kind, self.detail,
        )

    def as_dict(self):
        return {
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "kind": self.kind,
            "detail": self.detail,
        }


class ReferenceGap:
    """A citation that cannot be resolved inside the visible graph.

    In the public view ``target_ref`` is always ``None`` and ``reason`` is
    always ``GAP_UNRESOLVED``.  A restricted target and a genuinely missing
    target therefore produce byte-identical public findings.  The custodian
    view resolves restricted targets to ordinary edges and leaves genuinely
    missing targets as gaps.
    """

    __slots__ = ("source_ref", "target_ref", "kind", "detail", "reason")

    def __init__(self, source_ref, target_ref, kind, detail, reason):
        self.source_ref = source_ref
        self.target_ref = target_ref
        self.kind = kind
        self.detail = detail
        self.reason = reason

    @property
    def target_redacted(self):
        return self.target_ref is None

    def __repr__(self):
        return (
            "ReferenceGap(source_ref={!r}, target_ref={!r}, kind={!r}, "
            "detail={!r}, reason={!r})"
        ).format(
            self.source_ref, self.target_ref, self.kind, self.detail,
            self.reason,
        )

    def as_dict(self):
        return {
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "kind": self.kind,
            "detail": self.detail,
            "reason": self.reason,
            "target_redacted": self.target_redacted,
        }


class SourceComponent:
    """One connected component of the observation provenance graph.

    Every observation in a component traces back to the same collection
    event, so a component contributes at most one independent source.

    Attributes:
        observation_refs (list): Sorted STIX IDs of the observations in the
            component.  The public view only lists visible observations.
        open (bool): True when the component contains an unresolved reference.
        label (str): A human-readable name for a fully visible component, or
            ``None`` for an open public component.
        unresolved_ref_count (int): Number of distinct unresolved target IDs
            merged into this component.
    """

    __slots__ = ("observation_refs", "open", "label", "unresolved_ref_count")

    def __init__(
        self, observation_refs, open, label, unresolved_ref_count=0,
    ):
        self.observation_refs = list(observation_refs)
        self.open = bool(open)
        self.label = label
        self.unresolved_ref_count = int(unresolved_ref_count)

    @property
    def closed(self):
        return not self.open

    @property
    def member_count(self):
        return len(self.observation_refs)

    def __repr__(self):
        return (
            "SourceComponent(observation_refs={!r}, open={!r}, label={!r}, "
            "unresolved_ref_count={!r})"
        ).format(
            self.observation_refs, self.open, self.label,
            self.unresolved_ref_count,
        )

    def as_dict(self):
        return {
            "observation_refs": list(self.observation_refs),
            "open": self.open,
            "closed": self.closed,
            "label": self.label,
            "unresolved_ref_count": self.unresolved_ref_count,
        }


class ProvenanceResult:
    """Outcome of a local source-independence check.

    Attributes:
        view (str): ``PUBLIC_VIEW`` or ``CUSTODIAN_VIEW``.
        edges (list): Resolved ``ProvenanceEdge`` objects.
        gaps (list): ``ReferenceGap`` objects.  Public gaps are redacted.
        components (list): ``SourceComponent`` objects.
        independent_sources_lower_bound (int): Lower bound obtained from the
            visible evidence graph.  It counts every fully resolved component
            plus one for all open components.  Restricted content is never
            inspected in the public view.
        independent_sources (int): Exact local component count in the
            custodian view; ``None`` in the public view.
        conservative_lower_bound (int): Stricter bound for callers who assume a
            restricted observation may itself cite visible observations.  In
            the public view it drops to one whenever any open component exists;
            in the custodian view it equals the exact count.
        closed_plus_open_bound (int): Alias for the evidence-model lower bound
            used by ``independent_sources_lower_bound``.
        observation_count (int): Number of visible observations.
        report_count (int): Number of visible report objects.
        referenced_observation_count (int): Number of distinct visible
            observations referenced by those reports.
        closed_component_count (int): Components without unresolved links.
        open_component_count (int): Components with unresolved links.
    """

    __slots__ = (
        "view",
        "edges",
        "gaps",
        "components",
        "independent_sources_lower_bound",
        "independent_sources",
        "conservative_lower_bound",
        "closed_plus_open_bound",
        "observation_count",
        "report_count",
        "referenced_observation_count",
        "closed_component_count",
        "open_component_count",
    )

    def __init__(
        self,
        view,
        edges,
        gaps,
        components,
        independent_sources_lower_bound,
        independent_sources,
        conservative_lower_bound,
        closed_plus_open_bound,
        observation_count,
        report_count,
        referenced_observation_count,
        closed_component_count,
        open_component_count,
    ):
        self.view = view
        self.edges = list(edges)
        self.gaps = list(gaps)
        self.components = list(components)
        self.independent_sources_lower_bound = independent_sources_lower_bound
        self.independent_sources = independent_sources
        self.conservative_lower_bound = conservative_lower_bound
        self.closed_plus_open_bound = closed_plus_open_bound
        self.observation_count = observation_count
        self.report_count = report_count
        self.referenced_observation_count = referenced_observation_count
        self.closed_component_count = closed_component_count
        self.open_component_count = open_component_count

    @property
    def lower_bound(self):
        return self.independent_sources_lower_bound

    @property
    def exact_sources(self):
        return self.independent_sources

    def __repr__(self):
        return (
            "ProvenanceResult(view={!r}, lower_bound={!r}, exact={!r})"
        ).format(
            self.view, self.independent_sources_lower_bound,
            self.independent_sources,
        )

    def as_dict(self):
        return {
            "view": self.view,
            "independent_sources_lower_bound": self.independent_sources_lower_bound,
            "independent_sources": self.independent_sources,
            "conservative_lower_bound": self.conservative_lower_bound,
            "closed_plus_open_bound": self.closed_plus_open_bound,
            "observation_count": self.observation_count,
            "report_count": self.report_count,
            "referenced_observation_count": self.referenced_observation_count,
            "closed_component_count": self.closed_component_count,
            "open_component_count": self.open_component_count,
            "components": [component.as_dict() for component in self.components],
            "edges": [edge.as_dict() for edge in self.edges],
            "gaps": [gap.as_dict() for gap in self.gaps],
        }


def _get(obj, key, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    getter = getattr(obj, "get", None)
    if callable(getter):
        try:
            return getter(key, default)
        except TypeError:
            return getter(key)
    return getattr(obj, key, default)


def _as_sequence(value):
    if value is None:
        return []
    if isinstance(value, (str, bytes, dict)):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if hasattr(value, "__iter__") and not hasattr(value, "get"):
        return list(value)
    return [value]


def _stix_id_type(ref):
    if not isinstance(ref, str) or "--" not in ref:
        return None
    prefix, _, suffix = ref.partition("--")
    if not prefix or not suffix:
        return None
    return prefix


def _looks_like_stix_id(value):
    return isinstance(value, str) and bool(_STIX_ID_RE.match(value.strip()))


def _ref_text(value):
    if not isinstance(value, str):
        return None
    return value.strip()


def _version_sort_key(obj):
    return (
        str(_get(obj, "modified") or ""),
        str(_get(obj, "created") or ""),
    )


def _load_objects(stix_data):
    if stix_data is None:
        return []

    if isinstance(stix_data, str):
        stix_data = json.loads(stix_data)
    elif isinstance(stix_data, (bytes, bytearray)):
        stix_data = json.loads(bytes(stix_data).decode("utf-8"))

    if (
        isinstance(stix_data, dict)
        and "type" not in stix_data
    ):
        values = list(stix_data.values())
        if values and all(
            isinstance(value, dict) or hasattr(value, "get")
            for value in values
        ):
            stix_data = values

    if isinstance(stix_data, DataSource) or callable(
        getattr(stix_data, "query", None),
    ):
        return list(stix_data.query() or [])

    if (
        not isinstance(stix_data, (str, bytes, dict))
        and not hasattr(stix_data, "get")
        and hasattr(stix_data, "__iter__")
    ):
        stix_data = list(stix_data)

    source = MemorySource(stix_data=stix_data)
    return list(source.query())


def _dedupe_latest(objects):
    by_id = {}
    for obj in objects:
        object_id = _get(obj, "id")
        if not object_id:
            continue
        current = by_id.get(object_id)
        if current is None or _version_sort_key(obj) >= _version_sort_key(current):
            by_id[object_id] = obj
    return list(by_id.values())


def _statement_text(definition):
    if isinstance(definition, str):
        return definition
    statement = _get(definition, "statement")
    if statement:
        return str(statement)
    name = _get(definition, "name")
    if name:
        return str(name)
    return ""


def _restricted_marking_ids(
    objects, explicit, name_patterns, auto_detect,
):
    restricted = {
        item if isinstance(item, str) else _get(item, "id")
        for item in _as_sequence(explicit)
    }
    restricted.discard(None)
    if not auto_detect:
        return restricted

    patterns = [
        pattern.upper() for pattern in (name_patterns or ()) if pattern
    ]
    for obj in objects:
        if _get(obj, "type") != MARKING_DEFINITION_TYPE:
            continue
        object_id = _get(obj, "id")
        if not object_id or object_id in restricted:
            continue

        definition_type = str(
            _get(obj, "definition_type") or "",
        ).strip().lower()
        name = str(_get(obj, "name") or "")
        statement = _statement_text(_get(obj, "definition"))
        haystack = " ".join((definition_type, name, statement)).upper()
        if (
            definition_type in {"custodian", "custodian-only", "custody"}
            or any(pattern in haystack for pattern in patterns)
        ):
            restricted.add(object_id)
    return restricted


def _referenced_marking_ids(obj):
    refs = []
    for ref in _as_sequence(_get(obj, "object_marking_refs")):
        if isinstance(ref, str):
            refs.append(ref)
    for marking in _as_sequence(_get(obj, "granular_markings")):
        ref = _get(marking, "marking_ref")
        if isinstance(ref, str):
            refs.append(ref)
    return refs


def _is_restricted(obj, restricted_ids):
    if _get(obj, "x_custodian_only") is True:
        return True
    if _get(obj, "custodian_only") is True:
        return True
    return any(
        ref in restricted_ids for ref in _referenced_marking_ids(obj)
    )


def _normalize_relationship_type(value):
    if not isinstance(value, str):
        return value
    return value.strip().lower().replace("_", "-")


def _relationship_matches(obj, relationship_types):
    if "*" in relationship_types:
        return True
    relationship_type = _normalize_relationship_type(
        _get(obj, "relationship_type"),
    )
    return relationship_type in relationship_types


def _citation_target(item):
    if isinstance(item, str):
        ref = item.strip()
        return ref if _looks_like_stix_id(ref) else None
    for key in (
        "target_ref",
        "ref",
        "id",
        "observation_ref",
        "cited_ref",
        "source_ref",
    ):
        ref = _ref_text(_get(item, key))
        if ref and _looks_like_stix_id(ref):
            return ref
    return None


def _iter_citation_refs(
    obj, citation_properties, use_external_references,
):
    seen = set()
    for prop in citation_properties:
        for item in _as_sequence(_get(obj, prop)):
            ref = _citation_target(item)
            if ref and (ref, prop) not in seen:
                seen.add((ref, prop))
                yield ref, prop

    if not use_external_references:
        return

    for external_ref in _as_sequence(_get(obj, "external_references")):
        for key in ("external_id", "source_name"):
            ref = _ref_text(_get(external_ref, key))
            if not ref or not _looks_like_stix_id(ref):
                continue
            detail = "external_references." + key
            if (ref, detail) not in seen:
                seen.add((ref, detail))
                yield ref, detail


def _observation_name(obj, by_id):
    name = _get(obj, "name")
    if isinstance(name, str) and name:
        return name

    contained = _get(obj, "objects")
    if isinstance(contained, dict):
        for key in sorted(contained):
            inner_name = _get(contained[key], "name")
            if isinstance(inner_name, str) and inner_name:
                return inner_name

    for ref in _as_sequence(_get(obj, "object_refs")):
        target_name = _get(by_id.get(ref), "name")
        if isinstance(target_name, str) and target_name:
            return target_name
    return None


def _component_label(member_ids, observations, by_id):
    for member_id in member_ids:
        name = _observation_name(observations[member_id], by_id)
        if name:
            return name
    return None


def _ref_is_source_type(ref, source_types, by_id, visible_ids):
    if not isinstance(ref, str):
        return False
    if ref in visible_ids:
        return _get(by_id.get(ref), "type") in source_types
    return _stix_id_type(ref) in source_types


def _first_value(obj, keys):
    for key in keys:
        value = _get(obj, key)
        if value is not None:
            return value
    return None


def _iter_registered_items(value):
    if value is None:
        return
    if isinstance(value, (str, bytes)):
        raise TypeError(
            "Expected a mapping or an iterable of relation descriptions",
        )
    if (
        isinstance(value, (tuple, list))
        and len(value) == 2
        and all(isinstance(item, str) for item in value)
    ):
        yield {"source_ref": value[0], "target_ref": value[1]}
        return
    if isinstance(value, dict):
        if _first_value(
            value,
            (
                "source_ref",
                "source",
                "left",
                "from_ref",
                "citing_ref",
            ),
        ) is not None:
            yield value
            return
        for left, right in value.items():
            if isinstance(right, dict) and (
                "target_ref" in right or "source_ref" in right
            ):
                spec = dict(right)
                spec.setdefault("source_ref", left)
                yield spec
                continue
            for item in _as_sequence(right):
                yield {"source_ref": left, "target_ref": item}
        return

    for item in value:
        if isinstance(item, dict):
            yield item
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            yield {"source_ref": item[0], "target_ref": item[1]}
        else:
            source = _get(item, "source_ref")
            target = _get(item, "target_ref")
            if source is not None or target is not None:
                yield {
                    "source_ref": source,
                    "target_ref": target,
                    "relationship_type": _get(item, "relationship_type"),
                }


def _endpoint_value(value, keys):
    if isinstance(value, str) or value is None:
        return value
    if isinstance(value, dict) or callable(getattr(value, "get", None)):
        return _first_value(value, keys)
    return value


def _relation_parts(spec):
    source = _endpoint_value(
        _first_value(
            spec,
            ("source_ref", "source", "left", "from_ref", "citing_ref"),
        ),
        ("source_ref", "ref", "id"),
    )
    target = _endpoint_value(
        _first_value(
            spec,
            ("target_ref", "target", "right", "to_ref", "cited_ref"),
        ),
        ("target_ref", "ref", "id"),
    )
    collection = _first_value(
        spec,
        ("collection", "collection_key", "collection_id", "group", "key"),
    )
    detail = _first_value(spec, ("relationship_type", "detail"))
    return source, target, collection, detail


class _UnionFind:
    def __init__(self, members=()):
        self._parent = {member: member for member in members}

    def add(self, member):
        self._parent.setdefault(member, member)

    def find(self, member):
        self.add(member)
        root = member
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[member] != member:
            parent = self._parent[member]
            self._parent[member] = root
            member = parent
        return root

    def union(self, left, right):
        self.add(left)
        self.add(right)
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root

    def groups(self):
        grouped = defaultdict(list)
        for member in self._parent:
            grouped[self.find(member)].append(member)
        return list(grouped.values())


def _normalize_view(view):
    if view is None:
        return PUBLIC_VIEW
    key = str(view).strip().lower()
    try:
        return _VIEW_ALIASES[key]
    except KeyError:
        raise ValueError(
            "Unsupported view {!r}; expected one of {}".format(
                view, sorted(set(_VIEW_ALIASES.values())),
            ),
        )


def _normalize_names(value, default):
    if value is None:
        return tuple(default)
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def check_independence(
    stix_data,
    view=PUBLIC_VIEW,
    restricted_markings=None,
    restricted_marking_name_patterns=DEFAULT_RESTRICTED_MARKING_NAME_PATTERNS,
    auto_detect_restricted_markings=True,
    collection_relationship_types=DEFAULT_COLLECTION_RELATIONSHIP_TYPES,
    citation_properties=DEFAULT_CITATION_PROPERTIES,
    use_external_references=True,
    source_types=DEFAULT_SOURCE_TYPES,
    collection_relations=None,
    citations=None,
):
    """Check how many independent collection sources sit behind observations.

    Args:
        stix_data: A STIX ``DataSource``, bundle, list of STIX objects, single
            STIX object, JSON string, or a mapping of IDs to objects.
        view (str): ``"public"`` (default) or ``"custodian"``.  The public
            view removes restricted observations and redacts every unresolved
            target.  The custodian view sees all observations and returns the
            exact local component count.
        restricted_markings (iterable): Marking-definition IDs that make an
            observation custodian-only.  A single string is accepted.
        restricted_marking_name_patterns (iterable): Case-insensitive text
            patterns used to recognise custodian marking definitions
            automatically.  Defaults to ``CUSTODIAN``, ``CUSTODY`` and
            ``保管``.
        auto_detect_restricted_markings (bool): If False, only
            ``restricted_markings`` is used.
        collection_relationship_types (iterable): Relationship types treated
            as caller-registered provenance links.  Defaults to
            ``derived-from`` and ``based-on``; use ``"*"`` for all types.
        citation_properties (iterable): Observation properties that may hold
            self-declared STIX-ID citations.  A single string is accepted.
        use_external_references (bool): Also read STIX-ID-shaped
            ``external_references.external_id`` / ``source_name`` values.
        source_types (iterable): STIX object types that represent collection
            observations.  Defaults to ``("observed-data",)``.
        collection_relations (mapping or iterable): Caller-registered links.
            Supported forms include ``{observation_id: collection_key}``,
            ``{collection_key: [observation_ids]}``, ``(left, right)`` pairs,
            and dictionaries with ``source_ref`` / ``target_ref`` or
            ``source_ref`` / ``collection`` keys.
        citations (mapping or iterable): Caller-supplied self-reported
            citations, using the same shapes as ``collection_relations``.

    Returns:
        ProvenanceResult: Components, resolved edges, reference gaps, counts,
            and the public lower bound or custodian exact count.

    Raises:
        ValueError: If ``view`` is not supported.
    """

    view = _normalize_view(view)
    source_types = _normalize_names(source_types, DEFAULT_SOURCE_TYPES)
    citation_properties = _normalize_names(
        citation_properties, DEFAULT_CITATION_PROPERTIES,
    )
    relationship_types = frozenset(
        _normalize_relationship_type(item)
        for item in _normalize_names(
            collection_relationship_types,
            DEFAULT_COLLECTION_RELATIONSHIP_TYPES,
        )
    )
    name_patterns = _normalize_names(
        restricted_marking_name_patterns,
        DEFAULT_RESTRICTED_MARKING_NAME_PATTERNS,
    )

    objects = _dedupe_latest(_load_objects(stix_data))
    by_id = {
        _get(obj, "id"): obj
        for obj in objects
        if _get(obj, "id")
    }
    restricted_ids = _restricted_marking_ids(
        objects,
        restricted_markings,
        name_patterns,
        auto_detect_restricted_markings,
    )

    all_observation_ids = {
        object_id
        for object_id, obj in by_id.items()
        if _get(obj, "type") in source_types
    }
    if view == PUBLIC_VIEW:
        hidden_ids = {
            object_id
            for object_id in all_observation_ids
            if _is_restricted(by_id[object_id], restricted_ids)
        }
    else:
        hidden_ids = set()
    visible_ids = all_observation_ids - hidden_ids
    observations = {
        object_id: by_id[object_id] for object_id in visible_ids
    }
    if view == CUSTODIAN_VIEW:
        label_by_id = by_id
    else:
        label_by_id = {
            object_id: obj for object_id, obj in by_id.items()
            if not _is_restricted(obj, restricted_ids)
        }

    reports = []
    for obj in objects:
        if _get(obj, "type") != REPORT_TYPE:
            continue
        if view == PUBLIC_VIEW and _is_restricted(obj, restricted_ids):
            continue
        reports.append(obj)

    union_find = _UnionFind(visible_ids)
    edge_records = set()
    gap_records = set()

    def add_reference(source_ref, target_ref, kind, detail):
        if source_ref not in visible_ids:
            return
        if not _ref_is_source_type(
            target_ref, source_types, by_id, visible_ids,
        ):
            return
        if target_ref in visible_ids:
            union_find.union(source_ref, target_ref)
            edge_records.add((source_ref, target_ref, kind, detail))
            return

        synthetic_ref = ("unresolved", target_ref)
        union_find.add(synthetic_ref)
        union_find.union(source_ref, synthetic_ref)
        gap_records.add((source_ref, target_ref, kind, detail))

    for obj in objects:
        if _get(obj, "type") != RELATIONSHIP_TYPE:
            continue
        if view == PUBLIC_VIEW and _is_restricted(obj, restricted_ids):
            continue
        if not _relationship_matches(obj, relationship_types):
            continue
        relationship_type = _normalize_relationship_type(
            _get(obj, "relationship_type"),
        )
        add_reference(
            _get(obj, "source_ref"),
            _get(obj, "target_ref"),
            COLLECTION_RELATIONSHIP,
            relationship_type or "relationship",
        )

    for object_id in sorted(visible_ids):
        for target_ref, detail in _iter_citation_refs(
            observations[object_id],
            citation_properties,
            use_external_references,
        ):
            add_reference(
                object_id,
                target_ref,
                SELF_CITATION,
                detail,
            )

    group_members = defaultdict(list)
    for spec in _iter_registered_items(collection_relations):
        source, target, collection, detail = _relation_parts(spec)
        if collection is not None:
            if _ref_is_source_type(
                source, source_types, by_id, visible_ids,
            ):
                group_members[collection].append(source)
            elif _ref_is_source_type(
                target, source_types, by_id, visible_ids,
            ):
                group_members[collection].append(target)
            continue

        if source is None or target is None:
            continue
        source_is_source = _ref_is_source_type(
            source, source_types, by_id, visible_ids,
        )
        target_is_source = _ref_is_source_type(
            target, source_types, by_id, visible_ids,
        )
        if source_is_source and target_is_source:
            add_reference(
                source,
                target,
                CALLER_RELATION,
                detail or "caller-registered",
            )
        elif source_is_source:
            group_members[target].append(source)
        elif target_is_source:
            group_members[source].append(target)

    for members in group_members.values():
        visible_members = [
            member for member in members if member in visible_ids
        ]
        if len(visible_members) < 2:
            continue
        base = visible_members[0]
        for member in visible_members[1:]:
            union_find.union(base, member)

    for spec in _iter_registered_items(citations):
        source, target, collection, detail = _relation_parts(spec)
        if collection is not None or source is None or target is None:
            continue
        if not _ref_is_source_type(
            source, source_types, by_id, visible_ids,
        ):
            continue
        if not _ref_is_source_type(
            target, source_types, by_id, visible_ids,
        ):
            continue
        add_reference(
            source,
            target,
            SELF_CITATION,
            detail or "caller-citation",
        )

    components = []
    for group in union_find.groups():
        members = sorted(
            member for member in group
            if isinstance(member, str) and member in observations
        )
        if not members:
            continue
        synthetic_members = [
            member for member in group
            if not (isinstance(member, str) and member in observations)
        ]
        is_open = bool(synthetic_members)
        label = None
        if view == CUSTODIAN_VIEW or not is_open:
            label = _component_label(members, observations, label_by_id)
        components.append(
            SourceComponent(
                members,
                is_open,
                label,
                len(synthetic_members),
            ),
        )
    components.sort(key=lambda component: component.observation_refs)

    edges = [
        ProvenanceEdge(*record)
        for record in sorted(
            edge_records,
            key=lambda record: (
                record[0], record[1], record[2], record[3],
            ),
        )
    ]

    gaps = []
    for source_ref, target_ref, kind, detail in sorted(
        gap_records,
        key=lambda record: (
            record[0], record[3], record[2], record[1] or "",
        ),
    ):
        if view == PUBLIC_VIEW:
            gaps.append(
                ReferenceGap(
                    source_ref,
                    None,
                    kind,
                    detail,
                    GAP_UNRESOLVED,
                ),
            )
        else:
            gaps.append(
                ReferenceGap(
                    source_ref,
                    target_ref,
                    kind,
                    detail,
                    GAP_UNRESOLVED,
                ),
            )

    closed_component_count = sum(
        1 for component in components if not component.open
    )
    open_component_count = sum(
        1 for component in components if component.open
    )
    closed_plus_open_bound = closed_component_count + (
        1 if open_component_count else 0
    )
    if view == CUSTODIAN_VIEW:
        lower_bound = len(components)
        closed_plus_open_bound = len(components)
        conservative_lower_bound = len(components)
    else:
        lower_bound = closed_plus_open_bound
        conservative_lower_bound = (
            len(components)
            if not open_component_count
            else (1 if components else 0)
        )

    referenced_observations = set()
    for report in reports:
        for ref in _as_sequence(_get(report, "object_refs")):
            if ref in visible_ids:
                referenced_observations.add(ref)

    return ProvenanceResult(
        view=view,
        edges=edges,
        gaps=gaps,
        components=components,
        independent_sources_lower_bound=lower_bound,
        independent_sources=(
            len(components) if view == CUSTODIAN_VIEW else None
        ),
        conservative_lower_bound=conservative_lower_bound,
        closed_plus_open_bound=closed_plus_open_bound,
        observation_count=len(visible_ids),
        report_count=len(reports),
        referenced_observation_count=len(referenced_observations),
        closed_component_count=closed_component_count,
        open_component_count=open_component_count,
    )


class IndependenceChecker:
    """Callable wrapper around :func:`check_independence`."""

    def __init__(self, **options):
        self.options = dict(options)

    def check(self, stix_data):
        return check_independence(stix_data, **self.options)

    def __call__(self, stix_data):
        return self.check(stix_data)


check_source_independence = check_independence
IndependenceReport = ProvenanceResult
