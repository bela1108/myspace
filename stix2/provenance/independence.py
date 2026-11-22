"""Core source-independence algorithm for local STIX 2 provenance checks.
"""

from stix2.datastore import DataSource
from stix2.datastore.memory import MemorySource

OBSERVED_DATA_TYPE = "observed-data"
RELATIONSHIP_TYPE = "relationship"
MARKING_DEFINITION_TYPE = "marking-definition"

DEFAULT_COLLECTION_RELATIONSHIPS = frozenset((
    "derived-from",
    "based-on",
))

DEFAULT_CITATION_PROPERTIES = ("citation_refs",)
DEFAULT_EXTERNAL_ID_REFERENCES = True

PUBLIC_VIEW = "public"
CUSTODIAN_VIEW = "custodian"
_VIEWS = frozenset((PUBLIC_VIEW, CUSTODIAN_VIEW))

SELF_CITATION = "self-citation"
COLLECTION_RELATIONSHIP = "collection-relationship"
GAP_UNRESOLVED = "unresolved"
GAP_RESTRICTED = "restricted"


class ProvenanceEdge:
    """A provenance link between two observations.

    Attributes:
        source_ref (str): STIX ID of the citing/derived observation.
        target_ref (str): STIX ID of the cited/upstream observation.
        kind (str): Either ``SELF_CITATION`` or ``COLLECTION_RELATIONSHIP``.
        detail (str): STIX property or relationship type carrying the link.
    """

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
        return "ProvenanceEdge(source_ref={!r}, target_ref={!r}, kind={!r}, detail={!r})".format(
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
    """A citation that cannot be resolved within the visible graph.

    In public output the target identifier is always redacted, so the gap
    cannot reveal a hidden observation.

    Attributes:
        source_ref (str): STIX ID of the observation holding the citation.
        target_ref (str): STIX ID of the cited object, or ``None`` in the
            public view.
        kind (str): Kind of citation carrying the dangling reference.
        detail (str): STIX property or relationship type carrying it.
        reason (str): ``GAP_UNRESOLVED`` or, in the custodian view only,
            ``GAP_RESTRICTED``.
    """

    def __init__(self, source_ref, target_ref, kind, detail, reason):
        self.source_ref = source_ref
        self.target_ref = target_ref
        self.kind = kind
        self.detail = detail
        self.reason = reason

    def __repr__(self):
        return "ReferenceGap(source_ref={!r}, target_ref={!r}, kind={!r}, detail={!r}, reason={!r})".format(
            self.source_ref, self.target_ref, self.kind, self.detail, self.reason,
        )

    def as_dict(self):
        return {
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "kind": self.kind,
            "detail": self.detail,
            "reason": self.reason,
        }


class SourceComponent:
    """A connected component of the provenance graph.

    Every observation in one component traces back to the same underlying
    collection event, so each component contributes at most one independent
    source.

    Attributes:
        observation_refs (list): Sorted STIX IDs of the member observations.
        open (bool): True if the component cites anything outside the
            visible graph (a reference gap).
        label (str): Human-readable name of a representative member, or
            ``None`` in the public view to avoid naming-derived disclosure.
    """

    def __init__(self, observation_refs, open_component, label):
        self.observation_refs = observation_refs
        self.open = open_component
        self.label = label

    def __repr__(self):
        return "SourceComponent(observation_refs={!r}, open={!r}, label={!r})".format(
            self.observation_refs, self.open, self.label,
        )

    def as_dict(self):
        return {
            "observation_refs": list(self.observation_refs),
            "open": self.open,
            "label": self.label,
        }


class ProvenanceResult:
    """Outcome of a local source-independence check.

    Attributes:
        view (str): ``PUBLIC_VIEW`` or ``CUSTODIAN_VIEW``.
        edges (list): ProvenanceEdge objects visible in this view.
        gaps (list): ReferenceGap objects visible in this view.
        components (list): SourceComponent objects visible in this view.
        independent_sources_lower_bound (int): Guarantee on the number of
            distinct collection events behind the visible observations.
        independent_sources (int): Exact number of independent sources; only
            available in the custodian view, otherwise ``None``.
        report_count (int): Number of report objects found in the input.
        referenced_observation_count (int): Number of distinct visible
            observations referenced by those reports.
    """

    def __init__(
        self, view, edges, gaps, components,
        independent_sources_lower_bound, independent_sources,
        report_count, referenced_observation_count,
    ):
        self.view = view
        self.edges = edges
        self.gaps = gaps
        self.components = components
        self.independent_sources_lower_bound = independent_sources_lower_bound
        self.independent_sources = independent_sources
        self.report_count = report_count
        self.referenced_observation_count = referenced_observation_count

    def __repr__(self):
        return ("ProvenanceResult(view={!r}, lower_bound={}, exact={})").format(
            self.view, self.independent_sources_lower_bound, self.independent_sources,
        )

    def as_dict(self):
        return {
            "view": self.view,
            "edges": [edge.as_dict() for edge in self.edges],
            "gaps": [gap.as_dict() for gap in self.gaps],
            "components": [component.as_dict() for component in self.components],
            "independent_sources_lower_bound": self.independent_sources_lower_bound,
            "independent_sources": self.independent_sources,
            "report_count": self.report_count,
            "referenced_observation_count": self.referenced_observation_count,
        }


def _coerce_source(stix_data):
    if isinstance(stix_data, DataSource):
        return stix_data
    return MemorySource(stix_data=stix_data)


def _all_objects(source):
    objects = source.query()
    if objects is None:
        return []
    return list(objects)


def _restricted_marking_ids(objects, restricted_markings):
    configured = set(restricted_markings or ())
    discovered = set()
    for obj in objects:
        if obj.get("type") != MARKING_DEFINITION_TYPE:
            continue
        name = obj.get("name") or ""
        definition_type = obj.get("definition_type") or ""
        if obj.id in configured or "CUSTODIAN" in name.upper() or definition_type == "custodian-only":
            discovered.add(obj.id)
    return configured | discovered


def _is_restricted(obj, restricted_marking_ids):
    markings = obj.get("object_marking_refs") or []
    return any(marking in restricted_marking_ids for marking in markings)


def _observation_name(obj):
    if obj.get("name"):
        return obj["name"]
    contained = obj.get("objects") or {}
    for key in sorted(contained):
        inner = contained[key]
        name = inner.get("name") if isinstance(inner, dict) else getattr(inner, "name", None)
        if name:
            return name
    return None


def _self_citations(obj, citation_properties, use_external_references):
    refs = []
    for prop in citation_properties:
        value = obj.get(prop)
        if isinstance(value, str):
            refs.append((value, prop))
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str):
                    refs.append((item, prop))
    if use_external_references:
        for reference in obj.get("external_references") or []:
            external_id = _external_id(reference)
            if isinstance(external_id, str) and "--" in external_id:
                refs.append((external_id, "external_references.external_id"))
    return refs


def _external_id(reference):
    if isinstance(reference, dict):
        return reference.get("external_id")
    return getattr(reference, "external_id", None)


class _UnionFind:
    def __init__(self, members):
        self._parent = {member: member for member in members}

    def find(self, member):
        root = member
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[member] != member:
            parent = self._parent[member]
            self._parent[member] = root
            member = parent
        return root

    def union(self, left, right):
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root

    def groups(self):
        grouped = {}
        for member in sorted(self._parent):
            grouped.setdefault(self.find(member), []).append(member)
        return list(grouped.values())


def check_independence(
    stix_data,
    view=PUBLIC_VIEW,
    restricted_markings=None,
    collection_relationship_types=DEFAULT_COLLECTION_RELATIONSHIPS,
    citation_properties=DEFAULT_CITATION_PROPERTIES,
    use_external_id_references=DEFAULT_EXTERNAL_ID_REFERENCES,
):
    """Check how many independent sources lie behind the observed data.

    Args:
        stix_data: A STIX DataSource, bundle, list of STIX objects, or any
            other value accepted by MemorySource.
        view (str): ``"public"`` (default) hides every observation carrying
            a restricted marking; ``"custodian"`` sees everything.
        restricted_markings (iterable): Explicit marking-definition IDs whose
            marked objects are restricted. Marking definitions whose name
            contains ``CUSTODIAN`` are detected automatically.
        collection_relationship_types (iterable): Relationship types treated
            as caller-registered collection links.
        citation_properties (iterable): Custom properties on observations
            that hold self-declared STIX ID citations.
        use_external_id_references (bool): If True, treat external reference
            ``external_id`` values shaped like STIX IDs as citations too.

    Returns:
        ProvenanceResult: Components, edges, reference gaps, and the public
            lower bound (plus the exact count in the custodian view).

    Raises:
        ValueError: If ``view`` is not one of the supported views.
    """
    if view not in _VIEWS:
        raise ValueError("Unsupported view {!r}; expected one of {}".format(view, sorted(_VIEWS)))

    source = _coerce_source(stix_data)
    objects = _all_objects(source)
    by_id = {obj.id: obj for obj in objects}
    restricted_ids = _restricted_marking_ids(objects, restricted_markings)
    relationship_types = frozenset(collection_relationship_types)
    citation_properties = tuple(citation_properties)

    observations = {
        obj.id: obj for obj in objects
        if obj.get("type") == OBSERVED_DATA_TYPE
    }
    hidden_ids = set()
    if view == PUBLIC_VIEW:
        hidden_ids = {
            obs_id for obs_id, obs in observations.items()
            if _is_restricted(obs, restricted_ids)
        }
    visible_observations = {
        obs_id: obs for obs_id, obs in observations.items()
        if obs_id not in hidden_ids
    }

    edges = set()
    gaps = []
    open_sources = set()

    def record_link(src_ref, dst_ref, kind, detail):
        if src_ref not in visible_observations:
            return
        target = by_id.get(dst_ref)
        if target is None:
            gaps.append(ReferenceGap(src_ref, dst_ref, kind, detail, GAP_UNRESOLVED))
            open_sources.add(src_ref)
            return
        if view == PUBLIC_VIEW and dst_ref in hidden_ids:
            gaps.append(ReferenceGap(src_ref, None, kind, detail, GAP_RESTRICTED))
            open_sources.add(src_ref)
            return
        if target.get("type") != OBSERVED_DATA_TYPE:
            gaps.append(ReferenceGap(src_ref, dst_ref, kind, detail, GAP_UNRESOLVED))
            open_sources.add(src_ref)
            return
        edges.add(ProvenanceEdge(src_ref, dst_ref, kind, detail))

    for obs_id, obs in visible_observations.items():
        for dst_ref, detail in _self_citations(
            obs, citation_properties, use_external_id_references,
        ):
            record_link(obs_id, dst_ref, SELF_CITATION, detail)

    for obj in objects:
        if obj.get("type") != RELATIONSHIP_TYPE:
            continue
        if obj.get("relationship_type") not in relationship_types:
            continue
        record_link(
            obj.get("source_ref"), obj.get("target_ref"),
            COLLECTION_RELATIONSHIP, obj.get("relationship_type"),
        )

    union_find = _UnionFind(visible_observations.keys())
    for edge in edges:
        union_find.union(edge.source_ref, edge.target_ref)

    components = []
    closed_components = 0
    open_components = 0
    for member_ids in union_find.groups():
        is_open = any(member in open_sources for member in member_ids)
        if is_open:
            open_components += 1
            label = None
        else:
            closed_components += 1
            label = _observation_name(visible_observations[member_ids[0]])
        components.append(SourceComponent(sorted(member_ids), is_open, label))
    components.sort(key=lambda component: component.observation_refs)

    lower_bound = closed_components + (1 if open_components else 0)
    exact = None
    if view == CUSTODIAN_VIEW:
        exact = len(components)

    reports = [obj for obj in objects if obj.get("type") == "report"]
    referenced = set()
    for report in reports:
        for ref in report.get("object_refs") or []:
            if ref in visible_observations:
                referenced.add(ref)

    edge_list = sorted(edges, key=lambda edge: (edge.source_ref, edge.target_ref, edge.kind))
    gap_list = sorted(gaps, key=lambda gap: (gap.source_ref, gap.detail, gap.kind))
    return ProvenanceResult(
        view=view,
        edges=edge_list,
        gaps=gap_list,
        components=components,
        independent_sources_lower_bound=lower_bound,
        independent_sources=exact,
        report_count=len(reports),
        referenced_observation_count=len(referenced),
    )
