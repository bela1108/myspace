"""
Offline provenance review for STIX relationship claims.

When several feeds submit the same relationship, the number of submitted
records is not the number of independent sources.  Feeds may merely republish
an earlier report (a "转引"), and the citation graph may even contain cycles.
This module collapses citation chains and cycles onto their original sources,
aggregates every submission that asserts the same conclusion, then applies a
caller-supplied source-independence list to decide which conclusions retain
enough evidence.

Everything in this module works offline: it only reasons over the citation
edges and independence partitions supplied by the caller and never performs
network lookups against external reference identifiers.
"""

from dataclasses import dataclass
from enum import Enum


class ClaimStatus(str, Enum):
    """Outcome of the provenance review for one submitted record."""

    #: The submitted record gives no citation or reaches no external root.
    UNATTRIBUTED = "unattributed"
    #: Roots exist, but the conclusion lacks enough independent evidence.
    INSUFFICIENT = "insufficient"
    #: The conclusion has at least ``min_independent_sources`` independent sources.
    RETAINED = "retained"


@dataclass(frozen=True)
class Claim:
    """A relationship conclusion submitted by one feed.

    Args:
        claim_id: Stable identifier of the submitted record (e.g. the STIX
            SRO id).
        source: Identifier of the feed record the claim was found in.
        cited_sources: Records that ``source`` cites as its provenance.
            May be empty when the feed gave no citation.
        conclusion_key: Identity of the asserted conclusion.  Submissions
            sharing a key are corroborating records of one relationship and
            are pooled for the independent-source count.  Defaults to the
            claim id when omitted.
    """

    claim_id: str
    source: str
    cited_sources: tuple = ()
    conclusion_key: str = None

    def __post_init__(self):
        object.__setattr__(
            self,
            "cited_sources",
            tuple(_ensure_iterable(self.cited_sources)),
        )
        if self.conclusion_key is None:
            object.__setattr__(self, "conclusion_key", self.claim_id)


@dataclass(frozen=True)
class IndependenceList:
    """A source-independence policy supplied by the caller.

    Sources grouped together in ``source_groups`` are treated as a single
    independent source (e.g. imprints of the same publisher, feeds sharing
    an editorial pipeline).  Sources not mentioned in any group are assumed
    independent of every other source.

    Args:
        name: Human-readable name of the policy, used in comparison output.
        source_groups: Iterable of iterables, each holding root-unit labels
            that must be counted as one independent source.
    """

    name: str
    source_groups: tuple = ()

    def __post_init__(self):
        groups = tuple(
            tuple(sorted(set(_ensure_iterable(group))))
            for group in self.source_groups
        )
        object.__setattr__(self, "source_groups", groups)

    def group_index(self):
        """Map each grouped root-unit label to its group key."""
        index = {}
        for group in self.source_groups:
            for label in group:
                index[label] = group
        return index



@dataclass(frozen=True)
class CitationGraph:
    """Citation structure of all submitted records.

    A citation edge ``a -> b`` means record ``a`` republished record ``b``.
    Strongly connected components collapse citation cycles: every record in a
    cyclic SCC can only be traced to the same set of original sources, so the
    repeated records inside the cycle must not be counted as separate support.
    """

    edges: dict
    components: tuple
    component_of: dict
    root_components: frozenset
    cyclic_components: frozenset

    def root_units_for(self, source):
        """Root-unit labels reachable from ``source`` (its original sources).

        A *root unit* is either a single source with no outgoing citations or
        a whole cyclic SCC that has no citation leaving the cycle.
        """
        if source not in self.component_of:
            return frozenset()

        seen = set()
        stack = [self.component_of[source]]
        while stack:
            component = stack.pop()
            if component in seen:
                continue
            seen.add(component)
            if component in self.root_components:
                continue
            for target in self._neighbour_components(component):
                if target not in seen:
                    stack.append(target)

        return frozenset(
            _root_unit_label(component, self.cyclic_components)
            for component in seen
            if component in self.root_components
        )

    def _neighbour_components(self, component):
        neighbours = set()
        for node in component:
            for target in self.edges.get(node, ()):
                target_component = self.component_of.get(target)
                if target_component is not None and target_component != component:
                    neighbours.add(target_component)
        return neighbours



@dataclass(frozen=True)
class ClaimAssessment:
    """Provenance decision for one submitted record under one policy."""

    claim_id: str
    conclusion_key: str
    status: ClaimStatus
    root_units: frozenset
    independent_sources: tuple
    independent_source_count: int
    evidence_records: tuple


@dataclass(frozen=True)
class ConclusionAssessment:
    """Pooled evidence decision for one relationship conclusion."""

    conclusion_key: str
    status: ClaimStatus
    claim_ids: tuple
    root_units: frozenset
    independent_sources: tuple
    independent_source_count: int
    unattributed_claims: tuple


@dataclass(frozen=True)
class ProvenanceResult:
    """Result of evaluating one claim set under one independence list."""

    independence_list_name: str
    graph: CitationGraph
    assessments: dict
    conclusions: dict
    unattributed: tuple
    retained: tuple
    insufficient: tuple

    def assessment_for(self, claim_id):
        return self.assessments[claim_id]

    def conclusion_for(self, conclusion_key):
        return self.conclusions[conclusion_key]


@dataclass(frozen=True)
class ProvenanceReview:
    """Comparison of one claim set evaluated under two independence lists."""

    baseline: ProvenanceResult
    alternative: ProvenanceResult
    lost_support: tuple
    gained_support: tuple
    unattributed: tuple



def build_citation_graph(claims):
    """Build the :class:`CitationGraph` for a set of claims.

    All cited identifiers become graph nodes, including identifiers whose
    records were not themselves submitted; those unattached originals are
    trivially their own root units.
    """

    edges = {}
    nodes = set()
    for claim in claims:
        nodes.add(claim.source)
        nodes.update(claim.cited_sources)
        edges.setdefault(claim.source, [])
        for target in claim.cited_sources:
            edges.setdefault(target, [])
        edges[claim.source] = list(
            dict.fromkeys(
                list(edges.get(claim.source, [])) +
                list(claim.cited_sources),
            ),
        )

    for node in nodes:
        edges.setdefault(node, [])

    components = _strongly_connected_components(edges)
    component_of = {}
    cyclic = set()
    for component in components:
        if len(component) > 1:
            cyclic.add(component)
            continue
        only_node = next(iter(component))
        if only_node in edges.get(only_node, ()):
            cyclic.add(component)

    for component in components:
        for node in component:
            component_of[node] = component

    roots = set()
    for component in components:
        has_external_edge = False
        for node in component:
            for target in edges.get(node, ()):
                if component_of[target] != component:
                    has_external_edge = True
                    break
            if has_external_edge:
                break
        if not has_external_edge:
            roots.add(component)

    return CitationGraph(
        edges={node: tuple(targets) for node, targets in edges.items()},
        components=tuple(components),
        component_of=component_of,
        root_components=frozenset(roots),
        cyclic_components=frozenset(cyclic),
    )



def evaluate_claims(
    claims,
    independence_list,
    min_independent_sources=2,
    citation_records=None,
):
    """Decide which conclusions retain enough evidence, fully offline.

    Submissions that share a ``conclusion_key`` are treated as corroborating
    records of one relationship: their traced root units are pooled, then
    bucketed through ``independence_list``.  A conclusion is retained only
    when the pool yields at least ``min_independent_sources`` distinct
    independent sources.

    Args:
        claims: Iterable of :class:`Claim` records, one per submitted
            relationship record that must be assessed.
        independence_list: Caller-supplied :class:`IndependenceList`.
        min_independent_sources: Number of distinct independent sources
            required to keep a conclusion.  Defaults to two.
        citation_records: Optional iterable of extra :class:`Claim`-like
            records that only describe feed-level 转引 edges used to trace
            origins.  They are added to the citation graph but are never
            treated as submitted conclusions.

    Returns:
        ProvenanceResult: Per-record and per-conclusion assessments plus
        retained, insufficient and unattributed groupings.
    """

    if min_independent_sources < 1:
        raise ValueError("min_independent_sources must be at least 1")

    claims = tuple(claims)
    citation_records = tuple(citation_records or ())
    seen_ids = set()
    for claim in claims:
        if claim.claim_id in seen_ids:
            raise ValueError("Duplicate claim id: %s" % claim.claim_id)
        seen_ids.add(claim.claim_id)

    graph = build_citation_graph(tuple(claims) + citation_records)
    group_index = independence_list.group_index()

    def bucket(root_unit):
        return group_index.get(root_unit, (root_unit,))

    per_claim = {}
    grouped = {}
    unattributed = []

    for claim in claims:
        # A submitted record with no citation at all has no provenance.  Its
        # own node is a graph root, but a record cannot be its own source, so
        # such self-roots are dropped before counting evidence.
        root_units = graph.root_units_for(claim.source)
        if not claim.cited_sources:
            root_units = frozenset()
        else:
            root_units = frozenset(
                unit for unit in root_units if unit != claim.source
            )
        if not root_units:
            record_status = ClaimStatus.UNATTRIBUTED
            independent_sources = ()
            evidence_records = ()
            unattributed.append(claim.claim_id)
        else:
            buckets = {}
            for root_unit in sorted(root_units):
                buckets.setdefault(bucket(root_unit), set()).add(root_unit)
            independent_sources = _bucket_labels(buckets)
            evidence_records = tuple(sorted(root_units))
            record_status = None

        per_claim[claim.claim_id] = ClaimAssessment(
            claim_id=claim.claim_id,
            conclusion_key=claim.conclusion_key,
            status=record_status,
            root_units=root_units,
            independent_sources=independent_sources,
            independent_source_count=len(independent_sources),
            evidence_records=evidence_records,
        )
        grouped.setdefault(claim.conclusion_key, []).append(claim)

    conclusions = {}
    retained = []
    insufficient = []

    for conclusion_key in sorted(grouped, key=lambda key: str(key)):
        members = grouped[conclusion_key]
        member_ids = tuple(sorted(claim.claim_id for claim in members))
        pooled_units = set()
        pooled_buckets = {}
        naked = []
        for claim in members:
            member_assessment = per_claim[claim.claim_id]
            if member_assessment.status is ClaimStatus.UNATTRIBUTED:
                naked.append(claim.claim_id)
                continue
            pooled_units.update(member_assessment.root_units)
            for root_unit in member_assessment.root_units:
                pooled_buckets.setdefault(bucket(root_unit), set()).add(root_unit)

        independent_sources = _bucket_labels(pooled_buckets)
        if not pooled_units:
            conclusion_status = ClaimStatus.UNATTRIBUTED
        elif len(pooled_buckets) >= min_independent_sources:
            conclusion_status = ClaimStatus.RETAINED
            retained.append(conclusion_key)
        else:
            conclusion_status = ClaimStatus.INSUFFICIENT
            insufficient.append(conclusion_key)

        conclusions[conclusion_key] = ConclusionAssessment(
            conclusion_key=conclusion_key,
            status=conclusion_status,
            claim_ids=member_ids,
            root_units=frozenset(pooled_units),
            independent_sources=independent_sources,
            independent_source_count=len(independent_sources),
            unattributed_claims=tuple(sorted(naked)),
        )

        for claim in members:
            assessment = per_claim[claim.claim_id]
            if assessment.status is None:
                object.__setattr__(assessment, "status", conclusion_status)

    return ProvenanceResult(
        independence_list_name=independence_list.name,
        graph=graph,
        assessments=per_claim,
        conclusions=conclusions,
        unattributed=tuple(sorted(unattributed)),
        retained=tuple(sorted(retained, key=str)),
        insufficient=tuple(sorted(insufficient, key=str)),
    )


def _bucket_labels(buckets):
    return tuple(
        sorted(tuple(sorted(units)) for units in buckets.values())
    )



def review_independence_lists(
    claims,
    baseline_list,
    alternative_list,
    min_independent_sources=2,
    citation_records=None,
):
    """Evaluate one claim set against two independence lists.

    The returned :class:`ProvenanceReview` names every conclusion that loses
    sufficient evidence when the policy switches from ``baseline_list`` to
    ``alternative_list``, and any that gain it.  Records with no citation
    roots stay unattributed under both lists.
    """

    baseline = evaluate_claims(
        claims, baseline_list, min_independent_sources, citation_records,
    )
    alternative = evaluate_claims(
        claims, alternative_list, min_independent_sources, citation_records,
    )

    baseline_retained = set(baseline.retained)
    alternative_retained = set(alternative.retained)

    lost = tuple(sorted(baseline_retained - alternative_retained, key=str))
    gained = tuple(sorted(alternative_retained - baseline_retained, key=str))

    return ProvenanceReview(
        baseline=baseline,
        alternative=alternative,
        lost_support=lost,
        gained_support=gained,
        unattributed=baseline.unattributed,
    )


def claims_from_stix_relationships(relationships, citation_map=None, conclusion_key_fn=None):
    """Build :class:`Claim` objects from STIX relationship (SRO) objects.

    A claim's own source is the relationship id.  Provenance is taken from, in
    order of preference:

    1. The explicit ``citation_map`` entry for the relationship id (mapping an
       id to the source ids it republished).
    2. The ``external_id`` / ``source_name`` values in the relationship's own
       ``external_references``.

    Args:
        relationships: Iterable of STIX SRO dictionaries (or objects exposing
            ``.get``).
        citation_map: Optional mapping of record id -> iterable of cited
            record ids, describing feed-level 转引 edges.
        conclusion_key_fn: Optional callable mapping a relationship to its
            conclusion key.  Defaults to a (source_ref, relationship_type,
            target_ref) triple so equivalent uses-relationships submitted by
            different feeds are pooled together.
    """

    citation_map = citation_map or {}
    claims = []
    for relationship in relationships:
        relationship_id = relationship.get("id")
        cited = tuple(citation_map.get(relationship_id, ()))
        if not cited:
            cited = tuple(_reference_labels(relationship))
        if conclusion_key_fn is None:
            key = _default_conclusion_key(relationship, relationship_id)
        else:
            key = conclusion_key_fn(relationship)
        claims.append(
            Claim(
                claim_id=relationship_id,
                source=relationship_id,
                cited_sources=cited,
                conclusion_key=key,
            ),
        )
    return claims



def citations_from_reports(reports):
    """Build a citation map from STIX report objects.

    Each report id maps to the external-reference labels it cites, so the
    map can be merged with report-to-relationship containment information by
    the caller.
    """

    citation_map = {}
    for report in reports:
        citation_map[report.get("id")] = tuple(_reference_labels(report))
    return citation_map


def _reference_labels(stix_object):
    labels = []
    for reference in stix_object.get("external_references", ()) or ():
        label = reference.get("external_id") or reference.get("source_name")
        if label and label not in labels:
            labels.append(label)
    return labels


def _default_conclusion_key(relationship, relationship_id):
    source_ref = relationship.get("source_ref")
    relationship_type = relationship.get("relationship_type")
    target_ref = relationship.get("target_ref")
    if source_ref and relationship_type and target_ref:
        return (source_ref, relationship_type, target_ref)
    return relationship_id


def _strongly_connected_components(edges):
    """Tarjan's strongly connected components, in deterministic order."""

    index_counter = [0]
    stack = []
    on_stack = set()
    indices = {}
    low_links = {}
    components = []

    def visit(node):
        indices[node] = index_counter[0]
        low_links[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack.add(node)

        for target in edges.get(node, ()):
            if target not in indices:
                visit(target)
                low_links[node] = min(low_links[node], low_links[target])
            elif target in on_stack:
                low_links[node] = min(low_links[node], indices[target])

        if low_links[node] == indices[node]:
            component = set()
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.add(member)
                if member == node:
                    break
            components.append(component)

    for node in sorted(edges):
        if node not in indices:
            visit(node)

    return [frozenset(component) for component in components]


def _root_unit_label(component, cyclic_components):
    if component in cyclic_components:
        return "cycle:" + "|".join(sorted(component))
    return next(iter(component))


def _ensure_iterable(value):
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)

