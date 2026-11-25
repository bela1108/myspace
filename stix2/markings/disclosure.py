"""Bounded fixed-point diagnostics for disclosure markings."""

from __future__ import annotations

from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field
from typing import Any, Iterable


UNKNOWN = "unknown"
PUBLIC = "public"
RESTRICTED = "restricted"
_VERDICTS = frozenset({UNKNOWN, PUBLIC, RESTRICTED})
_POLICIES = frozenset({"allow", "flag", "block"})


class DisclosureGraphError(ValueError):
    """Raised when a disclosure graph definition is invalid."""


def _first(mapping: MappingABC[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return None


def _string_set(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    return frozenset(str(item) for item in value)


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, MappingABC):
        return dict(value)
    if hasattr(value, "to_dict"):
        return dict(value.to_dict())
    if hasattr(value, "keys") and hasattr(value, "__getitem__"):
        return {key: value[key] for key in value.keys()}
    raise DisclosureGraphError(
        f"Expected mapping-like graph value, got {type(value)!r}",
    )


@dataclass(frozen=True)
class DisclosureNode:
    """A graph node with optional case identity and disclosure claim."""

    id: str
    case_id: str | None = None
    markers: frozenset[str] = field(default_factory=frozenset)
    public_claim: bool = False
    restricted_claim: bool = False
    explicit_unknown: bool = False
    missing: bool = False


def coerce_node(raw: Any) -> DisclosureNode:
    if isinstance(raw, DisclosureNode):
        return raw

    data = _mapping(raw)
    node_id = _first(data, "id", "node_id", "ref")
    if node_id is None:
        raise DisclosureGraphError("A disclosure node requires an id")

    verdict = _first(
        data,
        "verdict",
        "disclosure_state",
        "classification",
        "state",
    )
    disclosure = data.get("disclosure")
    if verdict is None and isinstance(disclosure, str) and disclosure in _VERDICTS:
        verdict = disclosure

    markers: set[str] = set()
    for key in (
        "markers",
        "disclosure_markers",
        "marking_refs",
        "object_marking_refs",
    ):
        markers.update(_string_set(data.get(key)))

    if disclosure is not None and verdict not in _VERDICTS:
        markers.update(_string_set(disclosure))

    public_claim = bool(data.get("public", False)) or verdict == PUBLIC
    restricted_claim = bool(data.get("restricted", False)) or verdict == RESTRICTED
    explicit_unknown = (
        bool(data.get("unknown", False))
        or bool(data.get("unresolved", False))
        or verdict == UNKNOWN
    )

    if verdict is not None and verdict not in _VERDICTS:
        markers.add(str(verdict))
        restricted_claim = True

    return DisclosureNode(
        id=str(node_id),
        case_id=_first(data, "case_id", "case", "x_case_id"),
        markers=frozenset(markers),
        public_claim=public_claim,
        restricted_claim=restricted_claim,
        explicit_unknown=explicit_unknown,
        missing=bool(data.get("missing", False)),
    )


@dataclass(frozen=True)
class DisclosureEdge:
    """A directed object reference."""

    source: str
    target: str
    ref: str | None = None
    index: int = -1
    markers: frozenset[str] = field(default_factory=frozenset)


def coerce_edge(raw: Any, index: int) -> DisclosureEdge:
    if isinstance(raw, DisclosureEdge):
        return DisclosureEdge(
            source=raw.source,
            target=raw.target,
            ref=raw.ref,
            index=index,
            markers=raw.markers,
        )

    if isinstance(raw, (tuple, list)):
        if len(raw) < 2:
            raise DisclosureGraphError(
                f"Edge at index {index} needs source and target",
            )
        ref = raw[2] if len(raw) > 2 else None
        markers = _string_set(raw[3]) if len(raw) > 3 else frozenset()
        return DisclosureEdge(str(raw[0]), str(raw[1]), ref, index, markers)

    data = _mapping(raw)
    source = _first(data, "source", "from", "source_ref", "src")
    target = _first(data, "target", "to", "target_ref", "dst")
    if source is None or target is None:
        raise DisclosureGraphError(
            f"Edge at index {index} requires source and target",
        )

    return DisclosureEdge(
        source=str(source),
        target=str(target),
        ref=_first(data, "ref", "property", "name", "relationship_type"),
        index=index,
        markers=_string_set(
            _first(data, "markers", "disclosure_markers", "marking_refs"),
        ),
    )


class DisclosureGraph:
    """Ordered directed graph preserving node and edge input order."""

    def __init__(
        self,
        nodes: Iterable[Any] = (),
        edges: Iterable[Any] = (),
    ) -> None:
        self.nodes: dict[str, DisclosureNode] = {}
        for raw_node in nodes:
            node = coerce_node(raw_node)
            if node.id in self.nodes:
                raise DisclosureGraphError(
                    f"Duplicate disclosure node id: {node.id}",
                )
            self.nodes[node.id] = node

        self.edges: list[DisclosureEdge] = []
        for index, raw_edge in enumerate(edges):
            edge = coerce_edge(raw_edge, index)
            for node_id in (edge.source, edge.target):
                if node_id not in self.nodes:
                    self.nodes[node_id] = DisclosureNode(
                        id=node_id,
                        explicit_unknown=True,
                        missing=True,
                    )
            self.edges.append(edge)

    def adjacency(self) -> dict[str, list[DisclosureEdge]]:
        result = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            result[edge.source].append(edge)
        return result


@dataclass
class NodeState:
    """Monotone disclosure state for one object."""

    node_id: str
    markers: set[str] = field(default_factory=set)
    case_ids: set[str] = field(default_factory=set)
    origins: set[str] = field(default_factory=set)
    depth: int | None = None
    public_claim: bool = False
    restricted_claim: bool = False
    unresolved: bool = False
    missing: bool = False

    @property
    def verdict(self) -> str:
        if self.unresolved:
            return UNKNOWN
        if self.markers or self.restricted_claim:
            return RESTRICTED
        if self.public_claim:
            return PUBLIC
        return UNKNOWN

    @property
    def known_verdict(self) -> str:
        if self.markers or self.restricted_claim:
            return RESTRICTED
        if self.public_claim:
            return PUBLIC
        return UNKNOWN

    @property
    def is_public(self) -> bool:
        return self.verdict == PUBLIC

    def copy(self) -> "NodeState":
        return NodeState(
            node_id=self.node_id,
            markers=set(self.markers),
            case_ids=set(self.case_ids),
            origins=set(self.origins),
            depth=self.depth,
            public_claim=self.public_claim,
            restricted_claim=self.restricted_claim,
            unresolved=self.unresolved,
            missing=self.missing,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "verdict": self.verdict,
            "known_verdict": self.known_verdict,
            "is_public": self.is_public,
            "markers": sorted(self.markers),
            "case_ids": sorted(self.case_ids),
            "origins": sorted(self.origins),
            "depth": self.depth,
            "missing": self.missing,
        }


@dataclass
class DisclosureDiagnostic:
    """Result of a bounded fixed-point disclosure propagation run."""

    root_ids: list[str]
    stable: bool
    iterations: int
    max_iterations: int
    states: dict[str, NodeState]
    stable_boundary: dict[str, Any]
    cycles: list[list[str]]
    cycle_edges: list[dict[str, Any]]
    cross_case_edges: list[dict[str, Any]]
    first_over_limit_edge: dict[str, Any] | None
    limit_reached: str | None
    max_depth: int | None = None
    max_nodes: int | None = None

    @property
    def converged(self) -> bool:
        return self.stable

    @property
    def first_overflow_edge(self) -> dict[str, Any] | None:
        return self.first_over_limit_edge

    @property
    def over_limit_edge(self) -> dict[str, Any] | None:
        return self.first_over_limit_edge

    @property
    def cycle(self) -> list[str]:
        return self.cycles[0] if self.cycles else []

    @property
    def boundary(self) -> list[dict[str, Any]]:
        return self.stable_boundary["edges"]

    @property
    def labels(self) -> dict[str, list[str]]:
        return {
            node_id: sorted(state.markers)
            for node_id, state in self.states.items()
        }

    @property
    def verdicts(self) -> dict[str, str]:
        return {node_id: state.verdict for node_id, state in self.states.items()}

    @property
    def public_node_ids(self) -> list[str]:
        return [
            node_id
            for node_id, state in self.states.items()
            if state.is_public
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_ids": list(self.root_ids),
            "stable": self.stable,
            "converged": self.stable,
            "cycle": self.cycle,
            "iterations": self.iterations,
            "max_iterations": self.max_iterations,
            "max_depth": self.max_depth,
            "max_nodes": self.max_nodes,
            "limit_reached": self.limit_reached,
            "states": {
                key: value.to_dict()
                for key, value in self.states.items()
            },
            "labels": self.labels,
            "verdicts": self.verdicts,
            "public_node_ids": self.public_node_ids,
            "stable_boundary": self.stable_boundary,
            "boundary": self.boundary,
            "cycles": self.cycles,
            "cycle_edges": self.cycle_edges,
            "cross_case_edges": self.cross_case_edges,
            "first_over_limit_edge": self.first_over_limit_edge,
            "first_overflow_edge": self.first_over_limit_edge,
            "over_limit_edge": self.first_over_limit_edge,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


def _edge_record(edge: DisclosureEdge, **changes: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "index": edge.index,
        "source": edge.source,
        "target": edge.target,
        "ref": edge.ref,
    }
    if edge.markers:
        record["edge_markers"] = sorted(edge.markers)
    record.update(changes)
    return record


def _find_first_cycle(graph: DisclosureGraph) -> tuple[list[str], list[int]]:
    adjacency = graph.adjacency()
    color = {node_id: 0 for node_id in graph.nodes}

    for start in graph.nodes:
        if color[start] != 0:
            continue

        color[start] = 1
        node_stack = [start]
        next_edge = [0]
        entry_edges: list[DisclosureEdge] = []

        while node_stack:
            source = node_stack[-1]
            edge_position = next_edge[-1]

            if edge_position < len(adjacency[source]):
                edge = adjacency[source][edge_position]
                next_edge[-1] = edge_position + 1
                target = edge.target

                if color[target] == 0:
                    color[target] = 1
                    node_stack.append(target)
                    next_edge.append(0)
                    entry_edges.append(edge)
                elif color[target] == 1:
                    cycle_position = node_stack.index(target)
                    cycle_nodes = node_stack[cycle_position:] + [target]
                    cycle_edges = entry_edges[cycle_position:] + [edge]
                    return cycle_nodes, [item.index for item in cycle_edges]
            else:
                color[source] = 2
                node_stack.pop()
                next_edge.pop()
                if entry_edges and len(entry_edges) == len(node_stack):
                    entry_edges.pop()

    return [], []


def _merge_state(target: NodeState, source: NodeState, edge: DisclosureEdge) -> None:
    target.markers.update(source.markers)
    target.markers.update(edge.markers)
    target.case_ids.update(source.case_ids)
    target.origins.update(source.origins)
    target.public_claim = target.public_claim or source.public_claim
    target.restricted_claim = (
        target.restricted_claim
        or source.restricted_claim
        or bool(edge.markers)
    )
    target.unresolved = target.unresolved or source.unresolved


def _fingerprint(states: MappingABC[str, NodeState]) -> dict[str, tuple[Any, ...]]:
    return {
        node_id: (
            state.verdict,
            tuple(sorted(state.markers)),
            tuple(sorted(state.case_ids)),
            tuple(sorted(state.origins)),
            state.depth,
            state.public_claim,
            state.restricted_claim,
            state.unresolved,
        )
        for node_id, state in states.items()
    }


def _coerce_graph_argument(
    graph: DisclosureGraph | MappingABC[str, Any] | None,
    nodes: Any,
    edges: Any,
) -> DisclosureGraph:
    if isinstance(graph, DisclosureGraph):
        return graph

    if graph is not None:
        data = _mapping(graph)
        if "objects" in data and "nodes" not in data:
            return graph_from_stix_objects(data)
        nodes = nodes if nodes is not None else data.get("nodes", ())
        edges = edges if edges is not None else data.get("edges", ())

    return DisclosureGraph(nodes or (), edges or ())


def propagate_disclosure(
    graph: DisclosureGraph | MappingABC[str, Any] | None = None,
    *,
    nodes: Any = None,
    edges: Any = None,
    root: str | None = None,
    roots: Iterable[str] | None = None,
    limit: int | None = None,
    max_depth: int | None = None,
    max_nodes: int | None = None,
    max_visited: int | None = None,
    max_iterations: int | None = None,
    cross_case_policy: str = "block",
) -> DisclosureDiagnostic:
    """Propagate markings to a bounded monotone fixed point."""
    if cross_case_policy not in _POLICIES:
        raise DisclosureGraphError(
            f"cross_case_policy must be one of {sorted(_POLICIES)}",
        )

    if limit is not None and max_depth is None:
        max_depth = limit
    if max_nodes is None and max_visited is not None:
        max_nodes = max_visited

    for name, value in (
        ("max_depth", max_depth),
        ("max_nodes", max_nodes),
        ("max_iterations", max_iterations),
    ):
        if value is not None and (not isinstance(value, int) or value < 0):
            raise DisclosureGraphError(f"{name} must be a non-negative integer")

    graph_obj = _coerce_graph_argument(graph, nodes, edges)

    requested_roots: list[str] = []
    if root is not None:
        requested_roots.append(str(root))
    if roots is not None:
        requested_roots.extend(str(item) for item in roots)
    if graph is not None and not requested_roots:
        data = _mapping(graph) if not isinstance(graph, DisclosureGraph) else {}
        if data.get("root") is not None:
            requested_roots.append(str(data["root"]))
        if data.get("roots") is not None:
            requested_roots.extend(str(item) for item in data["roots"])
    if not requested_roots:
        requested_roots = list(graph_obj.nodes)

    root_ids: list[str] = []
    for node_id in requested_roots:
        if node_id not in graph_obj.nodes:
            graph_obj.nodes[node_id] = DisclosureNode(
                id=node_id,
                explicit_unknown=True,
                missing=True,
            )
            graph_obj.adjacency()
        if node_id not in root_ids:
            root_ids.append(node_id)

    if max_iterations is None:
        max_iterations = max(16, len(graph_obj.nodes) + 1)

    states: dict[str, NodeState] = {}
    for node in graph_obj.nodes.values():
        states[node.id] = NodeState(
            node_id=node.id,
            markers=set(node.markers),
            case_ids={node.case_id} if node.case_id is not None else set(),
            origins={node.id},
            public_claim=node.public_claim,
            restricted_claim=node.restricted_claim,
            unresolved=node.explicit_unknown,
            missing=node.missing,
        )
    for node_id in root_ids:
        states[node_id].depth = 0

    cross_case_edges: list[dict[str, Any]] = []
    cross_case_indices: set[int] = set()
    for edge in graph_obj.edges:
        source_case = graph_obj.nodes[edge.source].case_id
        target_case = graph_obj.nodes[edge.target].case_id
        if source_case is not None and target_case is not None and source_case != target_case:
            cross_case_indices.add(edge.index)
            cross_case_edges.append(
                _edge_record(
                    edge,
                    source_case=source_case,
                    target_case=target_case,
                    limit_type="cross_case",
                ),
            )

    node_overflow_indices: set[int] = set()
    stable = False
    iterations = 0

    for iteration in range(1, max_iterations + 1):
        iterations = iteration
        next_states = {node_id: state.copy() for node_id, state in states.items()}

        for edge in graph_obj.edges:
            source_state = states[edge.source]
            if source_state.depth is None:
                continue

            if edge.index in cross_case_indices and cross_case_policy == "block":
                continue

            candidate_depth = source_state.depth + 1
            if max_depth is not None and candidate_depth > max_depth:
                continue

            target_state = next_states[edge.target]
            if max_nodes is not None and target_state.depth is None:
                admitted = sum(state.depth is not None for state in next_states.values())
                if admitted >= max_nodes:
                    node_overflow_indices.add(edge.index)
                    continue

            if target_state.depth is None or candidate_depth < target_state.depth:
                target_state.depth = candidate_depth
            _merge_state(target_state, source_state, edge)

        if _fingerprint(next_states) == _fingerprint(states):
            stable = True
            states = next_states
            break
        states = next_states

    limit_reached = None if stable else "iterations"

    cycle_path, cycle_edge_indices = _find_first_cycle(graph_obj)
    boundary_by_index: dict[int, dict[str, Any]] = {}

    def boundary_record(edge_index: int) -> dict[str, Any]:
        if edge_index not in boundary_by_index:
            edge = graph_obj.edges[edge_index]
            boundary_by_index[edge_index] = _edge_record(edge, conditions=[])
        return boundary_by_index[edge_index]

    def add_condition(edge_index: int, condition: str, **changes: Any) -> None:
        record = boundary_record(edge_index)
        conditions = record.setdefault("conditions", [])
        if condition not in conditions:
            conditions.append(condition)
        record.update(changes)
        record["reason"] = conditions[0]

    if cross_case_policy == "block":
        for edge_index in sorted(cross_case_indices):
            edge = graph_obj.edges[edge_index]
            if states[edge.source].depth is not None:
                add_condition(
                    edge_index,
                    "cross_case_blocked",
                    limit_type="cross_case",
                    stable=stable,
                )

    if max_depth is not None:
        for edge in graph_obj.edges:
            source_state = states[edge.source]
            observed_depth = None if source_state.depth is None else source_state.depth + 1
            if observed_depth is not None and observed_depth > max_depth:
                add_condition(
                    edge.index,
                    "depth_limit",
                    limit_type="depth",
                    limit=max_depth,
                    observed_depth=observed_depth,
                    stable=stable,
                )

    for edge_index in sorted(node_overflow_indices):
        add_condition(
            edge_index,
            "node_limit",
            limit_type="nodes",
            limit=max_nodes,
            stable=stable,
        )

    cycle_edges: list[dict[str, Any]] = []
    for edge_index in cycle_edge_indices:
        record = _edge_record(graph_obj.edges[edge_index], part_of_cycle=True)
        cycle_edges.append(record)
    if cycle_edge_indices:
        closing_index = cycle_edge_indices[-1]
        add_condition(closing_index, "cycle_fixed_point", cycle_closing=True, stable=stable)
        boundary_by_index[closing_index]["cycle_closing"] = True

    boundary_edges = [boundary_by_index[index] for index in sorted(boundary_by_index)]
    first_over_limit_edge = next(
        (record for record in boundary_edges if record.get("limit_type") is not None),
        None,
    )

    boundary_node_ids: list[str] = []
    frontier_node_ids: list[str] = []
    outside_node_ids: list[str] = []
    for record in boundary_edges:
        for node_id in (record["source"], record["target"]):
            if node_id not in boundary_node_ids:
                boundary_node_ids.append(node_id)
        if record["source"] not in frontier_node_ids:
            frontier_node_ids.append(record["source"])
        target_id = record["target"]
        if target_id not in outside_node_ids and states[target_id].depth is None:
            outside_node_ids.append(target_id)

    stable_boundary = {
        "stable": stable,
        "nodes": boundary_node_ids,
        "frontier_nodes": frontier_node_ids,
        "outside_nodes": outside_node_ids,
        "edges": boundary_edges,
        "cycle": cycle_path,
    }

    diagnostic = DisclosureDiagnostic(
        root_ids=root_ids,
        stable=stable,
        iterations=iterations,
        max_iterations=max_iterations,
        states=states,
        stable_boundary=stable_boundary,
        cycles=[cycle_path] if cycle_path else [],
        cycle_edges=cycle_edges,
        cross_case_edges=cross_case_edges,
        first_over_limit_edge=first_over_limit_edge,
        limit_reached=limit_reached,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    return diagnostic


def graph_from_stix_objects(objects: Any, root_id: str | None = None) -> DisclosureGraph:
    """Build a generic graph from STIX-like objects or a STIX bundle."""
    data = _mapping(objects) if not isinstance(objects, (list, tuple)) else None
    if data is not None:
        if "objects" in data:
            objects = data["objects"]
        elif "id" in data:
            objects = [data]

    raw_objects = list(objects or ())
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for raw_object in raw_objects:
        obj = _mapping(raw_object)
        object_id = obj.get("id")
        if object_id is None:
            continue

        markers = set(_string_set(obj.get("object_marking_refs")))
        field_markers: dict[str, set[str]] = {}
        for granular in obj.get("granular_markings", []) or []:
            marking = granular.get("marking_ref") or granular.get("lang")
            granular_markers = _string_set(marking)
            for selector in granular.get("selectors", []) or []:
                property_name = str(selector).split(".", 1)[0].split("[", 1)[0]
                field_markers.setdefault(property_name, set()).update(granular_markers)

        nodes.append({
            "id": object_id,
            "case_id": obj.get("x_case_id") or obj.get("case_id"),
            "markers": markers,
        })

        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        if source_ref and target_ref:
            edges.append({
                "source": source_ref,
                "target": target_ref,
                "ref": obj.get("relationship_type") or obj.get("type"),
                "markers": markers | field_markers.get("source_ref", set()),
            })

        for property_name, value in obj.items():
            if property_name in {"object_marking_refs", "granular_markings"}:
                continue
            if property_name in {"source_ref", "target_ref"} and source_ref and target_ref:
                continue

            values: list[Any]
            if property_name.endswith("_ref") and isinstance(value, str):
                values = [value]
            elif property_name.endswith("_refs") and isinstance(value, (list, tuple)):
                values = list(value)
            else:
                continue

            for position, reference in enumerate(values):
                if not isinstance(reference, str):
                    continue
                selector_markers = set(field_markers.get(property_name, set()))
                indexed_selector = f"{property_name}[{position}]"
                selector_markers.update(field_markers.get(indexed_selector, set()))
                edges.append({
                    "source": object_id,
                    "target": reference,
                    "ref": property_name,
                    "markers": selector_markers,
                })

    graph = DisclosureGraph(nodes, edges)
    if root_id is not None and root_id not in graph.nodes:
        graph.nodes[root_id] = DisclosureNode(id=root_id, explicit_unknown=True, missing=True)
    return graph


graph_from_stix_bundle = graph_from_stix_objects
propagate = propagate_disclosure
diagnose = propagate_disclosure
diagnose_disclosure = propagate_disclosure
bounded_fixed_point = propagate_disclosure


__all__ = [
    "UNKNOWN",
    "PUBLIC",
    "RESTRICTED",
    "DisclosureGraphError",
    "DisclosureNode",
    "DisclosureEdge",
    "DisclosureGraph",
    "NodeState",
    "DisclosureDiagnostic",
    "coerce_node",
    "coerce_edge",
    "propagate_disclosure",
    "graph_from_stix_objects",
    "graph_from_stix_bundle",
    "propagate",
    "diagnose",
    "diagnose_disclosure",
    "bounded_fixed_point",
]
