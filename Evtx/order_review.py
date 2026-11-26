"""Source-aware local ordering review for repeated EVTX acquisitions.

The module intentionally treats an observed record occurrence inside an
acquisition as its identity.  Raw record/sequence numbers are evidence that
may support a continuity edge, but they are never global identifiers and a
reused sequence number cannot merge occurrences or override an explicit
acquisition/physical relation.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

RECORD_CONTINUITY = "record_continuity"
PHYSICAL_ORDER = "physical_order"
ACQUISITION_RELATION = "acquisition_relation"
TESTIMONY = "testimony"
GENERIC_EVIDENCE = "evidence"

SOURCE_LABELS_ZH = {
    RECORD_CONTINUITY: "可信记录连续性",
    PHYSICAL_ORDER: "同一采集的物理顺序",
    ACQUISITION_RELATION: "明确采集关系",
    TESTIMONY: "人工声明",
    GENERIC_EVIDENCE: "来源化证据",
}

SOURCE_KIND_ALIASES = {
    "record_continuity": RECORD_CONTINUITY,
    "continuity": RECORD_CONTINUITY,
    "trusted_record_continuity": RECORD_CONTINUITY,
    "可信记录连续性": RECORD_CONTINUITY,
    "记录连续性": RECORD_CONTINUITY,
    "physical_order": PHYSICAL_ORDER,
    "physical": PHYSICAL_ORDER,
    "同一采集的物理顺序": PHYSICAL_ORDER,
    "物理顺序": PHYSICAL_ORDER,
    "acquisition_relation": ACQUISITION_RELATION,
    "acquisition": ACQUISITION_RELATION,
    "collection_relation": ACQUISITION_RELATION,
    "明确采集关系": ACQUISITION_RELATION,
    "采集关系": ACQUISITION_RELATION,
    "testimony": TESTIMONY,
    "witness": TESTIMONY,
    "witness_statement": TESTIMONY,
    "人工声明": TESTIMONY,
    "证人陈述": TESTIMONY,
}

_PRIORITY = {
    ACQUISITION_RELATION: 40,
    PHYSICAL_ORDER: 30,
    GENERIC_EVIDENCE: 25,
    RECORD_CONTINUITY: 20,
    TESTIMONY: 0,
}


def _stable_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple, set)):
        return tuple(_stable_value(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((str(k), _stable_value(v)) for k, v in value.items()))
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _jsonable(value: Any) -> Any:
    stable = _stable_value(value)
    if isinstance(stable, tuple):
        return [_jsonable(v) for v in stable]
    return stable


@dataclass(frozen=True)
class Source:
    """Provenance attached to one ordering relation."""

    kind: str
    source_id: str = ""
    label: Optional[str] = None
    acquisition_id: Optional[str] = None
    locator: Optional[str] = None
    details: Tuple[Tuple[str, Any], ...] = ()

    def detail_dict(self) -> Dict[str, Any]:
        return {key: _jsonable(value) for key, value in self.details}

    def as_dict(self) -> Dict[str, Any]:
        result = {
            "kind": self.kind,
            "kind_zh": SOURCE_LABELS_ZH.get(self.kind, self.kind),
            "source_id": self.source_id or self.kind,
        }
        if self.label:
            result["label"] = self.label
        if self.acquisition_id is not None:
            result["acquisition_id"] = self.acquisition_id
        if self.locator is not None:
            result["locator"] = self.locator
        if self.details:
            result["details"] = self.detail_dict()
        return result


def make_source(
    kind: Union[str, Source, Mapping[str, Any], None] = None, source_id: Optional[str] = None, **details: Any
) -> Source:
    if isinstance(kind, Source):
        return kind
    if isinstance(kind, Mapping):
        values = dict(kind)
        nested_details = values.pop("details", {}) or {}
        if isinstance(nested_details, Mapping):
            for key, value in nested_details.items():
                values.setdefault(key, value)
        kind_value = values.pop("kind", values.pop("type", GENERIC_EVIDENCE))
        source_id = source_id or values.pop("source_id", values.pop("id", None))
        details.update(values)
        kind = kind_value
    kind = SOURCE_KIND_ALIASES.get(str(kind), str(kind or GENERIC_EVIDENCE))
    label = details.pop("label", None)
    acquisition_id = details.pop("acquisition_id", details.pop("acquisition", None))
    locator = details.pop("locator", None)
    priority = details.pop("priority", None)
    if priority is not None:
        details["priority"] = priority
    if source_id is None:
        source_id = kind
    clean_details = tuple(
        sorted((str(key), _stable_value(value)) for key, value in details.items() if value is not None)
    )
    return Source(
        kind=kind,
        source_id=str(source_id),
        label=str(label) if label is not None else None,
        acquisition_id=str(acquisition_id) if acquisition_id is not None else None,
        locator=str(locator) if locator is not None else None,
        details=clean_details,
    )


@dataclass(frozen=True)
class Relation:
    before: str
    after: str
    source: Source
    relation_id: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        source = self.source.as_dict()
        return {
            "relation_id": self.relation_id,
            "before": self.before,
            "after": self.after,
            "source": source,
            "provenance": source,
        }


class WitnessStatement:
    """A human ordering claim from a witness table."""

    def __init__(
        self,
        before: Any = None,
        after: Any = None,
        statement_id: Optional[str] = None,
        *,
        id: Optional[str] = None,
        witness: Optional[str] = None,
        table_name: Optional[str] = None,
        row_number: Optional[Union[int, str]] = None,
        recorded_at: Optional[str] = None,
        note: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if before is None or after is None:
            raise TypeError("WitnessStatement requires before and after")
        sid = statement_id if statement_id is not None else id
        self.before = str(before)
        self.after = str(after)
        self.statement_id = "" if sid is None else str(sid)
        self.witness = None if witness is None else str(witness)
        self.table_name = None if table_name is None else str(table_name)
        self.row_number = row_number
        self.recorded_at = None if recorded_at is None else str(recorded_at)
        self.note = None if note is None else str(note)
        self.details: Tuple[Tuple[str, Any], ...] = tuple(
            sorted((str(k), _stable_value(v)) for k, v in (details or {}).items())
        )

    @property
    def id(self) -> str:
        return self.statement_id

    def source(self) -> Source:
        return make_source(
            TESTIMONY,
            self.statement_id or "witness-statement",
            witness=self.witness,
            table=self.table_name,
            row=self.row_number,
            recorded_at=self.recorded_at,
            note=self.note,
            **dict(self.details),
        )

    def relation(self) -> Relation:
        return Relation(self.before, self.after, self.source(), self.statement_id or None)

    def as_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "statement_id": self.statement_id or None,
            "before": self.before,
            "after": self.after,
            "source": self.source().as_dict(),
        }
        result["provenance"] = result["source"]
        if self.witness is not None:
            result["witness"] = self.witness
        if self.table_name is not None:
            result["table_name"] = self.table_name
        if self.row_number is not None:
            result["row_number"] = self.row_number
        if self.recorded_at is not None:
            result["recorded_at"] = self.recorded_at
        if self.note is not None:
            result["note"] = self.note
        if self.details:
            result["details"] = {k: _jsonable(v) for k, v in self.details}
        return result

    def __repr__(self) -> str:
        return f"WitnessStatement(id={self.statement_id!r}, {self.before!r} < {self.after!r})"


@dataclass(frozen=True)
class RecordObservation:
    node_id: str
    acquisition_id: str
    physical_index: int
    chunk_id: Optional[str] = None
    chunk_index: Optional[int] = None
    sequence_number: Optional[int] = None
    offset: Optional[int] = None
    content_hash: Optional[str] = None
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    details: Tuple[Tuple[str, Any], ...] = ()

    @property
    def node(self) -> str:
        return self.node_id

    @property
    def segment_id(self) -> str:
        return self.node_id

    def as_dict(self) -> Dict[str, Any]:
        result = {
            "node_id": self.node_id,
            "acquisition_id": self.acquisition_id,
            "physical_index": self.physical_index,
        }
        for key in ("chunk_id", "chunk_index", "sequence_number", "offset", "content_hash", "event_id", "timestamp"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        if self.details:
            result["details"] = {k: _jsonable(v) for k, v in self.details}
        return result


def make_observation(
    node_id: Any = None,
    acquisition_id: Any = None,
    physical_index: Any = None,
    *,
    node: Any = None,
    segment_id: Any = None,
    segment: Any = None,
    operation_id: Any = None,
    position: Any = None,
    index: Any = None,
    **kwargs: Any,
) -> RecordObservation:
    resolved_node = (
        node_id
        if node_id is not None
        else next(
            value for value in (node, segment_id, segment, operation_id, kwargs.pop("id", None)) if value is not None
        )
    )
    resolved_index = physical_index if physical_index is not None else position if position is not None else index
    if resolved_index is None:
        raise TypeError("observation requires physical_index")
    return RecordObservation(
        node_id=str(resolved_node),
        acquisition_id=str(
            acquisition_id if acquisition_id is not None else kwargs.pop("acquisition", "unknown-acquisition")
        ),
        physical_index=int(resolved_index),
        **kwargs,
    )


Observation = RecordObservation


def _first_key(data: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _pair_from_direction(data: Mapping[str, Any]) -> Tuple[Any, Any]:
    direct_before = _first_key(
        data,
        "before",
        "before_id",
        "earlier",
        "earlier_id",
        "first",
        "first_operation",
        "operation_before",
        "op_before",
        "predecessor",
        "先发生",
        "先操作",
        "前操作",
        "操作前",
    )
    direct_after = _first_key(
        data,
        "after",
        "after_id",
        "later",
        "later_id",
        "second",
        "second_operation",
        "operation_after",
        "op_after",
        "successor",
        "后发生",
        "后操作",
        "后操作",
        "操作后",
    )
    if direct_before is not None and direct_after is not None:
        return direct_before, direct_after

    first_value = _first_key(data, "operation_1", "op_1", "操作1", "操作一", "first_op")
    second_value = _first_key(data, "operation_2", "op_2", "操作2", "操作二", "second_op")
    if first_value is not None and second_value is not None:
        return first_value, second_value

    a_value = _first_key(data, "operation_a", "op_a", "a", "操作A", "操作甲")
    b_value = _first_key(data, "operation_b", "op_b", "b", "操作B", "操作乙")
    direction = str(_first_key(data, "direction", "order", "relation", "先后", "顺序", "关系") or "").strip().lower()
    if a_value is not None and b_value is not None:
        reverse_tokens = ("b_before_a", "b<a", "b→a", "后a先b", "b先a后", "reverse", "desc")
        if any(token in direction for token in reverse_tokens):
            return b_value, a_value
        return a_value, b_value

    raise ValueError(f"could not find before/after operation pair in row: {dict(data)!r}")


def coerce_witness(item: Any, index: int = 0) -> WitnessStatement:
    if isinstance(item, WitnessStatement):
        return item
    if isinstance(item, Mapping):
        before, after = _pair_from_direction(item)
        sid = _first_key(item, "statement_id", "witness_statement_id", "id", "编号", "陈述编号", "证言编号")
        details = item.get("details") if isinstance(item.get("details"), Mapping) else {}
        return WitnessStatement(
            before=before,
            after=after,
            statement_id=str(sid) if sid is not None else None,
            witness=_first_key(item, "witness", "witness_name", "author", "证人", "记录人"),
            table_name=_first_key(item, "table_name", "table", "source_table", "表", "表格"),
            row_number=_first_key(item, "row_number", "row", "_row", "行号"),
            recorded_at=_first_key(item, "recorded_at", "timestamp", "记录时间"),
            note=_first_key(item, "note", "comment", "备注"),
            details={**{k: v for k, v in item.items() if k.startswith("x_")}, **dict(details or {})},
        )
    if isinstance(item, (tuple, list)):
        if len(item) == 2:
            return WitnessStatement(item[0], item[1])
        if len(item) == 3:
            return WitnessStatement(item[0], item[1], statement_id=str(item[2]))
        if len(item) >= 4:
            return WitnessStatement(item[0], item[1], statement_id=str(item[2]), witness=item[3])
    raise TypeError(f"unsupported witness statement at index {index}: {item!r}")


def coerce_observation(item: Any, index: int = 0) -> RecordObservation:
    if isinstance(item, RecordObservation):
        return item
    if isinstance(item, Mapping):
        node = _first_key(item, "node_id", "node", "segment_id", "segment", "operation_id", "operation", "id")
        acquisition = _first_key(item, "acquisition_id", "acquisition", "collection_id", "collection")
        physical = _first_key(item, "physical_index", "physical_order", "position", "index")
        if node is None or acquisition is None or physical is None:
            raise ValueError(f"observation requires node, acquisition and physical_index: {item!r}")
        details = item.get("details") if isinstance(item.get("details"), Mapping) else {}
        known = {
            "node_id",
            "node",
            "segment_id",
            "segment",
            "operation_id",
            "operation",
            "id",
            "acquisition_id",
            "acquisition",
            "collection_id",
            "collection",
            "physical_index",
            "physical_order",
            "position",
            "index",
            "details",
        }
        extra = {k: v for k, v in item.items() if k not in known}
        extra.update(details or {})
        clean_details = tuple(sorted((str(k), _stable_value(v)) for k, v in extra.items()))
        return RecordObservation(
            node_id=str(node),
            acquisition_id=str(acquisition),
            physical_index=int(physical),
            chunk_id=str(item["chunk_id"]) if item.get("chunk_id") is not None else None,
            chunk_index=int(item["chunk_index"]) if item.get("chunk_index") is not None else None,
            sequence_number=(
                int(item["sequence_number"])
                if item.get("sequence_number") is not None
                else (
                    int(item["record_number"])
                    if item.get("record_number") is not None
                    else (
                        int(item["record_num"])
                        if item.get("record_num") is not None
                        else (int(item["sequence"]) if item.get("sequence") is not None else None)
                    )
                )
            ),
            offset=(
                int(item["offset"])
                if item.get("offset") is not None
                else (int(item["record_offset"]) if item.get("record_offset") is not None else None)
            ),
            content_hash=(
                str(item["content_hash"])
                if item.get("content_hash") is not None
                else (str(item["hash"]) if item.get("hash") is not None else None)
            ),
            event_id=str(item["event_id"]) if item.get("event_id") is not None else None,
            timestamp=str(item["timestamp"]) if item.get("timestamp") is not None else None,
            details=clean_details,
        )
    raise TypeError(f"unsupported observation at index {index}: {item!r}")


def coerce_relation(item: Any, index: int = 0, default_kind: str = GENERIC_EVIDENCE) -> Relation:
    if isinstance(item, Relation):
        return item
    if isinstance(item, Mapping):
        before = _first_key(item, "before", "before_id", "from_id", "from")
        after = _first_key(item, "after", "after_id", "target", "to")
        if before is None or after is None:
            raise ValueError(f"relation requires before/after: {item!r}")
        source_value = item.get("source", item.get("provenance"))
        if not isinstance(source_value, Source):
            extra = {
                k: v
                for k, v in item.items()
                if k
                not in {
                    "before",
                    "before_id",
                    "source",
                    "from",
                    "after",
                    "after_id",
                    "target",
                    "to",
                    "source_id",
                    "relation_id",
                    "id",
                    "provenance",
                }
            }
            if isinstance(source_value, str) and source_value not in SOURCE_KIND_ALIASES:
                source_value = make_source(default_kind, source_value, **extra)
            else:
                source_value = make_source(
                    source_value if source_value is not None else default_kind,
                    item.get("source_id"),
                    **extra,
                )
        rid = _first_key(item, "relation_id", "id")
        return Relation(str(before), str(after), source_value, str(rid) if rid is not None else None)
    if isinstance(item, (tuple, list)):
        if len(item) == 2:
            before, after = item
            source = make_source(default_kind, f"{default_kind}-{index}")
            return Relation(str(before), str(after), source)
        if len(item) == 3:
            first, second, third = item
            if isinstance(first, str) and re.match(r"^(?:R|REL)[-_]?\d+$", first, flags=re.IGNORECASE):
                source = make_source(default_kind, first)
                return Relation(str(second), str(third), source, first)
            if isinstance(third, str) and third in SOURCE_KIND_ALIASES:
                source = make_source(third, f"{SOURCE_KIND_ALIASES[third]}-{index}")
            elif isinstance(third, str):
                source = make_source(default_kind, third)
            else:
                source = make_source(third, f"{default_kind}-{index}")
            return Relation(str(first), str(second), source)
        if (
            len(item) >= 4
            and isinstance(item[0], str)
            and re.match(r"^(?:R|REL)[-_]?\d+$", item[0], flags=re.IGNORECASE)
        ):
            relation_id, before, after, source = item[0], item[1], item[2], item[3]
            return Relation(
                str(before),
                str(after),
                make_source(source, f"{default_kind}-{index}"),
                str(relation_id),
            )
        if len(item) >= 4:
            before, after, source = item[0], item[1], item[2]
            relation_id = item[3] if len(item) > 3 else None
            return Relation(
                str(before),
                str(after),
                make_source(source, f"{default_kind}-{index}"),
                str(relation_id) if relation_id is not None else None,
            )
    raise TypeError(f"unsupported relation at index {index}: {item!r}")


class _DAG:
    def __init__(self) -> None:
        self.adj: Dict[str, Set[str]] = defaultdict(set)
        self.edges: Dict[Tuple[str, str], List[Relation]] = defaultdict(list)
        self.nodes: Set[str] = set()

    def add(self, relation: Relation) -> None:
        self.nodes.add(relation.before)
        self.nodes.add(relation.after)
        self.adj[relation.before].add(relation.after)
        self.edges[(relation.before, relation.after)].append(relation)

    def path(self, start: str, end: str) -> Optional[List[str]]:
        if start == end:
            return [start]
        if start not in self.nodes or end not in self.nodes:
            return None
        previous: Dict[str, Optional[str]] = {start: None}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for nxt in sorted(self.adj.get(current, ())):
                if nxt in previous:
                    continue
                previous[nxt] = current
                if nxt == end:
                    path = [end]
                    while previous[path[-1]] is not None:
                        path.append(previous[path[-1]])  # type: ignore[arg-type]
                    path.reverse()
                    return path
                queue.append(nxt)
        return None


def find_cycle(adjacency: Mapping[str, Iterable[str]]) -> Optional[List[str]]:
    adj = {node: set(neighbors) for node, neighbors in adjacency.items()}
    for neighbors in list(adj.values()):
        for neighbor in neighbors:
            adj.setdefault(neighbor, set())
    color = {node: 0 for node in adj}
    parent: Dict[str, Optional[str]] = {}
    cycle: Optional[List[str]] = None

    import sys

    sys.setrecursionlimit(max(1000, len(adj) * 3 + 100))

    def visit(node: str) -> None:
        nonlocal cycle
        if cycle is not None:
            return
        color[node] = 1
        for nxt in sorted(adj.get(node, ())):
            if cycle is not None:
                return
            state = color.get(nxt, 0)
            if state == 0:
                parent[nxt] = node
                visit(nxt)
            elif state == 1:
                found = [node]
                current = node
                while current != nxt:
                    current_parent = parent.get(current)
                    if current_parent is None:
                        found = None  # type: ignore[assignment]
                        break
                    current = current_parent
                    found.append(current)
                if found is not None:
                    found.reverse()
                    found.append(nxt)
                    cycle = found
                    return
        color[node] = 2

    for node in sorted(adj):
        if color.get(node, 0) == 0:
            visit(node)
            if cycle is not None:
                return cycle
    return None


def _is_cyclic(adjacency: Mapping[str, Iterable[str]]) -> bool:
    return find_cycle(adjacency) is not None


@dataclass(frozen=True)
class CycleEdge:
    before: str
    after: str
    relations: Tuple[Relation, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"before": self.before, "after": self.after, "relations": [r.as_dict() for r in self.relations]}


@dataclass(frozen=True)
class WitnessConflict:
    statements: Tuple[WitnessStatement, ...]
    edges: Tuple[CycleEdge, ...]
    minimal: bool = True

    @property
    def statement_ids(self) -> Tuple[str, ...]:
        return tuple(s.id or "" for s in self.statements)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "minimal": self.minimal,
            "statement_ids": list(self.statement_ids),
            "inconsistent_witness_statements": [s.as_dict() for s in self.statements],
            "statements": [s.as_dict() for s in self.statements],
            "conflict_cycle": [edge.as_dict() for edge in self.edges],
            "minimal_conflict_basis": [edge.as_dict() for edge in self.edges],
            "basis": " -> ".join([edge.before for edge in self.edges] + ([self.edges[-1].after] if self.edges else [])),
        }


@dataclass(frozen=True)
class RejectedRelation:
    relation: Relation
    reason: str
    message: str
    basis_relation_ids: Tuple[str, ...] = ()
    cycle_nodes: Tuple[str, ...] = ()
    basis_relations: Tuple[Relation, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        result = {
            "relation": self.relation.as_dict(),
            "reason": self.reason,
            "message": self.message,
        }
        if self.basis_relation_ids:
            result["basis_relation_ids"] = list(self.basis_relation_ids)
        if self.cycle_nodes:
            result["cycle_nodes"] = list(self.cycle_nodes)
        if self.basis_relations:
            result["basis_relations"] = [relation.as_dict() for relation in self.basis_relations]
        return result


@dataclass(frozen=True)
class OrderedPair:
    before: str
    after: str
    direct: bool
    relation_ids: Tuple[str, ...]
    sources: Tuple[Source, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "before": self.before,
            "after": self.after,
            "direct": self.direct,
            "relation_ids": list(self.relation_ids),
            "sources": [source.as_dict() for source in self.sources],
        }


@dataclass
class LocalOrderReview:
    nodes: Tuple[str, ...]
    relations: Tuple[Relation, ...]
    ordered_pairs: Tuple[OrderedPair, ...]
    incomparable_pairs: Tuple[Tuple[str, str], ...]
    topological_generations: Tuple[Tuple[str, ...], ...]
    legal_orders: Tuple[Tuple[str, ...], ...]
    legal_orders_truncated: bool
    witness_conflict: Optional[WitnessConflict]
    rejected_relations: Tuple[RejectedRelation, ...] = ()
    warnings: Tuple[Dict[str, Any], ...] = ()
    observations: Tuple[RecordObservation, ...] = ()
    witness_statements: Tuple[WitnessStatement, ...] = ()
    provisional_relations: Tuple[Relation, ...] = ()

    @property
    def partial_order(self) -> Dict[str, Any]:
        return self.partial_order_report()

    def partial_order_report(self) -> Dict[str, Any]:
        possible_orders = [list(order) for order in self.legal_orders]
        return {
            "nodes": list(self.nodes),
            "direct_relations": [relation.as_dict() for relation in self.relations],
            "ordered_pairs": [pair.as_dict() for pair in self.ordered_pairs],
            "incomparable_pairs": [list(pair) for pair in self.incomparable_pairs],
            "topological_generations": [list(generation) for generation in self.topological_generations],
            "legal_orders": possible_orders,
            "possible_orders": possible_orders,
            "valid_orders": possible_orders,
            "legal_orders_truncated": self.legal_orders_truncated,
            "rejected_relations": [item.as_dict() for item in self.rejected_relations],
            "provisional_relations": [relation.as_dict() for relation in self.provisional_relations],
            "warnings": list(self.warnings),
        }

    def inconsistent_witness_statements(self) -> Dict[str, Any]:
        conflict_ids = set(self.witness_conflict.statement_ids if self.witness_conflict else ())
        all_statements = []
        for statement in self.witness_statements:
            statement_data = statement.as_dict()
            statement_data["in_minimal_conflict"] = statement.statement_id in conflict_ids
            all_statements.append(statement_data)
        if self.witness_conflict is None:
            return {
                "minimal": True,
                "statement_ids": [],
                "statements": [],
                "all_statements": all_statements,
                "message": "未发现无法同时成立的证人陈述。",
            }
        result = self.witness_conflict.as_dict()
        result["all_statements"] = all_statements
        result["minimal_conflict_set"] = list(self.witness_conflict.statement_ids)
        return result

    @property
    def minimal_conflict(self) -> Optional[WitnessConflict]:
        return self.witness_conflict

    def investigator_package(self) -> Dict[str, Any]:
        """The two artifacts requested for the investigator."""
        return {
            "still_valid_partial_order": self.partial_order_report(),
            "inconsistent_witness_statements": self.inconsistent_witness_statements(),
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "still_valid_partial_order": self.partial_order_report(),
            "inconsistent_witness_statements": self.inconsistent_witness_statements(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=indent, default=str)

    def to_markdown(self) -> str:
        return render_markdown_report(self)


def _priority(relation: Relation) -> int:
    override = relation.source.detail_dict().get("priority")
    if isinstance(override, int):
        return override
    return _PRIORITY.get(relation.source.kind, 10)


def _assign_relation_ids(relations: Sequence[Relation]) -> List[Relation]:
    used = set()
    result = []
    for index, relation in enumerate(relations, 1):
        rid = relation.relation_id
        if not rid:
            rid = f"R{index:04d}"
        base = rid
        suffix = 2
        while rid in used:
            rid = f"{base}-{suffix}"
            suffix += 1
        used.add(rid)
        result.append(replace(relation, relation_id=rid))
    return result


def _observation_relations(
    observations: Sequence[RecordObservation],
    physical_order: bool,
    continuity: bool,
) -> Tuple[List[Relation], List[Dict[str, Any]], List[Dict[str, Any]]]:
    relations: List[Relation] = []
    warnings: List[Dict[str, Any]] = []
    sequence_reuse: List[Dict[str, Any]] = []
    by_acquisition: Dict[str, List[RecordObservation]] = defaultdict(list)
    for observation in observations:
        by_acquisition[observation.acquisition_id].append(observation)

    for acquisition_id in sorted(by_acquisition):
        items = sorted(
            by_acquisition[acquisition_id],
            key=lambda item: (
                item.physical_index,
                item.chunk_index if item.chunk_index is not None else 10**9,
                item.offset if item.offset is not None else 10**18,
                item.node_id,
            ),
        )
        if physical_order:
            for left, right in zip(items, items[1:]):
                source = make_source(
                    PHYSICAL_ORDER,
                    f"physical:{acquisition_id}:{left.physical_index}-{right.physical_index}",
                    acquisition_id=acquisition_id,
                    locator=f"physical_index {left.physical_index}->{right.physical_index}",
                    chunk_id=right.chunk_id or left.chunk_id,
                    from_offset=left.offset,
                    to_offset=right.offset,
                )
                relations.append(Relation(left.node_id, right.node_id, source))

        seq_groups: Dict[int, List[RecordObservation]] = defaultdict(list)
        for item in items:
            if item.sequence_number is not None:
                seq_groups[int(item.sequence_number)].append(item)

        for sequence_number, owners in sorted(seq_groups.items()):
            node_ids = sorted({item.node_id for item in owners})
            if len(node_ids) > 1:
                entry = {
                    "code": "sequence_number_reuse",
                    "acquisition_id": acquisition_id,
                    "sequence_number": sequence_number,
                    "node_ids": node_ids,
                    "rule": "sequence numbers are not global identities; occurrence-scoped acquisition identity is retained",
                }
                sequence_reuse.append(entry)
                warnings.append(entry)

        if continuity:
            for sequence_number, owners in sorted(seq_groups.items()):
                next_owners = seq_groups.get(sequence_number + 1, [])
                if not next_owners:
                    continue
                reused = len({item.node_id for item in owners}) > 1 or len({item.node_id for item in next_owners}) > 1
                for left in owners:
                    for right in next_owners:
                        if left.node_id == right.node_id:
                            continue
                        source = make_source(
                            RECORD_CONTINUITY,
                            f"continuity:{acquisition_id}:{sequence_number}-{sequence_number + 1}",
                            acquisition_id=acquisition_id,
                            locator=f"record_num {sequence_number}->{sequence_number + 1}",
                            reused_sequence=reused,
                            ambiguous=reused,
                            trusted=not reused,
                        )
                        relations.append(Relation(left.node_id, right.node_id, source))
    return relations, warnings, sequence_reuse


def _rejection_for_relation(dag: _DAG, relation: Relation) -> Optional[RejectedRelation]:
    if relation.before == relation.after:
        return RejectedRelation(
            relation=relation,
            reason="self_order_conflict",
            message="节点不能严格早于自身；该来源化关系未纳入偏序。",
        )
    cycle_path = dag.path(relation.after, relation.before)
    if cycle_path is None:
        return None

    basis_ids: List[str] = []
    basis_relations: List[Relation] = []
    kinds = set()
    for left, right in zip(cycle_path, cycle_path[1:]):
        for existing in dag.edges.get((left, right), ()):
            kinds.add(existing.source.kind)
            if existing.relation_id and existing.relation_id not in basis_ids:
                basis_ids.append(existing.relation_id)
                basis_relations.append(existing)
    reused = bool(relation.source.detail_dict().get("reused_sequence"))
    untrusted = relation.source.detail_dict().get("trusted") is False
    if reused and ACQUISITION_RELATION in kinds:
        reason = "reused_sequence_cannot_override_acquisition_relation"
        message = "复用序号块形成的顺序会形成闭环；按规则保留明确采集关系，降级该序号连续性依据。"
    elif reused and PHYSICAL_ORDER in kinds:
        reason = "reused_sequence_cannot_override_physical_order"
        message = "复用序号块形成的顺序会推翻同一采集物理顺序；物理遍历顺序继续有效。"
    elif untrusted:
        reason = "untrusted_continuity_conflict"
        message = "不可信的序号连续性依据与已成立偏序冲突，未纳入仍成立的偏序。"
    else:
        reason = "would_create_cycle"
        message = "该关系与已接受的更高优先级来源冲突，未纳入仍成立的偏序。"
    return RejectedRelation(
        relation,
        reason,
        message,
        tuple(basis_ids),
        tuple(cycle_path),
        tuple(basis_relations),
    )


def _accept_evidence(
    candidate_relations: Sequence[Relation],
) -> Tuple[_DAG, List[Relation], List[RejectedRelation]]:
    dag = _DAG()
    accepted: List[Relation] = []
    rejected: List[RejectedRelation] = []
    ordered = sorted(
        candidate_relations,
        key=lambda relation: (
            -_priority(relation),
            relation.source.kind,
            relation.relation_id or "",
            relation.before,
            relation.after,
        ),
    )
    for relation in ordered:
        rejection = _rejection_for_relation(dag, relation)
        if rejection is not None:
            rejected.append(rejection)
            continue
        dag.add(relation)
        accepted.append(relation)
    accepted.sort(key=lambda relation: relation.relation_id or "")
    return dag, accepted, rejected


def _topological_generations(dag: _DAG, nodes: Sequence[str]) -> List[List[str]]:
    indegree = {node: 0 for node in nodes}
    for node in nodes:
        for nxt in dag.adj.get(node, ()):  # only unique adjacency set
            indegree[nxt] = indegree.get(nxt, 0) + 1
    ready = sorted(node for node in nodes if indegree[node] == 0)
    generations: List[List[str]] = []
    while ready:
        generation = sorted(ready)
        generations.append(generation)
        next_ready: List[str] = []
        for node in generation:
            for nxt in sorted(dag.adj.get(node, ())):
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    next_ready.append(nxt)
        ready = next_ready
    return generations


def _enumerate_topological_orders(
    dag: _DAG,
    nodes: Sequence[str],
    limit: int,
) -> Tuple[List[Tuple[str, ...]], bool]:
    if limit <= 0:
        return [], False
    adjacency = {node: set(dag.adj.get(node, set())) for node in nodes}
    indegree = {node: 0 for node in nodes}
    for node in nodes:
        for nxt in adjacency[node]:
            indegree[nxt] = indegree.get(nxt, 0) + 1
    orders: List[Tuple[str, ...]] = []
    truncated = False

    def backtrack(order: List[str], remaining_indegree: Dict[str, int]) -> None:
        nonlocal truncated
        if len(orders) >= limit:
            truncated = True
            return
        if len(order) == len(nodes):
            orders.append(tuple(order))
            return
        ready = sorted(node for node in nodes if node not in order and remaining_indegree[node] == 0)
        for node in ready:
            next_indegree = dict(remaining_indegree)
            for nxt in adjacency.get(node, ()):
                next_indegree[nxt] -= 1
            order.append(node)
            backtrack(order, next_indegree)
            order.pop()
            if len(orders) >= limit:
                truncated = True
                return

    backtrack([], indegree)
    return orders, truncated


def _build_ordered_pairs(dag: _DAG, nodes: Sequence[str], relation_by_id: Mapping[str, Relation]) -> List[OrderedPair]:
    pairs: List[OrderedPair] = []
    node_set = set(nodes)
    for start in nodes:
        previous: Dict[str, Optional[str]] = {start: None}
        previous_relation: Dict[str, Optional[str]] = {}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for nxt in sorted(dag.adj.get(current, ())):
                if nxt in previous:
                    continue
                previous[nxt] = current
                relations = dag.edges.get((current, nxt), [])
                previous_relation[nxt] = relations[0].relation_id if relations else None
                queue.append(nxt)
        for end in sorted(previous):
            if end == start or end not in node_set:
                continue
            path = [end]
            rel_ids: List[str] = []
            current = end
            while previous[current] is not None:
                rel_id = previous_relation.get(current)
                if rel_id:
                    rel_ids.append(rel_id)
                current = previous[current]  # type: ignore[assignment]
                path.append(current)
            path.reverse()
            rel_ids.reverse()
            relation_ids: List[str] = []
            sources: List[Source] = []
            for left, right in zip(path, path[1:]):
                edge_relations = dag.edges.get((left, right), ())
                for relation in edge_relations:
                    if relation.relation_id and relation.relation_id not in relation_ids:
                        relation_ids.append(relation.relation_id)
                    if relation.source not in sources:
                        sources.append(relation.source)
            pairs.append(OrderedPair(start, end, len(path) == 2, tuple(relation_ids), tuple(sources)))
    return pairs


def _witness_adjacency(
    witnesses: Sequence[WitnessStatement], selected_ids: Optional[Set[str]] = None
) -> Dict[str, Set[str]]:
    adjacency: Dict[str, Set[str]] = defaultdict(set)
    for witness in witnesses:
        if selected_ids is not None and witness.statement_id not in selected_ids:
            continue
        adjacency[witness.before].add(witness.after)
    return dict(adjacency)


def _combined_adjacency(
    dag: _DAG, witnesses: Sequence[WitnessStatement], selected_ids: Optional[Set[str]] = None
) -> Dict[str, Set[str]]:
    combined: Dict[str, Set[str]] = {node: set(neighbors) for node, neighbors in dag.adj.items()}
    for witness in witnesses:
        if selected_ids is not None and witness.statement_id not in selected_ids:
            continue
        combined.setdefault(witness.before, set()).add(witness.after)
    return combined


def _cycle_conflict(
    dag: _DAG,
    witnesses: Sequence[WitnessStatement],
    selected_ids: Set[str],
) -> Optional[WitnessConflict]:
    selected = {w for w in witnesses if w.statement_id in selected_ids}
    cycle_nodes = find_cycle(_combined_adjacency(dag, witnesses, selected_ids))
    if cycle_nodes is None:
        return None
    edges: List[CycleEdge] = []
    witness_by_pair: Dict[Tuple[str, str], List[WitnessStatement]] = defaultdict(list)
    for witness in selected:
        witness_by_pair[(witness.before, witness.after)].append(witness)
    for left, right in zip(cycle_nodes, cycle_nodes[1:]):
        hard_relations = tuple(dag.edges.get((left, right), ()))
        if hard_relations:
            relations = hard_relations
        else:
            claims = witness_by_pair.get((left, right), [])
            relations = tuple(w.relation() for w in claims)
        edges.append(CycleEdge(left, right, relations))
    ordered_statements = tuple(sorted(selected, key=lambda w: w.statement_id))
    return WitnessConflict(ordered_statements, tuple(edges), True)


def find_minimal_witness_conflict(
    dag: Any = None,
    witnesses: Optional[Sequence[Any]] = None,
    *,
    evidence_relations: Optional[Sequence[Relation]] = None,
    hard_relations: Optional[Sequence[Relation]] = None,
    relations: Optional[Sequence[Relation]] = None,
    witness_statements: Optional[Sequence[Any]] = None,
    statements: Optional[Sequence[Any]] = None,
) -> Optional[WitnessConflict]:
    """Find one inclusion-minimal witness subset incompatible with hard order."""
    if dag is None:
        dag = evidence_relations if evidence_relations is not None else hard_relations
    if dag is None:
        dag = relations or []
    if witnesses is None:
        witnesses = witness_statements if witness_statements is not None else statements or []
    normalized_witnesses = [coerce_witness(item, i + 1) for i, item in enumerate(witnesses)]
    normalized_witnesses = _assign_witness_ids(normalized_witnesses)

    if not isinstance(dag, _DAG):
        relations: List[Relation] = []
        if isinstance(dag, Sequence) and not isinstance(dag, Mapping):
            relations = [coerce_relation(item, i) for i, item in enumerate(dag)]
        built = _DAG()
        for relation in relations:
            built.add(relation)
        dag = built

    for witness in sorted(normalized_witnesses, key=lambda w: w.statement_id):
        if witness.before == witness.after:
            return WitnessConflict(
                (witness,),
                (CycleEdge(witness.before, witness.after, (witness.relation(),)),),
                True,
            )
        path = dag.path(witness.after, witness.before)
        if path is not None:
            edges: List[CycleEdge] = []
            closed_path = path + [witness.before] if path[-1] != witness.before else path
            for left, right in zip(closed_path, closed_path[1:]):
                hard = tuple(dag.edges.get((left, right), ()))
                if hard:
                    edges.append(CycleEdge(left, right, hard))
                else:
                    edges.append(CycleEdge(left, right, (witness.relation(),)))
            edges.append(CycleEdge(witness.before, witness.after, (witness.relation(),)))
            return WitnessConflict((witness,), tuple(edges), True)

    cycle = find_cycle(_combined_adjacency(dag, normalized_witnesses))
    if cycle is None:
        return None

    witness_ids_by_pair: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for witness in normalized_witnesses:
        witness_ids_by_pair[(witness.before, witness.after)].append(witness.statement_id)

    candidate: Set[str] = set()
    for left, right in zip(cycle, cycle[1:]):
        if right in dag.adj.get(left, set()):
            continue
        ids = sorted(witness_ids_by_pair.get((left, right), ()))
        if ids:
            candidate.add(ids[0])

    if not candidate:
        return None

    for witness_id in sorted(candidate):
        trial = candidate - {witness_id}
        if find_cycle(_combined_adjacency(dag, normalized_witnesses, trial)) is not None:
            candidate = trial

    return _cycle_conflict(dag, normalized_witnesses, candidate)


def _assign_witness_ids(witnesses: Sequence[WitnessStatement]) -> List[WitnessStatement]:
    result: List[WitnessStatement] = []
    used: Set[str] = set()
    for index, witness in enumerate(witnesses, 1):
        sid = witness.statement_id or f"W{index:04d}"
        base = sid
        suffix = 2
        while sid in used:
            sid = f"{base}-{suffix}"
            suffix += 1
        used.add(sid)
        if witness.statement_id == sid:
            result.append(witness)
        else:
            result.append(
                WitnessStatement(
                    witness.before,
                    witness.after,
                    sid,
                    witness=witness.witness,
                    table_name=witness.table_name,
                    row_number=witness.row_number,
                    recorded_at=witness.recorded_at,
                    note=witness.note,
                    details=dict(witness.details),
                )
            )
    return result


def review_local_order(
    observations: Optional[Iterable[Any]] = None,
    witnesses: Optional[Iterable[Any]] = None,
    *,
    segments: Optional[Iterable[Any]] = None,
    statements: Optional[Iterable[Any]] = None,
    witness_statements: Optional[Iterable[Any]] = None,
    acquisition_relations: Optional[Iterable[Any]] = None,
    collection_relations: Optional[Iterable[Any]] = None,
    evidence_relations: Optional[Iterable[Any]] = None,
    hard_relations: Optional[Iterable[Any]] = None,
    edges: Optional[Iterable[Any]] = None,
    physical_order: bool = True,
    continuity: bool = True,
    max_legal_orders: int = 32,
    nodes: Optional[Iterable[str]] = None,
    allow_ambiguous_continuity: bool = False,
    **legacy_kwargs: Any,
) -> LocalOrderReview:
    """Build the surviving partial order and one minimal witness conflict."""
    if observations is None:
        observations = segments
    if witnesses is None:
        witnesses = statements if statements is not None else witness_statements
    if witnesses is None:
        witnesses = legacy_kwargs.get("witness_claims") or legacy_kwargs.get("claims")
    if acquisition_relations is None:
        acquisition_relations = collection_relations
    if evidence_relations is None:
        evidence_relations = hard_relations if hard_relations is not None else edges
    if nodes is None:
        nodes = legacy_kwargs.get("node_ids")
    if isinstance(witnesses, (str, Path)):
        witnesses = load_witness_table(witnesses)
    normalized_observations = [coerce_observation(item, i + 1) for i, item in enumerate(observations or [])]
    normalized_witnesses = _assign_witness_ids([coerce_witness(item, i + 1) for i, item in enumerate(witnesses or [])])

    candidates: List[Relation] = []
    for i, item in enumerate(acquisition_relations or [], 1):
        relation = coerce_relation(item, i, ACQUISITION_RELATION)
        if relation.source.kind != ACQUISITION_RELATION:
            relation = replace(
                relation,
                source=make_source(
                    ACQUISITION_RELATION, relation.source.source_id, original_source=relation.source.as_dict()
                ),
            )
        candidates.append(relation)
    for i, item in enumerate(evidence_relations or [], 1):
        candidates.append(coerce_relation(item, i, GENERIC_EVIDENCE))

    observed_relations, observation_warnings, _ = _observation_relations(
        normalized_observations, physical_order=physical_order, continuity=continuity
    )
    candidates.extend(observed_relations)
    candidates = _assign_relation_ids(candidates)

    hard_candidates: List[Relation] = []
    ambiguous_continuity: List[Relation] = []
    for relation in candidates:
        details = relation.source.detail_dict()
        untrusted_sequence = relation.source.kind == RECORD_CONTINUITY and (
            details.get("reused_sequence") is True
            or details.get("ambiguous") is True
            or details.get("trusted") is False
        )
        if untrusted_sequence and not allow_ambiguous_continuity:
            ambiguous_continuity.append(relation)
        else:
            hard_candidates.append(relation)

    dag, accepted, rejected = _accept_evidence(hard_candidates)
    provisional_relations: List[Relation] = []
    for relation in sorted(
        ambiguous_continuity,
        key=lambda item: (-_priority(item), item.relation_id or "", item.before, item.after),
    ):
        rejection = _rejection_for_relation(dag, relation)
        if rejection is not None:
            rejected.append(rejection)
        else:
            provisional_relations.append(relation)
    relation_by_id = {relation.relation_id: relation for relation in accepted if relation.relation_id}

    all_nodes: Set[str] = set(str(node) for node in (nodes or ()))
    all_nodes.update(dag.nodes)
    for relation in candidates:
        all_nodes.add(relation.before)
        all_nodes.add(relation.after)
    all_nodes.update(observation.node_id for observation in normalized_observations)
    for witness in normalized_witnesses:
        all_nodes.add(witness.before)
        all_nodes.add(witness.after)
    ordered_nodes = tuple(sorted(all_nodes))

    generations = tuple(tuple(generation) for generation in _topological_generations(dag, ordered_nodes))
    legal_orders, truncated = _enumerate_topological_orders(dag, ordered_nodes, max_legal_orders)
    ordered_pairs = tuple(_build_ordered_pairs(dag, ordered_nodes, relation_by_id))

    reachable: Set[Tuple[str, str]] = {(pair.before, pair.after) for pair in ordered_pairs}
    incomparable: List[Tuple[str, str]] = []
    for i, left in enumerate(ordered_nodes):
        for right in ordered_nodes[i + 1 :]:
            if (left, right) not in reachable and (right, left) not in reachable:
                incomparable.append((left, right))

    conflict = find_minimal_witness_conflict(dag, normalized_witnesses)
    warnings = tuple(observation_warnings)
    return LocalOrderReview(
        nodes=ordered_nodes,
        relations=tuple(accepted),
        ordered_pairs=ordered_pairs,
        incomparable_pairs=tuple(incomparable),
        topological_generations=generations,
        legal_orders=legal_orders,
        legal_orders_truncated=truncated,
        witness_conflict=conflict,
        rejected_relations=tuple(rejected),
        warnings=warnings,
        observations=tuple(normalized_observations),
        witness_statements=tuple(normalized_witnesses),
        provisional_relations=tuple(provisional_relations),
    )


def observations_from_evtx(
    path: Union[str, Path],
    acquisition_id: Optional[str] = None,
    *,
    node_map: Optional[Mapping[str, str]] = None,
    node_resolver: Optional[Callable[[Any, Mapping[str, Any]], Optional[str]]] = None,
    skip_timestamp_errors: bool = True,
) -> List[RecordObservation]:
    """Extract source-aware record observations using python-evtx traversal."""
    from .Evtx import Evtx

    path = Path(path)
    acquisition_id = acquisition_id or path.stem
    node_map = node_map or {}
    observations: List[RecordObservation] = []
    physical_index = -1
    with Evtx(str(path)) as log:
        for chunk_index, chunk in enumerate(log.chunks()):
            chunk_id = f"chunk-{chunk_index}@0x{chunk.offset():x}"
            for local_index, record in enumerate(chunk.records()):
                physical_index += 1
                sequence_number = int(record.record_num()) if record.record_num() is not None else None
                timestamp = None
                try:
                    timestamp_value = record.timestamp()
                    timestamp = (
                        timestamp_value.isoformat() if hasattr(timestamp_value, "isoformat") else str(timestamp_value)
                    )
                except Exception:
                    if not skip_timestamp_errors:
                        raise
                context = {
                    "path": str(path),
                    "acquisition_id": acquisition_id,
                    "chunk_index": chunk_index,
                    "chunk_id": chunk_id,
                    "local_index": local_index,
                    "physical_index": physical_index,
                    "sequence_number": sequence_number,
                    "offset": record.offset(),
                }
                node_id = None
                if node_resolver is not None:
                    node_id = node_resolver(record, context)
                if node_id is None:
                    keys = [
                        f"{acquisition_id}:{chunk_index}:{record.offset()}",
                        f"{acquisition_id}:{chunk_index}:{local_index}",
                        f"{acquisition_id}:{sequence_number}",
                        str(sequence_number),
                    ]
                    node_id = next((node_map[key] for key in keys if key in node_map), None)
                if node_id is None:
                    node_id = f"{acquisition_id}:{chunk_index}:record@{record.offset():x}"
                observations.append(
                    RecordObservation(
                        node_id=str(node_id),
                        acquisition_id=acquisition_id,
                        physical_index=physical_index,
                        chunk_id=chunk_id,
                        chunk_index=chunk_index,
                        sequence_number=sequence_number,
                        offset=int(record.offset()),
                        timestamp=timestamp,
                        details=(("local_index", local_index), ("path", str(path))),
                    )
                )
    return observations


def review_evtx_acquisitions(
    acquisitions: Union[Mapping[str, Union[str, Path]], Sequence[Union[str, Path, Tuple[str, Union[str, Path]]]]],
    witnesses: Optional[Iterable[Any]] = None,
    *,
    node_map: Optional[Mapping[str, str]] = None,
    acquisition_relations: Optional[Iterable[Any]] = None,
    evidence_relations: Optional[Iterable[Any]] = None,
    max_legal_orders: int = 32,
    **kwargs: Any,
) -> LocalOrderReview:
    all_observations: List[RecordObservation] = []
    if isinstance(acquisitions, Mapping):
        items = list(acquisitions.items())
    else:
        items = []
        for item in acquisitions:
            if isinstance(item, tuple):
                items.append(item)
            else:
                path = Path(item)
                items.append((path.stem, path))
    for acquisition_id, path in items:
        all_observations.extend(observations_from_evtx(path, str(acquisition_id), node_map=node_map))
    return review_local_order(
        all_observations,
        witnesses,
        acquisition_relations=acquisition_relations,
        evidence_relations=evidence_relations,
        max_legal_orders=max_legal_orders,
        **kwargs,
    )


def load_witness_table(path: Union[str, Path]) -> List[Dict[str, Any]]:
    path = Path(path)
    if path.suffix.lower() in {".json", ".ndjson"}:
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix.lower() == ".ndjson":
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        data = json.loads(text)
        if isinstance(data, Mapping):
            for key in ("witnesses", "statements", "witness_statements", "rows", "data"):
                if key in data:
                    return list(data[key])
            return [data]
        return list(data)
    delimiter = "\t" if path.suffix.lower() in {".tsv", ".tab"} else ","
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        rows: List[Dict[str, Any]] = []
        for row_number, row in enumerate(reader, 2):
            row = {key: value for key, value in row.items() if key is not None}
            row["_row"] = row_number
            rows.append(row)
        return rows


def load_relations_file(path: Union[str, Path]) -> List[Dict[str, Any]]:
    path = Path(path)
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, Mapping):
            for key in ("relations", "acquisition_relations", "edges", "data"):
                if key in data:
                    return list(data[key])
            return [data]
        return list(data)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _format_source(source: Source) -> str:
    parts = [SOURCE_LABELS_ZH.get(source.kind, source.kind)]
    if source.source_id and source.source_id != source.kind:
        parts.append(source.source_id)
    if source.acquisition_id:
        parts.append(f"采集 `{source.acquisition_id}`")
    if source.locator:
        parts.append(source.locator)
    details = source.detail_dict()
    for key in ("witness", "table", "row", "reused_sequence"):
        if key in details and details[key] not in (None, False):
            parts.append(f"{key}={details[key]}")
    return "；".join(parts)


def render_markdown_report(review: LocalOrderReview) -> str:
    lines = ["# 本地顺序复核报告", ""]
    package = review.investigator_package()
    order = package["still_valid_partial_order"]
    conflict = package["inconsistent_witness_statements"]

    lines.extend(["## 仍成立的局部顺序", ""])
    lines.append(f"已知节点：{', '.join(f'`{node}`' for node in order['nodes']) or '无'}。")
    lines.append("")
    if review.relations:
        lines.append("**直接来源关系**")
        lines.append("")
        for relation in review.relations:
            lines.append(
                f"- `{relation.before}` 早于 `{relation.after}` `[{relation.relation_id}]` — {_format_source(relation.source)}。"
            )
        lines.append("")
    inferred = [pair for pair in review.ordered_pairs if not pair.direct]
    if inferred:
        lines.append("**可传递推出的先后**")
        lines.append("")
        for pair in inferred:
            lines.append(f"- `{pair.before}` ≤ `{pair.after}`，依据 `{', '.join(pair.relation_ids)}`。")
        lines.append("")
    if review.topological_generations:
        lines.append("**未知段的合法层级（同层可互换）**")
        lines.append("")
        for index, generation in enumerate(review.topological_generations, 1):
            lines.append(f"{index}. {', '.join(f'`{node}`' for node in generation)}")
        lines.append("")
    if review.legal_orders:
        lines.append("**合法顺序示例**")
        lines.append("")
        shown = review.legal_orders[:8]
        for candidate_order in shown:
            lines.append("- " + " → ".join(f"`{node}`" for node in candidate_order))
        if review.legal_orders_truncated or len(review.legal_orders) < len(review.legal_orders):
            lines.append("- …还有其他合法拓扑顺序；报告只枚举了有限数量。")
        lines.append("")
    if review.rejected_relations:
        lines.append("**未采纳的来源化顺序**")
        lines.append("")
        for rejected in review.rejected_relations:
            rel = rejected.relation
            lines.append(f"- `{rel.before}` 早于 `{rel.after}` 未采纳：{rejected.message}（{rejected.reason}）。")
        lines.append("")
    if review.provisional_relations:
        lines.append("**暂不定序的歧义序号线索**")
        lines.append("")
        for relation in review.provisional_relations:
            lines.append(
                f"- `{relation.before}` 与 `{relation.after}` 之间有序号连续表象，但序号已复用/不唯一；"
                "保留为侦查线索，不纳入仍成立的偏序。"
            )
        lines.append("")

    lines.extend(["## 无法同时成立的证人陈述", ""])
    if not conflict.get("statement_ids"):
        lines.append("未发现与仍成立偏序矛盾、或彼此形成闭环的证人陈述。")
    else:
        lines.append("以下陈述构成一组 inclusion-minimal 冲突集合，无法同时成立：")
        lines.append("")
        for statement in conflict["inconsistent_witness_statements"]:
            sid = statement.get("statement_id") or "(未编号)"
            witness = f"，证人 `{statement['witness']}`" if statement.get("witness") else ""
            lines.append(f"- `{sid}`：`{statement['before']}` 早于 `{statement['after']}`{witness}。")
        lines.append("")
        lines.append("最小闭环依据（每条边均带来源）：")
        lines.append("")
        for edge in conflict["conflict_cycle"]:
            source_texts = []
            for relation_data in edge["relations"]:
                source = relation_data["source"]
                source_texts.append(
                    f"`{relation_data.get('relation_id') or source.get('source_id')}`:{source.get('kind_zh')}"
                )
            lines.append(f"- `{edge['before']}` → `{edge['after']}` — {'; '.join(source_texts)}")
        lines.append("")
    conflict_ids = set(conflict.get("statement_ids", []))
    other_statements = [
        statement for statement in review.witness_statements if statement.statement_id not in conflict_ids
    ]
    if other_statements:
        lines.append("**未进入该最小冲突集合的人工声明**")
        lines.append("")
        for statement in other_statements:
            sid = statement.statement_id or "(未编号)"
            lines.append(f"- `{sid}`：`{statement.before}` 早于 `{statement.after}`，暂未发现与当前偏序矛盾。")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


review_order = review_local_order
reconcile_order = review_local_order
reconcile_local_order = review_local_order
build_partial_order = review_local_order
establish_local_order = review_local_order
build_local_order_review = review_local_order
find_minimal_conflict = find_minimal_witness_conflict
minimal_witness_conflict = find_minimal_witness_conflict
OrderReview = LocalOrderReview
OrderReconciliation = LocalOrderReview


def minimal_conflict_set(*args: Any, **kwargs: Any) -> Tuple[str, ...]:
    conflict = find_minimal_witness_conflict(*args, **kwargs)
    return tuple(conflict.statement_ids) if conflict is not None else ()


__all__ = [
    "ACQUISITION_RELATION",
    "GENERIC_EVIDENCE",
    "PHYSICAL_ORDER",
    "RECORD_CONTINUITY",
    "TESTIMONY",
    "LocalOrderReview",
    "OrderReview",
    "OrderReconciliation",
    "Observation",
    "OrderedPair",
    "Relation",
    "Source",
    "WitnessConflict",
    "WitnessStatement",
    "coerce_observation",
    "coerce_relation",
    "coerce_witness",
    "find_minimal_witness_conflict",
    "minimal_witness_conflict",
    "minimal_conflict_set",
    "load_relations_file",
    "load_witness_table",
    "make_observation",
    "make_source",
    "observations_from_evtx",
    "render_markdown_report",
    "review_evtx_acquisitions",
    "review_local_order",
    "review_order",
    "reconcile_order",
    "reconcile_local_order",
    "build_local_order_review",
]
