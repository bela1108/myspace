# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

# Offline timeline audit for evidence spread across CycloneDX BOMs.

import os
import sys
import types
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import combinations
from typing import Any, Iterable, Optional, Sequence, Union, cast

from .constraints import parse_constraints, resolve_constraints
from .evidence import extract_evidence
from .loader import load_documents
from .model import Conflict, ConstraintEdge, Evidence, OrderConstraint
from .solver import TimelineSolver
from .timeutil import format_microseconds

PathLike = Union[str, os.PathLike[str]]

PHASE_RANK = {
    'design': 0,
    'pre-build': 1,
    'build': 2,
    'post-build': 3,
    'operations': 4,
    'discovery': 5,
    'decommission': 6,
}


def _digest(value: str) -> str:
    return sha256(value.encode('utf-8')).hexdigest()


@dataclass
class AuditReport:
    evidence: list[Evidence]
    constraints: list[OrderConstraint]
    entailed: list[list[str]] = field(default_factory=list)
    possible: list[list[str]] = field(default_factory=list)
    ambiguous: list[list[str]] = field(default_factory=list)
    equal_possible: list[list[str]] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    witness: dict[str, Optional[str]] = field(default_factory=dict)
    consistent: bool = True
    complete: bool = True
    order_complete: bool = True
    order_scope: dict[str, Any] = field(default_factory=dict)
    legal_orders: Optional[list[list[str]]] = None
    legal_orders_truncated: bool = False

    def to_json(self) -> dict[str, Any]:
        conflicts = [conflict.to_json() for conflict in self.conflicts]
        bom_ids = sorted({item.bom_id for item in self.evidence})
        return {
            'schemaVersion': '1.0',
            'tool': 'cyclonedx-timeline-audit',
            'consistent': self.consistent,
            'complete': self.complete,
            'evidenceCount': len(self.evidence),
            'bomCount': len(bom_ids),
            'evidence': [item.to_json() for item in self.evidence],
            'constraints': [constraint.to_json() for constraint in self.constraints],
            'order': {
                'entailed': self.entailed,
                'possible': self.possible,
                'ambiguous': self.ambiguous,
                'equalPossible': self.equal_possible,
                'scope': self.order_scope,
                'legalOrders': self.legal_orders,
                'legalOrdersTruncated': self.legal_orders_truncated,
            },
            'minimalConflict': conflicts[0] if conflicts else None,
            'minimalConflicts': conflicts,
            'errors': self.errors,
            'witness': self.witness,
        }


def _as_paths(paths: object) -> list[object]:
    if isinstance(paths, (str, os.PathLike, dict, bytes, bytearray)):
        return [paths]
    return list(cast(Iterable[object], paths))


def _as_constraints(value: object) -> list[OrderConstraint]:
    if value is None:
        return []
    if isinstance(value, OrderConstraint):
        return [value]
    if isinstance(value, (list, tuple)) and all(isinstance(item, OrderConstraint) for item in value):
        return list(value)
    return parse_constraints(value)


def _phase_order_constraints(evidence: list[Evidence]) -> list[OrderConstraint]:
    entries: list[tuple[int, str, str]] = []
    for item in evidence:
        if item.kind != 'manifest':
            continue
        labels = [str(label).lower() for label in item.details.get('lifecycleLabels', [])]
        ranked = [PHASE_RANK[label] for label in labels if label in PHASE_RANK]
        if len(ranked) == 1:
            entries.append((ranked[0], labels[0], item.id))
    entries.sort()
    constraints: list[OrderConstraint] = []
    for (rank_a, label_a, id_a), (rank_b, label_b, id_b) in combinations(entries, 2):
        if rank_a == rank_b:
            continue
        before, after = (id_a, id_b) if rank_a < rank_b else (id_b, id_a)
        label_before, label_after = (label_a, label_b) if rank_a < rank_b else (label_b, label_a)
        identifier = 'inferred:phase-order:' + _digest(f'{before}|{after}')[:12]
        edge = ConstraintEdge(
            id=identifier + ':edge',
            constraint_id=identifier,
            before=before,
            after=after,
            kind='strict_before',
        )
        constraints.append(OrderConstraint(
            id=identifier,
            before_selector=before,
            after_selector=after,
            relation='strict_before',
            origin='inferred:phase-order',
            note=f'{label_before} before {label_after}',
            edges=[edge],
        ))
    return constraints


def _legal_stage_orders(  # noqa: C901
    evidence: list[Evidence],
    entailed: Sequence[Sequence[str]],
    *,
    cap: int = 128,
    max_nodes: int = 8,
) -> tuple[Optional[list[list[str]]], bool]:
    stages = sorted(item.id for item in evidence if item.kind == 'manifest')
    if not stages:
        stages = sorted(item.id for item in evidence if item.kind == 'lifecycle')
    if not stages:
        return [], False
    if len(stages) > max_nodes:
        return None, True
    stage_set = set(stages)
    before: dict[str, set[str]] = {stage: set() for stage in stages}
    for left, right in entailed:
        if left in stage_set and right in stage_set:
            before[right].add(left)
    orders: list[list[str]] = []
    truncated = False

    def visit(order: list[str], remaining: set[str]) -> None:
        nonlocal truncated
        if len(orders) >= cap:
            truncated = True
            return
        if not remaining:
            orders.append(list(order))
            return
        for node in sorted(remaining):
            if before[node] & remaining:
                continue
            visit(order + [node], remaining - {node})

    visit([], set(stages))
    return orders, truncated


def _order_pairs(  # noqa: C901
    solver: TimelineSolver,
    evidence: list[Evidence],
    constraints: Sequence[OrderConstraint],
    limit: int,
) -> tuple[list[list[str]], list[list[str]], list[list[str]], list[list[str]], dict[str, Any], bool]:
    all_ids = sorted(item.id for item in evidence)
    referenced: set[str] = set()
    for constraint in constraints:
        for edge in constraint.edges:
            referenced.add(edge.before)
            referenced.add(edge.after)
    order_nodes = {
        item.id for item in evidence
        if item.kind in ('manifest', 'lifecycle', 'component', 'property')
        or item.id in referenced
        or (item.kind == 'occurrence' and item.time_source.startswith('occurrence.'))
    }
    order_ids = sorted(order_nodes)
    if len(order_ids) <= limit:
        candidates = order_ids
        complete = True
    else:
        selected = set(referenced)
        for identifier in order_ids:
            if len(selected) >= limit:
                break
            selected.add(identifier)
        candidates = sorted(selected)[:limit]
        complete = len(candidates) == len(order_ids)
    entailed: set[tuple[str, str]] = set()
    possible: set[tuple[str, str]] = set()
    ambiguous: set[tuple[str, str]] = set()
    equal_possible: set[tuple[str, str]] = set()
    for left, right in combinations(candidates, 2):
        left_before = solver.feasible(extra_edges=((left, right, 'strict_before'),))
        right_before = solver.feasible(extra_edges=((right, left, 'strict_before'),))
        entailed_left = not solver.feasible(extra_edges=((right, left, 'non_strict_before'),))
        entailed_right = not solver.feasible(extra_edges=((left, right, 'non_strict_before'),))
        if entailed_left:
            entailed.add((left, right))
            possible.add((left, right))
        elif entailed_right:
            entailed.add((right, left))
            possible.add((right, left))
        if left_before:
            possible.add((left, right))
        if right_before:
            possible.add((right, left))
        if left_before and right_before:
            ambiguous.add((left, right))
        if solver.feasible(extra_edges=(
            (left, right, 'non_strict_before'),
            (right, left, 'non_strict_before'),
        )):
            equal_possible.add((left, right))
    scope = {
        'evidenceCount': len(candidates),
        'totalEvidence': len(all_ids),
        'complete': complete,
        'limit': limit,
    }
    return (
        [list(pair) for pair in sorted(entailed)],
        [list(pair) for pair in sorted(possible)],
        [list(pair) for pair in sorted(ambiguous)],
        [list(pair) for pair in sorted(equal_possible)],
        scope,
        complete,
    )


def _build_conflict(
    constraint_ids: Sequence[str],
    constraints: Sequence[OrderConstraint],
    evidence_by_id: dict[str, Evidence],
    solver: TimelineSolver,
) -> Conflict:
    constraint_id_set = set(constraint_ids)
    selected = [constraint for constraint in constraints if constraint.id in constraint_id_set]
    selected.sort(key=lambda item: item.id)
    edge_constraints: list[OrderConstraint] = []
    for constraint in selected:
        for edge in constraint.edges:
            edge_constraints.append(OrderConstraint(
                id=edge.id,
                before_selector=edge.before,
                after_selector=edge.after,
                relation=edge.kind,
                origin=constraint.origin,
                note=constraint.note,
                source=constraint.source,
                edges=[edge],
            ))
    edge_solver = TimelineSolver(solver.spans, edge_constraints)
    edge_conflict = edge_solver.minimal_conflict() if edge_constraints else []
    if edge_conflict:
        chosen_ids = set(edge_conflict)
        chosen_edges = [
            entry.edges[0]
            for entry in edge_constraints
            if entry.id in chosen_ids
        ]
        filtered: list[OrderConstraint] = []
        for constraint in selected:
            chosen = [edge for edge in constraint.edges if edge.id in chosen_ids]
            if not chosen:
                continue
            filtered.append(OrderConstraint(
                id=constraint.id,
                before_selector=constraint.before_selector,
                after_selector=constraint.after_selector,
                relation=constraint.relation,
                origin=constraint.origin,
                note=constraint.note,
                source=constraint.source,
                edges=chosen,
            ))
        selected = filtered
    else:
        chosen_edges = [edge for constraint in selected for edge in constraint.edges]
        chosen_ids = {edge.id for edge in chosen_edges}
    edge_ids = sorted(chosen_ids)
    evidence_ids: set[str] = set()
    for edge in chosen_edges:
        evidence_ids.add(edge.before)
        evidence_ids.add(edge.after)
    if not evidence_ids:
        evidence_ids = {
            identifier for identifier, span in solver.spans.items()
            if span.start is not None and span.end is not None and span.start > span.end
        }
    ordered_evidence = [
        evidence_by_id[identifier]
        for identifier in sorted(evidence_ids)
        if identifier in evidence_by_id
    ]
    final_constraint_ids = sorted({edge.constraint_id for edge in chosen_edges})
    reason = (
        'order-cycle' if edge_solver.constraint_cycle(edge_ids)
        else 'evidence-order-conflict'
    )
    if not selected:
        reason = 'inconsistent-evidence'
    return Conflict(
        constraint_ids=final_constraint_ids,
        edge_ids=edge_ids,
        evidence_ids=[item.id for item in ordered_evidence],
        bom_ids=sorted({item.bom_id for item in ordered_evidence}),
        sources=sorted({item.source for item in ordered_evidence}),
        constraints=[constraint.to_json() for constraint in selected],
        reason=reason,
    )


def audit_timelines(
    paths: Union[PathLike, Iterable[PathLike]],
    constraints: object = None,
    *,
    include_phase_order: bool = False,
    order_limit: int = 40,
) -> AuditReport:
    # Audit one or more CycloneDX documents without network access.
    # constraints may be a constraint document (JSON/text), a path to one,
    # or an iterable of OrderConstraint objects.
    order_limit = max(0, order_limit)
    documents = load_documents(_as_paths(paths))
    evidence = extract_evidence(documents)
    evidence_by_id = {item.id: item for item in evidence}
    resolved = _as_constraints(constraints)
    resolved, errors = resolve_constraints(resolved, evidence)
    if include_phase_order:
        inferred = _phase_order_constraints(evidence)
        resolved = sorted(resolved + inferred, key=lambda item: item.id)

    solver = TimelineSolver({item.id: item.span for item in evidence}, resolved)
    conflict_ids = solver.minimal_conflict()
    conflicts: list[Conflict] = []
    if conflict_ids is not None:
        conflicts.append(_build_conflict(conflict_ids, resolved, evidence_by_id, solver))
    consistent = not conflicts

    entailed: list[list[str]] = []
    possible: list[list[str]] = []
    ambiguous: list[list[str]] = []
    equal_possible: list[list[str]] = []
    witness: dict[str, Optional[str]] = {}
    order_scope: dict[str, Any] = {}
    order_complete = False
    legal_orders: Optional[list[list[str]]] = None
    legal_orders_truncated = False
    if consistent:
        entailed, possible, ambiguous, equal_possible, order_scope, order_complete = _order_pairs(
            solver, evidence, resolved, order_limit,
        )
        legal_orders, legal_orders_truncated = _legal_stage_orders(evidence, entailed)
        assignment = solver.solve()
        if assignment is not None:
            for item in evidence:
                witness[item.id] = format_microseconds(assignment[item.id])

    return AuditReport(
        evidence=evidence,
        constraints=resolved,
        entailed=entailed,
        possible=possible,
        ambiguous=ambiguous,
        equal_possible=equal_possible,
        conflicts=conflicts,
        errors=errors,
        witness=witness,
        consistent=consistent,
        complete=not errors and order_complete,
        order_complete=order_complete,
        order_scope=order_scope,
        legal_orders=legal_orders,
        legal_orders_truncated=legal_orders_truncated,
    )


audit = audit_timelines
audit_timeline = audit_timelines
audit_boms = audit_timelines


def collect_evidence(paths: Union[PathLike, Iterable[PathLike]]) -> list[Evidence]:
    return extract_evidence(load_documents(_as_paths(paths)))


class _CallableAuditModule(types.ModuleType):
    # Allow both import cyclonedx.timeline.audit and audit(...).
    def __call__(self, *args: Any, **kwargs: Any) -> AuditReport:
        return audit_timelines(*args, **kwargs)


sys.modules[__name__].__class__ = _CallableAuditModule  # type: ignore[misc]
