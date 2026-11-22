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

# Difference-constraint solver used by the offline timeline audit.

from itertools import combinations
from typing import Iterable, Optional, Sequence

from .model import ConstraintEdge, OrderConstraint, TimeSpan

# An edge (u, v, w) means x_v <= x_u + w.
_Edge = tuple[int, int, int]
_ExtraEdge = tuple[str, str, str]

_MAX_COMBINATION_TESTS = 200_000


class TimelineSolver:
    def __init__(self, spans: dict[str, TimeSpan], constraints: Sequence[OrderConstraint]) -> None:
        self.spans = spans
        self.constraints = list(constraints)
        self.constraint_by_id = {constraint.id: constraint for constraint in self.constraints}

    def _constraint_edges(self, constraint_ids: Optional[set[str]]) -> Iterable[ConstraintEdge]:
        for constraint in self.constraints:
            if constraint_ids is not None and constraint.id not in constraint_ids:
                continue
            for edge in constraint.edges:
                yield edge

    def _translate(self, index: dict[str, int], before: str, after: str, kind: str) -> list[_Edge]:
        if before not in index or after not in index:
            return []
        left = index[before]
        right = index[after]
        if kind == 'strict_before':
            return [(right, left, -1)]
        if kind == 'non_strict_before':
            return [(right, left, 0)]
        if kind == 'equal':
            return [(left, right, 0), (right, left, 0)]
        raise ValueError(f'unsupported edge kind: {kind!r}')

    def _build(
        self,
        constraint_ids: Optional[set[str]] = None,
        extra_edges: Sequence[_ExtraEdge] = (),
    ) -> tuple[list[str], dict[str, int], list[_Edge]]:
        identifiers = set(self.spans)
        for edge in self._constraint_edges(constraint_ids):
            identifiers.add(edge.before)
            identifiers.add(edge.after)
        for before, after, _ in extra_edges:
            identifiers.add(before)
            identifiers.add(after)
        ordered = sorted(identifiers)
        index = {identifier: position + 1 for position, identifier in enumerate(ordered)}
        edges: list[_Edge] = []
        for identifier in ordered:
            span = self.spans.get(identifier)
            if span is None:
                continue
            node = index[identifier]
            if span.end is not None:
                edges.append((0, node, span.end))
            if span.start is not None:
                edges.append((node, 0, -span.start))
        for edge in self._constraint_edges(constraint_ids):
            edges.extend(self._translate(index, edge.before, edge.after, edge.kind))
        for before, after, kind in extra_edges:
            edges.extend(self._translate(index, before, after, kind))
        return ordered, index, sorted(edges)

    def solve(
        self,
        constraint_ids: Optional[set[str]] = None,
        extra_edges: Sequence[_ExtraEdge] = (),
    ) -> Optional[dict[str, int]]:
        ordered, index, edges = self._build(constraint_ids, extra_edges)
        size = len(ordered) + 1
        distance = [0] * size
        for _ in range(size):
            changed = False
            for left, right, weight in edges:
                candidate = distance[left] + weight
                if candidate < distance[right]:
                    distance[right] = candidate
                    changed = True
            if not changed:
                break
        else:
            return None
        offset = distance[0]
        return {identifier: distance[index[identifier]] - offset for identifier in ordered}

    def feasible(
        self,
        constraint_ids: Optional[set[str]] = None,
        extra_edges: Sequence[_ExtraEdge] = (),
    ) -> bool:
        return self.solve(constraint_ids, extra_edges) is not None

    def _active_constraints(self) -> list[OrderConstraint]:
        return [constraint for constraint in self.constraints if constraint.edges]

    def _subset_feasible(self, constraint_ids: set[str]) -> bool:
        return self.feasible(constraint_ids)

    def minimal_conflict(self) -> Optional[list[str]]:
        active = self._active_constraints()
        active_ids = [constraint.id for constraint in active]
        if self.feasible(set(active_ids)):
            return None
        if not active_ids:
            return []

        keep = sorted(active_ids)
        for identifier in list(keep):
            trial = [candidate for candidate in keep if candidate != identifier]
            if not self._subset_feasible(set(trial)):
                keep = trial
        keep = sorted(keep)

        total = len(active_ids)
        if total <= 24:
            tests = 0
            for size in range(1, len(keep)):
                for selection in combinations(sorted(active_ids), size):
                    tests += 1
                    if tests > _MAX_COMBINATION_TESTS:
                        return keep
                    if not self._subset_feasible(set(selection)):
                        return list(selection)
        return keep

    def constraint_cycle(self, constraint_ids: Sequence[str]) -> bool:
        graph: dict[str, set[str]] = {}
        for constraint in self.constraints:
            if constraint.id not in constraint_ids:
                continue
            for edge in constraint.edges:
                graph.setdefault(edge.before, set()).add(edge.after)
                graph.setdefault(edge.after, set())
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            for target in sorted(graph.get(node, ())):
                if visit(target):
                    return True
            visiting.remove(node)
            visited.add(node)
            return False

        return any(visit(node) for node in sorted(graph))
