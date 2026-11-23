"""
Dependency-chain analysis over parsed `pylock.*.toml` lock plans.

This module builds a directed dependency graph from an already-resolved
PEP 751 lock plan and answers "how does package X get pulled in?" questions
for a given optional group (or for the base environment).

All inputs are read from disk; no dependency resolution, network access, or
package installation is performed here.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from pip_audit._remediation.lockplan import LockPlan, evaluate_marker

#: The pseudo-group representing the lock plan's base environment, i.e.
#: packages reachable from lock-level roots rather than an optional group.
BASE_GROUP = "base"

#: Upper bound on the number of simple paths enumerated per root/target pair.
#: Path counting only distinguishes single-chain components from multi-path
#: ones, so a generous cap keeps the analysis bounded on dense graphs.
MAX_PATHS = 64


@dataclass(frozen=True)
class DependencyChain:
    """
    A dependency path from a group root down to a target package.

    `packages` lists canonical names from the root (inclusive) to the target
    (inclusive). `marker_gated` is set when at least one edge on the path
    carries a marker that cannot be decided without a live environment.
    """

    packages: tuple[str, ...]
    marker_gated: bool

    @property
    def length(self) -> int:
        """
        The number of dependency edges on this chain.
        """

        return len(self.packages) - 1


class DependencyGraph:
    """
    A directed, marker-aware dependency graph for one parsed lock plan.
    """

    def __init__(self, plan: LockPlan) -> None:
        """
        Build a `DependencyGraph` from a parsed `LockPlan`.
        """

        self._plan = plan
        self._dependents: dict[str, set[str]] = {name: set() for name in plan.packages}
        for parent_name, package in plan.packages.items():
            for requirement in package.dependencies:
                target = requirement.canonical_name
                if target in self._dependents:
                    self._dependents[target].add(parent_name)

    @property
    def plan(self) -> LockPlan:
        """
        The `LockPlan` this graph was built from.
        """

        return self._plan

    @property
    def top_level_packages(self) -> frozenset[str]:
        """
        The canonical names of lock-level roots.

        Optional-group members are excluded: they are roots of their own
        groups, even though nothing else in the lock depends on them.
        """

        return frozenset(self._plan.root_names)

    def has_package(self, name: str) -> bool:
        """
        Return whether the lock plan contains the given canonical package.
        """

        return name in self._plan.packages

    def groups(self) -> tuple[str, ...]:
        """
        Return every reportable group, including the base pseudo-group.
        """

        return (BASE_GROUP,) + tuple(sorted(self._plan.groups))

    def group_roots(self, group: str) -> frozenset[str]:
        """
        Return the canonical root package names for the given group.

        `BASE_GROUP` yields lock-level roots; any other value yields the
        members declared in the lock plan's `[groups]` table.
        """

        if group == BASE_GROUP:
            return self.top_level_packages
        return frozenset(self._plan.group_members(group))

    def reachable_from(self, roots: frozenset[str]) -> set[str]:
        """
        Return every canonical package reachable from any of `roots`.
        """

        seen: set[str] = set()
        queue: deque[str] = deque(roots)
        while queue:
            current = queue.popleft()
            if current in seen or current not in self._plan.packages:
                continue
            seen.add(current)
            for requirement in self._plan.packages[current].dependencies:
                queue.append(requirement.canonical_name)
        return seen

    def chains_to(self, roots: frozenset[str], target: str) -> list[DependencyChain]:
        """
        Enumerate simple dependency chains from any root to `target`.

        Returns an empty list when the target is absent or not reachable from
        the supplied roots. Each chain records whether any edge is behind an
        undecidable environment marker.
        """

        if target not in self._plan.packages:
            return []

        chains: list[DependencyChain] = []
        for root in sorted(roots):
            self._walk(root, target, (root,), False, chains)
        chains.sort(key=lambda chain: (chain.length, chain.packages))
        return chains

    def _walk(
        self,
        current: str,
        target: str,
        path: tuple[str, ...],
        marker_gated: bool,
        chains: list[DependencyChain],
    ) -> None:
        if len(chains) >= MAX_PATHS:
            return
        if current == target:
            chains.append(DependencyChain(packages=path, marker_gated=marker_gated))
            return

        package = self._plan.packages.get(current)
        if package is None:
            return
        for requirement in package.dependencies:
            name = requirement.canonical_name
            if name in path or name not in self._plan.packages:
                continue
            edge_state = evaluate_marker(requirement.marker)
            gated = marker_gated or edge_state is None
            self._walk(name, target, path + (name,), gated, chains)
