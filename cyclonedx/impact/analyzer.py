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


"""Offline reconstruction of vulnerability impact paths from a BOM dependency graph."""

from collections import deque
from collections.abc import Iterable, Sequence
from typing import Optional

from ..model.bom import Bom
from ..model.component import Component, ComponentScope
from ..model.impact_analysis import ImpactAnalysisAffectedStatus
from ..model.vulnerability import BomTarget, Vulnerability
from .enums import AffectedStatus, ImpactEdgeStatus, ImpactPathStatus
from .model import ImpactPath, ImpactReport, UnresolvedEdge, VulnerabilityImpact


def analyze_impact(
    bom: Bom,
    deployment_root: Component,
    applicable_scope: Iterable[ComponentScope] = (ComponentScope.REQUIRED,),
) -> ImpactReport:
    """Explain, fully offline, how the BOM's vulnerabilities reach a deployment root.

    For every vulnerability in ``bom`` the ``affects`` targets are interpreted against the actual components, and the
    :class:`~cyclonedx.model.dependency.Dependency` graph is walked from ``deployment_root`` to reconstruct every
    dependency path that reaches an affected component. Only components whose ``scope`` is part of
    ``applicable_scope`` are treated as applicable; edges that leave this scope are reported, not traversed.

    Cycles, dangling references and targets with an unknown affected status never invalidate the analysis. The
    affected edges are kept as :class:`UnresolvedEdge` entries and the paths touching them are marked
    :attr:`ImpactPathStatus.PENDING`, so a reviewer can confirm or dismiss them.

    :param bom: the BOM holding the components, dependency graph and vulnerabilities.
    :param deployment_root: the component representing the deployment (for example a production or test image).
    :param applicable_scope: component scopes considered applicable to the deployment; defaults to ``required`` only.
    :returns: an :class:`ImpactReport` with confirmed risks, pending paths and every edge awaiting confirmation.
    """
    scope = frozenset(applicable_scope)
    context = _AnalysisContext(bom, scope)
    root_ref = str(deployment_root.bom_ref)

    impacts = [
        context.analyze_vulnerability(vulnerability, root_ref)
        for vulnerability in sorted(bom.vulnerabilities, key=_vulnerability_sort_key)
    ]

    return ImpactReport(
        deployment_root=deployment_root,
        applicable_scope=scope,
        impacts=impacts,
        unresolved_edges=context.orphan_edges,
    )


def _vulnerability_sort_key(vulnerability: Vulnerability) -> str:
    return vulnerability.id or str(vulnerability.bom_ref)


def _dedupe_paths(paths: list[ImpactPath]) -> list[ImpactPath]:
    """Drop duplicate pending branches (for example the same cycle reached from several frames)."""
    unique: dict[tuple[tuple[str, ...], ImpactPathStatus, str], ImpactPath] = {}
    for path in paths:
        key = (path.bom_refs, path.status, path.affects_target.ref)
        existing = unique.get(key)
        if existing is None or len(path.unresolved_edges) > len(existing.unresolved_edges):
            unique[key] = path
    return list(unique.values())


class _AnalysisContext:
    """Graph indexes and traversal state shared while analyzing one deployment root."""

    def __init__(self, bom: Bom, applicable_scope: frozenset[ComponentScope]) -> None:
        self._applicable_scope = applicable_scope
        self._components: dict[str, Component] = {
            str(component.bom_ref): component for component in bom.components
        }
        # dependency graph: parent bom-ref -> ordered child bom-refs
        self._edges: dict[str, list[str]] = {}
        for dependency in bom.dependencies:
            self._edges.setdefault(str(dependency.ref), []).extend(
                str(child.ref) for child in dependency.dependencies
            )
        for children in self._edges.values():
            children.sort()
        self.orphan_edges: set[UnresolvedEdge] = set()

    def analyze_vulnerability(self, vulnerability: Vulnerability, root_ref: str) -> VulnerabilityImpact:
        paths: list[ImpactPath] = []
        unresolved: set[UnresolvedEdge] = set()
        missing_targets: list[BomTarget] = []

        for target in sorted(vulnerability.affects, key=lambda item: item.ref):
            affected_status = self._classify_target(target)
            if affected_status is AffectedStatus.MISSING_TARGET:
                missing_targets.append(target)
                continue
            if affected_status is AffectedStatus.UNAFFECTED:
                continue
            # edges are collected per target so they stay attributable to this affects entry
            target_edges: set[UnresolvedEdge] = set()
            paths.extend(self._find_paths(root_ref, target, affected_status, target_edges))
            unresolved.update(target_edges)

        return VulnerabilityImpact(
            vulnerability=vulnerability,
            paths=paths,
            unresolved_edges=unresolved,
            missing_targets=missing_targets,
        )

    def _classify_target(self, target: BomTarget) -> AffectedStatus:
        component = self._components.get(target.ref)
        if component is None:
            return AffectedStatus.MISSING_TARGET
        statuses = [
            version.status
            for version in target.versions
            if version.status is not None
        ]
        if not statuses:
            return AffectedStatus.UNKNOWN_RANGE
        if any(status is ImpactAnalysisAffectedStatus.AFFECTED for status in statuses):
            return AffectedStatus.AFFECTED
        if all(status is ImpactAnalysisAffectedStatus.UNAFFECTED for status in statuses):
            return AffectedStatus.UNAFFECTED
        # only `unknown` entries (or a mix without any explicit `affected`)
        return AffectedStatus.UNKNOWN_RANGE

    def _find_paths(
        self,
        root_ref: str,
        target: BomTarget,
        affected_status: AffectedStatus,
        unresolved: set[UnresolvedEdge],
    ) -> list[ImpactPath]:
        pending_range = affected_status is AffectedStatus.UNKNOWN_RANGE
        stack: deque[_Frame] = deque()
        if root_ref in self._components:
            stack.append(_Frame(root_ref, (self._components[root_ref],), frozenset((root_ref,)), ()))
        results: list[ImpactPath] = []

        while stack:
            frame = stack.pop()
            if frame.node_ref == target.ref:
                status = (
                    ImpactPathStatus.PENDING
                    if pending_range or frame.pending
                    else ImpactPathStatus.CONFIRMED
                )
                results.append(ImpactPath(
                    components=frame.chain,
                    status=status,
                    target_ref=target,
                    unresolved_edges=frame.pending,
                ))
                continue
            for child_ref in self._edges.get(frame.node_ref, ()):
                edge = self._verify_edge(frame.node_ref, child_ref, frame.visited)
                if edge is not None:
                    unresolved.add(edge)
                    self.orphan_edges.add(edge)
                    # keep the blocked branch in the report as a pending path ending on the known source
                    results.append(ImpactPath(
                        components=frame.chain,
                        status=ImpactPathStatus.PENDING,
                        target_ref=target,
                        unresolved_edges=frame.pending + (edge,),
                    ))
                    continue
                child = self._components[child_ref]
                stack.append(_Frame(
                    child_ref,
                    frame.chain + (child,),
                    frame.visited | frozenset((child_ref,)),
                    frame.pending,
                ))
        return _dedupe_paths(results)

    def _verify_edge(
        self,
        source_ref: str,
        target_ref: str,
        visited: frozenset[str],
    ) -> Optional[UnresolvedEdge]:
        target = self._components.get(target_ref)
        if target is None:
            return UnresolvedEdge(
                source=source_ref,
                target=target_ref,
                status=ImpactEdgeStatus.MISSING_REFERENCE,
                detail=(
                    f'bom-ref {target_ref!r} is referenced by a dependency edge '
                    'but no component in the BOM declares it'
                ),
            )
        if target_ref in visited:
            return UnresolvedEdge(
                source=source_ref,
                target=target_ref,
                status=ImpactEdgeStatus.CYCLE,
                detail=f'edge closes a cycle: {target_ref!r} is already on the current path',
            )
        if target.scope is not None and target.scope not in self._applicable_scope:
            return UnresolvedEdge(
                source=source_ref,
                target=target_ref,
                status=ImpactEdgeStatus.OUT_OF_SCOPE,
                detail=(
                    f'component scope {target.scope.value!r} is outside the applicable scope '
                    f'{sorted(scope.value for scope in self._applicable_scope)}'
                ),
            )
        return None


class _Frame:
    """A single DFS frame: current node, component chain, visited refs and unresolved edges on the branch."""

    def __init__(
        self,
        node_ref: str,
        chain: tuple[Component, ...],
        visited: frozenset[str],
        pending: Sequence[UnresolvedEdge],
    ) -> None:
        self.node_ref = node_ref
        self.chain = chain
        self.visited = visited
        self.pending = pending
