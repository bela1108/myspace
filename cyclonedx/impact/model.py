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


"""Result objects of the offline impact explanation API.

These classes are plain, non-serializable data containers. They deliberately keep the references to the underlying
model objects (components and vulnerabilities) so that callers can cross-check every reported path against the BOM.
"""

from typing import TYPE_CHECKING, Iterable, Optional

from .enums import AffectedStatus, ImpactEdgeStatus, ImpactPathStatus

if TYPE_CHECKING:  # pragma: no cover
    from ..model.component import Component, ComponentScope
    from ..model.vulnerability import BomTarget, Vulnerability


class UnresolvedEdge:
    """A dependency edge that could not be fully verified while reconstructing impact paths.

    The edge is kept in the report instead of being silently discarded, so a reviewer can decide whether it actually
    transports the vulnerability into the deployment root.

    :param source: ``bom-ref`` of the component the edge originates from.
    :param target: ``bom-ref`` the edge points at, or ``None`` if even the target identifier was missing.
    :param status: reason why the edge could not be verified -- see :class:`ImpactEdgeStatus`.
    :param detail: human-readable explanation of what needs confirmation.
    """

    def __init__(
        self, *,
        source: str,
        target: Optional[str],
        status: ImpactEdgeStatus,
        detail: str,
    ) -> None:
        self.source = source
        self.target = target
        self.status = status
        self.detail = detail

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UnresolvedEdge):
            return (
                self.source == other.source
                and self.target == other.target
                and self.status == other.status
                and self.detail == other.detail
            )
        return False

    def __hash__(self) -> int:
        return hash((self.source, self.target, self.status, self.detail))

    def __lt__(self, other: object) -> bool:
        if isinstance(other, UnresolvedEdge):
            return (self.source, self.target or '', self.status.value) < \
                (other.source, other.target or '', other.status.value)
        return NotImplemented

    def __repr__(self) -> str:
        return f'<UnresolvedEdge {self.source} -> {self.target} ({self.status.value})>'


class ImpactPath:
    """One reconstructed dependency path from the deployment root to a vulnerable component.

    :param components: ordered components, starting at the deployment root and ending at the component referenced by
        the vulnerability's ``affects`` entry.
    :param status: :attr:`ImpactPathStatus.CONFIRMED` when every edge is verified and the target is asserted affected;
        :attr:`ImpactPathStatus.PENDING` when the path is reachable but at least one edge or the affected status needs
        human confirmation.
    :param unresolved_edges: edges on this path that could not be verified.
    """

    def __init__(
        self, *,
        components: Iterable['Component'],
        status: ImpactPathStatus,
        target_ref: 'BomTarget',
        unresolved_edges: Iterable[UnresolvedEdge] = (),
    ) -> None:
        self.components = tuple(components)
        self.status = status
        self.affects_target = target_ref
        self.unresolved_edges = tuple(unresolved_edges)

    @property
    def bom_refs(self) -> tuple[str, ...]:
        """``bom-ref`` values of the components along the path, in traversal order."""
        return tuple(str(component.bom_ref) for component in self.components)

    @property
    def target(self) -> 'Component':
        """The component the path ends on (the one referenced by ``affects``)."""
        return self.components[-1]

    @property
    def is_confirmed(self) -> bool:
        return self.status is ImpactPathStatus.CONFIRMED

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ImpactPath):
            return (
                self.bom_refs == other.bom_refs
                and self.status == other.status
                and self.affects_target == other.affects_target
            )
        return False

    def __hash__(self) -> int:
        return hash((self.bom_refs, self.status, self.affects_target.ref))

    def __lt__(self, other: object) -> bool:
        if isinstance(other, ImpactPath):
            return self.bom_refs < other.bom_refs
        return NotImplemented

    def __len__(self) -> int:
        return len(self.components)

    def __repr__(self) -> str:
        return f'<ImpactPath {" -> ".join(self.bom_refs)} [{self.status.value}]>'


class VulnerabilityImpact:
    """Reconstructed impact of a single :class:`~cyclonedx.model.vulnerability.Vulnerability` on a deployment root."""

    def __init__(
        self, *,
        vulnerability: 'Vulnerability',
        paths: Iterable[ImpactPath] = (),
        unresolved_edges: Iterable[UnresolvedEdge] = (),
        missing_targets: Iterable['BomTarget'] = (),
    ) -> None:
        self.vulnerability = vulnerability
        self.paths = tuple(sorted(paths))
        self.unresolved_edges = tuple(sorted(set(unresolved_edges)))
        # targets whose bom-ref does not match any component in the BOM
        self.missing_targets = tuple(sorted(missing_targets, key=lambda t: t.ref))

    @property
    def vulnerability_id(self) -> Optional[str]:
        return self.vulnerability.id

    @property
    def confirmed_paths(self) -> tuple[ImpactPath, ...]:
        """Paths that connect the root to a component asserted affected, over verified edges only."""
        return tuple(path for path in self.paths if path.is_confirmed)

    @property
    def pending_paths(self) -> tuple[ImpactPath, ...]:
        """Reachable paths whose conclusion needs human confirmation."""
        return tuple(path for path in self.paths if not path.is_confirmed)

    @property
    def is_risk(self) -> bool:
        """``True`` when at least one confirmed path reaches an asserted-affected component."""
        return bool(self.confirmed_paths)

    def __repr__(self) -> str:
        return (
            f'<VulnerabilityImpact {self.vulnerability_id!r} '
            f'confirmed={len(self.confirmed_paths)} pending={len(self.pending_paths)}>'
        )


class ImpactReport:
    """Full result of :func:`cyclonedx.impact.analyze_impact` for one deployment root.

    The report aggregates the per-vulnerability results and additionally exposes every
    :class:`UnresolvedEdge` that was encountered, including edges leading nowhere and therefore not
    attributable to a specific path.
    """

    def __init__(
        self, *,
        deployment_root: 'Component',
        applicable_scope: frozenset['ComponentScope'],
        impacts: Iterable[VulnerabilityImpact] = (),
        unresolved_edges: Iterable[UnresolvedEdge] = (),
    ) -> None:
        self.deployment_root = deployment_root
        self.applicable_scope = applicable_scope
        self.impacts = tuple(sorted(
            impacts,
            key=lambda impact: impact.vulnerability_id or str(impact.vulnerability.bom_ref),
        ))
        self.unresolved_edges = tuple(sorted(set(unresolved_edges)))

    @property
    def risks(self) -> tuple[VulnerabilityImpact, ...]:
        """Vulnerabilities with at least one confirmed impact path to the deployment root."""
        return tuple(impact for impact in self.impacts if impact.is_risk)

    @property
    def pending(self) -> tuple[VulnerabilityImpact, ...]:
        """Vulnerabilities that are only reachable via pending paths or reference unresolved edges."""
        return tuple(
            impact for impact in self.impacts
            if not impact.is_risk and (impact.pending_paths or impact.unresolved_edges or impact.missing_targets)
        )

    @property
    def all_unresolved_edges(self) -> tuple[UnresolvedEdge, ...]:
        """Every unresolved edge in the report, both path-bound and orphaned, de-duplicated and sorted."""
        edges = set(self.unresolved_edges)
        for impact in self.impacts:
            edges.update(impact.unresolved_edges)
        return tuple(sorted(edges))

    def __repr__(self) -> str:
        return (
            f'<ImpactReport root={str(self.deployment_root.bom_ref)!r} '
            f'risks={len(self.risks)} pending={len(self.pending)}>'
        )
