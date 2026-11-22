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

"""
Engine that produces a VEX verdict reuse list from two BOM revisions.

The analysis never compares ``bom-ref`` strings across documents: a bom-ref is
only a BOM-local reference role used to walk each document's own dependency
graph and to resolve which component a ``vulnerabilities[].affects`` entry
points at. Correlation between the old and the new BOM is done by component
coordinates first and by artifact identity (hashes / SWHIDs / OmniBOR ids)
second.
"""

from collections import defaultdict
from typing import TYPE_CHECKING, Optional

from ....model.bom_ref import BomRef
from ....model.component import ComponentScope
from ....model.impact_analysis import ImpactAnalysisState
from .model import (
    ArtifactIdentity,
    ComponentCoordinates,
    ReuseDecision,
    ReuseReason,
    SignedVerdict,
    VexReuseEntry,
    VexReuseReport,
)

if TYPE_CHECKING:  # pragma: no cover
    from ....model.bom import Bom
    from ....model.component import Component
    from ....model.vulnerability import Vulnerability


class _ComponentRecord:
    """Everything the analysis needs to know about one component instance."""

    def __init__(self, component: 'Component') -> None:
        self.component = component
        self.bom_ref = component.bom_ref
        self.coordinates = ComponentCoordinates.from_component(component)
        self.identity = ArtifactIdentity.from_component(component)

    @staticmethod
    def _content_tuple(component: 'Component') -> tuple[object, ...]:
        """
        Component content excluding the BOM-local bom-ref.

        The bom-ref is a per-document reference role, not part of what was
        delivered, so it must not influence change classification.
        """
        return (
            component.type, component.group, component.name, component.version,
            component.scope, component.purl, component.cpe,
            tuple(component.hashes), tuple(component.swhids),
            tuple(component.omnibor_ids), tuple(component.licenses),
            tuple(component.external_references), tuple(component.properties),
            tuple(component.tags), component.mime_type, component.description,
            component.copyright, component.is_external, component.modified,
        )

    def content_signature(self) -> tuple[object, ...]:
        return self._content_tuple(self.component)

    def __repr__(self) -> str:
        return f'<_ComponentRecord bom_ref={self.bom_ref.value!r}, coordinates={self.coordinates!r}>'


class VexReuseEngine:
    """
    Compare a previously signed BOM with a new BOM revision and rule, for each
    signed VEX verdict, whether it may be reused.

    The engine is stateless apart from the two BOMs handed to
    :meth:`compare`; a single instance can analyze any number of BOM pairs.
    """

    #: Verdicts in these states express a concrete, signed-off analysis that
    #: is worth carrying over. Verdicts without any analysis state are ignored.
    _SIGNED_STATES = frozenset((
        ImpactAnalysisState.NOT_AFFECTED,
        ImpactAnalysisState.FALSE_POSITIVE,
        ImpactAnalysisState.RESOLVED,
        ImpactAnalysisState.RESOLVED_WITH_PEDIGREE,
        ImpactAnalysisState.EXPLOITABLE,
        ImpactAnalysisState.IN_TRIAGE,
    ))

    def compare(self, old_bom: 'Bom', new_bom: 'Bom') -> VexReuseReport:
        """
        Build the :class:`VexReuseReport` for an ``old_bom`` / ``new_bom`` pair.

        Args:
            old_bom: the BOM whose VEX verdicts were previously signed off.
            new_bom: the re-issued BOM that may contain replacement builds.
        """
        old_records = self._index_components(old_bom)
        new_records = self._index_components(new_bom)
        old_by_ref = {r.bom_ref: r for r in old_records}

        new_graph = self._build_dependency_graph(new_bom)
        new_roots = self._deployment_roots(new_bom, new_graph)
        new_reachability = self._reachability(new_graph, new_roots)

        entries = []
        for verdict in self._collect_signed_verdicts(old_bom):
            record = old_by_ref.get(verdict.target_bom_ref)
            if record is None:
                # The verdict points at a service or an unknown target - there
                # is no component-level evidence to correlate on.
                entries.append(VexReuseEntry(
                    decision=ReuseDecision.INSUFFICIENT_EVIDENCE,
                    reason=ReuseReason.AMBIGUOUS_COORDINATES,
                    verdict=verdict,
                    detail='verdict target is not a component known in the old BOM',
                ))
                continue
            entries.append(self._rule_on_verdict(
                verdict=verdict,
                old_record=record,
                new_records=new_records,
                reachability=new_reachability,
            ))

        return VexReuseReport(entries)

    # region indexing

    @staticmethod
    def _index_components(bom: 'Bom') -> list[_ComponentRecord]:
        return [_ComponentRecord(c) for c in bom._get_all_components()]

    @staticmethod
    def _collect_signed_verdicts(bom: 'Bom') -> list[SignedVerdict]:
        verdicts: list[SignedVerdict] = []
        for vulnerability in bom.vulnerabilities:
            if not VexReuseEngine._is_signed(vulnerability):
                continue
            for target in vulnerability.affects:
                verdicts.append(SignedVerdict(
                    vulnerability_id=vulnerability.id or str(vulnerability.bom_ref),
                    target_bom_ref=BomRef(value=target.ref),
                    analysis=vulnerability.analysis,
                    source_vulnerability=vulnerability,
                ))
        return sorted(verdicts)

    @classmethod
    def _is_signed(cls, vulnerability: 'Vulnerability') -> bool:
        analysis = vulnerability.analysis
        return (
            analysis is not None
            and analysis.state is not None
            and analysis.state in cls._SIGNED_STATES
        )

    # endregion indexing

    # region dependency graph

    @staticmethod
    def _build_dependency_graph(bom: 'Bom') -> dict[BomRef, set[BomRef]]:
        """Map each bom-ref to the bom-refs it directly depends on."""
        graph: dict[BomRef, set[BomRef]] = defaultdict(set)
        for dependency in bom.dependencies:
            graph[dependency.ref].update(dependency.dependencies_as_bom_refs())
        return graph

    @staticmethod
    def _deployment_roots(bom: 'Bom', graph: dict[BomRef, set[BomRef]]) -> set[BomRef]:
        """
        Deployment entry points of the BOM.

        When ``bom.metadata.component`` is present it is the canonical entry
        point. Otherwise the sources of the dependency graph (the bom-refs that
        appear as a dependency subject) are treated as deployment roots, which
        covers BOMs describing several independently deployed top-level
        assemblies. Components floating in the BOM without any graph role are
        never roots.
        """
        if bom.metadata.component is not None:
            # The component the BOM describes is the canonical entry point.
            return {bom.metadata.component.bom_ref}
        # No described component: deployment roots are the sources of the
        # dependency graph, never components that merely float in the BOM.
        return set(graph.keys())

    @staticmethod
    def _reachability(
        graph: dict[BomRef, set[BomRef]],
        roots: set[BomRef],
    ) -> dict[BomRef, set[BomRef]]:
        """Map each reachable bom-ref to the deployment roots that reach it."""
        reachability: dict[BomRef, set[BomRef]] = defaultdict(set)
        for root in roots:
            # A deployment root is reachable from itself by definition; any
            # other component is only reachable via an actual dependency edge.
            reachability[root].add(root)
            stack: list[BomRef] = list(graph.get(root, set()))
            seen: set[BomRef] = set()
            while stack:
                current = stack.pop()
                if current in seen:
                    continue
                seen.add(current)
                reachability[current].add(root)
                stack.extend(graph.get(current, set()))
        return reachability

    # endregion dependency graph

    # region rulings

    def _rule_on_verdict(
        self, *,
        verdict: SignedVerdict,
        old_record: _ComponentRecord,
        new_records: list[_ComponentRecord],
        reachability: dict[BomRef, set[BomRef]],
    ) -> VexReuseEntry:
        same_coordinates = [
            r for r in new_records
            if r.coordinates == old_record.coordinates
        ]

        if not same_coordinates:
            return self._entry(
                decision=ReuseDecision.OBSOLETE,
                reason=ReuseReason.COMPONENT_REMOVED,
                verdict=verdict,
                old_record=old_record,
                same_coordinates=[],
                detail='no component at these coordinates exists in the new BOM',
            )

        decision, reason, matched = self._associate(old_record, same_coordinates)
        entry = self._entry(
            decision=decision,
            reason=reason,
            verdict=verdict,
            old_record=old_record,
            same_coordinates=same_coordinates,
        )

        if decision is not ReuseDecision.REUSE:
            return entry

        # The build is provably the same - now verify its deployment context.
        assert matched is not None
        roots = reachability.get(matched.bom_ref, set())
        if not roots:
            entry.decision = ReuseDecision.OBSOLETE
            entry.reason = ReuseReason.NO_LONGER_REACHABLE
            entry.detail = 'the unchanged artifact is no longer reachable from any deployment root'
            return entry

        if self._is_order_only_change(old_record, matched):
            entry.reason = ReuseReason.ORDER_ONLY_CHANGE
        else:
            # Same build, but the BOM-local reference role changed as well -
            # the artifact identity is what keeps the verdict valid.
            entry.reason = ReuseReason.ARTIFACT_UNCHANGED
        # Shared optional dependencies must state which deployment roots pull
        # them in; required components are reachable from every root by design.
        if matched.component.scope is ComponentScope.OPTIONAL:
            entry.deployment_roots = tuple(sorted(roots))
        return entry

    def _associate(
        self,
        old_record: _ComponentRecord,
        candidates: list[_ComponentRecord],
    ) -> tuple[ReuseDecision, ReuseReason, Optional[_ComponentRecord]]:
        """
        Decide whether the signed build can be associated with exactly one
        build at the same coordinates in the new BOM.

        Returns the ``(decision, reason, matched record)`` tuple; ``matched``
        is ``None`` when no 1:1 association could be evidenced.
        """
        # Several builds occupy the same coordinates. The data must prove which
        # one replaces the signed build; coordinates alone cannot do that.
        if len(candidates) > 1:
            return ReuseDecision.INSUFFICIENT_EVIDENCE, ReuseReason.AMBIGUOUS_COORDINATES, None

        candidate = candidates[0]
        if not old_record.identity.is_evidenced:
            # Exactly one candidate and no build-level evidence on either side:
            # coordinates are the only available, and here sufficient, key.
            return ReuseDecision.REUSE, ReuseReason.ARTIFACT_UNCHANGED, candidate

        if candidate.identity == old_record.identity:
            return ReuseDecision.REUSE, ReuseReason.ARTIFACT_UNCHANGED, candidate

        # The sole candidate carries different build-level evidence: the
        # coordinates kept their version but the delivered build changed.
        if candidate.identity.is_evidenced:
            return ReuseDecision.REOPEN, ReuseReason.HASH_CHANGED_AT_SAME_COORDINATES, None
        # The replacement build publishes no evidence, so identity continuity
        # cannot be proven either way.
        return ReuseDecision.INSUFFICIENT_EVIDENCE, ReuseReason.AMBIGUOUS_COORDINATES, None

    @staticmethod
    def _is_order_only_change(old_record: _ComponentRecord, new_record: _ComponentRecord) -> bool:
        """
        A pure ordering/cardinality change leaves both the delivered content
        and the BOM-local bom-ref untouched; only collection positions changed.
        """
        return (
            old_record.bom_ref == new_record.bom_ref
            and old_record.content_signature() == new_record.content_signature()
        )

    def _entry(
        self, *,
        decision: ReuseDecision,
        reason: ReuseReason,
        verdict: SignedVerdict,
        old_record: _ComponentRecord,
        same_coordinates: list[_ComponentRecord],
        detail: Optional[str] = None,
    ) -> VexReuseEntry:
        return VexReuseEntry(
            decision=decision,
            reason=reason,
            verdict=verdict,
            coordinates=old_record.coordinates,
            old_bom_ref=old_record.bom_ref,
            new_bom_refs=(r.bom_ref for r in same_coordinates),
            old_identity=old_record.identity,
            new_identities=(r.identity for r in same_coordinates),
            detail=detail,
        )

    # endregion rulings
