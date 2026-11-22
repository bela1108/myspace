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
Domain model of the VEX verdict reuse analysis.

The classes in this module are deliberately plain, non-serializable value
objects. They describe the outcome of comparing two BOM revisions - they are
not part of the CycloneDX wire format itself.
"""

from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Optional

from ...._internal.compare import ComparableTuple as _ComparableTuple
from ....model.bom_ref import BomRef

if TYPE_CHECKING:  # pragma: no cover
    from ....model.component import Component
    from ....model.vulnerability import Vulnerability, VulnerabilityAnalysis


class ReuseDecision(str, Enum):
    """
    The verdict reached for a single previously signed VEX verdict.
    """

    #: The new build is provably the same artifact in the same deployment
    #: context - the signed verdict stays valid.
    REUSE = 'reuse'

    #: The component coordinates stayed the same but the delivered artifact
    #: (hashes) changed - a fresh analysis must be performed.
    REOPEN = 'reopen'

    #: Same coordinates are shared by several builds and the available data
    #: does not prove which new build replaces the signed one.
    INSUFFICIENT_EVIDENCE = 'insufficient_evidence'

    #: The signed component is no longer reachable from any deployment root
    #: in the new BOM, so the verdict has no remaining subject.
    OBSOLETE = 'obsolete'


class ReuseReason(str, Enum):
    """
    Machine-readable explanation of *why* a :class:`ReuseDecision` was taken.
    """

    #: Nothing changed beyond ordering/cardinality of BOM collections.
    ORDER_ONLY_CHANGE = 'order_only_change'
    #: Same coordinates and the same artifact identity was found 1:1.
    ARTIFACT_UNCHANGED = 'artifact_unchanged'
    #: Same coordinates, but the hash set differs between the two BOMs.
    HASH_CHANGED_AT_SAME_COORDINATES = 'hash_changed_at_same_coordinates'
    #: More than one build exists at the same coordinates and no hashes (or
    #: other artifact identifiers) are available to disambiguate them.
    AMBIGUOUS_COORDINATES = 'ambiguous_coordinates'
    #: The component disappeared from the new BOM entirely.
    COMPONENT_REMOVED = 'component_removed'
    #: The component still exists but is no longer reachable from any
    #: deployment root in the new dependency graph.
    NO_LONGER_REACHABLE = 'no_longer_reachable'


class ComponentCoordinates:
    """
    The *publishing coordinates* of a component, independent of the concrete
    build artifact and independent of any BOM-local ``bom-ref``.

    Two components at the same coordinates may still be two different builds;
    coordinates alone are never enough to establish artifact identity.
    """

    def __init__(
        self, *,
        component_type: 'str',
        group: Optional[str],
        name: str,
        version: Optional[str],
        purl: Optional[str],
        cpe: Optional[str],
    ) -> None:
        self.component_type = component_type
        self.group = group
        self.name = name
        self.version = version
        self.purl = purl
        self.cpe = cpe

    @classmethod
    def from_component(cls, component: 'Component') -> 'ComponentCoordinates':
        return cls(
            component_type=component.type.value,
            group=component.group,
            name=component.name,
            version=component.version,
            purl=None if component.purl is None else str(component.purl),
            cpe=component.cpe,
        )

    @property
    def key(self) -> tuple[Optional[str], str, Optional[str], Optional[str], Optional[str], str]:
        """
        Hashable key used to group components that occupy the same
        coordinates across the two BOM revisions.
        """
        return self.purl, self.cpe, self.group, self.name, self.version, self.component_type

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ComponentCoordinates):
            return self.key == other.key
        return False

    def __hash__(self) -> int:
        return hash(self.key)

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, ComponentCoordinates):
            return _ComparableTuple(self.key) < _ComparableTuple(other.key)
        return NotImplemented

    def __repr__(self) -> str:
        return f'<ComponentCoordinates group={self.group}, name={self.name}, version={self.version}>'


class ArtifactIdentity:
    """
    The identity of the concrete *build artifact* behind a component.

    Hashes (plus SWHIDs / OmniBOR ids when present) identify what was
    actually delivered. Two components with identical
    :class:`ComponentCoordinates` but different :class:`ArtifactIdentity`
    values are different builds and must never share a VEX verdict.
    """

    def __init__(
        self, *,
        hashes: Iterable[tuple[str, str]],
        swhids: Iterable[str],
        omnibor_ids: Iterable[str],
    ) -> None:
        self._hashes = frozenset(hashes)
        self._swhids = frozenset(swhids)
        self._omnibor_ids = frozenset(omnibor_ids)

    @classmethod
    def from_component(cls, component: 'Component') -> 'ArtifactIdentity':
        return cls(
            hashes=((h.alg.value, h.content) for h in component.hashes),
            swhids=(str(i) for i in component.swhids),
            omnibor_ids=(str(i) for i in component.omnibor_ids),
        )

    @property
    def hashes(self) -> frozenset[tuple[str, str]]:
        return self._hashes

    @property
    def is_evidenced(self) -> bool:
        """
        Whether this identity carries any build-level evidence at all.

        A component without hashes or other artifact identifiers cannot be
        distinguished from another build at the same coordinates.
        """
        return bool(self._hashes or self._swhids or self._omnibor_ids)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ArtifactIdentity):
            return (
                self._hashes == other._hashes
                and self._swhids == other._swhids
                and self._omnibor_ids == other._omnibor_ids
            )
        return False

    def __hash__(self) -> int:
        return hash((self._hashes, self._swhids, self._omnibor_ids))

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, ArtifactIdentity):
            return _ComparableTuple((
                _ComparableTuple(sorted(self._hashes)),
                _ComparableTuple(sorted(self._swhids)),
                _ComparableTuple(sorted(self._omnibor_ids)),
            )) < _ComparableTuple((
                _ComparableTuple(sorted(other._hashes)),
                _ComparableTuple(sorted(other._swhids)),
                _ComparableTuple(sorted(other._omnibor_ids)),
            ))
        return NotImplemented

    def __repr__(self) -> str:
        return f'<ArtifactIdentity hashes={len(self._hashes)}, swhids={len(self._swhids)}>'


class SignedVerdict:
    """
    A VEX verdict that was signed off in the previous BOM.

    The verdict is bound to an *artifact identity* via the component it
    targets, not to the BOM-local ``bom-ref`` string.
    """

    def __init__(
        self, *,
        vulnerability_id: str,
        target_bom_ref: BomRef,
        analysis: Optional['VulnerabilityAnalysis'],
        source_vulnerability: 'Vulnerability',
    ) -> None:
        self.vulnerability_id = vulnerability_id
        self.target_bom_ref = target_bom_ref
        self.analysis = analysis
        self.source_vulnerability = source_vulnerability

    @property
    def is_signed_off(self) -> bool:
        """
        A verdict counts as signed off once an analysis state was asserted.
        """
        return self.analysis is not None and self.analysis.state is not None

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, SignedVerdict):
            return _ComparableTuple((
                self.vulnerability_id, self.target_bom_ref.value,
            )) < _ComparableTuple((
                other.vulnerability_id, other.target_bom_ref.value,
            ))
        return NotImplemented

    def __repr__(self) -> str:
        state = None if self.analysis is None else self.analysis.state
        return f'<SignedVerdict vulnerability={self.vulnerability_id}, state={state}>'


class VexReuseEntry:
    """
    The reuse ruling for one previously signed :class:`SignedVerdict`.
    """

    def __init__(
        self, *,
        decision: ReuseDecision,
        reason: ReuseReason,
        verdict: SignedVerdict,
        coordinates: Optional[ComponentCoordinates] = None,
        old_bom_ref: Optional[BomRef] = None,
        new_bom_refs: Optional[Iterable[BomRef]] = None,
        old_identity: Optional[ArtifactIdentity] = None,
        new_identities: Optional[Iterable[ArtifactIdentity]] = None,
        deployment_roots: Optional[Iterable[BomRef]] = None,
        detail: Optional[str] = None,
    ) -> None:
        self.decision = decision
        self.reason = reason
        self.verdict = verdict
        self.coordinates = coordinates
        self.old_bom_ref = old_bom_ref
        self.new_bom_refs = tuple(new_bom_refs or ())
        self.old_identity = old_identity
        self.new_identities = tuple(new_identities or ())
        self.deployment_roots = tuple(deployment_roots or ())
        self.detail = detail

    @property
    def can_reuse(self) -> bool:
        return self.decision is ReuseDecision.REUSE

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, VexReuseEntry):
            return _ComparableTuple((
                self.verdict.vulnerability_id,
                None if self.old_bom_ref is None else self.old_bom_ref.value,
                self.decision.value,
            )) < _ComparableTuple((
                other.verdict.vulnerability_id,
                None if other.old_bom_ref is None else other.old_bom_ref.value,
                other.decision.value,
            ))
        return NotImplemented

    def __repr__(self) -> str:
        return (
            f'<VexReuseEntry decision={self.decision.value}, '
            f'reason={self.reason.value}, verdict={self.verdict.vulnerability_id}>'
        )


class VexReuseReport:
    """
    The full VEX reuse list produced by comparing two BOM revisions.
    """

    def __init__(self, entries: Optional[Iterable[VexReuseEntry]] = None) -> None:
        self._entries = tuple(sorted(entries or ()))

    @property
    def entries(self) -> tuple[VexReuseEntry, ...]:
        return self._entries

    @property
    def reusable(self) -> tuple[VexReuseEntry, ...]:
        return tuple(e for e in self._entries if e.can_reuse)

    @property
    def requiring_action(self) -> tuple[VexReuseEntry, ...]:
        """
        Entries that cannot be carried over automatically (reopen,
        insufficient evidence or obsolete).
        """
        return tuple(e for e in self._entries if not e.can_reuse)

    def __iter__(self) -> Iterator["VexReuseEntry"]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f'<VexReuseReport entries={len(self._entries)}, reusable={len(self.reusable)}>'
