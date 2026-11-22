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
Domain objects for split succession checking.

The objects are deliberately independent of serialization: a caller typically
builds them from two BOM versions and its own split declaration exchange
format. BOM references are kept as :class:`~cyclonedx.model.bom_ref.BomRef`
so the link back to the originating BOM documents is never lost.
"""

__all__ = [
    'DispositionRecord',
    'DispositionScope',
    'Material',
    'MergeDeclaration',
    'SplitPackageDeclaration',
    'SplitSuccessionStatus',
    'SuccessionResult',
]

from dataclasses import dataclass, field
from enum import Enum, unique
from typing import FrozenSet, Optional, Tuple

from ...model.bom_ref import BomRef


@unique
class DispositionScope(Enum):
    """
    Coverage of a vulnerability disposition at the time it was signed off.

    * :attr:`FULL` means the sign-off covered the whole component and every
      material it contained at that point in time.
    * :attr:`PARTIAL` means the sign-off named an explicit subset of
      materials. A partial sign-off can never cover more than that subset,
      even after a split or a later merge.
    """

    FULL = 'full'
    PARTIAL = 'partial'


@unique
class SplitSuccessionStatus(Enum):
    """
    Result of checking one successor package (or one re-merged component).

    * :attr:`SUCCESSION_OK` - an existing disposition fully covers every
      material of the package and the new responsible owner has accepted the
      handoff. No additional evidence is required.
    * :attr:`RESPONSIBILITY_UNDETERMINED` - the evidence would be sufficient,
      but no responsible owner has accepted the package yet.
    * :attr:`INSUFFICIENT_EVIDENCE_SCOPE` - at least one material is not
      covered by any applicable disposition, or a disposition explicitly only
      covers part of the package's materials. The new owner must supplement
      the evidence.
    """

    SUCCESSION_OK = 'succession_ok'
    RESPONSIBILITY_UNDETERMINED = 'responsibility_undetermined'
    INSUFFICIENT_EVIDENCE_SCOPE = 'insufficient_evidence_scope'


@dataclass(frozen=True)
class Material:
    """
    A smallest addressable piece of evidence inside a component.

    Materials are identified by a stable identifier that stays comparable
    across BOM versions, for example a source path, an artifact name or a
    content hash. The optional ``bom_ref`` points at the component or
    evidence object describing the material in a BOM.
    """

    identifier: str
    bom_ref: Optional[BomRef] = None

    def __post_init__(self) -> None:
        if not self.identifier:
            raise ValueError('Material.identifier must not be empty')


@dataclass(frozen=True)
class DispositionRecord:
    """
    A vulnerability disposition signed off against the pre-split component.

    ``scope`` together with ``covered_materials`` describe how far the
    sign-off reaches:

    * for :attr:`DispositionScope.FULL`, ``covered_materials`` is left empty
      and the disposition covers every material of the source component;
    * for :attr:`DispositionScope.PARTIAL`, ``covered_materials`` lists the
      exact materials that were assessed, and the disposition must never be
      extended beyond them.

    ``source_component_ref`` is the BOM reference of the component the
    disposition was signed for in the pre-split BOM.
    """

    identifier: str
    vulnerability_id: str
    scope: DispositionScope
    source_component_ref: BomRef
    covered_materials: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.identifier:
            raise ValueError('DispositionRecord.identifier must not be empty')
        if not self.vulnerability_id:
            raise ValueError(
                'DispositionRecord.vulnerability_id must not be empty')
        if self.scope is DispositionScope.PARTIAL and not self.covered_materials:
            raise ValueError(
                'PARTIAL disposition must name at least one covered material')
        if self.scope is DispositionScope.FULL and self.covered_materials:
            raise ValueError(
                'FULL disposition must not enumerate covered materials')

    def covers(self, material_identifier: str,
               source_material_ids: FrozenSet[str]) -> bool:
        """Return whether this disposition reaches ``material_identifier``."""
        if material_identifier not in source_material_ids:
            return False
        if self.scope is DispositionScope.FULL:
            return True
        return material_identifier in self.covered_materials


@dataclass(frozen=True)
class SplitPackageDeclaration:
    """
    A successor package as declared by the caller.

    * ``package_ref`` identifies the package in the post-split BOM.
    * ``source_component_ref`` identifies the pre-split component it was
      carved out of.
    * ``materials`` are the materials inherited from that component.
    * ``responsible_owner`` is the party accepting responsibility for the
      package; ``None`` means the handoff has no owner yet.
    * ``accepted_dispositions`` are the dispositions the owner believes carry
      over. It is the job of the checker to verify that belief.
    """

    package_ref: BomRef
    source_component_ref: BomRef
    materials: Tuple[Material, ...]
    responsible_owner: Optional[str] = None
    accepted_dispositions: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.materials:
            raise ValueError(
                'SplitPackageDeclaration must contain at least one material')
        if len({material.identifier for material in self.materials}) \
                != len(self.materials):
            raise ValueError(
                'duplicate material identifiers in split package declaration')

    @property
    def material_ids(self) -> FrozenSet[str]:
        return frozenset(material.identifier for material in self.materials)


@dataclass(frozen=True)
class MergeDeclaration:
    """
    Declaration of a component created by merging successor packages again.

    ``merged_component_ref`` identifies the re-merged component in the latest
    BOM and ``package_refs`` lists the successor packages it consists of.
    """

    merged_component_ref: BomRef
    package_refs: Tuple[BomRef, ...]

    def __post_init__(self) -> None:
        if not self.package_refs:
            raise ValueError('MergeDeclaration must name at least one package')
        if len({ref.value for ref in self.package_refs}) != len(self.package_refs):
            raise ValueError(
                'duplicate package references in merge declaration')


@dataclass(frozen=True)
class SuccessionResult:
    """
    Verdict for one successor package or one re-merged component.

    ``uncovered_materials`` lists the materials for which no applicable
    disposition exists. ``applicable_dispositions`` lists the dispositions
    that were actually found to reach the subject, regardless of their
    individual scope. ``supplements_required`` is ``True`` when the new
    responsible owner has to submit additional evidence.
    """

    subject_ref: BomRef
    status: SplitSuccessionStatus
    applicable_dispositions: FrozenSet[str]
    uncovered_materials: FrozenSet[str]
    supplements_required: bool
    reasons: Tuple[str, ...] = field(default_factory=tuple)
