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
Split succession check engine.

The engine takes the three inputs handed over by the caller - the split
declarations, the BOM references anchoring them to both BOM versions and the
scope of the dispositions signed off before the split - and produces one
verdict per successor package. A second entry point re-checks a component
created by merging successor packages again, making sure that a disposition
which only covered part of the original component never gains a wider scope.
"""

__all__ = [
    'ResponsibilitySuccessionMatrix',
    'check_split_succession',
    'recheck_merge',
]

from typing import Dict, FrozenSet, Iterable, List, Mapping, Set, Tuple

from ...model.bom_ref import BomRef
from .exception import SplitSuccessionException
from .model import (
    DispositionRecord,
    DispositionScope,
    MergeDeclaration,
    SplitPackageDeclaration,
    SplitSuccessionStatus,
    SuccessionResult,
)


def _require_named_ref(ref: BomRef, role: str) -> None:
    if not ref.value:
        raise SplitSuccessionException(
            f'{role} must be a BOM reference with a non-empty value')


def _index_dispositions(
        dispositions: Iterable[DispositionRecord]
        ) -> Dict[str, DispositionRecord]:
    records: Dict[str, DispositionRecord] = {}
    for disposition in dispositions:
        _require_named_ref(disposition.source_component_ref,
                           'DispositionRecord.source_component_ref')
        if disposition.identifier in records:
            raise SplitSuccessionException(
                f'duplicate disposition identifier: {disposition.identifier}')
        records[disposition.identifier] = disposition
    return records


def _validate_declarations(
        declarations: Tuple[SplitPackageDeclaration, ...]
        ) -> Dict[BomRef, FrozenSet[str]]:
    """Run structural checks and return the material universe per source."""
    if not declarations:
        raise SplitSuccessionException(
            'at least one split package declaration is required')

    source_materials: Dict[BomRef, FrozenSet[str]] = {}
    seen_package_refs: Set[BomRef] = set()
    for declaration in declarations:
        _require_named_ref(declaration.package_ref,
                           'SplitPackageDeclaration.package_ref')
        _require_named_ref(declaration.source_component_ref,
                           'SplitPackageDeclaration.source_component_ref')
        if declaration.package_ref in seen_package_refs:
            raise SplitSuccessionException(
                f'package ref {declaration.package_ref.value} is declared '
                'more than once')
        seen_package_refs.add(declaration.package_ref)

        source_ref = declaration.source_component_ref
        known_materials = source_materials.get(source_ref, frozenset())
        overlap = known_materials & declaration.material_ids
        if overlap:
            raise SplitSuccessionException(
                'material(s) assigned to more than one successor package of '
                f'{source_ref.value}: {sorted(overlap)}')
        source_materials[source_ref] = \
            known_materials | declaration.material_ids
    return dict(source_materials)


def _applicable_dispositions(
        declaration: SplitPackageDeclaration,
        dispositions: Mapping[str, DispositionRecord],
        source_material_ids: FrozenSet[str]
        ) -> Tuple[FrozenSet[str], FrozenSet[str], List[str]]:
    """
    Check the dispositions the caller explicitly accepted for this package.

    Only dispositions named in the split declaration may carry over - a
    sign-off that the caller never claimed cannot silently cover a package.
    Return the disposition ids that actually reach at least one material of
    the package, the covered material ids and human readable reasons.
    """
    applicable: List[str] = []
    covered: Set[str] = set()
    reasons: List[str] = []

    for claimed_id in sorted(declaration.accepted_dispositions):
        disposition = dispositions.get(claimed_id)
        if disposition is None:
            raise SplitSuccessionException(
                f'package {declaration.package_ref.value} accepts unknown '
                f'disposition: {claimed_id}')
        if disposition.source_component_ref != declaration.source_component_ref:
            reasons.append(
                f'disposition {claimed_id} was signed for component '
                f'{disposition.source_component_ref.value} and cannot carry '
                f'over to package {declaration.package_ref.value}')
            continue
        reached = frozenset(
            material_id
            for material_id in declaration.material_ids
            if disposition.covers(material_id, source_material_ids))
        if not reached:
            reasons.append(
                f'disposition {claimed_id} does not reach any material of '
                f'package {declaration.package_ref.value}; its evidence '
                'scope is too narrow')
            continue
        applicable.append(claimed_id)
        covered.update(reached)
    return frozenset(applicable), frozenset(covered), reasons


def _check_package(
        declaration: SplitPackageDeclaration,
        dispositions: Mapping[str, DispositionRecord],
        source_material_ids: FrozenSet[str]) -> SuccessionResult:
    applicable, covered, reasons = _applicable_dispositions(
        declaration, dispositions, source_material_ids)
    uncovered = frozenset(declaration.material_ids - covered)

    if uncovered:
        reasons.append(
            'no disposition covers material(s): ' + ', '.join(sorted(uncovered)))
        return SuccessionResult(
            subject_ref=declaration.package_ref,
            status=SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE,
            applicable_dispositions=applicable,
            uncovered_materials=uncovered,
            supplements_required=True,
            reasons=tuple(reasons))

    if declaration.responsible_owner is None:
        reasons.append(
            f'no responsible owner has accepted package '
            f'{declaration.package_ref.value} yet')
        return SuccessionResult(
            subject_ref=declaration.package_ref,
            status=SplitSuccessionStatus.RESPONSIBILITY_UNDETERMINED,
            applicable_dispositions=applicable,
            uncovered_materials=frozenset(),
            supplements_required=False,
            reasons=tuple(reasons))

    if reasons:
        return SuccessionResult(
            subject_ref=declaration.package_ref,
            status=SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE,
            applicable_dispositions=applicable,
            uncovered_materials=frozenset(),
            supplements_required=True,
            reasons=tuple(reasons))

    return SuccessionResult(
        subject_ref=declaration.package_ref,
        status=SplitSuccessionStatus.SUCCESSION_OK,
        applicable_dispositions=applicable,
        uncovered_materials=frozenset(),
        supplements_required=False)


class ResponsibilitySuccessionMatrix:
    """
    Responsibility succession matrix derived from two BOM versions.

    Every row links one post-split package (or later re-merged component) to
    the pre-split dispositions that still reach it and to the resulting
    status. The matrix is the single object to re-inspect when packages are
    merged again later.
    """

    def __init__(self, results: Iterable[SuccessionResult],
                 package_materials: Mapping[BomRef, FrozenSet[str]]) -> None:
        self._results: Tuple[SuccessionResult, ...] = tuple(results)
        self._package_materials: Dict[BomRef, FrozenSet[str]] = \
            dict(package_materials)
        self._results_by_ref: Dict[BomRef, SuccessionResult] = {
            result.subject_ref: result for result in self._results}

    @property
    def results(self) -> Tuple[SuccessionResult, ...]:
        return self._results

    @property
    def requires_supplements(self) -> bool:
        return any(result.supplements_required for result in self._results)

    def result_for_ref(self, package_ref: BomRef) -> SuccessionResult:
        try:
            return self._results_by_ref[package_ref]
        except KeyError:
            raise SplitSuccessionException(
                f'unknown successor package ref: {package_ref.value}') \
                from None

    def results_with_status(
            self, status: SplitSuccessionStatus
    ) -> Tuple[SuccessionResult, ...]:
        return tuple(result for result in self._results
                     if result.status is status)

    def materials_of(self, package_ref: BomRef) -> FrozenSet[str]:
        try:
            return self._package_materials[package_ref]
        except KeyError:
            raise SplitSuccessionException(
                f'unknown successor package ref: {package_ref.value}') \
                from None


def check_split_succession(
        declarations: Iterable[SplitPackageDeclaration],
        dispositions: Iterable[DispositionRecord]
        ) -> ResponsibilitySuccessionMatrix:
    """
    Verify how pre-split vulnerability dispositions carry over to successor
    packages and produce the responsibility succession matrix.

    Structural problems (unknown BOM references, duplicate declarations or
    references to dispositions that do not exist) raise
    :class:`SplitSuccessionException`. Coverage problems are expressed through
    the per-package status instead.
    """
    declaration_tuple = tuple(declarations)
    disposition_index = _index_dispositions(dispositions)
    source_materials = _validate_declarations(declaration_tuple)

    results = tuple(
        _check_package(declaration, disposition_index,
                       source_materials[declaration.source_component_ref])
        for declaration in declaration_tuple)
    package_materials = {
        declaration.package_ref: declaration.material_ids
        for declaration in declaration_tuple}
    return ResponsibilitySuccessionMatrix(results, package_materials)


def _merged_result(
        merge: MergeDeclaration,
        matrix: ResponsibilitySuccessionMatrix) -> SuccessionResult:
    package_results = tuple(
        matrix.result_for_ref(package_ref)
        for package_ref in merge.package_refs)

    applicable = frozenset(
        disposition_id
        for result in package_results
        for disposition_id in result.applicable_dispositions)
    uncovered = frozenset(
        material_id
        for result in package_results
        for material_id in result.uncovered_materials)
    reasons = tuple(
        reason
        for result in package_results
        for reason in result.reasons)
    needs_supplement = any(
        result.supplements_required for result in package_results)

    if needs_supplement:
        status = SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE
    elif any(result.status is SplitSuccessionStatus.RESPONSIBILITY_UNDETERMINED
             for result in package_results):
        status = SplitSuccessionStatus.RESPONSIBILITY_UNDETERMINED
    else:
        status = SplitSuccessionStatus.SUCCESSION_OK

    return SuccessionResult(
        subject_ref=merge.merged_component_ref,
        status=status,
        applicable_dispositions=applicable,
        uncovered_materials=uncovered,
        supplements_required=needs_supplement,
        reasons=reasons)


def recheck_merge(merge: MergeDeclaration,
                  matrix: ResponsibilitySuccessionMatrix) -> SuccessionResult:
    """
    Re-check a component built by merging successor packages again.

    The verdicts of the merged packages are combined without widening any
    evidence scope: a disposition that only covered part of the original
    component still covers only that part of the re-merged component, so the
    merged component inherits every uncovered material and every open
    responsibility gap.
    """
    _require_named_ref(merge.merged_component_ref,
                       'MergeDeclaration.merged_component_ref')
    for package_ref in merge.package_refs:
        _require_named_ref(package_ref, 'MergeDeclaration.package_refs')
    return _merged_result(merge, matrix)
