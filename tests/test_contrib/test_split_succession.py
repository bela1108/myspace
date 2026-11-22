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

from typing import FrozenSet, Tuple
from unittest import TestCase

from cyclonedx.contrib.split_succession import (
    DispositionRecord,
    DispositionScope,
    Material,
    MergeDeclaration,
    ResponsibilitySuccessionMatrix,
    SplitPackageDeclaration,
    SplitSuccessionException,
    SplitSuccessionStatus,
    check_split_succession,
    recheck_merge,
)
from cyclonedx.model.bom_ref import BomRef


class SplitSuccessionTestCase(TestCase):

    def setUp(self) -> None:
        self.source_ref = BomRef('component-big')
        self.full_disposition = DispositionRecord(
            'D-FULL', 'CVE-2026-0001', DispositionScope.FULL,
            self.source_ref)
        self.partial_disposition = DispositionRecord(
            'D-PARTIAL', 'CVE-2026-0002', DispositionScope.PARTIAL,
            self.source_ref, frozenset({'m1'}))

    def _package(
            self, name: str, materials: Tuple[str, ...],
            owner: object = 'team-a',
            accepted: FrozenSet[str] = frozenset({'D-FULL'})
    ) -> SplitPackageDeclaration:
        return SplitPackageDeclaration(
            BomRef(name), self.source_ref,
            tuple(Material(material_id) for material_id in materials),
            owner if isinstance(owner, str) else None,
            accepted)

    def _matrix(self) -> ResponsibilitySuccessionMatrix:
        package_a = self._package(
            'pkg-a', ('m1', 'm2'), 'team-a', frozenset({'D-FULL'}))
        package_b = self._package(
            'pkg-b', ('m3',), None, frozenset({'D-FULL'}))
        package_c = self._package(
            'pkg-c', ('m4', 'm5'), 'team-c', frozenset({'D-PARTIAL'}))
        return check_split_succession(
            (package_a, package_b, package_c),
            (self.full_disposition, self.partial_disposition))

    def test_three_packages_lead_to_three_different_statuses(self) -> None:
        matrix = self._matrix()

        by_ref = {
            result.subject_ref.value: result for result in matrix.results}
        self.assertIs(
            by_ref['pkg-a'].status,
            SplitSuccessionStatus.SUCCESSION_OK)
        self.assertFalse(by_ref['pkg-a'].supplements_required)
        self.assertIs(
            by_ref['pkg-b'].status,
            SplitSuccessionStatus.RESPONSIBILITY_UNDETERMINED)
        self.assertFalse(by_ref['pkg-b'].supplements_required)
        self.assertIs(
            by_ref['pkg-c'].status,
            SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE)
        self.assertTrue(by_ref['pkg-c'].supplements_required)
        self.assertEqual(
            by_ref['pkg-c'].uncovered_materials, frozenset({'m4', 'm5'}))

    def test_matrix_exposes_results_by_status_and_ref(self) -> None:
        matrix = self._matrix()

        self.assertEqual(
            len(matrix.results_with_status(
                SplitSuccessionStatus.SUCCESSION_OK)),
            1)
        self.assertEqual(
            len(matrix.results_with_status(
                SplitSuccessionStatus.RESPONSIBILITY_UNDETERMINED)),
            1)
        self.assertEqual(
            len(matrix.results_with_status(
                SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE)),
            1)
        self.assertTrue(matrix.requires_supplements)
        self.assertEqual(
            matrix.result_for_ref(BomRef('pkg-b')).status,
            SplitSuccessionStatus.RESPONSIBILITY_UNDETERMINED)
        self.assertEqual(
            matrix.materials_of(BomRef('pkg-c')),
            frozenset({'m4', 'm5'}))

    def test_partial_disposition_never_widens_after_merge(self) -> None:
        matrix = self._matrix()

        merged = recheck_merge(
            MergeDeclaration(
                BomRef('component-remerged'),
                (BomRef('pkg-a'), BomRef('pkg-b'), BomRef('pkg-c'))),
            matrix)

        self.assertIs(
            merged.status,
            SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE)
        self.assertTrue(merged.supplements_required)
        self.assertEqual(
            merged.uncovered_materials, frozenset({'m4', 'm5'}))
        self.assertIn('D-FULL', merged.applicable_dispositions)

    def test_merge_of_fully_covered_owned_packages_succeeds(self) -> None:
        package_a = self._package(
            'pkg-a', ('m1', 'm2'), 'team-a', frozenset({'D-FULL'}))
        package_b = self._package(
            'pkg-b', ('m3',), 'team-b', frozenset({'D-FULL'}))
        matrix = check_split_succession(
            (package_a, package_b), (self.full_disposition,))

        merged = recheck_merge(
            MergeDeclaration(
                BomRef('component-remerged'),
                (BomRef('pkg-a'), BomRef('pkg-b'))),
            matrix)

        self.assertIs(
            merged.status, SplitSuccessionStatus.SUCCESSION_OK)
        self.assertFalse(merged.supplements_required)
        self.assertEqual(merged.uncovered_materials, frozenset())

    def test_owner_missing_with_full_coverage_is_undetermined(self) -> None:
        package = self._package(
            'pkg-b', ('m3',), None, frozenset({'D-FULL'}))
        matrix = check_split_succession(
            (package,), (self.full_disposition,))

        result = matrix.result_for_ref(BomRef('pkg-b'))
        self.assertIs(
            result.status,
            SplitSuccessionStatus.RESPONSIBILITY_UNDETERMINED)
        self.assertEqual(result.uncovered_materials, frozenset())

    def test_partial_evidence_requires_supplement_even_with_owner(self) -> None:
        package = self._package(
            'pkg-c', ('m1', 'm2'), 'team-c',
            frozenset({'D-PARTIAL'}))
        matrix = check_split_succession(
            (package,), (self.partial_disposition,))

        result = matrix.result_for_ref(BomRef('pkg-c'))
        self.assertIs(
            result.status,
            SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE)
        self.assertEqual(result.uncovered_materials, frozenset({'m2'}))
        self.assertTrue(result.supplements_required)

    def test_unclaimed_disposition_does_not_silently_cover_package(self) -> None:
        package = self._package(
            'pkg-a', ('m1', 'm2'), 'team-a', frozenset())
        matrix = check_split_succession(
            (package,), (self.full_disposition,))

        result = matrix.result_for_ref(BomRef('pkg-a'))
        self.assertIs(
            result.status,
            SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE)
        self.assertEqual(
            result.uncovered_materials, frozenset({'m1', 'm2'}))

    def test_disposition_from_other_component_cannot_carry_over(self) -> None:
        other_ref = BomRef('component-other')
        foreign = DispositionRecord(
            'D-OTHER', 'CVE-2026-0009', DispositionScope.FULL, other_ref)
        package = SplitPackageDeclaration(
            BomRef('pkg-a'), self.source_ref,
            (Material('m1'),), 'team-a', frozenset({'D-OTHER'}))

        matrix = check_split_succession((package,), (foreign,))
        result = matrix.result_for_ref(BomRef('pkg-a'))
        self.assertIs(
            result.status,
            SplitSuccessionStatus.INSUFFICIENT_EVIDENCE_SCOPE)
        self.assertEqual(result.uncovered_materials, frozenset({'m1'}))

    def test_unknown_accepted_disposition_raises(self) -> None:
        package = self._package(
            'pkg-a', ('m1',), 'team-a', frozenset({'D-GHOST'}))
        with self.assertRaises(SplitSuccessionException):
            check_split_succession((package,), (self.full_disposition,))

    def test_material_assigned_to_two_packages_raises(self) -> None:
        package_a = self._package(
            'pkg-a', ('m1',), 'team-a', frozenset({'D-FULL'}))
        package_b = self._package(
            'pkg-b', ('m1', 'm2'), 'team-b', frozenset({'D-FULL'}))
        with self.assertRaises(SplitSuccessionException):
            check_split_succession(
                (package_a, package_b), (self.full_disposition,))

    def test_duplicate_disposition_identifier_raises(self) -> None:
        duplicate = DispositionRecord(
            'D-FULL', 'CVE-2026-0003', DispositionScope.FULL,
            self.source_ref)
        with self.assertRaises(SplitSuccessionException):
            check_split_succession(
                (self._package('pkg-a', ('m1',)),),
                (self.full_disposition, duplicate))

    def test_merge_with_unknown_package_ref_raises(self) -> None:
        matrix = self._matrix()
        with self.assertRaises(SplitSuccessionException):
            recheck_merge(
                MergeDeclaration(
                    BomRef('merged'), (BomRef('pkg-ghost'),)),
                matrix)

    def test_model_validates_disposition_scope_consistency(self) -> None:
        with self.assertRaises(ValueError):
            DispositionRecord(
                'D', 'CVE-1', DispositionScope.PARTIAL, self.source_ref)
        with self.assertRaises(ValueError):
            DispositionRecord(
                'D', 'CVE-1', DispositionScope.FULL, self.source_ref,
                frozenset({'m1'}))
        with self.assertRaises(ValueError):
            Material('')

    def test_model_validates_declaration_and_merge_shapes(self) -> None:
        with self.assertRaises(ValueError):
            SplitPackageDeclaration(
                BomRef('pkg'), self.source_ref, ())
        with self.assertRaises(ValueError):
            SplitPackageDeclaration(
                BomRef('pkg'), self.source_ref,
                (Material('m1'), Material('m1')))
        with self.assertRaises(ValueError):
            MergeDeclaration(
                BomRef('merged'),
                (BomRef('pkg-a'), BomRef('pkg-a')))
