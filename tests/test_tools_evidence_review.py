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

import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / 'tools' / 'evidence_review'
BOM_PRODUCTION = FIXTURES / 'bom-production.json'
BOM_TEST = FIXTURES / 'bom-test.json'

_spec = importlib.util.spec_from_file_location('evidence_review', REPO_ROOT / 'tools' / 'evidence_review.py')
evidence_review = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evidence_review)


class TestEvidenceReviewReplay(TestCase):
    """用两份小 BOM 重放：一组来自正式构建，另一组只用于测试。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reviews = {review.key: review for review in evidence_review.review_boms(BOM_PRODUCTION, BOM_TEST)}

    def test_only_shared_materials_are_reviewed(self) -> None:
        self.assertEqual({'pkg:pypi/libalpha@1.4.2', 'pkg:pypi/libbeta@2.0.0'}, set(self.reviews))

    def test_three_judgments_for_libalpha(self) -> None:
        review = self.reviews['pkg:pypi/libalpha@1.4.2']
        self.assertIs(evidence_review.ByteIdentity.IDENTICAL, review.byte_identity)
        self.assertEqual(['SHA-256'], review.compared_algorithms)
        self.assertIs(evidence_review.MaterialRole.PRODUCTION, review.left.role)
        self.assertIs(evidence_review.MaterialRole.TEST, review.right.role)
        self.assertEqual('production', review.left.environment)
        self.assertEqual('test', review.right.environment)

    def test_traceability_across_different_collectors(self) -> None:
        review = self.reviews['pkg:pypi/libalpha@1.4.2']
        self.assertNotEqual(review.left.collectors, review.right.collectors)
        self.assertEqual(['Acme Build Systems acme-build-attestor 1.3.0'], review.left.collectors)
        self.assertEqual('2026-11-20T02:00:00+00:00', review.left.timestamp.isoformat())
        self.assertEqual([], review.left.sources)
        self.assertEqual([], review.right.sources)

    def test_verdict_libalpha_provenance_unprovable(self) -> None:
        review = self.reviews['pkg:pypi/libalpha@1.4.2']
        self.assertFalse(evidence_review.production_provenance_provable(review))
        self.assertEqual('这份材料可以确认内容相同，生产出处目前无从证明。',
                         evidence_review.verdict_sentence(review))

    def test_verdict_libbeta_provenance_traceable(self) -> None:
        review = self.reviews['pkg:pypi/libbeta@2.0.0']
        self.assertTrue(evidence_review.production_provenance_provable(review))
        self.assertEqual('这份材料可以确认内容相同，生产出处可追溯至 vcs: https://github.com/acme/libbeta。',
                         evidence_review.verdict_sentence(review))

    def test_query_cli_prints_verdict(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = evidence_review.main(
                ['query', str(BOM_PRODUCTION), str(BOM_TEST), '--component', 'libalpha'])
        self.assertEqual(0, exit_code)
        self.assertIn('这份材料可以确认内容相同，生产出处目前无从证明。', out.getvalue())

    def test_query_cli_unknown_component(self) -> None:
        with redirect_stdout(io.StringIO()):
            exit_code = evidence_review.main(
                ['query', str(BOM_PRODUCTION), str(BOM_TEST), '--component', 'no-such-lib'])
        self.assertEqual(1, exit_code)


class TestCompareHashes(TestCase):

    def test_identical(self) -> None:
        identity, algorithms = evidence_review.compare_hashes(
            {'SHA-256': 'aa', 'MD5': 'bb'}, {'SHA-256': 'aa'})
        self.assertIs(evidence_review.ByteIdentity.IDENTICAL, identity)
        self.assertEqual(['SHA-256'], algorithms)

    def test_different(self) -> None:
        identity, _ = evidence_review.compare_hashes({'SHA-256': 'aa'}, {'SHA-256': 'cc'})
        self.assertIs(evidence_review.ByteIdentity.DIFFERENT, identity)

    def test_unknown_without_common_algorithm(self) -> None:
        identity, algorithms = evidence_review.compare_hashes({'SHA-256': 'aa'}, {'MD5': 'bb'})
        self.assertIs(evidence_review.ByteIdentity.UNKNOWN, identity)
        self.assertEqual([], algorithms)
