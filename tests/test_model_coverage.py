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

from json import loads as json_loads
from unittest import TestCase

from cyclonedx.model.component_evidence import (
    ComponentEvidence,
    CoverageCategory,
    CoverageReconciliation,
    DirectoryObject,
    Occurrence,
    reconcile_coverage,
)
from cyclonedx.model.coverage import BuildManifest


class TestCoverageReconciliation(TestCase):

    def setUp(self) -> None:
        self.manifest = BuildManifest(
            root="/tmp/example-pkg",
            directories=["src"],
            files=["src/known.py"],
        )

    def test_classifies_three_coverage_buckets(self) -> None:
        evidence = ComponentEvidence(occurrences=[
            Occurrence(location="/tmp/example-pkg"),
            Occurrence(location="/tmp/example-pkg/src/known.py", line=7),
            Occurrence(location="/tmp/example-pkg/src/generated/sample.py", line=9),
            Occurrence(location="/outside/missing.py"),
        ])

        report = evidence.reconcile_coverage(self.manifest)

        self.assertEqual(1, len(report.whole_package))
        self.assertEqual(2, len(report.declared_scope))
        self.assertEqual(1, len(report.unlocated))
        whole = report.whole_package[0]
        self.assertIsInstance(whole.directory, DirectoryObject)
        self.assertEqual("/tmp/example-pkg", whole.path)
        self.assertEqual("/outside/missing.py", report.unlocated[0].path)

    def test_directory_summary_is_not_expanded(self) -> None:
        directory = DirectoryObject("dist/example", summary={"files": 3})
        report = reconcile_coverage(
            directory_summaries=[directory],
            manifest=BuildManifest(root="dist/example"),
        )

        self.assertEqual(1, len(report.whole_package))
        self.assertEqual(1, len(report.all_bindings()))
        self.assertEqual(directory.summary, report.whole_package[0].directory.summary)

    def test_reconciliation_json_roundtrip_is_invariant(self) -> None:
        report = reconcile_coverage(
            ComponentEvidence(occurrences=[
                Occurrence(location="/tmp/example-pkg/src/known.py", line=7),
                Occurrence(location="/outside/missing.py"),
            ]),
            self.manifest,
        )

        restored = CoverageReconciliation.from_json(report.as_json())
        encoded = json_loads(report.as_json())

        self.assertEqual(report, restored)
        self.assertEqual(
            {"whole_package", "declared_scope", "unlocated"},
            set(encoded),
        )
        self.assertEqual(1, len(restored.declared_scope))
        self.assertEqual(7, restored.declared_scope[0].occurrence.line)

    def test_component_evidence_json_roundtrip_preserves_coverage(self) -> None:
        report = reconcile_coverage(
            ComponentEvidence(occurrences=[Occurrence(location="/outside/missing.py")]),
            self.manifest,
        )
        evidence = ComponentEvidence(coverage=report)

        restored = ComponentEvidence.from_json(json_loads(evidence.as_json()))

        self.assertIsNotNone(restored.coverage)
        self.assertEqual(report, restored.coverage)
        self.assertEqual(evidence, restored)

    def test_category_aliases_and_chinese_lookup(self) -> None:
        report = CoverageReconciliation(
            whole=[DirectoryObject(".")],
            declared=[],
            unknown=[],
        )

        self.assertIs(CoverageCategory.WHOLE_PACKAGE, CoverageCategory("package-wide"))
        self.assertEqual(1, len(report["整包"]))
        self.assertEqual(1, len(report.package_wide))

    def test_does_not_infer_file_conclusions_from_directory_summary(self) -> None:
        report = reconcile_coverage(
            ["src/a.py", "src/b.py", "src/c.py"],
            BuildManifest(directories=["src"]),
        )

        self.assertEqual(3, len(report.declared_scope))
        self.assertEqual(0, len(report.whole_package))
        self.assertEqual(
            {"src/a.py", "src/b.py", "src/c.py"},
            {item.path for item in report.declared_scope},
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
