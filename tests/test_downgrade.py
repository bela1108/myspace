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


from datetime import datetime, timezone
from unittest import TestCase

from cyclonedx.downgrade import (
    DowngradePolicy,
    DowngradeRejectedError,
    LossCategory,
    LossKind,
    analyze_downgrade,
    enforce,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.model.impact_analysis import (
    ImpactAnalysisJustification,
    ImpactAnalysisState,
)
from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilityAnalysis,
    VulnerabilityReference,
    VulnerabilitySource,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion


def _build_bom() -> Bom:
    # One legacy-sensitive cryptographic algorithm asset ...
    algorithm_component = Component(
        type=ComponentType.LIBRARY,
        bom_ref="crypto-lib",
        name="crypto-lib",
        crypto_properties=CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=AlgorithmProperties(
                primitive=CryptoPrimitive.KEY_WRAP,
            ),
        ),
    )
    # ... and one vulnerability carrying impact analysis plus a cross-source reference.
    vulnerability = Vulnerability(
        bom_ref="CVE-2024-0001",
        id="CVE-2024-0001",
        analysis=VulnerabilityAnalysis(
            state=ImpactAnalysisState.NOT_AFFECTED,
            justification=ImpactAnalysisJustification.CODE_NOT_PRESENT,
            first_issued=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_updated=datetime(2024, 2, 1, tzinfo=timezone.utc),
        ),
        references=[
            VulnerabilityReference(
                id="GHSA-aaaa-bbbb-cccc",
                source=VulnerabilitySource(name="GitHub Security Advisories"),
            ),
        ],
    )
    bom = Bom()
    bom.components.add(algorithm_component)
    bom.vulnerabilities.add(vulnerability)
    return bom



class TestAnalyzeDowngrade(TestCase):

    def setUp(self) -> None:
        self.bom = _build_bom()

    def test_no_loss_when_targeting_current_version(self) -> None:
        report = analyze_downgrade(self.bom, SchemaVersion.V1_7)
        self.assertEqual(0, len(report))
        self.assertFalse(bool(report))

    def test_new_primitive_is_normalized_with_equivalent(self) -> None:
        report = analyze_downgrade(self.bom, SchemaVersion.V1_6)
        normalized = report.of_kind(LossKind.NORMALIZED)
        self.assertEqual(1, len(normalized))
        loss = normalized[0]
        self.assertIs(LossCategory.CRYPTO_ASSET, loss.category)
        self.assertIs(SchemaVersion.V1_7, loss.introduced_in)
        self.assertIn("other", loss.equivalent or "")

    def test_crypto_asset_is_dropped_before_v1_6(self) -> None:
        report = analyze_downgrade(self.bom, SchemaVersion.V1_5)
        crypto_drops = [
            loss for loss in report.for_category(LossCategory.CRYPTO_ASSET)
            if loss.kind is LossKind.DROPPED
        ]
        self.assertEqual(1, len(crypto_drops))
        # When the whole block is dropped there must be no contradictory NORMALIZED item.
        self.assertEqual(0, len(report.of_kind(LossKind.NORMALIZED)))

    def test_impact_analysis_timestamps_dropped_but_state_survives_on_v1_4(self) -> None:
        report = analyze_downgrade(self.bom, SchemaVersion.V1_4)
        sources = {loss.source for loss in report}
        self.assertIn("VulnerabilityAnalysis.first_issued", sources)
        self.assertIn("VulnerabilityAnalysis.last_updated", sources)
        # The core triage state is representable on 1.4, hence no loss item for it.
        self.assertNotIn("Vulnerability.analysis", sources)

    def test_vulnerability_and_reference_disappear_before_v1_4(self) -> None:
        report = analyze_downgrade(self.bom, SchemaVersion.V1_3)
        self.assertIn(LossCategory.VULNERABILITY_ANALYSIS, report.categories())
        reference_losses = report.for_category(LossCategory.REFERENCE)
        self.assertEqual(1, len(reference_losses))
        self.assertIs(LossKind.DROPPED, reference_losses[0].kind)



class TestFormatAgnosticJudgment(TestCase):

    def test_json_and_xml_share_the_same_loss_judgment(self) -> None:
        bom = _build_bom()
        for target in (SchemaVersion.V1_6, SchemaVersion.V1_5,
                       SchemaVersion.V1_4, SchemaVersion.V1_3):
            json_outputter = make_outputter(bom, OutputFormat.JSON, target)
            xml_outputter = make_outputter(bom, OutputFormat.XML, target)
            json_keys = [(l.category, l.kind, l.source) for l in json_outputter.get_downgrade_report()]
            xml_keys = [(l.category, l.kind, l.source) for l in xml_outputter.get_downgrade_report()]
            self.assertEqual(json_keys, xml_keys, target)


class TestDowngradePolicy(TestCase):

    def setUp(self) -> None:
        self.bom = _build_bom()
        self.report = analyze_downgrade(self.bom, SchemaVersion.V1_4)

    def test_report_only_policy_allows_everything(self) -> None:
        policy = DowngradePolicy.report_only()
        self.assertTrue(policy.allows(self.report))
        self.assertEqual((), policy.blocking_losses(self.report))
        # enforce must not raise and must hand back the same report.
        self.assertIs(self.report, enforce(policy, self.report))

    def test_category_policy_blocks_only_configured_category(self) -> None:
        policy = DowngradePolicy(blocked_categories={LossCategory.CRYPTO_ASSET})
        blocking = policy.blocking_losses(self.report)
        self.assertTrue(blocking)
        self.assertTrue(all(l.category is LossCategory.CRYPTO_ASSET for l in blocking))
        with self.assertRaises(DowngradeRejectedError) as ctx:
            enforce(policy, self.report)
        self.assertIs(self.report, ctx.exception.report)

    def test_kind_policy_blocks_dropped_only(self) -> None:
        policy = DowngradePolicy.block_dropped()
        self.assertFalse(policy.allows(self.report))
        self.assertTrue(all(l.kind is LossKind.DROPPED for l in policy.blocking_losses(self.report)))

    def test_block_any_also_catches_normalization(self) -> None:
        report_1_6 = analyze_downgrade(self.bom, SchemaVersion.V1_6)
        self.assertTrue(DowngradePolicy.block_dropped().allows(report_1_6))
        self.assertFalse(DowngradePolicy.block_any().allows(report_1_6))



class TestOutputIntegration(TestCase):

    def setUp(self) -> None:
        self.bom = _build_bom()

    def test_blocking_policy_aborts_generation_for_json_and_xml(self) -> None:
        policy = DowngradePolicy(blocked_categories={LossCategory.CRYPTO_ASSET})
        for output_format in (OutputFormat.JSON, OutputFormat.XML):
            outputter = make_outputter(self.bom, output_format, SchemaVersion.V1_4,
                                       downgrade_policy=policy)
            with self.assertRaises(DowngradeRejectedError):
                outputter.output_as_string()

    def test_policy_can_be_set_after_construction(self) -> None:
        outputter = make_outputter(self.bom, OutputFormat.JSON, SchemaVersion.V1_4)
        outputter.set_downgrade_policy(DowngradePolicy.block_any())
        with self.assertRaises(DowngradeRejectedError):
            outputter.output_as_string()

    def test_legacy_json_is_valid_but_keeps_the_security_gap_in_the_report(self) -> None:
        from cyclonedx.validation.json import JsonStrictValidator

        outputter = make_outputter(self.bom, OutputFormat.JSON, SchemaVersion.V1_4)
        document = outputter.output_as_string()

        # The downgraded document still passes the target schema validation ...
        self.assertIsNone(JsonStrictValidator(SchemaVersion.V1_4).validate_str(document))
        # ... while the dropped security information is still surfaced in the report.
        report = outputter.downgrade_report
        self.assertIsNotNone(report)
        self.assertIn(LossCategory.CRYPTO_ASSET, report.categories())
        self.assertTrue(any(
            "VulnerabilityAnalysis" in loss.source for loss in report
        ))
        # and the information really is absent from the serialized document.
        self.assertNotIn("cryptoProperties", document)
        self.assertNotIn("firstIssued", document)
        self.assertNotIn("lastUpdated", document)

    def test_same_bom_instance_still_serializes_to_newest_schema(self) -> None:
        old_outputter = make_outputter(self.bom, OutputFormat.JSON, SchemaVersion.V1_4)
        old_outputter.output_as_string()

        new_outputter = make_outputter(self.bom, OutputFormat.JSON, SchemaVersion.V1_7)
        newest_document = new_outputter.output_as_string()
        self.assertEqual(0, len(new_outputter.get_downgrade_report()))
        self.assertIn("key-wrap", newest_document)
        self.assertIn("cryptoProperties", newest_document)
