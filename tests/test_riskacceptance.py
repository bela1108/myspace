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
from xml.etree.ElementTree import fromstring as xml_fromstring
from unittest import TestCase

from cyclonedx.model import ExternalReference, ExternalReferenceType
from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot7
from cyclonedx.riskacceptance import (
    ArtifactCoordinates,
    SignOffStatus,
    evaluate_bom,
    extract_signoffs,
    make_evidence_reference,
    make_signoff_component,
)

ARTIFACT = ArtifactCoordinates(
    group="com.example", name="acme-lib", version="1.2.3",
    bom_ref="acme-lib-1.2.3-old",
)


def _three_node_cycle(evidence_for_procurement=None) -> Bom:
    procurement = make_signoff_component(
        ARTIFACT,
        signoff_id="RA-PROCUREMENT",
        owner="procurement",
        references=("RA-PLATFORM",),
        evidence=list(evidence_for_procurement or ()),
    )
    platform = make_signoff_component(
        ARTIFACT,
        signoff_id="RA-PLATFORM",
        owner="platform",
        references=("RA-PRODUCT",),
    )
    product = make_signoff_component(
        ARTIFACT,
        signoff_id="RA-PRODUCT",
        owner="product",
        references=("RA-PROCUREMENT",),
    )
    return Bom(components=[procurement, platform, product])


class TestRiskAcceptanceCycle(TestCase):
    def test_three_node_cycle_without_material_stays_pending(self) -> None:
        # acceptance step 1: no independent material anywhere
        verdicts = {item.signoff_id: item
                    for item in evaluate_bom(_three_node_cycle())}
        self.assertEqual(set(verdicts), {
            "RA-PROCUREMENT", "RA-PLATFORM", "RA-PRODUCT"})
        for verdict in verdicts.values():
            self.assertEqual(verdict.status, SignOffStatus.CIRCULAR_REFERENCE)
            self.assertEqual(verdict.supporting_evidence, ())
            # every reported chain closes back on its first node
            self.assertEqual(verdict.chain[0], verdict.chain[-1])
            unique_members = set(verdict.chain[:-1])
            self.assertEqual(len(verdict.chain) - 1, len(unique_members))

    def test_adding_independent_material_establishes_all_three(self) -> None:
        # acceptance step 2a: one independently reviewable piece of
        # material breaks the deadlock for the whole cycle
        material = make_evidence_reference(
            "urn:evidence:audit-report-77", ARTIFACT)
        verdicts = {item.signoff_id: item for item in evaluate_bom(
            _three_node_cycle(evidence_for_procurement=[material]))}
        for verdict in verdicts.values():
            self.assertEqual(
                verdict.status, SignOffStatus.INDEPENDENTLY_SUPPORTED)
            self.assertEqual(
                verdict.supporting_evidence,
                ("urn:evidence:audit-report-77",))
        self.assertEqual(
            verdicts["RA-PROCUREMENT"].chain, ("RA-PROCUREMENT",))
        self.assertEqual(
            verdicts["RA-PLATFORM"].chain,
            ("RA-PLATFORM", "RA-PRODUCT", "RA-PROCUREMENT"))
        self.assertEqual(
            verdicts["RA-PRODUCT"].chain,
            ("RA-PRODUCT", "RA-PROCUREMENT"))

    def test_revoking_material_reopens_the_cycle(self) -> None:
        # acceptance step 2b: revoke the only material and compare which
        # decisions change relative to the supported state
        bom = _three_node_cycle(evidence_for_procurement=[
            make_evidence_reference("urn:evidence:audit-report-77", ARTIFACT)])
        before = {item.signoff_id: item.status
                  for item in evaluate_bom(bom)}
        procurement = next(
            component for component in bom.components
            if any(prop.name == "risk:signoff:id"
                   and prop.value == "RA-PROCUREMENT"
                   for prop in component.properties)
        )
        procurement.external_references = [ExternalReference(
            type=ExternalReferenceType.EVIDENCE,
            url="urn:evidence:unscoped-note",
        )]
        after = {item.signoff_id: item for item in evaluate_bom(bom)}
        changed = sorted(
            signoff_id for signoff_id, status in before.items()
            if after[signoff_id].status != status
        )
        self.assertEqual(changed, [
            "RA-PLATFORM", "RA-PROCUREMENT", "RA-PRODUCT"])
        for verdict in after.values():
            self.assertEqual(verdict.status, SignOffStatus.CIRCULAR_REFERENCE)
            self.assertEqual(verdict.supporting_evidence, ())


class TestEvidenceScope(TestCase):
    def test_bom_ref_change_keeps_support_when_coordinates_match(self) -> None:
        # component replacement may change the bom-ref; the declared
        # group/name/version remain the authority for evidence scope
        replaced = ArtifactCoordinates(
            group="com.example", name="acme-lib", version="1.2.3",
            bom_ref="replacement-bom-ref-9",
        )
        bom = Bom(components=[make_signoff_component(
            replaced,
            signoff_id="RA-SOLO",
            evidence=[make_evidence_reference(
                "urn:evidence:audit-report-77", replaced)],
        )])
        verdict = evaluate_bom(bom)[0]
        self.assertEqual(
            verdict.status, SignOffStatus.INDEPENDENTLY_SUPPORTED)
        self.assertEqual(
            verdict.supporting_evidence,
            ("urn:evidence:audit-report-77",))

    def test_evidence_scoped_to_old_version_is_rejected(self) -> None:
        bumped = ArtifactCoordinates(
            group="com.example", name="acme-lib", version="2.0.0",
            bom_ref="acme-lib-2.0.0",
        )
        old_scope = ArtifactCoordinates(
            group="com.example", name="acme-lib", version="1.2.3")
        bom = Bom(components=[make_signoff_component(
            bumped,
            signoff_id="RA-BUMPED",
            evidence=[make_evidence_reference(
                "urn:evidence:audit-report-77", old_scope)],
        )])
        verdict = evaluate_bom(bom)[0]
        self.assertEqual(verdict.status, SignOffStatus.EVIDENCE_INCOMPLETE)
        self.assertEqual(verdict.supporting_evidence, ())

    def test_unscoped_reference_is_not_independent_material(self) -> None:
        bom = Bom(components=[make_signoff_component(
            ARTIFACT, signoff_id="RA-UNSCOPED",
            evidence=[ExternalReference(
                type=ExternalReferenceType.EVIDENCE,
                url="urn:evidence:loose-note")],
        )])
        verdict = evaluate_bom(bom)[0]
        self.assertEqual(verdict.status, SignOffStatus.EVIDENCE_INCOMPLETE)

    def test_missing_reference_is_incomplete_not_circular(self) -> None:
        dangling = make_signoff_component(
            ARTIFACT, signoff_id="RA-DANGLING",
            references=("RA-DOES-NOT-EXIST",))
        verdict = evaluate_bom(Bom(components=[dangling]))[0]
        self.assertEqual(verdict.status, SignOffStatus.EVIDENCE_INCOMPLETE)
        self.assertEqual(
            verdict.chain, ("RA-DANGLING", "RA-DOES-NOT-EXIST"))

    def test_plain_chain_without_material_is_incomplete(self) -> None:
        head = make_signoff_component(
            ARTIFACT, signoff_id="RA-HEAD",
            references=("RA-TAIL",))
        tail = make_signoff_component(
            ARTIFACT, signoff_id="RA-TAIL")
        verdicts = {item.signoff_id: item
                    for item in evaluate_bom(Bom(components=[head, tail]))}
        self.assertEqual(
            verdicts["RA-HEAD"].status, SignOffStatus.EVIDENCE_INCOMPLETE)
        self.assertEqual(
            verdicts["RA-TAIL"].status, SignOffStatus.EVIDENCE_INCOMPLETE)

    def test_group_mismatch_breaks_evidence_scope(self) -> None:
        other_group = ArtifactCoordinates(
            group="com.vendor", name="acme-lib", version="1.2.3")
        bom = Bom(components=[make_signoff_component(
            ARTIFACT, signoff_id="RA-GROUP",
            evidence=[make_evidence_reference(
                "urn:evidence:other", other_group)],
        )])
        verdict = evaluate_bom(bom)[0]
        self.assertEqual(verdict.status, SignOffStatus.EVIDENCE_INCOMPLETE)

    def test_self_loop_is_circular(self) -> None:
        looped = make_signoff_component(
            ARTIFACT, signoff_id="RA-LOOP",
            references=("RA-LOOP",))
        verdict = evaluate_bom(Bom(components=[looped]))[0]
        self.assertEqual(verdict.status, SignOffStatus.CIRCULAR_REFERENCE)
        self.assertEqual(verdict.chain, ("RA-LOOP", "RA-LOOP"))


class TestOfflineRoundTrip(TestCase):
    def test_cyclonedx_json_round_trip_preserves_signoffs(self) -> None:
        bom = _three_node_cycle(evidence_for_procurement=[
            make_evidence_reference("urn:evidence:audit-report-77", ARTIFACT)])
        encoded = JsonV1Dot7(bom).output_as_string()
        # full offline parse through the library deserializer
        restored = Bom.from_json(json_loads(encoded))
        signoffs = {item.signoff_id: item for item in extract_signoffs(restored)}
        self.assertEqual(set(signoffs), {
            "RA-PROCUREMENT", "RA-PLATFORM", "RA-PRODUCT"})
        procurement = signoffs["RA-PROCUREMENT"]
        self.assertEqual(procurement.owner, "procurement")
        self.assertEqual(procurement.references, ["RA-PLATFORM"])
        self.assertEqual(procurement.artifact.name, "acme-lib")
        self.assertEqual(procurement.artifact.version, "1.2.3")
        self.assertTrue(procurement.has_independent_material)
        self.assertEqual(
            procurement.evidence[0].scope.group, "com.example")
        verdicts = {item.signoff_id: item.status
                    for item in evaluate_bom(restored)}
        self.assertTrue(all(
            status is SignOffStatus.INDEPENDENTLY_SUPPORTED
            for status in verdicts.values()))

    def test_attestation_reference_type_is_material(self) -> None:
        from cyclonedx.model import ExternalReferenceType
        attestation = make_evidence_reference(
            "urn:attestation:signed", ARTIFACT,
            reference_type=ExternalReferenceType.ATTESTATION)
        bom = Bom(components=[make_signoff_component(
            ARTIFACT, signoff_id="RA-ATTESTED",
            evidence=[attestation])])
        verdict = evaluate_bom(bom)[0]
        self.assertEqual(
            verdict.status, SignOffStatus.INDEPENDENTLY_SUPPORTED)


class TestPropagation(TestCase):
    def test_material_propagates_through_a_non_cyclic_chain(self) -> None:
        head = make_signoff_component(
            ARTIFACT, signoff_id="RA-HEAD",
            references=("RA-MID",))
        mid = make_signoff_component(
            ARTIFACT, signoff_id="RA-MID",
            references=("RA-BASE",))
        base = make_signoff_component(
            ARTIFACT, signoff_id="RA-BASE",
            evidence=[make_evidence_reference(
                "urn:evidence:base-material", ARTIFACT)])
        verdicts = {item.signoff_id: item
                    for item in evaluate_bom(Bom(components=[head, mid, base]))}
        for signoff_id in ("RA-HEAD", "RA-MID", "RA-BASE"):
            self.assertEqual(
                verdicts[signoff_id].status,
                SignOffStatus.INDEPENDENTLY_SUPPORTED)
        self.assertEqual(
            verdicts["RA-HEAD"].chain,
            ("RA-HEAD", "RA-MID", "RA-BASE"))
        self.assertEqual(
            verdicts["RA-HEAD"].supporting_evidence,
            ("urn:evidence:base-material",))

    def test_node_leading_into_a_cycle_is_circular(self) -> None:
        lead = make_signoff_component(
            ARTIFACT, signoff_id="RA-LEAD",
            references=("RA-LOOP-A",))
        loop_a = make_signoff_component(
            ARTIFACT, signoff_id="RA-LOOP-A",
            references=("RA-LOOP-B",))
        loop_b = make_signoff_component(
            ARTIFACT, signoff_id="RA-LOOP-B",
            references=("RA-LOOP-A",))
        verdicts = {item.signoff_id: item for item in evaluate_bom(
            Bom(components=[lead, loop_a, loop_b]))}
        for verdict in verdicts.values():
            self.assertEqual(verdict.status, SignOffStatus.CIRCULAR_REFERENCE)
        self.assertEqual(
            verdicts["RA-LEAD"].chain[0], "RA-LEAD")
        self.assertIn("RA-LOOP-A", verdicts["RA-LEAD"].chain)

    def test_external_xml_document_is_classified_offline(self) -> None:
        # XML produced by other tools must parse; the analyzer itself is
        # format agnostic because it works on the in-memory BOM model
        xml_document = (
            "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.7\" version=\"1\">"
            "<components><component type=\"library\" bom-ref=\"r1\""
            " name=\"acme-lib\" version=\"1.2.3\">"
            "<properties><property name=\"risk:signoff:id\" value=\"RA-1\"/>"
            "</properties><externalReferences><reference type=\"evidence\">"
            "<url>urn:evidence:z</url><properties>"
            "<property name=\"risk:evidence:component\" value=\"acme-lib\"/>"
            "<property name=\"risk:evidence:version\" value=\"1.2.3\"/>"
            "</properties></reference></externalReferences>"
            "</component></components></bom>"
        )
        bom = Bom.from_xml(xml_fromstring(xml_document))
        verdict = evaluate_bom(bom)[0]
        self.assertEqual(
            verdict.status, SignOffStatus.INDEPENDENTLY_SUPPORTED)
        self.assertEqual(verdict.supporting_evidence, ("urn:evidence:z",))
