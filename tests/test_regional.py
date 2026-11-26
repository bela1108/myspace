# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for location-bound regional handoff policies."""

import unittest
from copy import deepcopy
from hashlib import sha256

from in_toto.models.layout import Layout, Step
from in_toto.models.metadata import Metablock
from in_toto.regional import (
    CENTRAL_STAGING,
    CONTRACT,
    EAST_ASSEMBLY,
    HANDOFF,
    RECEIPT,
    SUMMARY,
    WEST_DELIVERY,
    LocationObligation,
    RegionalLayout,
    RegionalPolicyError,
    create_two_transfer_layout,
    make_regional_link,
    replace_receipt,
    verify_regional_layout,
)
from in_toto.verifylib import verify_all_item_rules
from tests.common import SignerStore


class RegionalHandoffTest(unittest.TestCase):
    def setUp(self):
        self.keys = {
            "east": SignerStore.rsa_pub,
            "central": SignerStore.ecdsa_pub,
            "west": SignerStore.ed25519_pub,
        }
        self.signers = {
            EAST_ASSEMBLY: SignerStore.rsa,
            CENTRAL_STAGING: SignerStore.ecdsa,
            WEST_DELIVERY: SignerStore.ed25519,
        }
        self.regional_layout = create_two_transfer_layout(self.keys)
        self.summary_hash = (
            "a" * 64  # sha256 digest of the same product summary
        )
        self.documents = {
            HANDOFF: "east parts handoff to central storage",
            CONTRACT: "site contract for the obligation being performed",
            RECEIPT: "sealed custody receipt",
        }

    def test_regional_layout_obligations_must_cover_every_step_once(self):
        step = Step(name=EAST_ASSEMBLY)
        layout = Layout(steps=[step])

        with self.assertRaises(RegionalPolicyError):
            RegionalLayout(layout=layout, obligations=())

        obligation = LocationObligation(
            step=EAST_ASSEMBLY,
            region="east",
            site="east-assembly-plant",
            requires=(HANDOFF, CONTRACT, RECEIPT),
        )
        with self.assertRaises(RegionalPolicyError):
            RegionalLayout(
                layout=layout,
                obligations=(obligation, obligation),
            )

    def _artifacts(self, receipt):
        documents = {**self.documents, RECEIPT: receipt}
        hashes = {
            name: self._sha(document) for name, document in documents.items()
        }
        return {SUMMARY: {"sha256": self.summary_hash}, **hashes}, documents

    @staticmethod
    def _sha(value):
        return {"sha256": sha256(value.encode()).hexdigest()}

    def _link(  # noqa: PLR0913
        self,
        step,
        region,
        site,
        production_id,
        receipt,
        valid_until="2026-12-31T00:00:00Z",
        authorization_id=None,
        summary_hash=None,
    ):
        products, documents = self._artifacts(receipt)
        materials = {} if step == EAST_ASSEMBLY else deepcopy(products)
        return make_regional_link(
            step=step,
            region=region,
            site=site,
            production_id=production_id,
            authorization={
                "authorization_id": authorization_id or f"{step}-auth",
                "summary_digest": summary_hash or self.summary_hash,
            },
            signer=self.signers[step],
            materials=materials,
            products=products,
            documents=documents,
            receipt_valid_until=valid_until,
        )

    def _valid_links(self):
        return {
            EAST_ASSEMBLY: self._link(
                EAST_ASSEMBLY,
                "east",
                "east-assembly-plant",
                "production-1",
                "east sealed receipt",
            ),
            CENTRAL_STAGING: self._link(
                CENTRAL_STAGING,
                "central",
                "central-bonded-warehouse",
                "production-1",
                "central sealed receipt",
            ),
            WEST_DELIVERY: self._link(
                WEST_DELIVERY,
                "west",
                "west-delivery-gate",
                "production-1",
                "west sealed receipt",
            ),
        }

    def test_two_transfer_layout_binds_artifacts_between_all_steps(self):
        self.assertIsInstance(self.regional_layout, RegionalLayout)
        self.assertIsInstance(self.regional_layout.layout, Layout)

        links = {
            step: metadata.signed
            for step, metadata in self._valid_links().items()
        }
        verify_all_item_rules(self.regional_layout.layout.steps, links)

        conclusions = verify_regional_layout(
            self.regional_layout,
            self._valid_links(),
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertEqual(
            [conclusion.region for conclusion in conclusions],
            ["east", "central", "west"],
        )
        self.assertTrue(all(conclusion.valid for conclusion in conclusions))

    def test_replacing_expired_west_receipt_changes_only_west_result(self):
        links = self._valid_links()
        links[WEST_DELIVERY] = self._link(
            WEST_DELIVERY,
            "west",
            "west-delivery-gate",
            "production-1",
            "expired west receipt",
            valid_until="2026-10-31T00:00:00Z",
        )

        expired = verify_regional_layout(
            self.regional_layout,
            links,
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertTrue(expired[0].valid)
        self.assertTrue(expired[1].valid)
        self.assertFalse(expired[2].valid)
        self.assertIn("sealed receipt has expired", expired[2].failures)

        corrected_links = deepcopy(links)
        corrected_links[WEST_DELIVERY] = replace_receipt(
            corrected_links[WEST_DELIVERY],
            self.signers[WEST_DELIVERY],
            receipt="renewed west receipt",
            valid_until="2026-12-31T00:00:00Z",
        )
        corrected = verify_regional_layout(
            self.regional_layout,
            corrected_links,
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertTrue(all(conclusion.valid for conclusion in corrected))
        self.assertEqual(
            corrected[0],
            expired[0],
        )
        self.assertEqual(
            corrected[1],
            expired[1],
        )

    def test_independent_production_cannot_reuse_earlier_authorization(self):
        links = self._valid_links()
        independent_products, independent_documents = self._artifacts(
            "independent west sealed receipt"
        )
        links[WEST_DELIVERY] = make_regional_link(
            step=WEST_DELIVERY,
            region="west",
            site="west-delivery-gate",
            production_id="production-2",
            authorization={
                "authorization_id": "west-delivery-auth",
                "summary_digest": self.summary_hash,
            },
            signer=self.signers[WEST_DELIVERY],
            materials=deepcopy(independent_products),
            products=independent_products,
            documents=independent_documents,
            receipt_valid_until="2026-12-31T00:00:00Z",
        )

        conclusions = verify_regional_layout(
            self.regional_layout,
            links,
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertTrue(conclusions[0].valid)
        self.assertTrue(conclusions[1].valid)
        self.assertFalse(conclusions[2].valid)
        self.assertIn(
            "missing authorization from predecessor 'central-staging'",
            conclusions[2].failures,
        )

    def test_same_summary_rejects_authorization_from_another_production(self):
        links = self._valid_links()
        reused_authorization = deepcopy(
            links[CENTRAL_STAGING].signed.byproducts["authorization"]
        )
        products, documents = self._artifacts("independent west receipt")
        links[WEST_DELIVERY] = make_regional_link(
            step=WEST_DELIVERY,
            region="west",
            site="west-delivery-gate",
            production_id="production-2",
            authorization={
                "authorization_id": reused_authorization["authorization_id"],
                "summary_digest": self.summary_hash,
            },
            override_authorization=reused_authorization,
            signer=self.signers[WEST_DELIVERY],
            materials=deepcopy(products),
            products=products,
            documents=documents,
            receipt_valid_until="2026-12-31T00:00:00Z",
        )

        conclusions = verify_regional_layout(
            self.regional_layout,
            links,
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertFalse(conclusions[2].valid)
        self.assertIn(
            "authorization belongs to a different production",
            conclusions[2].failures,
        )
        self.assertIn(
            "authorization cannot be reused on another step",
            conclusions[2].failures,
        )

    def test_invalid_site_blocks_its_step_and_successor(self):
        links = self._valid_links()
        links[CENTRAL_STAGING] = self._link(
            CENTRAL_STAGING,
            "central",
            "unauthorized-warehouse",
            "production-1",
            "central sealed receipt",
        )
        conclusions = verify_regional_layout(
            self.regional_layout,
            links,
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertTrue(conclusions[0].valid)
        self.assertFalse(conclusions[1].valid)
        self.assertIn(
            "link was not produced at the required site",
            conclusions[1].failures,
        )
        self.assertFalse(conclusions[2].valid)
        self.assertIn(
            "missing authorization from predecessor 'central-staging'",
            conclusions[2].failures,
        )

    def test_unsigned_or_wrong_functionary_link_is_regionally_rejected(self):
        links = self._valid_links()
        links[WEST_DELIVERY] = Metablock(signed=links[WEST_DELIVERY].signed)
        conclusions = verify_regional_layout(
            self.regional_layout,
            links,
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertFalse(conclusions[2].valid)
        self.assertIn(
            "link signature is not valid for this step's functionary",
            conclusions[2].failures,
        )

    def test_tampered_document_and_invalid_receipt_date_fail_regionally(self):
        links = self._valid_links()
        tampered = links[CENTRAL_STAGING].signed
        tampered.products[CONTRACT] = {"sha256": "b" * 64}
        tampered.byproducts["sealed_receipt"]["valid_until"] = "not-a-date"
        tampered_metadata = Metablock(signed=tampered)
        tampered_metadata.create_signature(self.signers[CENTRAL_STAGING])
        links[CENTRAL_STAGING] = tampered_metadata

        conclusions = verify_regional_layout(
            self.regional_layout,
            links,
            as_of="2026-11-27T00:00:00Z",
        )
        self.assertFalse(conclusions[1].valid)
        self.assertIn(
            f"document hash mismatch for '{CONTRACT}'",
            conclusions[1].failures,
        )
        self.assertIn(
            "sealed receipt has an invalid expiration",
            conclusions[1].failures,
        )


if __name__ == "__main__":
    unittest.main()
