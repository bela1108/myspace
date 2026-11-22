import unittest

from lxml import etree

from signxml import (
    DeliveryContract,
    Recipient,
    SignatureConfiguration,
    SignatureMethod,
    XMLSigner,
    XMLVerifier,
    check_delivery_contract,
)
from signxml.delivery import DeliveryStatus

XML = (
    b'<Archive Id="ARCH-1"><Order><Amount>120.00</Amount><Currency>CNY</Currency><Buyer>ACME</Buyer></Order></Archive>'
)


class TestDeliveryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signed = XMLSigner(signature_algorithm=SignatureMethod.HMAC_SHA256).sign(
            etree.fromstring(XML), key=b"secret"
        )
        cls.result = XMLVerifier().verify(
            cls.signed,
            hmac_key=b"secret",
            expect_config=SignatureConfiguration(require_x509=False),
        )

    def make_contract(self, version, amount_owner="ARCH-1", currency_owner="ARCH-1"):
        return DeliveryContract(
            version=version,
            field_owners={
                "Order/Amount": amount_owner,
                "Order/Currency": currency_owner,
                "Order/Buyer": "ARCH-1",
            },
            recipients=[
                Recipient("erp", ["Order/Amount", "Order/Currency"], version),
                Recipient("analytics", ["Order/Buyer"], version),
            ],
        )

    def test_same_xml_under_two_contract_versions_is_independent_per_receiver(self):
        current = self.make_contract("v2")
        legacy = self.make_contract("v1", amount_owner="ARCH-OLD")

        current_report = current.check(self.result, object_identity="ARCH-1")
        legacy_report = legacy.check(self.result, object_identity="ARCH-1")

        self.assertEqual(current_report.status, DeliveryStatus.DELIVER)
        self.assertEqual(current_report["erp"].status, DeliveryStatus.DELIVER)
        self.assertEqual(current_report["analytics"].status, DeliveryStatus.DELIVER)

        self.assertEqual(legacy_report["erp"].status, DeliveryStatus.REFUSE)
        self.assertEqual(legacy_report["analytics"].status, DeliveryStatus.DELIVER)
        self.assertTrue(any("owned by" in reason for reason in legacy_report["erp"].reasons))

    def test_unexplained_required_field_refuses_only_that_receiver(self):
        contract = DeliveryContract(
            version="v2",
            field_owners={"Order/Amount": "ARCH-1", "Order/Buyer": "ARCH-1"},
            recipients=[
                Recipient("erp", ["Order/Missing"], "v2"),
                Recipient("analytics", ["Order/Buyer"], "v2"),
            ],
        )
        report = contract.check(self.result, object_identity="ARCH-1")
        self.assertEqual(report["erp"].status, DeliveryStatus.REFUSE)
        self.assertEqual(report["erp"].refused_fields, ("Order/Missing",))
        self.assertEqual(report["analytics"].status, DeliveryStatus.DELIVER)

    def test_optional_unexplained_field_produces_manual_review_sheet(self):
        contract = DeliveryContract(
            version="v2",
            field_owners={"Order/Amount": "ARCH-1"},
            recipients=[Recipient("reviewer", [{"path": "Order/Optional", "required": False}], "v2")],
        )
        report = contract.check(self.result, object_identity="ARCH-1")
        decision = report["reviewer"]
        self.assertEqual(decision.status, DeliveryStatus.MANUAL_REVIEW)
        self.assertEqual(decision.review_fields, ("Order/Optional",))
        self.assertIsNotNone(decision.manual_review_sheet)
        self.assertEqual(decision.manual_review_sheet["recipient"], "reviewer")
        self.assertEqual(report.manual_review_sheet[0]["action"], "manual_review")

    def test_cosign_requirement_blocks_only_receivers_that_depend_on_group(self):
        contract = DeliveryContract(
            version="v2",
            field_owners={"Order/Amount": "ARCH-1", "Order/Buyer": "ARCH-1"},
            must_sign_together=["Order/Amount", "Order/Currency"],
            recipients=[
                Recipient("erp", ["Order/Amount"], "v2"),
                Recipient("analytics", ["Order/Buyer"], "v2"),
            ],
        )
        report = contract.check(self.result, object_identity="ARCH-1")
        self.assertEqual(report["erp"].status, DeliveryStatus.REFUSE)
        self.assertIn("<co-sign>", report["erp"].refused_fields)
        self.assertEqual(report["analytics"].status, DeliveryStatus.DELIVER)

    def test_changing_shared_field_owner_marks_only_affected_receivers(self):
        old = self.make_contract("v2")
        new = old.with_field_owner("Order/Currency", "ARCH-2")

        self.assertEqual(old.changed_field_ownership(new), {"Order/Currency": ("ARCH-1", "ARCH-2")})
        self.assertEqual(old.affected_recipients(new), {"erp"})
        self.assertFalse(old.requires_resignature(new, "analytics"))

        old_report = old.check(self.result, object_identity="ARCH-1")
        new_report = new.check(self.result, object_identity="ARCH-1")
        self.assertEqual(old_report["erp"].status, DeliveryStatus.DELIVER)
        self.assertEqual(new_report["erp"].status, DeliveryStatus.REFUSE)
        self.assertEqual(new_report["analytics"].status, DeliveryStatus.DELIVER)

    def test_versioned_contract_selects_each_receiver_context(self):
        contract = DeliveryContract(
            versions={
                "v1": {"Order/Amount": "ARCH-OLD", "Order/Buyer": "ARCH-1"},
                "v2": {"Order/Amount": "ARCH-1", "Order/Buyer": "ARCH-1"},
            },
            recipients=[
                Recipient("erp", ["Order/Amount"], "v2"),
                Recipient("legacy", ["Order/Amount"], "v1"),
            ],
        )
        report = contract.check(self.result, object_identity="ARCH-1")
        self.assertEqual(report["erp"].status, DeliveryStatus.DELIVER)
        self.assertEqual(report["legacy"].status, DeliveryStatus.REFUSE)
        self.assertEqual(contract.view_for_context("latest").version, "v2")
        self.assertEqual(contract.view_for_context("old").version, "v1")

    def test_post_verification_entry_point_accepts_contract_components(self):
        report = check_delivery_contract(
            self.result,
            [
                Recipient("erp", ["Order/Amount"], "v2"),
                Recipient("analytics", ["Order/Buyer"], "v2"),
            ],
            object_identity="ARCH-1",
            field_owners={"Order/Amount": "ARCH-1", "Order/Buyer": "ARCH-1"},
            version="v2",
        )
        self.assertEqual(report["erp"].status, DeliveryStatus.DELIVER)
        self.assertEqual(report["analytics"].status, DeliveryStatus.DELIVER)

    def test_verified_result_exposes_object_identity(self):
        self.assertEqual(self.result.object_identity, "ARCH-1")
        self.assertEqual(self.result.object_id, "ARCH-1")
        field = self.result.signature_xml
        self.assertIsNotNone(field)


if __name__ == "__main__":
    unittest.main()
