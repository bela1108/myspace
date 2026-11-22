"""Tests for the offline seal reconciliation package."""

from __future__ import annotations

import unittest

from securesystemslib.signer import CryptoSigner, Signature

from seal_reconciliation.models import (
    Authorization,
    SealStatement,
    SourceLocation,
    public_key_from_dict,
    public_key_to_dict,
)
from seal_reconciliation.reconciler import Reconciler
from seal_reconciliation.signing import digest_material, issue_statement


class ReconciliationFixture:
    """Build fresh signers and ledger entries for every test."""

    def __init__(self) -> None:
        self.liu = CryptoSigner.generate_ed25519()
        self.chen = CryptoSigner.generate_ed25519()
        self.zhao = CryptoSigner.generate_ed25519()
        self.authorizations = [
            Authorization(
                officer_id="liu",
                keyid=self.liu.public_key.keyid,
                start=100,
                end=149,
                category="payment",
            ),
            Authorization(
                officer_id="chen",
                keyid=self.chen.public_key.keyid,
                start=150,
                end=199,
                category="payment",
                note="proxy half",
            ),
            Authorization(
                officer_id="zhao",
                keyid=self.zhao.public_key.keyid,
                start=100,
                end=149,
                category="contract",
            ),
        ]
        self.registry = {
            signer.public_key.keyid: signer.public_key
            for signer in (self.liu, self.chen, self.zhao)
        }

    def reconcile(self, statements: list[SealStatement]):
        return Reconciler(self.authorizations, self.registry).reconcile(
            statements
        )


class TestModels(unittest.TestCase):
    def test_canonical_payload_excludes_source(self) -> None:
        fixture = ReconciliationFixture()
        statement = issue_statement(
            fixture.liu,
            "ST-1",
            "payment",
            100,
            b"content",
            SourceLocation("primary", "p.1", 1),
        )
        relocated = SealStatement(
            statement_id=statement.statement_id,
            category=statement.category,
            seal_number=statement.seal_number,
            material_digest=statement.material_digest,
            keyid=statement.keyid,
            signature=statement.signature,
            source=SourceLocation("backup", "p.9", 7),
        )
        self.assertEqual(
            statement.canonical_payload(), relocated.canonical_payload()
        )

    def test_round_trip_serialization(self) -> None:
        fixture = ReconciliationFixture()
        statement = issue_statement(
            fixture.liu,
            "ST-2",
            "payment",
            101,
            b"content",
            SourceLocation("primary", "p.1", 2),
        )
        rebuilt = SealStatement.from_dict(statement.to_dict())
        self.assertEqual(rebuilt, statement)
        key_data = public_key_to_dict(fixture.liu.public_key)
        rebuilt_key = public_key_from_dict(key_data)
        self.assertEqual(rebuilt_key, fixture.liu.public_key)

    def test_digest_material_stable(self) -> None:
        self.assertEqual(
            digest_material(b"abc"), digest_material(b"abc")
        )
        self.assertNotEqual(
            digest_material(b"abc"), digest_material(b"abd")
        )

    def test_invalid_authorization_interval(self) -> None:
        with self.assertRaises(ValueError):
            Authorization(
                officer_id="liu",
                keyid="k",
                start=200,
                end=100,
                category="payment",
            )


class TestReconciliation(unittest.TestCase):
    def test_backup_copy_counts_once_but_keeps_both_locations(self) -> None:
        fixture = ReconciliationFixture()
        primary = issue_statement(
            fixture.liu,
            "ST-10",
            "payment",
            120,
            b"order-120",
            SourceLocation("primary-archive", "p.1", 1),
        )
        backup = SealStatement(
            statement_id=primary.statement_id,
            category=primary.category,
            seal_number=primary.seal_number,
            material_digest=primary.material_digest,
            keyid=primary.keyid,
            signature=primary.signature,
            source=SourceLocation("backup-tape", "p.1", 1),
        )
        report = fixture.reconcile([primary, backup])
        self.assertEqual(len(report.usages), 1)
        usage = report.usages[0]
        self.assertEqual(usage.seal_number, 120)
        self.assertEqual(len(usage.sources), 2)
        self.assertEqual(report.collisions, ())

    def test_same_number_repeats_across_categories(self) -> None:
        fixture = ReconciliationFixture()
        payment = issue_statement(
            fixture.liu,
            "ST-11",
            "payment",
            120,
            b"payment-120",
            SourceLocation("primary-archive", "p.1", 1),
        )
        contract = issue_statement(
            fixture.zhao,
            "ST-12",
            "contract",
            120,
            b"contract-120",
            SourceLocation("primary-archive", "p.2", 1),
        )
        report = fixture.reconcile([payment, contract])
        self.assertEqual(len(report.usages), 2)
        self.assertEqual(report.collisions, ())

    def test_different_content_sharing_number_freezes_with_locations(self) -> None:
        fixture = ReconciliationFixture()
        first = issue_statement(
            fixture.chen,
            "ST-13",
            "payment",
            160,
            b"order-160-a",
            SourceLocation("primary-archive", "p.2", 3),
        )
        second = issue_statement(
            fixture.chen,
            "ST-14",
            "payment",
            160,
            b"order-160-b",
            SourceLocation("primary-archive", "p.40", 5),
        )
        report = fixture.reconcile([first, second])
        self.assertEqual(report.usages, ())
        self.assertEqual(len(report.collisions), 1)
        collision = report.collisions[0]
        self.assertEqual(collision.seal_number, 160)
        self.assertEqual(len(collision.material_digests), 2)
        self.assertEqual(len(collision.sources), 2)
        self.assertEqual(collision.keyids, (fixture.chen.public_key.keyid,))

    def test_tampered_signature_is_rejected(self) -> None:
        fixture = ReconciliationFixture()
        statement = issue_statement(
            fixture.liu,
            "ST-15",
            "payment",
            130,
            b"order-130",
            SourceLocation("primary-archive", "p.5", 2),
        )
        tampered = SealStatement(
            statement_id=statement.statement_id,
            category=statement.category,
            seal_number=statement.seal_number,
            material_digest=statement.material_digest,
            keyid=statement.keyid,
            signature=Signature(keyid=statement.keyid, sig="00" * 64),
            source=statement.source,
        )
        report = fixture.reconcile([tampered])
        self.assertEqual(report.usages, ())
        self.assertEqual(len(report.invalid_signatures), 1)
        self.assertEqual(report.invalid_signatures[0].statement_id, "ST-15")

    def test_unknown_keyid_is_invalid(self) -> None:
        fixture = ReconciliationFixture()
        statement = issue_statement(
            fixture.liu,
            "ST-16",
            "payment",
            131,
            b"order-131",
            SourceLocation("primary-archive", "p.5", 3),
        )
        unknown = SealStatement(
            statement_id=statement.statement_id,
            category=statement.category,
            seal_number=statement.seal_number,
            material_digest=statement.material_digest,
            keyid="deadbeef",
            signature=statement.signature,
            source=statement.source,
        )
        report = fixture.reconcile([unknown])
        self.assertEqual(len(report.invalid_signatures), 1)
        self.assertIn("unknown keyid", report.invalid_signatures[0].reason)

    def test_out_of_range_usage_is_separated(self) -> None:
        fixture = ReconciliationFixture()
        statement = issue_statement(
            fixture.zhao,
            "ST-17",
            "contract",
            300,
            b"contract-300",
            SourceLocation("primary-archive", "p.9", 1),
        )
        report = fixture.reconcile([statement])
        self.assertEqual(report.usages, ())
        self.assertEqual(len(report.out_of_range), 1)
        self.assertEqual(report.out_of_range[0].seal_number, 300)

    def test_proxy_half_segment_is_attributed_to_substitute(self) -> None:
        fixture = ReconciliationFixture()
        statement = issue_statement(
            fixture.chen,
            "ST-18",
            "payment",
            170,
            b"proxy-order-170",
            SourceLocation("primary-archive", "p.3", 1),
        )
        report = fixture.reconcile([statement])
        self.assertEqual(len(report.usages), 1)
        self.assertEqual(report.usages[0].officer_id, "chen")
        interval = next(
            item for item in report.authorizations if item.officer_id == "chen"
        )
        self.assertEqual(interval.officer_id, "chen")
        self.assertEqual(interval.interval, "[150, 199]")
        self.assertEqual(interval.used_numbers, (170,))
        self.assertEqual(interval.note, "proxy half")

    def test_three_identical_copies_merge_into_one_usage(self) -> None:
        fixture = ReconciliationFixture()
        primary = issue_statement(
            fixture.liu,
            "ST-21",
            "payment",
            121,
            b"order-121",
            SourceLocation("primary-archive", "p.1", 1),
        )
        copies = [primary]
        for archive in ("backup-a", "backup-b"):
            copies.append(
                SealStatement(
                    statement_id=primary.statement_id,
                    category=primary.category,
                    seal_number=primary.seal_number,
                    material_digest=primary.material_digest,
                    keyid=primary.keyid,
                    signature=primary.signature,
                    source=SourceLocation(archive, "p.1", 1),
                )
            )
        report = fixture.reconcile(copies)
        self.assertEqual(len(report.usages), 1)
        self.assertEqual(len(report.usages[0].sources), 3)

    def test_collision_never_reaches_finance_settlement(self) -> None:
        fixture = ReconciliationFixture()
        first = issue_statement(
            fixture.chen,
            "ST-22",
            "payment",
            161,
            b"order-161-a",
            SourceLocation("primary-archive", "p.2", 3),
        )
        second = issue_statement(
            fixture.chen,
            "ST-23",
            "payment",
            161,
            b"order-161-b",
            SourceLocation("primary-archive", "p.40", 5),
        )
        report = fixture.reconcile([first, second])
        settled_numbers = {
            (usage.category, usage.seal_number) for usage in report.usages
        }
        self.assertNotIn(("payment", 161), settled_numbers)
        interval = next(
            item for item in report.authorizations if item.officer_id == "chen"
        )
        self.assertEqual(interval.used_numbers, ())

    def test_report_rendering_contains_both_pages(self) -> None:
        from seal_reconciliation.report import (
            render_finance_page,
            render_json_report,
            render_security_page,
        )

        fixture = ReconciliationFixture()
        first = issue_statement(
            fixture.chen,
            "ST-19",
            "payment",
            160,
            b"order-160-a",
            SourceLocation("primary-archive", "p.2", 3),
        )
        second = issue_statement(
            fixture.chen,
            "ST-20",
            "payment",
            160,
            b"order-160-b",
            SourceLocation("primary-archive", "p.40", 5),
        )
        report = fixture.reconcile([first, second])
        finance = render_finance_page(report)
        security = render_security_page(report)
        json_report = render_json_report(report)
        self.assertIn("授权区间", finance)
        self.assertIn("待冻结", security)
        self.assertIn("160", security)
        self.assertIn("p.002 / #3".replace("p.002", "p.2"), security)
        self.assertIn("freeze_candidates", json_report)


if __name__ == "__main__":
    unittest.main()
