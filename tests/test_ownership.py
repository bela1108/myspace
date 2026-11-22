"""Tests for offline ownership reconciliation."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.ownership import (
    OwnershipReconciler,
    Registration,
    Statement,
    StatementVerificationError,
    make_statement,
)
from securesystemslib.ownership._cli import main as cli_main
from securesystemslib.ownership._model import AUTHORIZATION, HANDOFF, canonical_payload
from securesystemslib.ownership._reconcile import (
    CONFLICTED,
    RECOGNIZED,
    UNDETERMINED,
)
from securesystemslib.signer import CryptoSigner, SSlibKey

PURPOSE = "release-signing"
JURISDICTION = "cn"
ORGA = "org-alpha"
ORGB = "org-beta"


def _registrations(signer_a, signer_b):
    """Two registrations for the same key material, filed by two orgs."""
    shared_key = SSlibKey(
        keyid=signer_a.public_key.keyid,
        keytype=signer_a.public_key.keytype,
        scheme=signer_a.public_key.scheme,
        keyval=dict(signer_a.public_key.keyval),
    )
    reg_a = Registration(ORGA, shared_key)
    reg_b = Registration(
        ORGB,
        SSlibKey(
            keyid=signer_b.public_key.keyid,
            keytype=signer_b.public_key.keytype,
            scheme=signer_b.public_key.scheme,
            keyval=dict(signer_b.public_key.keyval),
        ),
    )
    return reg_a, reg_b


def _authorization(signer, organization, valid_from, valid_to):
    payload = {
        "type": AUTHORIZATION,
        "organization": organization,
        "purpose": PURPOSE,
        "jurisdiction": JURISDICTION,
        "valid_from": valid_from,
        "valid_to": valid_to,
    }
    return make_statement(signer, payload)


def _handoff(signer, from_org, to_org, effective_at, witnesses):
    payload = {
        "type": HANDOFF,
        "from_organization": from_org,
        "to_organization": to_org,
        "purpose": PURPOSE,
        "jurisdiction": JURISDICTION,
        "effective_at": effective_at,
        "witnesses": list(witnesses),
    }
    return make_statement(signer, payload)


class OwnershipReconcilerTest(unittest.TestCase):
    def setUp(self):
        # One underlying ed25519 key, exposed through two signers so that the
        # two registrations genuinely share the same public key material.
        self.signer_a = CryptoSigner.generate_ed25519()
        self.signer_b = CryptoSigner(
            self.signer_a._private_key,
            SSlibKey(
                keyid="alt-keyid-for-same-material",
                keytype=self.signer_a.public_key.keytype,
                scheme=self.signer_a.public_key.scheme,
                keyval=dict(self.signer_a.public_key.keyval),
            ),
        )
        self.reg_a, self.reg_b = _registrations(self.signer_a, self.signer_b)
        self.reconciler = OwnershipReconciler([self.reg_a, self.reg_b])

    def test_registrations_share_key_material(self):
        self.assertEqual(
            self.reg_a.material_fingerprint, self.reg_b.material_fingerprint
        )
        self.assertNotEqual(self.reg_a.key.keyid, self.reg_b.key.keyid)

    def test_normal_handoff_is_recognized(self):
        statements = [
            _authorization(self.signer_a, ORGA, "2026-01-01", "2026-03-01"),
            _authorization(self.signer_b, ORGB, "2026-03-01", "2026-06-01"),
            _handoff(
                self.signer_a,
                ORGA,
                ORGB,
                "2026-03-01",
                ["witness-1", "witness-2"],
            ),
        ]
        report = self.reconciler.reconcile(statements)
        self.assertEqual(len(report.receipts), 1)
        receipt = report.get_receipt(PURPOSE, JURISDICTION)

        statuses = {(segment.start, segment.status) for segment in receipt.segments}
        self.assertIn(("2026-01-01", RECOGNIZED), statuses)
        self.assertIn(("2026-03-01", RECOGNIZED), statuses)

        owners = {segment.start: segment.organizations for segment in receipt.segments}
        self.assertEqual(owners["2026-01-01"], [ORGA])
        self.assertEqual(owners["2026-03-01"], [ORGB])

        self.assertEqual(len(receipt.witnesses), 1)
        witness = receipt.witnesses[0]
        self.assertEqual(witness["from_organization"], ORGA)
        self.assertEqual(witness["to_organization"], ORGB)
        self.assertEqual(witness["witnesses"], ["witness-1", "witness-2"])
        self.assertEqual(receipt.ambiguous_intervals, [])

    def test_overlapping_authorizations_are_conflicts_not_newer_wins(self):
        statements = [
            _authorization(self.signer_a, ORGA, "2026-01-01", "2026-04-01"),
            _authorization(self.signer_b, ORGB, "2026-02-01", "2026-05-01"),
        ]
        receipt = self.reconciler.reconcile(statements).get_receipt(
            PURPOSE, JURISDICTION
        )

        by_start = {segment.start: segment for segment in receipt.segments}
        self.assertEqual(by_start["2026-01-01"].status, RECOGNIZED)
        self.assertEqual(by_start["2026-01-01"].organizations, [ORGA])

        overlap = by_start["2026-02-01"]
        self.assertEqual(overlap.status, CONFLICTED)
        self.assertEqual(overlap.organizations, [ORGA, ORGB])
        self.assertEqual(len(overlap.evidence), 2)

        tail = by_start["2026-04-01"]
        self.assertEqual(tail.status, RECOGNIZED)
        self.assertEqual(tail.organizations, [ORGB])

        self.assertEqual(len(receipt.ambiguous_intervals), 1)
        self.assertEqual(receipt.ambiguous_intervals[0]["start"], "2026-02-01")
        self.assertEqual(receipt.ambiguous_intervals[0]["end"], "2026-04-01")

    def test_handoff_does_not_override_overlapping_conflict(self):
        statements = [
            _authorization(self.signer_a, ORGA, "2026-01-01", "2026-04-01"),
            _authorization(self.signer_b, ORGB, "2026-02-01", "2026-05-01"),
            _handoff(self.signer_a, ORGA, ORGB, "2026-03-01", ["w"]),
        ]
        receipt = self.reconciler.reconcile(statements).get_receipt(
            PURPOSE, JURISDICTION
        )
        by_start = {segment.start: segment for segment in receipt.segments}
        conflict = by_start["2026-02-01"]
        self.assertEqual(conflict.status, CONFLICTED)
        self.assertEqual(conflict.start, "2026-02-01")
        self.assertEqual(conflict.end, "2026-04-01")
        self.assertTrue(conflict.start <= "2026-03-01" <= conflict.end)
        self.assertEqual(len(receipt.witnesses), 1)

    def test_duplicate_payloads_are_merged(self):
        first = _authorization(self.signer_a, ORGA, "2026-01-01", "2026-02-01")
        duplicate = Statement.from_dict(first.to_dict())
        self.assertEqual(first.statement_id, duplicate.statement_id)

        receipt = self.reconciler.reconcile([first, duplicate]).get_receipt(
            PURPOSE, JURISDICTION
        )

        self.assertEqual(len(receipt.merged_duplicates), 1)
        self.assertEqual(
            receipt.merged_duplicates[0]["statement_id"], first.statement_id
        )
        evidence = {
            identifier
            for segment in receipt.segments
            for identifier in segment.evidence
        }
        self.assertEqual(evidence, {first.statement_id})

    def test_unregistered_keyid_is_rejected(self):
        stranger = CryptoSigner.generate_ed25519()
        statement = _authorization(stranger, ORGA, "2026-01-01", "2026-02-01")
        report = self.reconciler.reconcile([statement])
        self.assertEqual(report.receipts, [])
        with self.assertRaises(StatementVerificationError):
            OwnershipReconciler([self.reg_a, self.reg_b])._verifier.verify(statement)

    def test_tampered_signature_is_rejected(self):
        statement = _authorization(self.signer_a, ORGA, "2026-01-01", "2026-02-01")
        tampered = Statement.from_dict(copy.deepcopy(statement.to_dict()))
        raw = bytearray.fromhex(tampered.signature.signature)
        raw[0] ^= 0xFF
        tampered.signature.signature = raw.hex()

        with self.assertRaises(StatementVerificationError) as context:
            self.reconciler._verifier.verify(tampered)
        self.assertIsInstance(context.exception.__cause__, UnverifiedSignatureError)

        report = self.reconciler.reconcile([tampered])
        self.assertEqual(report.receipts, [])
        self.assertEqual(len(report.receipts), 0)

    def test_tampered_payload_breaks_canonical_verification(self):
        statement = _authorization(self.signer_a, ORGA, "2026-01-01", "2026-02-01")
        tampered = Statement.from_dict(copy.deepcopy(statement.to_dict()))
        tampered.payload["organization"] = ORGB
        with self.assertRaises(StatementVerificationError):
            self.reconciler._verifier.verify(tampered)

    def test_gap_without_evidence_is_undetermined(self):
        authorization = _authorization(self.signer_a, ORGA, "2026-01-01", "2026-02-01")
        later = _authorization(self.signer_b, ORGB, "2026-04-01", "2026-05-01")
        receipt = self.reconciler.reconcile([authorization, later]).get_receipt(
            PURPOSE, JURISDICTION
        )
        statuses = {segment.status for segment in receipt.segments}
        self.assertIn(UNDETERMINED, statuses)
        gap = next(
            segment for segment in receipt.segments if segment.status == UNDETERMINED
        )
        self.assertEqual(gap.organizations, [])
        self.assertEqual(gap.start, "2026-02-01")
        self.assertEqual(gap.end, "2026-04-01")
        self.assertTrue(
            any(item["start"] == gap.start for item in receipt.ambiguous_intervals)
        )

    def test_handoff_only_recognizes_receiver(self):
        handoff = _handoff(self.signer_a, ORGA, ORGB, "2026-03-01", ["witness-9"])
        receipt = self.reconciler.reconcile([handoff]).get_receipt(
            PURPOSE, JURISDICTION
        )
        only = receipt.segments[0]
        self.assertEqual(only.status, RECOGNIZED)
        self.assertEqual(only.organizations, [ORGB])
        self.assertEqual(receipt.witnesses[0]["witnesses"], ["witness-9"])

    def test_scope_separation_by_purpose_and_jurisdiction(self):
        other_purpose = "attestation"
        local = make_statement(
            self.signer_a,
            {
                "type": AUTHORIZATION,
                "organization": ORGA,
                "purpose": other_purpose,
                "jurisdiction": "eu",
                "valid_from": "2026-01-01",
                "valid_to": "2026-02-01",
            },
        )
        release = _authorization(self.signer_b, ORGB, "2026-01-01", "2026-02-01")
        report = self.reconciler.reconcile([local, release])
        self.assertEqual(len(report.receipts), 2)
        # Both orgs registered the same material, so every receipt lists both,
        # but each scope recognizes only its own authorizing organization.
        for receipt in report.receipts:
            self.assertEqual(receipt.registrations, [ORGA, ORGB])

        local_owner = report.get_receipt(other_purpose, "eu").segments[0]
        self.assertEqual(local_owner.organizations, [ORGA])
        release_owner = report.get_receipt(PURPOSE, JURISDICTION).segments[0]
        self.assertEqual(release_owner.organizations, [ORGB])

    def test_statement_serialization_roundtrip(self):
        statement = _handoff(self.signer_a, ORGA, ORGB, "2026-03-01", ["witness-1"])
        rendered = json.dumps(statement.to_dict())
        restored = Statement.from_dict(json.loads(rendered))
        self.assertEqual(restored.to_dict(), statement.to_dict())
        self.assertEqual(
            canonical_payload(restored.payload), canonical_payload(statement.payload)
        )

    def test_invalid_statement_type_rejected(self):
        with self.assertRaises(ValueError):
            make_statement(
                self.signer_a,
                {
                    "type": "not-a-real-type",
                    "purpose": PURPOSE,
                    "jurisdiction": JURISDICTION,
                },
            )

    def test_cli_writes_report(self):
        statements = [
            _authorization(self.signer_a, ORGA, "2026-01-01", "2026-03-01"),
            _handoff(self.signer_a, ORGA, ORGB, "2026-03-01", ["witness-1"]),
        ]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            regs_path = base / "registrations.json"
            stmts_path = base / "statements.json"
            out_path = base / "receipt.json"
            regs_path.write_text(
                json.dumps([self.reg_a.to_dict(), self.reg_b.to_dict()]),
                encoding="utf-8",
            )
            stmts_path.write_text(
                json.dumps([item.to_dict() for item in statements]),
                encoding="utf-8",
            )
            exit_code = cli_main(
                [
                    "--registrations",
                    str(regs_path),
                    "--statements",
                    str(stmts_path),
                    "--out",
                    str(out_path),
                ]
            )
            self.assertEqual(exit_code, 0)
            report = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(len(report["receipts"]), 1)
            self.assertEqual(
                report["receipts"][0]["witnesses"][0]["witnesses"],
                ["witness-1"],
            )


if __name__ == "__main__":
    unittest.main()
