"""Unit tests for the offline license-conflict audit engine."""
import json
import tempfile
import unittest
from pathlib import Path

from license_audit.engine import (
    AuditReport,
    LicenseAuditError,
    parse_book,
    run_review,
)
from license_audit.report import render_json, render_text

DATA = Path(__file__).resolve().parents[2] / 'examples' / 'license_audit'


def _books():
    books_dir = DATA / "books"
    return [(book.name, str(book)) for book in sorted(books_dir.glob("*.yar"))]


def _run():
    return run_review(
        _books(),
        DATA / "sample_manifest.json",
        DATA / "approvals.json",
        DATA / "frozen_rules.json",
    )


def _dossier(report, *names):
    wanted = set(names)
    for dossier in report.dossiers:
        if {item.rule_name for item in dossier.receipts} == wanted:
            return dossier
    raise AssertionError(f"no dossier for {names}")


class EngineTests(unittest.TestCase):
    """Check parsing, identity comparison and audit verdicts."""

    def test_parse_book_extracts_identity_and_location(self):
        """Each rule carries authorization identity and source coordinates."""
        receipts = parse_book(DATA / "books" / "book_beta.yar", "book_beta.yar")
        self.assertEqual(len(receipts), 4)
        banker = next(item for item in receipts if item.rule_name == "BankerStr_Beta")
        self.assertEqual(banker.authorization_id, "AZ-7741")
        self.assertEqual(banker.book, "book_beta.yar")
        self.assertTrue(Path(banker.source_path).exists())
        self.assertGreaterEqual(banker.start_line, 1)
        self.assertGreaterEqual(banker.stop_line, banker.start_line)
        self.assertTrue(banker.logic_hash.startswith("v1_sha256_"))

    def test_missing_metadata_is_rejected(self):
        """Rules without provenance keys fail loudly, not silently."""
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.yar"
            bad.write_text("rule Bad { meta: authorization_id = \"X\" condition: true }", encoding="utf-8")
            with self.assertRaises(LicenseAuditError):
                parse_book(bad, "bad.yar")

    def test_run_review_returns_report(self):
        """The full offline run returns a structured report."""
        report = _run()
        self.assertIsInstance(report, AuditReport)
        self.assertEqual(report.frozen_version, "v3.1")
        self.assertEqual(len(report.books), 3)

    def test_same_authorization_duplicate_is_foldable(self):
        """Identical text rules backed by the same authorization may fold."""
        report = _run()
        dossier = _dossier(report, "BankerStr_Beta", "BankerStr_Gamma")
        self.assertEqual(dossier.verdict, "foldable")
        self.assertEqual({item.authorization_id for item in dossier.receipts}, {"AZ-7741"})
        self.assertEqual(len(dossier.keep_receipts), 1)
        self.assertEqual(len(dossier.folded_receipts), 1)
        for receipt in dossier.receipts:
            self.assertTrue(Path(receipt.source_path).exists())

    def test_identical_text_different_authorization_must_be_kept(self):
        """Identical receipt text from two authorizations stays separate."""
        report = _run()
        dossier = _dossier(report, "LoaderSig_Beta", "LoaderSig_Gamma")
        self.assertEqual(dossier.verdict, "keep_duplicate")
        self.assertEqual(
            {item.authorization_id for item in dossier.receipts},
            {"AUTH-0003", "AUTH-0099"},
        )
        self.assertEqual(len(dossier.keep_receipts), 2)
        self.assertEqual(dossier.folded_receipts, [])
        self.assertTrue(any("distinct authorizations" in reason for reason in dossier.reasons))

    def test_scope_violation_is_flagged(self):
        """A rule published beyond its approved scope is a violation."""
        report = _run()
        dossier = _dossier(report, "RansomNote_Beta")
        self.assertEqual(dossier.verdict, "violation")
        self.assertTrue(any("scope" in reason for reason in dossier.reasons))

    def test_frozen_drift_is_flagged(self):
        """A rule whose frozen hash drifted is reported and not folded."""
        report = _run()
        dossier = _dossier(report, "BackdoorStr")
        self.assertEqual(dossier.verdict, "violation")
        self.assertTrue(any("drifted" in reason for reason in dossier.reasons))

    def test_report_contains_both_required_verdicts(self):
        """Acceptance needs one foldable and one must-keep case in output."""
        report = _run()
        text = render_text(report)
        self.assertIn("FOLDABLE", text)
        self.assertIn("KEEP_DUPLICATE", text)
        payload = json.loads(render_json(report))
        verdicts = {dossier["verdict"] for dossier in payload["dossiers"]}
        self.assertIn("foldable", verdicts)
        self.assertIn("keep_duplicate", verdicts)
        for dossier in payload["dossiers"]:
            for receipt in dossier["receipts"]:
                self.assertIn("location", receipt)
                path = receipt["location"].split(":", 1)[0]
                self.assertTrue(Path(path).exists())

    def test_summary_counts_are_consistent(self):
        """The summary tallies every dossier exactly once."""
        report = _run()
        summary = report.summary()
        self.assertEqual(sum(summary.values()), len(report.dossiers))
        self.assertGreaterEqual(summary["foldable"], 1)
        self.assertGreaterEqual(summary["keep_duplicate"], 1)
        self.assertGreaterEqual(summary["violation"], 1)


if __name__ == "__main__":
    unittest.main()
