# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for offline rework verification in `in_toto.reworklib`."""

import unittest
from datetime import datetime, timedelta, timezone

from in_toto.exceptions import InvalidMetadata
from in_toto.models.link import Link
from in_toto.reworklib import (
    ArtifactChange,
    ArtifactReport,
    InspectionRecord,
    InspectionStatus,
    ReplacementType,
    ReworkVerificationReport,
    classify_artifacts,
    verify_rework,
)

SHA256 = "sha256"


def hashes(digest):
    return {SHA256: digest}


class ClassifyArtifactsTest(unittest.TestCase):
    """Tests for material-identity based artifact classification."""

    def test_classifies_all_changes(self):
        original = {
            "unchanged": hashes("a"),
            "replaced": hashes("b"),
            "removed": hashes("c"),
        }
        reworked = {
            "unchanged": hashes("a"),
            "replaced": hashes("b2"),
            "added": hashes("d"),
        }

        changes = classify_artifacts(original, reworked)

        self.assertEqual(
            changes,
            {
                "unchanged": ArtifactChange.UNCHANGED,
                "replaced": ArtifactChange.REPLACED,
                "removed": ArtifactChange.REMOVED,
                "added": ArtifactChange.ADDED,
            },
        )

    def test_different_hash_algorithms_still_match_on_overlap(self):
        original = {"f": {"sha256": "x", "sha512": "y"}}
        reworked = {"f": {"sha256": "x"}}
        self.assertEqual(
            classify_artifacts(original, reworked),
            {"f": ArtifactChange.UNCHANGED},
        )

    def test_accepts_link_products(self):
        original = Link(name="before", products={"f": hashes("a")})
        reworked = Link(name="after", products={"f": hashes("b")})
        self.assertEqual(
            classify_artifacts(original, reworked),
            {"f": ArtifactChange.REPLACED},
        )

    def test_rejects_non_mapping(self):
        with self.assertRaises(InvalidMetadata):
            classify_artifacts({"f": hashes("a")}, ["f"])


class VerifyReworkTest(unittest.TestCase):
    """End-to-end tests for the three decision factors."""

    def setUp(self):
        self.tz = timezone.utc
        self.original = {
            "bolt": hashes("bolt-1"),
            "panel": hashes("panel-1"),
            "gasket": hashes("gasket-1"),
        }
        # Rework swaps the gasket (the inspected artifact) but leaves bolt and
        # panel untouched, and adds a previously absent label.
        self.reworked = {
            "bolt": hashes("bolt-1"),
            "panel": hashes("panel-1"),
            "gasket": hashes("gasket-2"),
            "label": hashes("label-1"),
        }
        self.rework_completed_at = datetime(2026, 11, 28, 12, 0, tzinfo=self.tz)
        self.before_rework = datetime(2026, 11, 28, 8, 0, tzinfo=self.tz)
        self.after_rework = datetime(2026, 11, 28, 14, 0, tzinfo=self.tz)

    def test_unchanged_artifacts_are_reusable(self):
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [],
        )

        self.assertIn("bolt", report.carried_over_artifacts)
        self.assertIn("panel", report.carried_over_artifacts)
        self.assertNotIn("gasket", report.carried_over_artifacts)
        self.assertEqual(report.replaced_artifacts, {"gasket"})

    def test_unrelated_material_keeps_inspection_when_authorized(self):
        # Inspection only covers bolt and panel, both unchanged. Replacing the
        # unrelated gasket must not invalidate this inspection.
        inspection = InspectionRecord(
            name="frame-check",
            artifacts=frozenset({"bolt", "panel"}),
            performed_at=self.before_rework,
            authorized_replacements=frozenset({ReplacementType.UNRELATED}),
        )
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )

        verdict = report.inspection_verdicts["frame-check"]
        self.assertEqual(verdict.status, InspectionStatus.CARRIED_OVER)
        self.assertEqual(verdict.affected_artifacts, frozenset())
        self.assertEqual(report.reopened_inspections, set())
        self.assertEqual(report.new_inspection_items, set())

    def test_replacing_inspected_artifact_always_reopens(self):
        # Even with every replacement type authorized, replacing the exact
        # inspected gasket forces a fresh inspection item.
        inspection = InspectionRecord(
            name="gasket-check",
            artifacts=frozenset({"gasket"}),
            performed_at=self.before_rework,
            authorized_replacements=frozenset(
                {
                    ReplacementType.UNRELATED,
                    ReplacementType.INSPECTED,
                }
            ),
        )
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )

        verdict = report.inspection_verdicts["gasket-check"]
        self.assertEqual(verdict.status, InspectionStatus.REOPENED)
        self.assertEqual(verdict.affected_artifacts, frozenset({"gasket"}))
        self.assertEqual(report.reopened_inspections, {"gasket-check"})
        self.assertEqual(report.new_inspection_items, {"gasket"})

    def test_partial_continuation_within_one_inspection(self):
        # A single inspection covers an unchanged bolt and a replaced gasket.
        # Bolt testimony continues while gasket responsibility reactivates.
        inspection = InspectionRecord(
            name="combined-check",
            artifacts=frozenset({"bolt", "gasket"}),
            performed_at=self.before_rework,
            authorized_replacements=frozenset({ReplacementType.UNRELATED}),
        )
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )

        verdict = report.inspection_verdicts["combined-check"]
        self.assertEqual(verdict.status, InspectionStatus.REOPENED)
        self.assertEqual(verdict.affected_artifacts, frozenset({"gasket"}))
        self.assertIn("bolt", report.carried_over_artifacts)

    def test_unrelated_change_without_authorization_reopens(self):
        # The added label is an unrelated, previously unseen material: without
        # explicit carry-over authorization coverage cannot be assumed.
        inspection = InspectionRecord(
            name="label-check",
            artifacts=frozenset({"label"}),
            performed_at=self.before_rework,
        )
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )

        verdict = report.inspection_verdicts["label-check"]
        self.assertEqual(verdict.status, InspectionStatus.REOPENED)
        self.assertIn("label", report.new_inspection_items)

    def test_inspection_after_rework_is_current(self):
        inspection = InspectionRecord(
            name="post-check",
            artifacts=frozenset({"gasket"}),
            performed_at=self.after_rework,
        )
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )

        verdict = report.inspection_verdicts["post-check"]
        self.assertEqual(verdict.status, InspectionStatus.CURRENT)
        self.assertEqual(report.reopened_inspections, set())

    def test_inspection_exactly_at_rework_completion_is_current(self):
        inspection = InspectionRecord(
            name="edge-check",
            artifacts=frozenset({"gasket"}),
            performed_at=self.rework_completed_at,
        )
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )
        self.assertEqual(
            report.inspection_verdicts["edge-check"].status,
            InspectionStatus.CURRENT,
        )

    def test_accepts_dict_inspection_records(self):
        inspection = {
            "name": "dict-check",
            "artifacts": ["bolt", "panel"],
            "performed_at": self.before_rework,
            "authorized": [ReplacementType.UNRELATED.value],
        }
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )
        self.assertEqual(
            report.inspection_verdicts["dict-check"].status,
            InspectionStatus.CARRIED_OVER,
        )

    def test_naive_timestamp_rejected(self):
        naive = datetime(2026, 11, 28, 12, 0)
        with self.assertRaises(InvalidMetadata):
            verify_rework(self.original, self.reworked, naive, [])

    def test_timezone_offset_comparison(self):
        # 16:00 in a +4 timezone equals 12:00 UTC (rework completion).
        plus_four = timezone(timedelta(hours=4))
        inspection = InspectionRecord(
            name="tz-check",
            artifacts=frozenset({"gasket"}),
            performed_at=datetime(2026, 11, 28, 16, 0, tzinfo=plus_four),
        )
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [inspection],
        )
        self.assertEqual(
            report.inspection_verdicts["tz-check"].status,
            InspectionStatus.CURRENT,
        )

    def test_invalid_inspection_input_rejected(self):
        with self.assertRaises(InvalidMetadata):
            verify_rework(
                self.original,
                self.reworked,
                self.rework_completed_at,
                ["not-a-record"],
            )

    def test_missing_dict_field_rejected(self):
        with self.assertRaises(InvalidMetadata):
            InspectionRecord.from_dict({"name": "x"})

    def test_unknown_replacement_type_rejected(self):
        with self.assertRaises(InvalidMetadata):
            InspectionRecord.from_dict(
                {
                    "name": "x",
                    "artifacts": ["f"],
                    "performed_at": self.before_rework,
                    "authorized": ["mystery"],
                }
            )

    def test_report_collections_are_consistent(self):
        report = verify_rework(
            self.original,
            self.reworked,
            self.rework_completed_at,
            [],
        )
        self.assertIsInstance(report, ReworkVerificationReport)
        gasket_report = report.artifact_reports["gasket"]
        self.assertIsInstance(gasket_report, ArtifactReport)
        self.assertEqual(
            gasket_report.replacement_type, ReplacementType.INSPECTED
        )
        # Reusable artifacts and replaced artifacts are disjoint.
        self.assertFalse(
            report.carried_over_artifacts & report.replaced_artifacts
        )


if __name__ == "__main__":
    unittest.main()
