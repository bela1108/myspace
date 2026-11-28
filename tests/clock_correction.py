#!/usr/bin/env python3
"""Tests for clock correction based on segmented evidence."""

import datetime
import decimal
import unittest

from dfdatetime import clock_correction
from dfdatetime import posix_time


class ClockCorrectionEvidenceTest(unittest.TestCase):
    """Tests for the clock correction evidence."""

    def testInitialize(self):
        """Tests the __init__ function."""
        evidence = clock_correction.ClockCorrectionEvidence(
            evidence_id="clock-change-1",
            start_timestamp=1000,
            end_timestamp=2000,
            clock_offset_seconds=30,
            priority=2,
        )

        self.assertEqual(evidence.evidence_id, "clock-change-1")
        self.assertEqual(evidence.start_timestamp, decimal.Decimal(1000))
        self.assertEqual(evidence.end_timestamp, decimal.Decimal(2000))
        self.assertEqual(evidence.clock_offset_seconds, decimal.Decimal(30))
        self.assertEqual(evidence.priority, 2)

        evidence = clock_correction.ClockCorrectionEvidence.FromDict(
            {
                "id": "clock-change-2",
                "start": 2000,
                "end": 3000,
                "offset": -10,
            }
        )

        self.assertEqual(evidence.evidence_id, "clock-change-2")
        self.assertEqual(evidence.clock_offset_seconds, decimal.Decimal(-10))

        with self.assertRaises(ValueError):
            clock_correction.ClockCorrectionEvidence(
                evidence_id="",
                start_timestamp=1000,
                end_timestamp=2000,
                clock_offset_seconds=0,
            )

        with self.assertRaises(ValueError):
            clock_correction.ClockCorrectionEvidence(
                evidence_id="invalid-range",
                start_timestamp=2000,
                end_timestamp=2000,
                clock_offset_seconds=0,
            )

        with self.assertRaises(TypeError):
            clock_correction.ClockCorrectionEvidence(
                evidence_id="unknown-argument",
                start_timestamp=1000,
                end_timestamp=2000,
                clock_offset_seconds=0,
                unknown=True,
            )

    def testAppliesAt(self):
        """Tests the AppliesAt function."""
        evidence = clock_correction.ClockCorrectionEvidence(
            evidence_id="clock-change-1",
            start_timestamp=1000,
            end_timestamp=2000,
            clock_offset_seconds=30,
        )

        self.assertFalse(evidence.AppliesAt(999))
        self.assertTrue(evidence.AppliesAt(1000))
        self.assertTrue(evidence.AppliesAt(1999))
        self.assertFalse(evidence.AppliesAt(2000))

        open_ended_evidence = clock_correction.ClockCorrectionEvidence(
            evidence_id="clock-change-2",
            start_timestamp=2000,
            clock_offset_seconds=30,
        )

        self.assertFalse(open_ended_evidence.AppliesAt(1999))
        self.assertTrue(open_ended_evidence.AppliesAt(2000))
        self.assertTrue(open_ended_evidence.AppliesAt(10**10))

    def testCopyToSerializableDict(self):
        """Tests the CopyToSerializableDict function."""
        evidence = clock_correction.ClockCorrectionEvidence(
            evidence_id="clock-change-1",
            start_timestamp=1000,
            end_timestamp=2000,
            clock_offset_seconds=30,
        )

        expected_dict = {
            "__class_name__": "ClockCorrectionEvidence",
            "__type__": "ClockCorrectionEvidence",
            "clock_offset_seconds": 30,
            "end_timestamp": 2000,
            "evidence_id": "clock-change-1",
            "priority": 0,
            "start_timestamp": 1000,
        }
        self.assertEqual(evidence.CopyToSerializableDict(), expected_dict)


class ClockCorrectionTest(unittest.TestCase):
    """Tests for the clock correction."""

    def testCorrectTimestamp(self):
        """Tests the CorrectTimestamp function."""
        correction = clock_correction.ClockCorrection(
            {
                "evidence_id": "clock-change-1",
                "start_timestamp": 1000,
                "end_timestamp": 2000,
                "clock_offset_seconds": 30,
            }
        )

        result = correction.CorrectTimestamp(1000)
        self.assertTrue(result.is_corrected)
        self.assertFalse(result.requires_manual_review)
        self.assertEqual(result.original_timestamp, decimal.Decimal(1000))
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(970))
        self.assertEqual(result.clock_offset_seconds, decimal.Decimal(30))
        self.assertEqual(result.evidence_id, "clock-change-1")
        self.assertEqual(result.status, clock_correction.STATUS_CORRECTED)
        self.assertIsNone(result.reason)

        result = correction.correct(1999)
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(1969))

        result = correction.CorrectTimestamp(999)
        self.assertTrue(result.requires_manual_review)
        self.assertIsNone(result.corrected_timestamp)
        self.assertIsNone(result.evidence_id)
        self.assertEqual(result.reason, clock_correction.REASON_EVIDENCE_MISSING)

        result = correction.CorrectTimestamp(2000)
        self.assertTrue(result.requires_manual_review)
        self.assertEqual(result.reason, clock_correction.REASON_EVIDENCE_MISSING)

    def testCorrectTimestampWithDateTimeValues(self):
        """Tests the CorrectTimestamp function with date time values."""
        correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-1",
                    start_timestamp=0,
                    clock_offset_seconds=60,
                )
            ]
        )

        result = correction.CorrectTimestamp(posix_time.PosixTime(timestamp=1000))
        self.assertEqual(result.original_timestamp, decimal.Decimal(1000))
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(940))

        date_time_value = datetime.datetime(
            1970, 1, 1, 0, 16, 40, tzinfo=datetime.timezone.utc
        )
        result = correction.CorrectTimestamp(date_time_value)
        self.assertEqual(result.original_timestamp, decimal.Decimal(1000))
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(940))

    def testCorrectTimestampWithOverlappingEvidence(self):
        """Tests the CorrectTimestamp function with overlapping evidence."""
        correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="lower-priority",
                    start_timestamp=1000,
                    end_timestamp=2000,
                    clock_offset_seconds=30,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="higher-priority",
                    start_timestamp=1500,
                    end_timestamp=2500,
                    clock_offset_seconds=60,
                    priority=1,
                ),
            ]
        )

        result = correction.CorrectTimestamp(1600)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(1540))
        self.assertEqual(result.evidence_id, "higher-priority")

        result = correction.CorrectTimestamp(1500)
        self.assertTrue(result.requires_manual_review)
        self.assertEqual(result.reason, clock_correction.REASON_SEGMENT_BOUNDARY)

        result = correction.CorrectTimestamp(1530)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.evidence_id, "higher-priority")

        conflicting_correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="evidence-a",
                    start_timestamp=1000,
                    end_timestamp=2000,
                    clock_offset_seconds=30,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="evidence-b",
                    start_timestamp=1500,
                    end_timestamp=2500,
                    clock_offset_seconds=60,
                ),
            ]
        )

        result = conflicting_correction.CorrectTimestamp(1600)
        self.assertTrue(result.requires_manual_review)
        self.assertIsNone(result.corrected_timestamp)
        self.assertEqual(result.reason, clock_correction.REASON_EVIDENCE_OVERLAP)
        self.assertEqual(result.candidate_evidence_ids, ["evidence-a", "evidence-b"])

        same_offset_correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="evidence-a",
                    start_timestamp=1000,
                    end_timestamp=2000,
                    clock_offset_seconds=30,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="evidence-b",
                    start_timestamp=1500,
                    end_timestamp=2500,
                    clock_offset_seconds=30,
                ),
            ]
        )

        result = same_offset_correction.CorrectTimestamp(1600)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(1570))
        self.assertEqual(result.evidence_id, "evidence-a")

        open_ended_correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="open-ended",
                    start_timestamp=1000,
                    clock_offset_seconds=30,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="replacement",
                    start_timestamp=2000,
                    end_timestamp=3000,
                    clock_offset_seconds=60,
                    priority=1,
                ),
            ]
        )

        result = open_ended_correction.CorrectTimestamp(2000)
        self.assertTrue(result.requires_manual_review)
        self.assertEqual(result.reason, clock_correction.REASON_SEGMENT_BOUNDARY)

        result = open_ended_correction.CorrectTimestamp(3000)
        self.assertTrue(result.requires_manual_review)
        self.assertEqual(result.reason, clock_correction.REASON_SEGMENT_BOUNDARY)

        result = open_ended_correction.CorrectTimestamp(3030)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.evidence_id, "open-ended")

    def testCorrectTimestampWithSegmentBoundary(self):
        """Tests the CorrectTimestamp function around a segment boundary."""
        correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-1",
                    start_timestamp=1000,
                    end_timestamp=1060,
                    clock_offset_seconds=10,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-2",
                    start_timestamp=1060,
                    end_timestamp=1120,
                    clock_offset_seconds=20,
                ),
            ]
        )

        result = correction.CorrectTimestamp(1029)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.evidence_id, "clock-change-1")

        for timestamp in (1030, 1059, 1060, 1089):
            result = correction.CorrectTimestamp(timestamp)
            self.assertTrue(result.requires_manual_review)
            self.assertIsNone(result.corrected_timestamp)
            self.assertIsNone(result.evidence_id)
            self.assertEqual(result.reason, clock_correction.REASON_SEGMENT_BOUNDARY)
            self.assertEqual(
                result.candidate_evidence_ids,
                ["clock-change-1", "clock-change-2"],
            )

        result = correction.CorrectTimestamp(1090)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(1070))
        self.assertEqual(result.evidence_id, "clock-change-2")

        correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-1",
                    start_timestamp=1000,
                    end_timestamp=1060,
                    clock_offset_seconds=10,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-2",
                    start_timestamp=1090,
                    end_timestamp=1120,
                    clock_offset_seconds=20,
                ),
            ]
        )

        result = correction.CorrectTimestamp(1045)
        self.assertTrue(result.requires_manual_review)
        result = correction.CorrectTimestamp(1105)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.evidence_id, "clock-change-2")

        correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-1",
                    start_timestamp=1000,
                    end_timestamp=1060,
                    clock_offset_seconds=10,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-2",
                    start_timestamp=1200,
                    end_timestamp=1300,
                    clock_offset_seconds=20,
                ),
            ]
        )

        result = correction.CorrectTimestamp(1100)
        self.assertEqual(result.reason, clock_correction.REASON_EVIDENCE_MISSING)

    def testCorrectTimestampWithDisabledAmbiguityWindow(self):
        """Tests the CorrectTimestamp function without an ambiguity window."""
        correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-1",
                    start_timestamp=1000,
                    end_timestamp=1060,
                    clock_offset_seconds=10,
                ),
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-2",
                    start_timestamp=1060,
                    end_timestamp=1120,
                    clock_offset_seconds=20,
                ),
            ],
            ambiguity_window_seconds=0,
        )

        result = correction.CorrectTimestamp(1060)
        self.assertTrue(result.is_corrected)
        self.assertEqual(result.evidence_id, "clock-change-2")
        self.assertEqual(result.corrected_timestamp, decimal.Decimal(1040))

    def testCopyToSerializableDict(self):
        """Tests the CopyToSerializableDict function."""
        correction = clock_correction.ClockCorrection(
            [
                clock_correction.ClockCorrectionEvidence(
                    evidence_id="clock-change-1",
                    start_timestamp=1000,
                    end_timestamp=2000,
                    clock_offset_seconds=30,
                )
            ]
        )

        result = correction.CorrectTimestamp(1234)
        expected_dict = {
            "__class_name__": "ClockCorrectionResult",
            "__type__": "ClockCorrectionResult",
            "clock_offset_seconds": 30,
            "corrected_timestamp": 1204,
            "evidence_id": "clock-change-1",
            "original_timestamp": 1234,
            "requires_manual_review": False,
            "status": "corrected",
        }
        self.assertEqual(result.CopyToSerializableDict(), expected_dict)

        result = correction.CorrectTimestamp(999)
        expected_dict = {
            "__class_name__": "ClockCorrectionResult",
            "__type__": "ClockCorrectionResult",
            "original_timestamp": 999,
            "reason": "missing-evidence",
            "requires_manual_review": True,
            "status": "manual-review",
        }
        self.assertEqual(result.CopyToSerializableDict(), expected_dict)


if __name__ == "__main__":
    unittest.main()
