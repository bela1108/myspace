#!/usr/bin/env python3
"""Tests for the independent time testimony implementation."""

import decimal
import unittest

from dfdatetime import definitions
from dfdatetime import fat_date_time
from dfdatetime import posix_time
from dfdatetime import time_testimony


class TimeTestimonyTest(unittest.TestCase):
    """Tests for independent time testimonies."""

    def testCreateFromDateTimeValues(self):
        """Tests the CreateTimeTestimony function using date time values."""
        base_timestamp = decimal.Decimal("1000000000")

        minute_time = posix_time.PosixTime(
            precision=definitions.PRECISION_1_MINUTE,
            timestamp=1000000000,
        )
        millisecond_time = posix_time.PosixTimeInMilliseconds(
            timestamp=1000000000250
        )
        fat_time = fat_date_time.FATDateTime()
        fat_time.CopyFromDateTimeString("2001-09-09 01:46:40")

        minute_testimony = time_testimony.CreateTimeTestimony(
            "log",
            date_time_values=minute_time,
            source="event-log",
            confidence=0.5,
        )
        millisecond_testimony = time_testimony.CreateTimeTestimony(
            "disk",
            date_time_values=millisecond_time,
            source="ntfs-mft",
            confidence=0.9,
        )
        fat_testimony = time_testimony.CreateTimeTestimony(
            "handoff",
            date_time_values=fat_time,
            source="fat-entry",
            confidence=0.75,
        )

        self.assertEqual(
            (minute_testimony.start_time, minute_testimony.end_time),
            (base_timestamp, base_timestamp + 60),
        )
        self.assertEqual(
            (millisecond_testimony.start_time, millisecond_testimony.end_time),
            (
                base_timestamp + decimal.Decimal("0.250"),
                base_timestamp + decimal.Decimal("0.251"),
            ),
        )
        self.assertEqual(
            (fat_testimony.start_time, fat_testimony.end_time),
            (base_timestamp, base_timestamp + 2),
        )
        self.assertEqual(minute_testimony.confidence, 0.5)
        self.assertEqual(millisecond_testimony.source, "ntfs-mft")
        with self.assertRaises(AttributeError):
            minute_testimony.confidence = 0.9

        synthesis = time_testimony.SynthesizeTimeTestimonies(
            [minute_testimony, millisecond_testimony, fat_testimony]
        )

        self.assertFalse(synthesis.has_conflicts)
        self.assertEqual(synthesis.conflicts, ())
        self.assertEqual(
            (synthesis.start_time, synthesis.end_time),
            (
                base_timestamp + decimal.Decimal("0.250"),
                base_timestamp + decimal.Decimal("0.251"),
            ),
        )

    def testSynthesizeMinimalConflict(self):
        """Tests synthesis reports the minimal supported conflicting pair."""
        base_timestamp = decimal.Decimal("1000000000")

        minute_time = posix_time.PosixTime(
            precision=definitions.PRECISION_1_MINUTE,
            timestamp=1000000000,
        )
        millisecond_time = posix_time.PosixTimeInMilliseconds(
            timestamp=1000000000250
        )
        later_fat_time = fat_date_time.FATDateTime()
        later_fat_time.CopyFromDateTimeString("2001-09-09 01:46:50")

        testimonies = [
            time_testimony.CreateTimeTestimony(
                "log",
                date_time_values=minute_time,
                confidence=1.0,
            ),
            time_testimony.CreateTimeTestimony(
                "disk",
                date_time_values=millisecond_time,
                confidence=0.8,
            ),
            time_testimony.CreateTimeTestimony(
                "handoff",
                date_time_values=later_fat_time,
                confidence=0.6,
            ),
        ]

        synthesis = time_testimony.SynthesizeTimeTestimonies(testimonies)

        self.assertTrue(synthesis.has_conflicts)
        self.assertIsNone(synthesis.start_time)
        self.assertIsNone(synthesis.end_time)
        self.assertEqual(len(synthesis.conflicts), 1)

        conflict = synthesis.conflicts[0]
        self.assertEqual(conflict.identifiers, ("disk", "handoff"))
        self.assertEqual(conflict.confidence, (0.8, 0.6))
        self.assertEqual(
            (conflict.start_time, conflict.end_time),
            (
                base_timestamp + decimal.Decimal("0.251"),
                base_timestamp + 10,
            ),
        )

    def testCreateWithExplicitInterval(self):
        """Tests creation from an explicit precision interval."""
        testimony = time_testimony.CreateTimeTestimony(
            "analyst-note",
            precision=definitions.PRECISION_1_SECOND,
            start_time=decimal.Decimal("10.25"),
            end_time=decimal.Decimal("11.75"),
            source="analyst",
            confidence={"score": 0.4, "basis": "interview"},
        )

        self.assertEqual(
            (testimony.start_time, testimony.end_time),
            (decimal.Decimal("10.25"), decimal.Decimal("11.75")),
        )
        self.assertEqual(testimony.precision, definitions.PRECISION_1_SECOND)
        self.assertEqual(testimony.confidence["score"], 0.4)

        mismatch_testimony = time_testimony.CreateTimeTestimony(
            "explicit-interval",
            precision=definitions.PRECISION_1_MINUTE,
            start_time=0,
            end_time=90,
        )
        self.assertEqual(
            (mismatch_testimony.start_time, mismatch_testimony.end_time),
            (decimal.Decimal(0), decimal.Decimal(90)),
        )

    def testCreateDerivesIntervalBoundary(self):
        """Tests precision determines a missing interval boundary."""
        from_start = time_testimony.CreateTimeTestimony(
            "from-start",
            precision=definitions.PRECISION_1_MINUTE,
            start_time=60,
        )
        from_end = time_testimony.CreateTimeTestimony(
            "from-end",
            precision=definitions.PRECISION_1_MINUTE,
            end_time=120,
        )

        self.assertEqual(
            (from_start.start_time, from_start.end_time),
            (decimal.Decimal(60), decimal.Decimal(120)),
        )
        self.assertEqual(
            (from_end.start_time, from_end.end_time),
            (decimal.Decimal(60), decimal.Decimal(120)),
        )

    def testInvalidArguments(self):
        """Tests invalid time testimony arguments."""
        with self.assertRaises(ValueError):
            time_testimony.CreateTimeTestimony(
                "",
                precision=definitions.PRECISION_1_SECOND,
                start_time=0,
                end_time=1,
            )

        with self.assertRaises(ValueError):
            time_testimony.CreateTimeTestimony(
                "empty",
                precision=definitions.PRECISION_1_SECOND,
                start_time=1,
                end_time=1,
            )

        with self.assertRaises(ValueError):
            time_testimony.CreateTimeTestimony(
                "unsupported",
                precision="1-year",
                start_time=0,
                end_time=1,
            )

        with self.assertRaises(ValueError):
            time_testimony.CreateTimeTestimony("missing")

        with self.assertRaises(ValueError):
            time_testimony.SynthesizeTimeTestimonies([])

        testimony = time_testimony.CreateTimeTestimony(
            "first",
            precision=definitions.PRECISION_1_SECOND,
            start_time=0,
            end_time=1,
        )
        duplicate = time_testimony.CreateTimeTestimony(
            "first",
            precision=definitions.PRECISION_1_SECOND,
            start_time=2,
            end_time=3,
        )

        with self.assertRaises(ValueError):
            time_testimony.SynthesizeTimeTestimonies([testimony, duplicate])

        with self.assertRaises(ValueError):
            time_testimony.SynthesizeTimeTestimonies(["not-a-testimony"])


if __name__ == "__main__":
    unittest.main()
