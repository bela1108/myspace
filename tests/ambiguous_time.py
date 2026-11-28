#!/usr/bin/env python3
"""Tests for the ambiguous local time implementation."""

import unittest

from dfdatetime import ambiguous_time
from dfdatetime import serializer
from dfdatetime import time_elements


class AmbiguousTimeTest(unittest.TestCase):
    """Tests for the ambiguous local time."""

    # pylint: disable=protected-access

    def _CreateCandidates(self):
        """Creates candidate interpretations of a repeated local hour."""
        first_candidate = time_elements.TimeElements(
            time_elements_tuple=(2021, 11, 7, 1, 30, 0), time_zone_offset=-240
        )
        second_candidate = time_elements.TimeElements(
            time_elements_tuple=(2021, 11, 7, 1, 30, 0), time_zone_offset=-300
        )
        return first_candidate, second_candidate

    def testRoundTripCandidates(self):
        """Tests that two offset-bearing candidates round-trip."""
        first_candidate, second_candidate = self._CreateCandidates()
        date_time_object = ambiguous_time.AmbiguousTime(
            candidates=[first_candidate, second_candidate],
            time_zone_hint="America/New_York",
        )

        expected_timestamps = [
            first_candidate._GetNormalizedTimestamp(),
            second_candidate._GetNormalizedTimestamp(),
        ]
        self.assertNotEqual(expected_timestamps[0], expected_timestamps[1])
        self.assertTrue(date_time_object.is_ambiguous)

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(date_time_object)
        self.assertTrue(json_dict["had_ambiguity"])
        self.assertEqual(len(json_dict["candidates"]), 2)

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(len(date_time_object.candidates), 2)
        self.assertEqual(date_time_object.candidates[0].time_zone_offset, -240)
        self.assertEqual(date_time_object.candidates[1].time_zone_offset, -300)
        self.assertTrue(date_time_object.had_ambiguity)
        self.assertTrue(date_time_object.is_ambiguous)

    def testExcludeCandidate(self):
        """Tests that evidence can exclude a candidate without losing history."""
        first_candidate, second_candidate = self._CreateCandidates()
        date_time_object = ambiguous_time.AmbiguousTime(
            candidates=[first_candidate, second_candidate]
        )

        evidence = "independent testimony: the visit was after the rollback"
        date_time_object.ExcludeTimeZoneCandidate(0, evidence)
        self.assertEqual(len(date_time_object.GetRemainingTimeZoneCandidates()), 1)
        self.assertFalse(date_time_object.is_ambiguous)
        self.assertTrue(date_time_object.had_ambiguity)

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(date_time_object)
        self.assertTrue(json_dict["had_ambiguity"])
        self.assertTrue(json_dict["candidates"][0]["is_excluded"])
        self.assertEqual(json_dict["exclusion_conditions"], [evidence])

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertEqual(len(date_time_object.GetRemainingTimeZoneCandidates()), 1)
        self.assertTrue(date_time_object.had_ambiguity)
        self.assertIsNotNone(date_time_object.ambiguity_note)
        self.assertEqual(
            date_time_object.GetSelectedTimeZoneCandidate().time_zone_offset, -300
        )

    def testLocalTimeZoneRules(self):
        """Tests that caller supplied local rules create both candidates."""
        date_time_object = time_elements.TimeElements(
            time_elements_tuple=(2021, 11, 7, 1, 30, 0)
        )
        date_time_object.is_local_time = True
        date_time_object.time_zone_hint = "America/New_York"

        json_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
            date_time_object,
            time_zone_rules={"America/New_York": [-240, -300]},
        )
        self.assertEqual(len(json_dict["candidates"]), 2)
        self.assertTrue(json_dict["had_ambiguity"])

    def testLegacySingleTimeRecord(self):
        """Tests that an old single-time record is still read."""
        json_dict = {
            "__class_name__": "TimeElements",
            "__type__": "DateTimeValues",
            "is_local_time": True,
            "time_elements_tuple": (2021, 11, 7, 1, 30, 0),
            "time_zone_offset": -300,
            "time_zone_hint": "America/New_York",
        }

        date_time_object = serializer.Serializer.ConvertJSONToDateTimeValues(json_dict)
        self.assertIsNone(date_time_object.time_zone_candidates)
        self.assertFalse(date_time_object.had_ambiguity)
        self.assertEqual(date_time_object.time_zone_offset, -300)


if __name__ == "__main__":
    unittest.main()
