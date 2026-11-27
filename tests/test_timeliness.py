# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_timeliness.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Nov 28, 2026

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test timeliness evaluation of trusted time ranges in signed link
  metadata.

"""

import unittest
from datetime import datetime, timedelta, timezone

import securesystemslib.exceptions

import in_toto.timeliness
from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.timeliness import (
    LATE,
    ON_TIME,
    TIMELINESS_REPORT_ENV_KEY,
    TRUSTED_TIME_RANGE_ENV_KEY,
    UNDECIDABLE,
    TimelinessReport,
    TrustedTimeRange,
    envelope,
    evaluate_timeliness,
    extract_trusted_time_range,
)
from in_toto.verifylib import in_toto_verify, verify_step_timeliness
from tests.common import SignerStore, TmpDirMixin

DEADLINE = datetime(2026, 11, 28, 18, 0, 0, tzinfo=timezone.utc)


def _range(hours_ago_start, hours_ago_end, reference=DEADLINE):
    """Create a trusted time range relative to a reference time."""
    return TrustedTimeRange(
        reference - timedelta(hours=hours_ago_start),
        reference - timedelta(hours=hours_ago_end),
    )


class TestTrustedTimeRange(unittest.TestCase):
    """Test TrustedTimeRange construction, validation and serialization."""

    def test_create_from_datetimes(self):
        time_range = _range(3, 1)
        self.assertEqual(time_range.earliest, DEADLINE - timedelta(hours=3))
        self.assertEqual(time_range.latest, DEADLINE - timedelta(hours=1))

    def test_create_from_iso8601_strings(self):
        time_range = TrustedTimeRange(
            "2026-11-28T13:00:00Z", "2026-11-28T15:00:00Z"
        )
        self.assertEqual(time_range.earliest.hour, 13)
        self.assertEqual(time_range.latest.hour, 15)

    def test_point_range_is_valid(self):
        TrustedTimeRange(DEADLINE, DEADLINE)

    def test_reject_inverted_range(self):
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            TrustedTimeRange("2026-11-28T15:00:00Z", "2026-11-28T13:00:00Z")

    def test_reject_naive_datetime(self):
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            TrustedTimeRange(datetime(2026, 11, 28, 13), DEADLINE)  # noqa: DTZ001

    def test_reject_malformed_string(self):
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            TrustedTimeRange("not-a-datetime", DEADLINE)

    def test_from_dict_roundtrip(self):
        time_range = _range(3, 1)
        self.assertEqual(
            TrustedTimeRange.from_dict(time_range.to_dict()).to_dict(),
            time_range.to_dict(),
        )

    def test_from_dict_rejects_missing_field(self):
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            TrustedTimeRange.from_dict({"earliest": "2026-11-28T13:00:00Z"})

    def test_from_dict_rejects_non_dict(self):
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            TrustedTimeRange.from_dict("2026-11-28T13:00:00Z")


class TestEvaluateTimeliness(unittest.TestCase):
    """Test interval-based timeliness verdicts against a deadline."""

    def test_on_time(self):
        """Range entirely before the deadline is on-time."""
        report = evaluate_timeliness(_range(3, 1), DEADLINE)
        self.assertEqual(report.verdict, ON_TIME)

    def test_on_time_at_deadline_boundary(self):
        """Range whose latest bound equals the deadline is on-time."""
        report = evaluate_timeliness(_range(3, 0), DEADLINE)
        self.assertEqual(report.verdict, ON_TIME)

    def test_point_range_at_deadline_is_on_time(self):
        report = evaluate_timeliness(
            TrustedTimeRange(DEADLINE, DEADLINE), DEADLINE
        )
        self.assertEqual(report.verdict, ON_TIME)

    def test_late(self):
        """Range entirely after the deadline is late."""
        report = evaluate_timeliness(_range(-1, -2), DEADLINE)
        self.assertEqual(report.verdict, LATE)

    def test_undecidable_crossing_deadline(self):
        """Range crossing the deadline is undecidable."""
        report = evaluate_timeliness(_range(2, -2), DEADLINE)
        self.assertEqual(report.verdict, UNDECIDABLE)

    def test_undecidable_earliest_at_deadline(self):
        """Range starting exactly at the deadline but ending after it is
        undecidable."""
        report = evaluate_timeliness(_range(0, -2), DEADLINE)
        self.assertEqual(report.verdict, UNDECIDABLE)

    def test_midpoint_before_deadline_is_not_on_time(self):
        """A midpoint comparison would wrongly pass this range as on-time:
        the midpoint is before the deadline, but the latest bound is after
        it, so the verdict must be undecidable."""
        time_range = TrustedTimeRange(
            DEADLINE - timedelta(hours=10),
            DEADLINE + timedelta(hours=2),
        )
        midpoint = (
            time_range.earliest + (time_range.latest - time_range.earliest) / 2
        )
        self.assertLess(midpoint, DEADLINE)
        report = evaluate_timeliness(time_range, DEADLINE)
        self.assertEqual(report.verdict, UNDECIDABLE)

    def test_midpoint_after_deadline_is_not_late(self):
        """A midpoint comparison would wrongly flag this range as late:
        the midpoint is after the deadline, but the earliest bound is
        before it, so the verdict must be undecidable."""
        time_range = TrustedTimeRange(
            DEADLINE - timedelta(hours=2),
            DEADLINE + timedelta(hours=10),
        )
        midpoint = (
            time_range.earliest + (time_range.latest - time_range.earliest) / 2
        )
        self.assertGreater(midpoint, DEADLINE)
        report = evaluate_timeliness(time_range, DEADLINE)
        self.assertEqual(report.verdict, UNDECIDABLE)

    def test_deadline_as_iso8601_string(self):
        report = evaluate_timeliness(_range(3, 1), "2026-11-28T18:00:00Z")
        self.assertEqual(report.verdict, ON_TIME)

    def test_report_serialization(self):
        report = evaluate_timeliness(_range(3, 1), DEADLINE)
        report_dict = report.to_dict()
        self.assertEqual(report_dict["verdict"], ON_TIME)
        self.assertEqual(report_dict["deadline"], DEADLINE.isoformat())
        self.assertEqual(
            report_dict["trusted_time_range"],
            report.time_range.to_dict(),
        )

    def test_report_rejects_bad_verdict(self):
        with self.assertRaises(ValueError):
            TimelinessReport("maybe", DEADLINE, None, "reason")


class TestExtractTrustedTimeRange(unittest.TestCase):
    """Test extraction of trusted time ranges from signed link material."""

    def test_extract_from_link_environment(self):
        link = Link(
            environment={
                TRUSTED_TIME_RANGE_ENV_KEY: {
                    "earliest": "2026-11-28T13:00:00Z",
                    "latest": "2026-11-28T15:00:00Z",
                }
            }
        )
        time_range = extract_trusted_time_range(link)
        self.assertEqual(time_range.earliest.hour, 13)
        self.assertEqual(time_range.latest.hour, 15)

    def test_extract_missing_returns_none(self):
        self.assertIsNone(extract_trusted_time_range(Link()))

    def test_extract_malformed_raises(self):
        link = Link(environment={TRUSTED_TIME_RANGE_ENV_KEY: {"earliest": "x"}})
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            extract_trusted_time_range(link)


class TestEnvelope(unittest.TestCase):
    """Test merging of trusted time ranges."""

    def test_envelope_spans_all_ranges(self):
        merged = envelope([_range(4, 2), _range(3, 1)])
        self.assertEqual(merged.earliest, DEADLINE - timedelta(hours=4))
        self.assertEqual(merged.latest, DEADLINE - timedelta(hours=1))

    def test_envelope_rejects_empty(self):
        with self.assertRaises(ValueError):
            envelope([])


def _metablock_with_range(step_name, time_range_dict=None):
    """Create a Metablock wrapping a Link with an optional trusted range."""
    environment = {}
    if time_range_dict is not None:
        environment[TRUSTED_TIME_RANGE_ENV_KEY] = time_range_dict
    return Metablock(signed=Link(name=step_name, environment=environment))


class TestVerifyStepTimeliness(unittest.TestCase):
    """Test per-step timeliness evaluation over verified link metadata."""

    def _evaluate(self, steps_metadata):
        return verify_step_timeliness(steps_metadata, DEADLINE)

    def test_on_time_step(self):
        steps_metadata = {
            "release": {
                "keyid": _metablock_with_range(
                    "release",
                    {
                        "earliest": "2026-11-28T13:00:00Z",
                        "latest": "2026-11-28T15:00:00Z",
                    },
                )
            }
        }
        reports = self._evaluate(steps_metadata)
        self.assertEqual(reports["release"].verdict, ON_TIME)

    def test_late_step(self):
        steps_metadata = {
            "release": {
                "keyid": _metablock_with_range(
                    "release",
                    {
                        "earliest": "2026-11-28T19:00:00Z",
                        "latest": "2026-11-28T20:00:00Z",
                    },
                )
            }
        }
        reports = self._evaluate(steps_metadata)
        self.assertEqual(reports["release"].verdict, LATE)

    def test_undecidable_step_range_crosses_deadline(self):
        steps_metadata = {
            "release": {
                "keyid": _metablock_with_range(
                    "release",
                    {
                        "earliest": "2026-11-28T16:00:00Z",
                        "latest": "2026-11-28T20:00:00Z",
                    },
                )
            }
        }
        reports = self._evaluate(steps_metadata)
        self.assertEqual(reports["release"].verdict, UNDECIDABLE)

    def test_undecidable_step_without_trusted_range(self):
        steps_metadata = {
            "release": {"keyid": _metablock_with_range("release")}
        }
        reports = self._evaluate(steps_metadata)
        self.assertEqual(reports["release"].verdict, UNDECIDABLE)
        self.assertIsNone(reports["release"].time_range)

    def test_threshold_links_use_envelope(self):
        """With multiple links per step, the enclosing range decides: one
        link is certainly on-time, but the other crosses the deadline, so
        the step verdict must be undecidable."""
        steps_metadata = {
            "release": {
                "keyid1": _metablock_with_range(
                    "release",
                    {
                        "earliest": "2026-11-28T13:00:00Z",
                        "latest": "2026-11-28T15:00:00Z",
                    },
                ),
                "keyid2": _metablock_with_range(
                    "release",
                    {
                        "earliest": "2026-11-28T14:00:00Z",
                        "latest": "2026-11-28T19:00:00Z",
                    },
                ),
            }
        }
        reports = self._evaluate(steps_metadata)
        self.assertEqual(reports["release"].verdict, UNDECIDABLE)

    def test_malformed_deadline_raises(self):
        steps_metadata = {
            "release": {"keyid": _metablock_with_range("release")}
        }
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            verify_step_timeliness(steps_metadata, "not-a-datetime")


class TestInTotoVerifyTimeliness(unittest.TestCase, TmpDirMixin):
    """Test timeliness evaluation through the local verification entry
    point in_toto_verify."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

        signer = SignerStore.rsa
        cls.key_dict = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}

        # Create and sign a link for the 'release' step, carrying a
        # trusted time range attested by an independent clock
        link_metadata = Metablock(
            signed=Link(
                name="release",
                environment={
                    TRUSTED_TIME_RANGE_ENV_KEY: {
                        "earliest": "2026-11-28T16:00:00Z",
                        "latest": "2026-11-28T20:00:00Z",
                    }
                },
            )
        )
        link_metadata.create_signature(signer)
        link_metadata.dump(
            in_toto.models.link.FILENAME_FORMAT.format(
                step_name="release", keyid=SignerStore.rsa_pub["keyid"]
            )
        )

        # Create and sign a layout authorizing the link's key
        layout = Layout(
            steps=[
                Step(
                    name="release",
                    pubkeys=[SignerStore.rsa_pub["keyid"]],
                )
            ],
            keys=cls.key_dict,
        )
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(signer)
        layout_metadata.dump("root.layout")

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def _verify(self, deadline):
        layout = Metablock.load("root.layout")
        return in_toto_verify(
            layout, self.key_dict, timeliness_deadline=deadline
        )

    def test_report_attached_to_summary_link(self):
        """The trusted range crosses the deadline, so the report on the
        summary link must show the step as undecidable."""
        summary_link = self._verify("2026-11-28T18:00:00Z")
        report = summary_link.environment[TIMELINESS_REPORT_ENV_KEY]["release"]
        self.assertEqual(report["verdict"], UNDECIDABLE)
        self.assertEqual(
            report["trusted_time_range"],
            {
                "earliest": "2026-11-28T16:00:00+00:00",
                "latest": "2026-11-28T20:00:00+00:00",
            },
        )

    def test_on_time_deadline(self):
        summary_link = self._verify("2026-11-28T21:00:00Z")
        report = summary_link.environment[TIMELINESS_REPORT_ENV_KEY]["release"]
        self.assertEqual(report["verdict"], ON_TIME)

    def test_late_deadline(self):
        summary_link = self._verify("2026-11-28T15:00:00Z")
        report = summary_link.environment[TIMELINESS_REPORT_ENV_KEY]["release"]
        self.assertEqual(report["verdict"], LATE)

    def test_no_deadline_no_report(self):
        """Without a deadline, verification behaves as before."""
        layout = Metablock.load("root.layout")
        summary_link = in_toto_verify(layout, self.key_dict)
        self.assertNotIn(TIMELINESS_REPORT_ENV_KEY, summary_link.environment)


if __name__ == "__main__":
    unittest.main()
