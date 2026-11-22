"""Tests for the offline drive-letter reconciliation feature."""

import base64
import json
import os
import tempfile
import unittest
from io import StringIO
from unittest import mock

import LnkParse3
from LnkParse3.reconcile import build_reconciliation
from LnkParse3.reconcile import make_target
from LnkParse3.reconcile import reconcile_target
from LnkParse3.reconcile.cli import main as cli_main
from LnkParse3.reconcile.lnk_adapter import descriptor_from_lnk
from LnkParse3.reconcile.normalization import normalize_drive_letter
from LnkParse3.reconcile.normalization import normalize_path_key
from LnkParse3.reconcile.normalization import normalize_serial


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")


def sample_bytes(name):
    with open(os.path.join(SAMPLE_DIR, name), "rb") as handle:
        return base64.b64decode(handle.read())


class NormalizationTests(unittest.TestCase):
    def test_serial_spellings_collapse_together(self):
        values = ["0x307A8A81", "307A8A81", "307a-8a81", "{307a8a81}", 0x307A8A81]
        self.assertEqual({normalize_serial(value) for value in values}, {"307a8a81"})

    def test_distinct_serials_never_collapse(self):
        self.assertNotEqual(
            normalize_serial("0xaaaabbbb"),
            normalize_serial("0xccccdddd"),
        )

    def test_drive_letter_and_path_key(self):
        self.assertEqual(normalize_drive_letter("e:"), "E")
        self.assertEqual(
            normalize_path_key("E:/Case/Report.doc/"),
            normalize_path_key(r"e:\case\report.doc"),
        )


class ReconciliationFixture(unittest.TestCase):
    def setUp(self):
        self.drive_history = {
            "periods": [
                {
                    "period": "2019-collection",
                    "mappings": [
                        {
                            "drive_letter": "E",
                            "volume_serial": "0xAAAABBBB",
                            "volume_label": "OLD-DISK",
                            "source": "collector-a",
                        }
                    ],
                },
                {
                    "period": "2022-collection",
                    "mappings": [
                        {
                            "drive_letter": "E",
                            "volume_serial": "0xCCCCDDDD",
                            "volume_label": "REPLACEMENT",
                            "source": "collector-b",
                        }
                    ],
                },
                {
                    "period": "2024-collection",
                    "mappings": [
                        {
                            "drive_letter": "F",
                            "volume_serial": "0xEEEEFFFF",
                            "volume_label": "ARCHIVE",
                            "source": "collector-c",
                        }
                    ],
                },
            ]
        }
        self.evidence = {
            "evidence": [
                {
                    "evidence_id": "image-old",
                    "volume_serial": "AAAA-BBBB",
                    "source": "exhibit-image-1",
                },
                {
                    "evidence_id": "image-new",
                    "volume_serial": "CCCC-DDDD",
                    "drive_letter": "E",
                    "source": "exhibit-image-2",
                },
            ]
        }


class DriveLetterReuseTests(ReconciliationFixture):
    """Acceptance: reusing a letter must not move old evidence attribution."""

    def setUp(self):
        super().setUp()
        self.target = make_target(
            source="backup/recovered.lnk",
            lnk_ref="recovered.lnk",
            written_path=r"E:\case\report.doc",
            volume_serial="0xaaaabbbb",
        )

    def test_written_target_kept_verbatim(self):
        result = reconcile_target(self.target, self.drive_history["periods"], [])
        self.assertEqual(result["written_path"], r"E:\case\report.doc")
        self.assertEqual(result["volume_serial"], "aaaabbbb")

    def test_historical_attribution_follows_embedded_serial_not_letter(self):
        result = reconcile_target(self.target, self.drive_history["periods"], [])
        attribution = result["historical_attribution"]
        by_period = {entry["period"]: entry for entry in attribution["by_period"]}

        first = by_period["2019-collection"]["candidates"][0]
        self.assertEqual(first["volume_serials"], ["aaaabbbb"])
        self.assertIn("volume_serial", first["matched_by"])
        self.assertTrue(first["authoritative"])

        reused = by_period["2022-collection"]["candidates"][0]
        self.assertEqual(reused["volume_serials"], ["ccccdddd"])
        self.assertEqual(reused["matched_by"], ["drive_letter"])
        self.assertFalse(reused["authoritative"])
        self.assertFalse(reused["matches_lnk_volume_id"])

    def test_period_without_observation_is_left_empty(self):
        result = reconcile_target(self.target, self.drive_history["periods"], [])
        attribution = result["historical_attribution"]
        by_period = {entry["period"]: entry for entry in attribution["by_period"]}

        gap = by_period["2024-collection"]
        self.assertFalse(gap["observed"])
        self.assertEqual(gap["candidates"], [])
        self.assertIn("2024-collection", attribution["unobserved_periods"])

    def test_collected_evidence_matches_old_volume_despite_reused_letter(self):
        result = reconcile_target(
            self.target,
            self.drive_history["periods"],
            self.evidence["evidence"],
        )
        collected = result["collected_evidence"]
        self.assertTrue(collected["matched"])
        self.assertEqual(collected["match_basis"], "volume_serial")
        self.assertEqual(
            [item["evidence_id"] for item in collected["items"]],
            ["image-old"],
        )

    def test_new_volume_on_same_letter_matches_its_own_evidence(self):
        new_target = make_target(
            source="backup/replacement.lnk",
            lnk_ref="replacement.lnk",
            written_path=r"E:\case\report.doc",
            volume_serial="0xccccdddd",
        )
        result = reconcile_target(
            new_target,
            self.drive_history["periods"],
            self.evidence["evidence"],
        )
        self.assertEqual(
            [item["evidence_id"] for item in result["collected_evidence"]["items"]],
            ["image-new"],
        )


class ConflictRetentionTests(ReconciliationFixture):
    """Acceptance: conflicting candidates both keep their provenance."""

    def test_two_candidates_in_one_period_are_both_retained(self):
        drive_history = {
            "periods": [
                {
                    "period": "2020-collection",
                    "mappings": [
                        {
                            "drive_letter": "E",
                            "volume_serial": "0x11111111",
                            "source": "source-one",
                        },
                        {
                            "drive_letter": "E",
                            "volume_serial": "0x22222222",
                            "source": "source-two",
                        },
                    ],
                }
            ]
        }
        target = make_target(source="backup/ambiguous.lnk", written_path=r"E:\data\f.txt")
        result = reconcile_target(target, drive_history["periods"], [])
        attribution = result["historical_attribution"]

        self.assertTrue(attribution["attribution_conflict"])
        self.assertEqual(attribution["conflict_periods"], ["2020-collection"])
        candidates = attribution["by_period"][0]["candidates"]
        self.assertEqual(
            {candidate["source"] for candidate in candidates},
            {"source-one", "source-two"},
        )
        self.assertTrue(all(candidate["authoritative"] for candidate in candidates))

    def test_embedded_serial_disambiguates_same_period_candidates(self):
        drive_history = {
            "periods": [
                {
                    "period": "2020-collection",
                    "mappings": [
                        {
                            "drive_letter": "E",
                            "volume_serial": "0x11111111",
                            "source": "source-one",
                        },
                        {
                            "drive_letter": "E",
                            "volume_serial": "0x22222222",
                            "source": "source-two",
                        },
                    ],
                }
            ]
        }
        target = make_target(
            source="backup/clear.lnk",
            written_path=r"E:\data\f.txt",
            volume_serial="0x22222222",
        )
        result = reconcile_target(target, drive_history["periods"], [])
        attribution = result["historical_attribution"]

        self.assertFalse(attribution["attribution_conflict"])
        authoritative = [
            candidate
            for candidate in attribution["by_period"][0]["candidates"]
            if candidate["authoritative"]
        ]
        self.assertEqual(len(authoritative), 1)
        self.assertEqual(authoritative[0]["source"], "source-two")


class SameNameDifferentSourceTests(ReconciliationFixture):
    """Acceptance: same logical path coming from two volumes is locatable."""

    def test_same_named_targets_from_two_sources_are_grouped(self):
        targets = [
            make_target(
                source="backup/old.lnk",
                lnk_ref="old.lnk",
                written_path=r"E:\case\report.doc",
                volume_serial="0xaaaabbbb",
            ),
            make_target(
                source="backup/new.lnk",
                lnk_ref="new.lnk",
                written_path=r"e:\CASE\report.doc",
                volume_serial="0xccccdddd",
            ),
        ]
        report = build_reconciliation(targets, self.drive_history, self.evidence)

        self.assertEqual(len(report["same_name_groups"]), 1)
        group = report["same_name_groups"][0]
        self.assertTrue(group["multiple_sources"])
        self.assertEqual(
            group["distinct_volume_serials"],
            ["aaaabbbb", "ccccdddd"],
        )
        self.assertEqual(
            {member["lnk_ref"] for member in group["members"]},
            {"old.lnk", "new.lnk"},
        )

    def test_identical_path_and_serial_is_not_flagged_as_multiple_sources(self):
        targets = [
            make_target(source="a.lnk", written_path=r"E:\f.txt", volume_serial="0xaaaabbbb"),
            make_target(source="b.lnk", written_path=r"E:\f.txt", volume_serial="0xaaaabbbb"),
        ]
        report = build_reconciliation(targets, self.drive_history, self.evidence)
        group = report["same_name_groups"][0]
        self.assertFalse(group["multiple_sources"])


class LnkAdapterTests(unittest.TestCase):
    def test_local_sample_exposes_embedded_volume_id(self):
        lnk = LnkParse3.lnk_file(indata=sample_bytes("sample"))
        descriptor = descriptor_from_lnk(lnk, lnk_ref="sample")

        self.assertEqual(descriptor["location"], "Local")
        self.assertEqual(descriptor["volume_serial"], "9e31fc72")
        self.assertEqual(
            descriptor["written_path"],
            r"C:\Users\Jonathan\AppData\Roaming\.minecraft",
        )
        self.assertEqual(descriptor["drive_letter"], "C")

    def test_microsoft_example_round_trips_through_reconciliation(self):
        lnk = LnkParse3.lnk_file(indata=sample_bytes("microsoft_example"))
        descriptor = descriptor_from_lnk(lnk, lnk_ref="microsoft_example")
        drive_history = {
            "periods": [
                {
                    "period": "2008",
                    "mappings": [
                        {
                            "drive_letter": "C",
                            "volume_serial": "0x307A8A81",
                            "source": "chris-xps",
                        }
                    ],
                }
            ]
        }
        evidence = {"evidence": [{"evidence_id": "disk-1", "volume_serial": "307a8a81"}]}
        report = build_reconciliation([descriptor], drive_history, evidence)
        result = report["targets"][0]

        self.assertEqual(result["written_path"], r"C:\test\a.txt")
        self.assertTrue(result["collected_evidence"]["matched"])
        self.assertEqual(
            result["collected_evidence"]["items"][0]["evidence_id"],
            "disk-1",
        )

    def test_network_sample_has_no_local_volume_id(self):
        lnk = LnkParse3.lnk_file(indata=sample_bytes("network_info"))
        descriptor = descriptor_from_lnk(lnk, lnk_ref="network_info")

        self.assertNotEqual(descriptor["location"], "Local")
        self.assertIsNone(descriptor["volume_serial"])
        self.assertIn("note", descriptor)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        base = self.tempdir.name

        self.drives_path = os.path.join(base, "drives.json")
        self.evidence_path = os.path.join(base, "evidence.json")
        self.targets_path = os.path.join(base, "targets.json")
        self.output_path = os.path.join(base, "report.json")

        with open(self.drives_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "periods": [
                        {
                            "period": "2019",
                            "mappings": [
                                {
                                    "drive_letter": "E",
                                    "volume_serial": "0xAAAABBBB",
                                    "source": "collector-a",
                                }
                            ],
                        },
                        {
                            "period": "2022",
                            "mappings": [
                                {
                                    "drive_letter": "E",
                                    "volume_serial": "0xCCCCDDDD",
                                    "source": "collector-b",
                                }
                            ],
                        },
                    ]
                },
                handle,
            )
        with open(self.evidence_path, "w", encoding="utf-8") as handle:
            json.dump(
                {"evidence": [{"evidence_id": "img", "volume_serial": "aaaa-bbbb"}]},
                handle,
            )
        with open(self.targets_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "targets": [
                        {
                            "source": "backup/recovered.lnk",
                            "lnk_ref": "recovered.lnk",
                            "written_path": r"E:\case\report.doc",
                            "volume_serial": "0xaaaabbbb",
                        }
                    ]
                },
                handle,
            )

    def test_cli_writes_report_file(self):
        exit_code = cli_main(
            [
                "--targets",
                self.targets_path,
                "--drives",
                self.drives_path,
                "--evidence",
                self.evidence_path,
                "--output",
                self.output_path,
            ]
        )
        self.assertEqual(exit_code, 0)
        with open(self.output_path, encoding="utf-8") as handle:
            report = json.load(handle)

        target = report["targets"][0]
        self.assertEqual(target["written_path"], r"E:\case\report.doc")
        self.assertEqual(
            target["collected_evidence"]["items"][0]["evidence_id"],
            "img",
        )
        by_period = {
            entry["period"]: entry for entry in target["historical_attribution"]["by_period"]
        }
        self.assertTrue(by_period["2019"]["observed"])
        self.assertFalse(by_period["2022"]["candidates"][0]["authoritative"])

    def test_cli_requires_some_target_input(self):
        with mock.patch("sys.stderr", new_callable=StringIO), self.assertRaises(SystemExit):
            cli_main(
                [
                    "--drives",
                    self.drives_path,
                    "--evidence",
                    self.evidence_path,
                ]
            )


if __name__ == "__main__":
    unittest.main()
