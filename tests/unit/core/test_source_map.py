#
# SPDX-License-Identifier: Apache-2.0
import json
import os
import tempfile

import testtools

from bandit.core import source_map


class SourceSegmentTests(testtools.TestCase):
    def test_point_segment_round_trip(self):
        segment = source_map.SourceSegment.from_dict(
            {
                "generated_start": 4,
                "generated_end": 4,
                "source_file": "t.tmpl",
                "source_line": 9,
            }
        )
        self.assertTrue(segment.is_point)
        self.assertEqual(
            segment.as_dict(),
            {
                "generated_start": 4,
                "generated_end": 4,
                "source_file": "t.tmpl",
                "source_line": 9,
            },
        )

    def test_range_segment_round_trip(self):
        segment = source_map.SourceSegment.from_dict(
            {
                "generated_start": 1,
                "generated_end": 3,
                "source_file": "t.tmpl",
                "source_start": 10,
                "source_end": 12,
            }
        )
        self.assertFalse(segment.is_point)
        self.assertEqual(segment.as_dict()["source_start"], 10)
        self.assertEqual(segment.as_dict()["source_end"], 12)

    def test_missing_required_field_raises(self):
        self.assertRaises(
            source_map.SourceMapError,
            source_map.SourceSegment.from_dict,
            {"generated_start": 1, "source_file": "t.tmpl"},
        )

    def test_missing_source_location_raises(self):
        self.assertRaises(
            source_map.SourceMapError,
            source_map.SourceSegment.from_dict,
            {
                "generated_start": 1,
                "generated_end": 1,
                "source_file": "t.tmpl",
            },
        )


class SourceMapLoadTests(testtools.TestCase):
    def _write_map(self, payload):
        fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        self.addCleanup(os.unlink, fh.name)
        json.dump(payload, fh)
        fh.close()
        return fh.name

    def test_load_round_trip(self):
        name = self._write_map(
            {
                "version": 1,
                "generated_files": {
                    "out.py": [
                        {
                            "generated_start": 1,
                            "generated_end": 1,
                            "source_file": "t.tmpl",
                            "source_line": 2,
                        }
                    ]
                },
            }
        )
        loaded = source_map.SourceMap.load(name, verify_files=False)
        self.assertTrue(loaded.has_mapping("out.py"))
        self.assertEqual(loaded.as_dict()["version"], 1)

    def test_unknown_version_rejected(self):
        name = self._write_map({"version": 99, "generated_files": {}})
        self.assertRaises(
            source_map.SourceMapError,
            source_map.SourceMap.load,
            name,
            verify_files=False,
        )

    def test_missing_file_raises(self):
        self.assertRaises(
            source_map.SourceMapError,
            source_map.SourceMap.load,
            "does-not-exist-map.json",
        )

    def test_path_normalisation_matches_dot_prefix(self):
        smap = source_map.SourceMap(
            files={
                "gen/out.py": [
                    source_map.SourceSegment(1, 1, "t.tmpl", 1)
                ]
            },
            verify_files=False,
        )
        self.assertTrue(smap.has_mapping(os.path.join(".", "gen", "out.py")))


class SourceMapProjectionTests(testtools.TestCase):
    """The three in-memory generated fragments live in one generated file.

    The map deliberately leaves a gap and points one generated region at two
    source locations so a single finding can straddle a mapping boundary.
    """

    def setUp(self):
        super().setUp()
        # generated layout (12 physical lines):
        #   lines 1-4   -> fragment one   -> template_a lines 10-13
        #   lines 5-6   -> uncovered gap (expansion boilerplate, unmapped)
        #   lines 7-9   -> fragment two   -> template_b lines 20-22, and
        #                                    also hand_written.py line 3
        #   lines 10-12 -> fragment three -> template_a lines 30-32
        self.smap = source_map.SourceMap(
            files={
                "build/generated.py": [
                    source_map.SourceSegment(1, 4, "template_a.tmpl", 10, 13),
                    source_map.SourceSegment(7, 9, "template_b.tmpl", 20, 22),
                    source_map.SourceSegment(
                        7, 9, "hand_written.py", 3, 3
                    ),
                    source_map.SourceSegment(
                        10, 12, "template_a.tmpl", 30, 32
                    ),
                ]
            },
            verify_files=False,
        )

    def test_point_projection_uses_supplied_line(self):
        refs = self.smap.project(
            "build/generated.py", 2, linerange=[2], line_count=12
        )
        self.assertEqual(1, len(refs))
        ref = refs[0]
        self.assertEqual("mapped", ref.as_dict()["status"])
        self.assertEqual(11, ref.source_line)
        self.assertEqual("template_a.tmpl", ref.source_file)

    def test_finding_crossing_mapping_breakpoint(self):
        # The finding spans generated lines 4..10: it overlaps fragment one,
        # the uncovered gap (5-6), both one-to-many candidates of fragment
        # two, and fragment three.  No unique line is fabricated for the
        # multi-line overlaps.
        refs = self.smap.project(
            "build/generated.py", 4, linerange=[4, 5, 6, 7, 8, 9, 10],
            line_count=12,
        )
        statuses = [ref.as_dict()["status"] for ref in refs]
        self.assertEqual(
            [
                "mapped",  # fragment one, line 4 -> template_a line 13
                "invalid",  # uncovered generated gap 5-6
                "mapped",  # fragment two -> template_b range
                "mapped",  # fragment two -> hand_written.py point
                "mapped",  # fragment three, line 10 -> template_a line 30
            ],
            statuses,
        )

        gap = refs[1].as_dict()
        self.assertEqual(
            source_map.REASON_UNMAPPED_GAP, gap["reason"]
        )
        self.assertEqual(5, gap["generated_start"])
        self.assertEqual(6, gap["generated_end"])

        # multi-line overlaps must not invent a unique line
        self.assertIsNone(refs[2].source_line)
        self.assertEqual(20, refs[2].source_start)
        self.assertEqual(22, refs[2].source_end)

        # the point candidate (hand_written.py line 3) keeps its real line
        self.assertEqual(3, refs[3].source_line)
        self.assertEqual("hand_written.py", refs[3].source_file)

        # every emitted source line number must come from the map itself:
        # each projected range is contained within a range the map declared
        mapped = [r for r in refs if r.as_dict()["status"] == "mapped"]
        declared = [
            (10, 13),
            (20, 22),
            (3, 3),
            (30, 32),
        ]
        for ref in mapped:
            self.assertTrue(
                any(
                    d_start <= ref.source_start
                    and ref.source_end <= d_end
                    for d_start, d_end in declared
                ),
                "projected source lines %s-%s are not backed by the map"
                % (ref.source_start, ref.source_end),
            )
            # a single-line projection may carry a line number, a range may
            # not invent one
            if ref.source_start != ref.source_end:
                self.assertIsNone(ref.source_line)

    def test_one_to_many_keeps_every_candidate(self):
        refs = self.smap.project(
            "build/generated.py", 8, linerange=[8], line_count=12
        )
        files = sorted(ref.source_file for ref in refs)
        self.assertEqual(
            ["hand_written.py", "template_b.tmpl"], files
        )
        self.assertEqual(2, len(refs))

    def test_range_only_overlap_has_null_line(self):
        # A single generated line inside a multi-line source segment still
        # has a deterministic line (offset math), but a finding covering more
        # than one generated line inside that segment stays range-only.
        refs = self.smap.project(
            "build/generated.py", 7, linerange=[7, 8], line_count=12
        )
        template_b = next(
            ref for ref in refs if ref.source_file == "template_b.tmpl"
        )
        self.assertIsNone(template_b.source_line)
        self.assertEqual((20, 21), (template_b.source_start,
                                    template_b.source_end))

    def test_fully_unmapped_gap_is_explicit(self):
        refs = self.smap.project(
            "build/generated.py", 5, linerange=[5, 6], line_count=12
        )
        self.assertEqual(1, len(refs))
        data = refs[0].as_dict()
        self.assertEqual("invalid", data["status"])
        self.assertEqual(source_map.REASON_UNMAPPED_GAP, data["reason"])

    def test_unknown_file_returns_no_mapping(self):
        refs = self.smap.project(
            "elsewhere.py", 1, linerange=[1], line_count=3
        )
        self.assertEqual(1, len(refs))
        self.assertEqual(
            source_map.REASON_NO_MAPPING, refs[0].as_dict()["reason"]
        )

    def test_generated_range_out_of_bounds_is_flagged(self):
        smap = source_map.SourceMap(
            files={
                "small.py": [
                    source_map.SourceSegment(1, 9, "t.tmpl", 1, 9)
                ]
            },
            verify_files=False,
        )
        refs = smap.project("small.py", 8, linerange=[8], line_count=3)
        self.assertEqual("invalid", refs[0].as_dict()["status"])
        self.assertEqual(
            source_map.REASON_GENERATED_RANGE_INVALID,
            refs[0].as_dict()["reason"],
        )

    def test_missing_source_file_is_kept_with_reason(self):
        tmp_dir = tempfile.mkdtemp()
        missing = os.path.join(tmp_dir, "gone.tmpl")
        smap = source_map.SourceMap(
            files={
                "out.py": [
                    source_map.SourceSegment(1, 1, missing, 1, 1)
                ]
            },
            verify_files=True,
        )
        refs = smap.project("out.py", 1, linerange=[1], line_count=2)
        data = refs[0].as_dict()
        self.assertEqual("invalid", data["status"])
        self.assertEqual(missing, data["source_file"])
        self.assertEqual(
            source_map.REASON_SOURCE_FILE_MISSING, data["reason"]
        )

    def test_source_range_out_of_bounds_is_flagged(self):
        fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".tmpl", delete=False
        )
        self.addCleanup(os.unlink, fh.name)
        fh.write("one line\n")
        fh.close()
        smap = source_map.SourceMap(
            files={
                "out.py": [
                    source_map.SourceSegment(1, 2, fh.name, 1, 5)
                ]
            },
            verify_files=True,
        )
        refs = smap.project("out.py", 1, linerange=[1, 2], line_count=4)
        self.assertEqual(
            source_map.REASON_SOURCE_RANGE_INVALID,
            refs[0].as_dict()["reason"],
        )

    def test_malformed_segment_is_flagged(self):
        smap = source_map.SourceMap(
            files={
                "out.py": [
                    source_map.SourceSegment(5, 2, "t.tmpl", 1, 1)
                ]
            },
            verify_files=False,
        )
        refs = smap.project("out.py", 5, linerange=[5], line_count=6)
        self.assertEqual(
            source_map.REASON_MALFORMED_SEGMENT,
            refs[0].as_dict()["reason"],
        )
