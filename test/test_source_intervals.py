#-------------------------------------------------------------------------------
# elftools tests
#
# Tests for DWARF line-table interval testimony and two-source comparison.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
import tempfile
import unittest

from elftools.dwarf.lineprogram import LineProgramEntry, LineState
from elftools.dwarf.source_intervals import (
    AddressInterval,
    CompileUnitExtent,
    LineInterval,
    LineTableHole,
    SourceIndex,
    SourceLocation,
    _intervals_from_entries,
    compare_witnesses,
    find_line_table_holes,
    read_source_index,
    report_to_dict,
)


SAMPLE = os.path.join('examples', 'sample_exe64.elf')


def location(address, line, repo='repo', filename=None):
    filename = filename or f'/src/repo/file{line}.c'
    return SourceLocation(repo, filename, line, None, 0, address)


def line_state(address, line, end_sequence=False):
    state = LineState(1)
    state.address = address
    state.file = 1
    state.line = line
    state.end_sequence = end_sequence
    return state


def entry(state):
    return LineProgramEntry(0, False, [], state)


class EndSequenceTest(unittest.TestCase):
    def test_end_sequence_closes_previous_row(self):
        entries = [
            entry(line_state(0x100, 1)),
            entry(line_state(0x110, 2)),
            entry(line_state(0x120, 2, end_sequence=True)),
            entry(line_state(0x140, 9)),
            entry(line_state(0x150, 9, end_sequence=True)),
        ]
        diagnostics = []
        intervals = _intervals_from_entries(
            entries,
            lambda state: location(state.address, state.line),
            cu_offset=0,
            sequence_base=0,
            address_bias=0,
            diagnostics=diagnostics)

        self.assertEqual(
            [(i.begin, i.end, i.location.line) for i in intervals],
            [(0x100, 0x110, 1), (0x110, 0x120, 2), (0x140, 0x150, 9)])
        # The end marker closes sequence 0; the gap [0x120, 0x140) is not
        # covered by the preceding row or extended to the next sequence.
        self.assertEqual(diagnostics, [])

    def test_row_without_end_sequence_has_no_extent(self):
        diagnostics = []
        intervals = _intervals_from_entries(
            [entry(line_state(0x100, 1)), entry(line_state(0x110, 2))],
            lambda state: location(state.address, state.line),
            cu_offset=0,
            sequence_base=0,
            address_bias=0,
            diagnostics=diagnostics)

        self.assertEqual([(i.begin, i.end) for i in intervals], [(0x100, 0x110)])
        self.assertTrue(any('without end_sequence' in d for d in diagnostics))


class HoleTest(unittest.TestCase):
    def test_hole_detection_requires_both_sides(self):
        intervals = (
            LineInterval(0x100, 0x120, location(0x100, 1), 0),
            LineInterval(0x140, 0x160, location(0x140, 9), 1),
        )
        holes = find_line_table_holes(
            0, [AddressInterval(0x100, 0x180)], intervals)

        # [0x120, 0x140) is internal and has rows on both sides.  The
        # trailing [0x160, 0x180) has only a left side and is not a legal
        # two-sided line-table hole.
        self.assertEqual(len(holes), 1)
        hole = holes[0]
        self.assertEqual((hole.begin, hole.end), (0x120, 0x140))
        self.assertEqual((hole.before.line, hole.after.line), (1, 9))
        self.assertEqual(
            (hole.before.address, hole.after.address), (0x100, 0x140))

    def test_leading_gap_is_not_a_two_sided_hole(self):
        intervals = (
            LineInterval(0x120, 0x140, location(0x120, 1), 0),
            LineInterval(0x160, 0x180, location(0x160, 2), 1),
        )
        holes = find_line_table_holes(
            0, [AddressInterval(0x100, 0x180)], intervals)
        self.assertEqual([(h.begin, h.end) for h in holes], [(0x140, 0x160)])

    def test_hole_is_reported_separately_and_sides_keep_sources(self):
        before = location(0x100, 1, filename='/src/repo/before.c')
        after = location(0x140, 9, filename='/src/repo/after.c')
        intervals = (
            LineInterval(0x100, 0x120, before, 0),
            LineInterval(0x140, 0x160, after, 1),
        )
        hole = LineTableHole(0x120, 0x140, 0, before, after)
        index = SourceIndex(
            'same.elf',
            intervals,
            (hole,),
            (CompileUnitExtent(0, (AddressInterval(0x100, 0x160),)),))

        report = compare_witnesses(index, index, [(0x100, 0x160)])
        self.assertEqual(
            [(s.begin, s.end, s.status) for s in report.segments],
            [(0x100, 0x120, 'unchanged'),
             (0x120, 0x140, 'unconfirmed'),
             (0x140, 0x160, 'unchanged')])
        self.assertEqual(report.unconfirmed[0].hole_sources, ('left', 'right'))
        self.assertEqual(len(report.holes), 2)
        for evidence in report.holes:
            self.assertEqual(evidence.before.file, '/src/repo/before.c')
            self.assertEqual(evidence.after.file, '/src/repo/after.c')

    def test_one_sided_hole_makes_the_range_changed(self):
        before = location(0x100, 1)
        after = location(0x140, 2)
        left = SourceIndex(
            'left.elf',
            (LineInterval(0x100, 0x120, before, 0),
             LineInterval(0x140, 0x160, after, 1)),
            (LineTableHole(0x120, 0x140, 0, before, after),),
            (CompileUnitExtent(0, (AddressInterval(0x100, 0x160),)),))
        right = SourceIndex(
            'right.elf',
            (LineInterval(0x100, 0x160, before, 0),),
            (),
            (CompileUnitExtent(0, (AddressInterval(0x100, 0x160),)),))

        report = compare_witnesses(left, right, [(0x100, 0x160)])
        self.assertEqual(
            [(s.begin, s.end, s.status) for s in report.segments],
            [(0x100, 0x120, 'unchanged'),
             (0x120, 0x140, 'changed'),
             (0x140, 0x160, 'unchanged')])
        self.assertEqual(report.changed[0].hole_sources, ('left',))
        self.assertEqual(len(report.holes), 1)
        self.assertEqual(report.holes[0].source, 'left')


class SampleFileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = read_source_index(SAMPLE)

    def test_line_table_and_cu_gaps(self):
        self.assertEqual(
            self.index.code_ranges(),
            (AddressInterval(0x400400, 0x40042a),
             AddressInterval(0x4004ec, 0x400517),
             AddressInterval(0x400520, 0x4005b9)))
        self.assertEqual(self.index.location_at(0x400503).line, 3)
        self.assertEqual(self.index.location_at(0x400503).file, '/tmp/ebenders/z.c')
        # The end_sequence row at 0x400517 is a boundary, not a row that
        # extends into the next CU.
        self.assertIsNone(self.index.location_at(0x400517))
        self.assertIsNone(self.index.location_at(0x40042a))

    def test_identical_sources_have_unchanged_and_unconfirmed_ranges(self):
        report = compare_witnesses(
            self.index, self.index, [(0x400400, 0x4005b9)])
        self.assertEqual(
            [(s.begin, s.end) for s in report.unchanged],
            [(0x400400, 0x40042a),
             (0x4004ec, 0x400517),
             (0x400520, 0x4005b9)])
        self.assertEqual(
            [(s.begin, s.end) for s in report.unconfirmed],
            [(0x40042a, 0x4004ec), (0x400517, 0x400520)])
        self.assertEqual(report.changed, ())
        self.assertEqual(report.holes, ())

    def test_load_intervals_clip_and_split_output(self):
        report = compare_witnesses(
            self.index, self.index,
            [(0x400400, 0x400410), (0x400500, 0x400510)])
        self.assertEqual(
            [(s.begin, s.end) for s in report.unchanged],
            [(0x400400, 0x400410), (0x400500, 0x400510)])

    def test_changed_repo_from_patched_debug_file(self):
        with open(SAMPLE, 'rb') as stream:
            data = stream.read()
        self.assertEqual(data.count(b'/tmp/ebenders'), 1)
        patched = data.replace(b'/tmp/ebenders', b'/tmp/otherdir')
        fd, path = tempfile.mkstemp(suffix='.elf')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(patched)
            other = read_source_index(path)
            report = compare_witnesses(
                self.index, other, [(0x4004e0, 0x400520)])
        finally:
            os.unlink(path)

        self.assertEqual(
            [(s.begin, s.end, s.status) for s in report.segments],
            [(0x4004e0, 0x4004ec, 'unconfirmed'),
             (0x4004ec, 0x400517, 'changed'),
             (0x400517, 0x400520, 'unconfirmed')])
        changed = report.changed[0]
        self.assertEqual(changed.left.repo, '/tmp/ebenders')
        self.assertEqual(changed.right.repo, '/tmp/otherdir')

    def test_report_dict_uses_hex_addresses(self):
        report = compare_witnesses(
            self.index, self.index, [(0x400400, 0x400410)])
        result = report_to_dict(report)
        self.assertEqual(result['load_intervals'], [
            {'begin': '0x400400', 'end': '0x400410'}])
        self.assertEqual(result['segments']['unchanged'][0]['begin'], '0x400400')

    def test_address_bias_moves_rows_and_cu_ranges(self):
        biased = read_source_index(SAMPLE, address_bias=0x1000)
        self.assertEqual(
            biased.code_ranges(),
            (AddressInterval(0x401400, 0x40142a),
             AddressInterval(0x4014ec, 0x401517),
             AddressInterval(0x401520, 0x4015b9)))
        report = compare_witnesses(
            biased, biased, [(0x401400, 0x4015b9)])
        self.assertEqual(
            [(s.begin, s.end) for s in report.unchanged],
            [(0x401400, 0x40142a),
             (0x4014ec, 0x401517),
             (0x401520, 0x4015b9)])

    def test_repo_prefix_mapping(self):
        index = read_source_index(SAMPLE, repo_roots={
            '/tmp/ebenders': 'z-repo',
            '/usr/src/packages/BUILD/glibc-2.11.1': 'glibc',
        })
        self.assertEqual(index.location_at(0x400503).repo, 'z-repo')
        self.assertEqual(index.location_at(0x400400).repo, 'glibc')

    def test_empty_load_list_means_no_loaded_addresses(self):
        report = compare_witnesses(self.index, self.index, [])
        self.assertEqual(report.load_intervals, ())
        self.assertEqual(report.segments, ())


class RealHoleTest(unittest.TestCase):
    def test_arm_fixture_has_a_two_sided_line_table_hole(self):
        index = read_source_index(os.path.join(
            'test', 'testfiles_for_unittests', 'arm_with_form_indirect.elf'))
        self.assertEqual(len(index.holes), 1)
        hole = index.holes[0]
        self.assertEqual((hole.begin, hole.end), (0x10006216, 0x10006218))
        self.assertEqual((hole.before.line, hole.after.line), (228, 249))

        report = compare_witnesses(
            index, index, [(hole.begin - 1, hole.end + 1)])
        self.assertEqual(
            [(s.begin, s.end, s.status) for s in report.segments],
            [(0x10006215, 0x10006216, 'unchanged'),
             (0x10006216, 0x10006218, 'unconfirmed'),
             (0x10006218, 0x10006219, 'unchanged')])
        self.assertEqual(report.unconfirmed[0].hole_sources, ('left', 'right'))
        self.assertEqual(len(report.holes), 2)


if __name__ == '__main__':
    unittest.main()
