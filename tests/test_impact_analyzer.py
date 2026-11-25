#!/usr/bin/env python3
"""
Tests for the read-only minidump impact analyzer.

The same hand-built sample is exercised through three trimmed variants so
the tests cover a complete dump, a missing substitutable stream and an
entry-present-but-data-missing dangling reference.
"""

import io
import json
import logging
import unittest

from minidump.analysis import (
    MinidumpImpactAnalyzer,
    ReferenceStatus,
    StreamRole,
)
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.minidumpfile import MinidumpFile

from tests.minidumpfixtures import (
    CONTEXT_FILLER,
    STACK_FILLER,
    build_variants,
    trim_stream,
)

logging.disable(logging.CRITICAL)


class ImpactAnalyzerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.variants = build_variants()
        cls.reports = {}
        for name, blob in cls.variants.items():
            parsed = MinidumpFile.parse_buff(io.BytesIO(blob))
            cls.reports[name] = parsed.investigate('crash')

    def _assessment(self, report, stream_type):
        return next(item for item in report.assessments
            if item.stream_type == stream_type)

    def _coverage_by_value(self, report):
        return {cap.value: state for cap, state
            in report.capability_coverage.items()}

    def test_all_samples_parse_as_real_minidumps(self):
        for name, blob in self.variants.items():
            parsed = MinidumpFile.parse_buff(io.BytesIO(blob))
            self.assertGreaterEqual(len(parsed.directories), 4)
            self.assertIsNotNone(parsed.threads)
            self.assertIsNotNone(parsed.sysinfo)

    def test_complete_dump_allows_full_reconstruction(self):
        report = self.reports['complete']
        self.assertEqual(report.verdict, 'full reconstruction possible')
        self.assertFalse(report.partial)
        self.assertEqual(report.blocking_reasons, [])
        self.assertEqual(report.dangling_references, [])

    def test_required_vs_substitutable_vs_explanatory_roles(self):
        report = self.reports['complete']
        self.assertEqual(
            self._assessment(report, MINIDUMP_STREAM_TYPE.ExceptionStream).role,
            StreamRole.REQUIRED,
        )
        self.assertEqual(
            self._assessment(report, MINIDUMP_STREAM_TYPE.ThreadListStream).role,
            StreamRole.REQUIRED,
        )
        self.assertEqual(
            self._assessment(report, MINIDUMP_STREAM_TYPE.MemoryListStream).role,
            StreamRole.SUBSTITUTABLE,
        )
        self.assertEqual(
            self._assessment(report, MINIDUMP_STREAM_TYPE.ModuleListStream).role,
            StreamRole.SUBSTITUTABLE,
        )
        self.assertEqual(
            self._assessment(report, MINIDUMP_STREAM_TYPE.SystemInfoStream).role,
            StreamRole.EXPLANATORY,
        )

    def test_missing_substitutable_stream_keeps_partial_reconstruction(self):
        report = self.reports['without_modules']
        self.assertEqual(report.verdict, 'partial reconstruction possible')
        self.assertTrue(report.partial)
        module_assessment = self._assessment(
            report, MINIDUMP_STREAM_TYPE.ModuleListStream,
        )
        self.assertFalse(module_assessment.present)
        self.assertEqual(module_assessment.role, StreamRole.SUBSTITUTABLE)
        # Hard crash evidence must remain available despite the trim.
        coverage = self._coverage_by_value(report)
        self.assertEqual(coverage['exception_facts'], 'resolved')
        self.assertEqual(coverage['thread_context'], 'resolved')
        self.assertEqual(coverage['stack_memory'], 'resolved')
        self.assertEqual(coverage['module_resolution'], 'absent')

    def test_dangling_entry_is_reported_without_raw_content(self):
        report = self.reports['dangling_exception']
        self.assertEqual(report.verdict, 'reconstruction blocked')
        self.assertTrue(report.blocking_reasons)
        self.assertEqual(len(report.dangling_references), 1)
        dangling = report.dangling_references[0]
        self.assertEqual(dangling.status, ReferenceStatus.DANGLING)
        self.assertEqual(dangling.kind, 'directory-entry')
        assessment = self._assessment(
            report, MINIDUMP_STREAM_TYPE.ExceptionStream,
        )
        self.assertTrue(assessment.present)
        self.assertEqual(assessment.status, ReferenceStatus.DANGLING)

    def test_thread_only_path_bypasses_missing_exception(self):
        parsed = MinidumpFile.parse_buff(
            io.BytesIO(self.variants['dangling_exception']),
        )
        report = parsed.investigate('threads')
        self.assertEqual(report.verdict, 'full reconstruction possible')
        self.assertEqual(report.dangling_references, [])

    def test_custom_path_string_and_invalid_stage(self):
        parsed = MinidumpFile.parse_buff(
            io.BytesIO(self.variants['complete']),
        )
        report = parsed.investigate('directory,thread,context')
        self.assertEqual(report.path.stages[0].value, 'directory')
        with self.assertRaises(ValueError):
            parsed.investigate('not-a-stage')

    def test_report_never_contains_raw_memory_content(self):
        markers = (STACK_FILLER, CONTEXT_FILLER)
        for report in self.reports.values():
            rendered = json.dumps(report.to_dict(), sort_keys=True) + str(report)
            encoded = rendered.encode('utf-8', 'ignore')
            for marker in markers:
                self.assertNotIn(marker, encoded)
            for assessment in report.assessments:
                for reference in assessment.references:
                    self.assertIsInstance(reference.rva, (int, type(None)))
                    self.assertIsInstance(reference.declared_size, (int, type(None)))

    def test_analyzer_is_read_only(self):
        blob = self.variants['complete']
        parsed = MinidumpFile.parse_buff(io.BytesIO(blob))
        before = blob
        MinidumpImpactAnalyzer(parsed).analyze('crash')
        self.assertEqual(blob, before)

    def test_memory_list_trim_still_resolves_stack_via_thread_descriptor(self):
        blob = trim_stream(
            self.variants['complete'],
            MINIDUMP_STREAM_TYPE.MemoryListStream,
        )
        parsed = MinidumpFile.parse_buff(io.BytesIO(blob))
        report = parsed.investigate('crash')
        stack_state = self._coverage_by_value(report)['stack_memory']
        self.assertEqual(stack_state, 'resolved')
        thread_assessment = self._assessment(
            report, MINIDUMP_STREAM_TYPE.ThreadListStream,
        )
        self.assertEqual(thread_assessment.status, ReferenceStatus.RESOLVED)


if __name__ == '__main__':
    unittest.main()
