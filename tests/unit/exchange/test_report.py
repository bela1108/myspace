#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
import json

import testtools

from bandit.exchange.errors import ReportValidationError
from bandit.exchange.report import (
    load_legacy_baseline_text,
    load_report,
    load_report_text,
)


class ReportLoaderTests(testtools.TestCase):
    def _report(self, **overrides):
        payload = {
            "results": [
                {
                    "filename": "a.py",
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "issue_text": "assert",
                    "line_number": 3,
                    "line_range": [3],
                    "code": "3 assert True",
                }
            ],
            "errors": [],
            "metrics": {},
            "generated_at": "2026-01-01T00:00:00Z",
        }
        payload.update(overrides)
        return payload

    def test_loads_modern_report(self):
        loaded = load_report(self._report())
        self.assertEqual(1, len(loaded["findings"]))
        self.assertEqual("B101", loaded["findings"][0].test_id)
        self.assertFalse(loaded["legacy"])
        self.assertEqual("2026-01-01T00:00:00Z", loaded["generated_at"])

    def test_legacy_baseline_remains_readable(self):
        text = json.dumps(self._report())
        loaded = load_legacy_baseline_text(text)
        self.assertTrue(loaded["legacy"])
        self.assertEqual(1, len(loaded["findings"]))

    def test_older_report_without_optional_fields(self):
        minimal = {
            "results": [
                {
                    "test_id": "B101",
                    "filename": "a.py",
                    "line_number": 1,
                    "issue_text": "x",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                }
            ]
        }
        loaded = load_report(minimal)
        self.assertEqual([], loaded["findings"][0].line_range)
        self.assertEqual("", loaded["findings"][0].code)

    def test_invalid_json_rejected(self):
        with self.assertRaises(ReportValidationError):
            load_report_text("{not json")

    def test_missing_results_rejected(self):
        with self.assertRaises(ReportValidationError):
            load_report({"metrics": {}})

    def test_non_object_entry_rejected(self):
        with self.assertRaises(ReportValidationError):
            load_report({"results": ["nope"]})
