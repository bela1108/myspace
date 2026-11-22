#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
import io
from unittest import mock
import json
import os
import tempfile

import testtools

from bandit.exchange import cli


class CliTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.report_path = os.path.join(self.tmp, "report.json")
        self.mapping_path = os.path.join(self.tmp, "mappings.json")
        with open(self.report_path, "w", encoding="utf-8") as handle:
            json.dump({
                "results": [
                    {
                        "filename": "a.py", "test_id": "B602",
                        "test_name": "shell", "issue_severity": "HIGH",
                        "issue_confidence": "MEDIUM", "issue_text": "shell",
                        "line_number": 1, "line_range": [1], "code": "1 x",
                    },
                    {
                        "filename": "b.py", "test_id": "B506",
                        "test_name": "yaml", "issue_severity": "MEDIUM",
                        "issue_confidence": "HIGH", "issue_text": "yaml",
                        "line_number": 2, "line_range": [2], "code": "2 y",
                    },
                ],
                "errors": [],
                "generated_at": "2026-06-01T00:00:00Z",
            }, handle)
        with open(self.mapping_path, "w", encoding="utf-8") as handle:
            json.dump({
                "document": "bandit-exception-mappings",
                "version": 1,
                "mappings": [
                    {
                        "id": "M1", "source_rule": "B602",
                        "target_rules": ["EXT-1"],
                        "valid_from": "2025-06-01T00:00:00Z",
                        "valid_until": "2027-01-01T00:00:00Z",
                    },
                    {
                        "id": "M2", "source_rule": "B506",
                        "target_rules": ["EXT-2"],
                        "valid_until": "2025-01-01T00:00:00Z",
                    },
                ],
            }, handle)

    def _run(self, *argv):
        return cli.main(list(argv))

    def test_views_command_stdout(self):
        stream = io.StringIO()
        with mock.patch("sys.stdout", stream):
            code = self._run("views", self.report_path, self.mapping_path)
            self.assertEqual(0, code)
        payload = json.loads(stream.getvalue())
        self.assertIn("local", payload)
        self.assertIn("exchange", payload)

    def test_local_and_exchange_subcommands(self):
        for command, key in (("local", "view"), ("exchange", "view")):
            stream = io.StringIO()
            with mock.patch("sys.stdout", stream):
                code = self._run(command, self.report_path, self.mapping_path)
                self.assertEqual(0, code)
            payload = json.loads(stream.getvalue())
            self.assertEqual(command, payload[key])

    def test_output_to_file(self):
        out_path = os.path.join(self.tmp, "out.json")
        code = self._run(
            "views", self.report_path, self.mapping_path, "-o", out_path
        )
        self.assertEqual(0, code)
        with open(out_path, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertIn("local", payload)

    def test_validate_command(self):
        stream = io.StringIO()
        with mock.patch("sys.stdout", stream):
            code = self._run("validate", self.mapping_path)
            self.assertEqual(0, code)
        self.assertEqual(2, json.loads(stream.getvalue())["mapping_count"])

    def test_drop_only_removes_named_approval(self):
        stream = io.StringIO()
        with mock.patch("sys.stdout", stream):
            code = self._run("drop", self.report_path, self.mapping_path, "M1")
            self.assertEqual(0, code)
        payload = json.loads(stream.getvalue())
        self.assertEqual(["M1"], payload["removed_mapping_ids"])
        external = {
            rule["external_rule"]: rule
            for rule in payload["views"]["exchange"]["rules"]
        }
        self.assertNotIn("EXT-1", external)
        self.assertIn("EXT-2", external)

    def test_invalid_report_returns_error_code(self):
        bad_path = os.path.join(self.tmp, "bad.json")
        with open(bad_path, "w", encoding="utf-8") as handle:
            handle.write("{broken")
        code = self._run("views", bad_path, self.mapping_path)
        self.assertEqual(2, code)

    def test_at_option_overrides_reference_time(self):
        stream = io.StringIO()
        with mock.patch("sys.stdout", stream):
            code = self._run(
                "exchange", self.report_path, self.mapping_path,
            "--at", "2024-01-01T00:00:00Z"
        )
        self.assertEqual(0, code)
        payload = json.loads(stream.getvalue())
        states = {
            d["external_rule"]: d["state"]
            for rule in payload["view_data"]["rules"]
            for d in rule["decisions"]
        }
        self.assertEqual("EXPIRED", states["EXT-1"])
