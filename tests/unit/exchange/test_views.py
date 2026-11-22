#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
import json

import testtools

from bandit.exchange.mapping import load_mappings
from bandit.exchange.report import load_report
from bandit.exchange.views import (
    build_exchange,
    export_exchange_view,
    export_local_view,
    export_views,
)

NOW_KW = {}


def report():
    return load_report({
        "results": [
            {
                "filename": "pkg/a.py", "test_id": "B602",
                "test_name": "shell", "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "issue_text": "shell=True", "line_number": 4,
                "line_range": [4], "code": "4 Popen()",
            },
            {
                "filename": "pkg/b.py", "test_id": "B506",
                "test_name": "yaml", "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": "yaml.load", "line_number": 9,
                "line_range": [9], "code": "9 yaml.load()",
            },
            {
                "filename": "pkg/b.py", "test_id": "B900",
                "test_name": "ghost", "issue_severity": "LOW",
                "issue_confidence": "LOW", "issue_text": "other",
                "line_number": 1, "line_range": [1],
                "code": "1 other()",
            },
        ],
        "errors": [{"filename": "skip.py", "reason": "syntax error"}],
        "generated_at": "2026-05-01T00:00:00Z",
    })


def mappings():
    return load_mappings({
        "document": "bandit-exception-mappings",
        "version": 1,
        "mappings": [
            {
                "id": "M1", "source_rule": "B602",
                "target_rules": ["EXT-SHELL", "EXT-AUDIT"],
                "valid_until": "2027-01-01T00:00:00Z",
            },
            {
                "id": "M2", "source_rule": "B506",
                "target_rules": [
                    {
                        "rule_id": "EXT-YAML",
                        "conditions": {
                            "line_number": {"op": "gte", "value": 10}
                        },
                    }
                ],
                "valid_until": "2027-01-01T00:00:00Z",
            },
            {
                "id": "M3", "source_rule": "B777",
                "target_rules": ["EXT-MISSING"],
                "valid_until": "2027-01-01T00:00:00Z",
            },
        ],
    })


class ViewExportTests(testtools.TestCase):
    def test_both_views_share_one_envelope_source(self):
        exported = export_views(report(), mappings())
        self.assertEqual(
            "bandit-exception-view",
            exported["local"]["document"],
        )
        self.assertEqual(
            "bandit-exception-view",
            exported["exchange"]["document"],
        )
        self.assertEqual(
            "2026-05-01T00:00:00Z",
            exported["local"]["source_report_generated_at"],
        )
        self.assertEqual(1, len(exported["local"]["errors"]))

    def test_local_view_marks_approved_findings(self):
        exported = export_local_view(report(), mappings())
        rules = {r["source_rule"]: r for r in exported["view_data"]["rules"]}
        shell_finding = rules["B602"]["findings"][0]
        self.assertTrue(shell_finding["approved"])
        self.assertEqual(["M1"], shell_finding["approved_by"])
        self.assertFalse(rules["B900"]["approved"])
        self.assertEqual([], rules["B900"]["findings"][0]["approved_by"])

    def test_exchange_view_records_each_decision_state(self):
        exported = export_exchange_view(report(), mappings())
        rules = {r["external_rule"]: r for r in exported["view_data"]["rules"]}
        self.assertTrue(rules["EXT-SHELL"]["has_approval"])
        self.assertTrue(rules["EXT-AUDIT"]["has_approval"])
        yaml_decision = rules["EXT-YAML"]["decisions"][0]
        self.assertEqual("NO_MATCH", yaml_decision["state"])
        missing = rules["EXT-MISSING"]["decisions"][0]
        self.assertEqual("MISSING_EVIDENCE", missing["state"])

    def test_views_are_json_serializable(self):
        json.dumps(export_views(report(), mappings()))

    def test_dropping_mapping_only_loses_that_approval(self):
        exchange = build_exchange(report(), mappings())
        reduced = exchange.without_mappings(["M1"])
        approved = reduced.approved_findings()
        self.assertTrue(all(f.test_id != "B602" for f in approved))
        external_rules = {
            r["external_rule"]
            for r in reduced.exchange_view()["rules"]
        }
        self.assertNotIn("EXT-SHELL", external_rules)
        self.assertNotIn("EXT-AUDIT", external_rules)
        remaining = reduced.exchange_view()["rules"]
        self.assertIn("EXT-YAML", {r["external_rule"] for r in remaining})

    def test_legacy_report_flag_propagates(self):
        loaded = report()
        loaded["legacy"] = True
        exported = export_views(loaded, mappings())
        self.assertTrue(exported["local"]["legacy_report"])
        self.assertTrue(exported["exchange"]["legacy_report"])
