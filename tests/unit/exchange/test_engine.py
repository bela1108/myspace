#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
import datetime
import json

import testtools

from bandit.exchange.engine import ExceptionExchange
from bandit.exchange.errors import MappingValidationError
from bandit.exchange.model import (
    APPROVED,
    CONFLICT,
    EXPIRED,
    MISSING_EVIDENCE,
    NO_MATCH,
    ExceptionMapping,
    Finding,
)

NOW = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)


def finding(test_id, line, severity="HIGH", filename="pkg/a.py", text="issue"):
    return Finding({
        "filename": filename,
        "test_id": test_id,
        "test_name": "plugin_" + test_id.lower(),
        "issue_severity": severity,
        "issue_confidence": "MEDIUM",
        "issue_text": text,
        "line_number": line,
        "line_range": [line],
        "code": f"{line} risky call",
    })


def mapping(mapping_id, source, targets, **kwargs):
    payload = {
        "id": mapping_id,
        "source_rule": source,
        "target_rules": targets,
        "valid_until": "2027-01-01T00:00:00Z",
    }
    payload.update(kwargs)
    return ExceptionMapping.from_dict(payload)


class EngineDecisionTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.findings = [
            finding("B602", 10, severity="HIGH"),
            finding("B602", 20, severity="LOW"),
            finding("B506", 5, severity="MEDIUM"),
        ]

    def test_approved_when_context_matches_within_validity(self):
        mappings = [mapping("M1", "B602", ["EXT-1"])]
        exchange = ExceptionExchange(self.findings, mappings, now=NOW)
        decision = exchange.decisions[0]
        self.assertEqual(APPROVED, decision.state)
        self.assertEqual(2, len(decision.matched_findings))

    def test_each_target_evaluates_own_context(self):
        targets = [
            {"rule_id": "EXT-HIGH", "conditions": {"severity": "HIGH"}},
            {
                "rule_id": "EXT-LINE",
                "conditions": {
                    "line_number": {"op": "gte", "value": 15}
                },
            },
        ]
        exchange = ExceptionExchange(
            self.findings, [mapping("M1", "B602", targets)], now=NOW
        )
        by_rule = {d.external_rule: d for d in exchange.decisions}
        self.assertEqual(
            [10], [f.line_number for f in by_rule["EXT-HIGH"].matched_findings]
        )
        self.assertEqual(
            [20], [f.line_number for f in by_rule["EXT-LINE"].matched_findings]
        )

    def test_shared_context_applies_to_every_target(self):
        mappings = [mapping(
            "M1", "B602", ["EXT-1"],
            context={"severity": "LOW"},
        )]
        exchange = ExceptionExchange(self.findings, mappings, now=NOW)
        low_line = exchange.decisions[0].matched_findings
        self.assertEqual([20], [f.line_number for f in low_line])

    def test_expired_mapping_not_approved(self):
        mappings = [mapping(
            "M1", "B602", ["EXT-1"], valid_until="2025-01-01T00:00:00Z"
        )]
        exchange = ExceptionExchange(self.findings, mappings, now=NOW)
        self.assertEqual(EXPIRED, exchange.decisions[0].state)
        self.assertEqual(0, len(exchange.approved_findings()))

    def test_not_yet_valid_mapping_is_expired_state(self):
        mappings = [mapping(
            "M1", "B602", ["EXT-1"], valid_from="2027-01-01T00:00:00Z"
        )]
        exchange = ExceptionExchange(self.findings, mappings, now=NOW)
        self.assertEqual(EXPIRED, exchange.decisions[0].state)

    def test_missing_evidence_when_check_not_evidenced(self):
        mappings = [mapping("M1", "B999", ["EXT-GHOST"])]
        exchange = ExceptionExchange(self.findings, mappings, now=NOW)
        decision = exchange.decisions[0]
        self.assertEqual(MISSING_EVIDENCE, decision.state)
        self.assertEqual(0, len(decision.matched_findings))

    def test_no_match_when_context_never_satisfied(self):
        targets = [{"rule_id": "EXT-1", "conditions": {"severity": "LOW"}}]
        mappings = [mapping("M1", "B506", targets)]
        exchange = ExceptionExchange(self.findings, mappings, now=NOW)
        self.assertEqual(NO_MATCH, exchange.decisions[0].state)

    def test_duplicate_mapping_id_rejected(self):
        mappings = [
            mapping("DUP", "B602", ["EXT-1"]),
            mapping("DUP", "B506", ["EXT-2"]),
        ]
        with self.assertRaises(MappingValidationError):
            ExceptionExchange(self.findings, mappings, now=NOW)


class ConflictTests(testtools.TestCase):
    def test_conflicting_mappings_keep_both_opinions(self):
        findings = [finding("B602", 1), finding("B307", 2)]
        mappings = [
            mapping("M1", "B602", ["EXT-DUP"]),
            mapping("M2", "B307", ["EXT-DUP"]),
        ]
        exchange = ExceptionExchange(findings, mappings, now=NOW)
        self.assertEqual(1, len(exchange.conflicts))
        conflict = exchange.conflicts[0]
        self.assertEqual("EXT-DUP", conflict["external_rule"])
        self.assertEqual(["B307", "B602"], conflict["source_rules"])
        for decision in exchange.decisions:
            self.assertEqual(CONFLICT, decision.state)
            self.assertEqual(1, len(decision.conflict_with))
        self.assertEqual(0, len(exchange.approved_findings()))

    def test_same_external_rule_from_same_source_is_not_conflict(self):
        findings = [finding("B602", 1)]
        mappings = [
            mapping("M1", "B602", ["EXT-DUP"]),
            mapping("M2", "B602", ["EXT-DUP"]),
        ]
        exchange = ExceptionExchange(findings, mappings, now=NOW)
        self.assertEqual(0, len(exchange.conflicts))
        self.assertTrue(all(d.state == APPROVED for d in exchange.decisions))


class DropMappingTests(testtools.TestCase):
    def test_dropping_one_mapping_only_removes_its_approval(self):
        findings = [finding("B602", 1), finding("B506", 2, severity="MEDIUM")]
        mappings = [
            mapping("KEEP", "B602", ["EXT-KEEP"]),
            mapping("DROP", "B506", ["EXT-DROP"]),
        ]
        exchange = ExceptionExchange(findings, mappings, now=NOW)
        self.assertEqual(2, len(exchange.approved_findings()))
        reduced = exchange.without_mappings(["DROP"])
        remaining = reduced.approved_findings()
        self.assertEqual(1, len(remaining))
        self.assertEqual("B602", next(iter(remaining)).test_id)
        states = {d.external_rule: d.state for d in reduced.decisions}
        self.assertNotIn("EXT-DROP", states)
        self.assertEqual(APPROVED, states["EXT-KEEP"])

    def test_views_agree_on_same_evaluation(self):
        findings = [finding("B602", 1), finding("B506", 2, severity="MEDIUM")]
        mappings = [mapping("M1", "B602", ["EXT-1", "EXT-2"])]
        exchange = ExceptionExchange(findings, mappings, now=NOW)
        views = exchange.build_views()
        local_approved = [
            item
            for rule in views["local"]["rules"]
            for item in rule["findings"]
            if item["approved"]
        ]
        exchange_approved = [
            rule
            for rule in views["exchange"]["rules"]
            if rule["has_approval"]
        ]
        self.assertEqual(1, len(local_approved))
        self.assertEqual(2, len(exchange_approved))
        self.assertEqual("local", views["local"]["view"])
        self.assertEqual("exchange", views["exchange"]["view"])
        json.dumps(views)

    def test_dropping_unknown_mapping_is_noop(self):
        mappings = [mapping("M1", "B602", ["EXT-1"])]
        exchange = ExceptionExchange([finding("B602", 1)], mappings, now=NOW)
        reduced = exchange.without_mappings(["DOES-NOT-EXIST"])
        self.assertEqual(1, len(reduced.approved_findings()))
