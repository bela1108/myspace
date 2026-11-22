#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
import datetime

import testtools

from bandit.exchange.errors import MappingValidationError
from bandit.exchange.model import (
    ContextMatcher,
    ExceptionMapping,
    Finding,
    TargetRule,
    utcnow,
)


def finding(**overrides):
    data = {
        "filename": "pkg/module.py",
        "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "issue_severity": "HIGH",
        "issue_confidence": "MEDIUM",
        "issue_text": "subprocess call with shell=True",
        "line_number": 12,
        "line_range": [12],
        "col_offset": 4,
        "code": "12 subprocess.Popen(cmd, shell=True)",
    }
    data.update(overrides)
    return Finding(data)


class FindingTests(testtools.TestCase):
    def test_identity_and_equality(self):
        first = finding()
        second = finding(issue_confidence="HIGH")
        third = finding(line_number=13)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertNotEqual(first, third)

    def test_unknown_context_field_rejected(self):
        with self.assertRaises(MappingValidationError):
            ContextMatcher({"not_a_field": "value"})

    def test_malformed_finding_input(self):
        with self.assertRaises(MappingValidationError):
            Finding("not-a-dict")


class ContextMatcherTests(testtools.TestCase):
    def test_scalar_means_equality(self):
        matcher = ContextMatcher({"test_id": "B602"})
        self.assertTrue(matcher.evaluate(finding()))
        self.assertFalse(matcher.evaluate(finding(test_id="B307")))

    def test_operators(self):
        sample = finding()
        self.assertTrue(
            ContextMatcher(
                {"line_number": {"op": "lte", "value": 12}}
            ).evaluate(sample)
        )
        self.assertFalse(
            ContextMatcher(
                {"line_number": {"op": "gt", "value": 12}}
            ).evaluate(sample)
        )
        self.assertTrue(
            ContextMatcher(
                {"filename": {"op": "glob", "value": "pkg/*.py"}}
            ).evaluate(sample)
        )
        self.assertTrue(
            ContextMatcher(
                {"issue_text": {"op": "regex", "value": "shell=True"}}
            ).evaluate(sample)
        )
        self.assertTrue(
            ContextMatcher(
                {
                    "test_id": {
                        "op": "in",
                        "value": ["B602", "B307"],
                    }
                }
            ).evaluate(sample)
        )
        self.assertTrue(
            ContextMatcher(
                {"code": {"op": "contains", "value": "Popen"}}
            ).evaluate(sample)
        )
        self.assertTrue(
            ContextMatcher(
                {"severity": {"op": "ne", "value": "LOW"}}
            ).evaluate(sample)
        )

    def test_all_conditions_must_match(self):
        matcher = ContextMatcher({
            "severity": "HIGH", "line_number": {"op": "gt", "value": 20}
        })
        self.assertFalse(matcher.evaluate(finding()))

    def test_unknown_operator_rejected(self):
        with self.assertRaises(MappingValidationError):
            ContextMatcher(
                {"line_number": {"op": "bogus", "value": 1}}
            ).evaluate(finding())


class ExceptionMappingTests(testtools.TestCase):
    def _payload(self, **overrides):
        payload = {
            "id": "EXC-1",
            "source_rule": "B602",
            "target_rules": [
                {"rule_id": "EXT-1", "conditions": {"severity": "HIGH"}},
                "EXT-2",
            ],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z",
        }
        payload.update(overrides)
        return payload

    def test_one_to_many_targets(self):
        mapping = ExceptionMapping.from_dict(self._payload())
        self.assertEqual(["EXT-1", "EXT-2"], mapping.target_ids())
        self.assertEqual(2, len(mapping.target_rules))

    def test_validity_window(self):
        mapping = ExceptionMapping.from_dict(self._payload())
        inside = datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc)
        before = datetime.datetime(2025, 12, 31, tzinfo=datetime.timezone.utc)
        after = datetime.datetime(2027, 1, 2, tzinfo=datetime.timezone.utc)
        self.assertTrue(mapping.is_active(inside))
        self.assertFalse(mapping.is_active(before))
        self.assertFalse(mapping.is_active(after))

    def test_open_ended_validity(self):
        mapping = ExceptionMapping.from_dict(
            self._payload(valid_from=None, valid_until=None)
        )
        self.assertTrue(mapping.is_active(utcnow()))

    def test_shared_and_target_context(self):
        mapping = ExceptionMapping.from_dict(
            self._payload(
                context={
                    "filename": {"op": "glob", "value": "pkg/*.py"}
                }
            )
        )
        target = mapping.target_rules[0]
        self.assertTrue(mapping.shared_matcher.evaluate(finding()))
        self.assertTrue(target.matcher.evaluate(finding()))

    def test_validation_failures(self):
        with self.assertRaises(MappingValidationError):
            ExceptionMapping.from_dict(self._payload(id=""))
        with self.assertRaises(MappingValidationError):
            ExceptionMapping.from_dict(self._payload(target_rules=[]))
        with self.assertRaises(MappingValidationError):
            ExceptionMapping.from_dict(
                self._payload(
                    valid_from="2027-01-01T00:00:00Z",
                    valid_until="2026-01-01T00:00:00Z",
                )
            )

    def test_round_trip(self):
        mapping = ExceptionMapping.from_dict(self._payload())
        encoded = mapping.as_dict()
        rebuilt = ExceptionMapping.from_dict(encoded)
        self.assertEqual(rebuilt.target_ids(), mapping.target_ids())
        self.assertEqual(rebuilt.valid_until, mapping.valid_until)
