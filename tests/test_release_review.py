"""Unit tests for the release-review helpers."""
import datetime
import unittest

from plyara.core import Plyara
from plyara.release_review import review_release
from plyara.utils import generate_hash


class TestReleaseReview(unittest.TestCase):
    """Check release review decisions driven by sample retention and coverage."""

    def setUp(self):
        """Build a colour-tagged ruleset used by the review tests."""
        self.rules = """
rule red_rule : red
{
    meta:
        display_name = "Red detector"
    strings:
        $red = "red-sample"
    condition:
        $red
}

rule blue_rule : blue
{
    meta:
        display_name = "Blue detector"
    strings:
        $blue = "blue-sample"
    condition:
        $blue
}
"""
        self.now = datetime.datetime(2026, 11, 21, 12, 0, 1, tzinfo=datetime.timezone.utc)

    def test_shared_sample_coverage_is_evaluated_per_rule(self):
        """Verify that a shared sample keeps only the coverage promised to each rule."""
        evidence = [
            {'id': 'ev-red', 'rule': 'red_rule', 'samples': ['shared'], 'approved': True},
            {'id': 'ev-blue', 'rule': 'blue_rule', 'samples': ['shared'], 'approved': True},
        ]
        commitments = {
            'shared': {
                'retention_until': datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc),
                'coverage': {
                    'red_rule': ['red'],
                    'blue_rule': ['red'],
                },
            },
        }

        report = review_release(self.rules, evidence, sample_commitments=commitments, now=self.now)

        self.assertEqual(report.valid_evidence_ids, ['ev-red'])
        self.assertEqual(report.pending_rule_names, ['blue_rule'])
        self.assertIn('missing_coverage:blue', report.pending_rule_details[0]['reasons'])

    def test_just_expired_sample_requires_substitute_per_rule(self):
        """Verify that the retention instant expires samples and substitutes are per rule."""
        rules = """
rule amber_rule : amber
{
    strings:
        $amber = "amber-sample"
    condition:
        $amber
}

rule green_rule : green
{
    strings:
        $green = "green-sample"
    condition:
        $green
}
"""
        evidence = [
            {'id': 'ev-amber', 'rule': 'amber_rule', 'samples': ['old'], 'approved': True},
            {'id': 'ev-green', 'rule': 'green_rule', 'samples': ['old'], 'approved': True},
        ]
        commitments = {
            'old': {
                'retention_until': datetime.datetime(2026, 11, 21, 12, 0, 0, tzinfo=datetime.timezone.utc),
                'coverage': {
                    'amber_rule': ['amber'],
                    'green_rule': ['green'],
                },
            },
            'replacement': {
                'retention_until': datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc),
                'coverage': {'amber_rule': ['amber']},
            },
        }
        substitutes = {'old': {'amber_rule': 'replacement'}}

        report = review_release(
            rules,
            evidence,
            sample_commitments=commitments,
            substitute_samples=substitutes,
            now=self.now,
        )

        self.assertEqual(report.valid_evidence_ids, ['ev-amber'])
        self.assertEqual(report.pending_rule_names, ['green_rule'])
        self.assertIn('expired:old', report.pending_rule_details[0]['reasons'])

    def test_display_name_change_does_not_trigger_review(self):
        """Verify that content identity ignores the display name and presentation metadata."""
        original = """
rule keeper : keeper
{
    meta:
        display_name = "Friendly name"
    strings:
        $a = "stable-content"
    condition:
        $a
}
"""
        renamed = """
rule keeper_new_name : keeper
{
    meta:
        display_name = "A completely different display name"
    strings:
        $a = "stable-content"
    condition:
        $a
}
"""
        changed = """
rule keeper_new_name : keeper
{
    meta:
        display_name = "A completely different display name"
    strings:
        $a = "changed-content"
    condition:
        $a
}
"""
        original_rule = Plyara().parse_string(original)[0]
        evidence = [{
            'id': 'ev-keeper',
            'rule_hash': generate_hash(original_rule),
            'samples': ['keeper-sample'],
            'approved': True,
        }]
        commitments = {
            'keeper-sample': {
                'retention_until': datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc),
                'coverage': ['keeper'],
            },
        }

        report = review_release(renamed, evidence, sample_commitments=commitments, now=self.now)
        self.assertEqual(report.valid_evidence_ids, ['ev-keeper'])
        self.assertEqual(report.pending_rule_names, [])

        changed_report = review_release(changed, evidence, sample_commitments=commitments, now=self.now)
        self.assertEqual(changed_report.valid_evidence_ids, [])
        self.assertEqual(changed_report.pending_rule_names, ['keeper_new_name'])

    def test_evidence_is_derived_from_rule_metadata(self):
        """Verify that approval ID, samples and coverage can come from rule metadata."""
        rules = """
rule metadata_rule : gold
{
    meta:
        approval_id = "ev-metadata"
        samples = "metadata-sample"
        approved = true
        coverage = "gold"
    strings:
        $a = "metadata-content"
    condition:
        $a
}
"""
        commitments = {
            "metadata-sample": {
                "retention_until": datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc),
                "coverage": ["gold"],
            },
        }

        report = review_release(rules, sample_commitments=commitments, now=self.now)

        self.assertEqual(report.valid_evidence_ids, ["ev-metadata"])
        self.assertEqual(report.pending_rule_names, [])

    def test_approved_snapshot_name_maps_to_current_rule(self):
        """Verify that a renamed rule still matches evidence from the approved snapshot."""
        approved = """
rule approved_name : red
{
    strings:
        $a = "same-content"
    condition:
        $a
}
"""
        current = """
rule current_name : red
{
    meta:
        display_name = "Renamed for display"
    strings:
        $a = "same-content"
    condition:
        $a
}
"""
        evidence = [{"id": "ev-approved", "rule": "approved_name", "samples": ["s"], "approved": True}]
        commitments = {
            "s": {
                "retention_until": datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc),
                "coverage": ["red"],
            },
        }

        report = review_release(
            current,
            evidence,
            sample_commitments=commitments,
            approved_rules=approved,
            now=self.now,
        )

        self.assertEqual(report.valid_evidence_ids, ["ev-approved"])
        self.assertEqual(report.pending_rule_names, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
