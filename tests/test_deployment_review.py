"""Tests for offline review of file-grouped YARA deployments."""
import json
import pathlib
import unittest

from plyara import Plyara
from plyara.deployment import Approval
from plyara.deployment import DeploymentManifest
from plyara.deployment import Review
from plyara.deployment import load_approvals
from plyara.deployment import load_file_group
from plyara.deployment import load_manifest
from plyara.deployment import parse_file_group
from plyara.deployment import resolve_deployment
from plyara.deployment import review_combinations
from plyara.deployment import upgrade_file_group


DATA = pathlib.Path(__file__).parent / 'data' / 'deployment'


class DeploymentReviewTest(unittest.TestCase):
    """Resolve manifests, trace approvals and build legal subsets."""

    def setUp(self):
        """Load the synthetic file groups used by the tests."""
        self.base = load_file_group('base', DATA / 'base.yar')
        self.windows = load_file_group('windows', DATA / 'windows.yar')
        self.extras_v1 = load_file_group(
            'extras', DATA / 'extras_v1.yar', optional=True, version='1.0'
        )
        self.windows_manifest = load_manifest(DATA / 'manifest_windows.json')

    def approvals(self):
        """Return the approval ledger shared by the deployment scenarios."""
        return [
            Approval(
                'APR-BASE-SHARED',
                'REV-BASE-01',
                rule='base_shared',
                group='base',
                source='reviews/2026-q1.json',
                review_ref='item 3',
            ),
            Approval(
                'APR-BASE-ALPHA',
                'REV-BASE-02',
                rule='base_alpha',
                group='base',
                source='reviews/2026-q1.json',
                review_ref='item 4',
            ),
            Approval(
                'APR-WIN-ALPHA',
                'REV-WIN-07',
                rule='windows_alpha',
                group='windows',
                selector_key='deploy',
                selector_value='windows',
                source='reviews/2026-q1.json',
                review_ref='item 9',
            ),
            Approval(
                'APR-UPGRADED',
                'REV-EXTRA-02',
                rule='extras_upgraded',
                group='extras',
                combination='upgraded',
            ),
            Approval(
                'APR-LEGACY',
                'REV-EXTRA-01',
                rule='extras_legacy',
                group='extras',
                combination='legacy',
                status='withdrawn',
                source='reviews/legacy.json',
            ),
        ]

    def test_manifest_resolves_effective_items_by_shared_metadata(self):
        """Verify that the same metadata key selects rules from several file groups."""
        report = resolve_deployment(
            self.windows_manifest,
            {'base': self.base, 'windows': self.windows},
            self.approvals(),
        )

        self.assertTrue(report.reviewable)
        self.assertEqual(
            [item.rule_id for item in report.enabled_items],
            ['base/base_alpha', 'base/base_shared', 'windows/windows_alpha'],
        )
        self.assertNotIn('base/base_linux', [item.rule_id for item in report.selected_items])
        alpha = report.item('base/base_alpha')
        self.assertEqual(alpha.selector_values, {'deploy': ('base', 'windows')})
        json.dumps(report.to_dict(), ensure_ascii=False)

    def test_trace_identifies_the_existing_review_segment(self):
        """Check that each allowed item points back to its approval and review row."""
        report = resolve_deployment(
            self.windows_manifest,
            {'base': self.base, 'windows': self.windows},
            self.approvals(),
        )

        trace = report.approval_traces('windows/windows_alpha')[0]
        self.assertEqual(trace.approval_id, 'APR-WIN-ALPHA')
        self.assertEqual(trace.review_id, 'REV-WIN-07')
        self.assertEqual(trace.combination, 'windows-live')
        self.assertEqual(trace.source, 'reviews/2026-q1.json')
        self.assertEqual(trace.review_ref, 'item 9')
        self.assertIn('rule:windows_alpha', trace.matched_on)
        self.assertIn('metadata:deploy=windows', trace.matched_on)
        self.assertIn('APR-WIN-ALPHA', report.item('windows/windows_alpha').approval_ids)

    def test_review_wrapper_supplies_missing_review_identity(self):
        """Verify that an approval grouped inside a review inherits the review identity."""
        approvals = [
            item for item in self.approvals() if item.approval_id != 'APR-WIN-ALPHA'
        ]
        approvals.append(Review(
            'REV-WIN-WRAPPED',
            (Approval('APR-WIN-WRAPPED', rule='windows_alpha', group='windows'),),
            source='reviews/windows.json',
        ))

        report = resolve_deployment(
            self.windows_manifest,
            {'base': self.base, 'windows': self.windows},
            approvals,
        )

        trace = report.approval_traces('windows/windows_alpha')[0]
        self.assertEqual(trace.review_id, 'REV-WIN-WRAPPED')
        self.assertEqual(trace.source, 'reviews/windows.json')

    def test_json_manifest_and_approval_ledger_are_loadable(self):
        """Verify that the offline inputs can be loaded from JSON files."""
        report = resolve_deployment(
            self.windows_manifest,
            {'base': self.base, 'windows': self.windows},
            load_approvals(DATA / 'approvals.json'),
        )

        self.assertTrue(report.reviewable)
        trace = report.approval_traces('windows/windows_alpha')[0]
        self.assertEqual(trace.review_id, 'REV-WIN')
        self.assertEqual(trace.source, 'reviews/windows.json')

    def test_partial_approval_builds_a_reparseable_subset(self):
        """Check that only approved rules are rendered when one selected rule is missing."""
        approvals = [
            item for item in self.approvals()
            if item.approval_id in ('APR-BASE-SHARED', 'APR-BASE-ALPHA')
        ]
        report = resolve_deployment(
            self.windows_manifest,
            {'base': self.base, 'windows': self.windows},
            approvals,
        )

        self.assertFalse(report.reviewable)
        self.assertEqual(report.subset_rule_ids, ('base/base_shared', 'base/base_alpha'))
        self.assertNotIn('windows_alpha', report.subset_text)
        self.assertEqual(report.verification_issues, ())

        missing = report.missing_for('windows/windows_alpha')
        self.assertIsNotNone(missing)
        self.assertEqual(missing.reason, 'no_approval')
        self.assertEqual(missing.required_selector, ('deploy', ('windows',)))
        self.assertIn('deploy=windows', missing.message)
        self.assertFalse(report.item('windows/windows_alpha').allowed)

        reparsed = Plyara().parse_string(report.subset_text)
        self.assertEqual(
            [entry['rule_name'] for entry in reparsed],
            ['base_shared', 'base_alpha'],
        )

    def test_dependency_is_pulled_in_without_becoming_enabled_root(self):
        """Verify that a referenced rule outside the selector result is still included."""
        manifest = DeploymentManifest(
            'alpha-only',
            groups=('base',),
            selectors={'deploy': {'windows'}},
            enabled_rules=('base_alpha',),
        )
        approvals = [
            Approval('APR-ALPHA', rule='base_alpha'),
            Approval('APR-SHARED', rule='base_shared'),
        ]

        report = resolve_deployment(manifest, self.base, approvals)

        self.assertTrue(report.reviewable)
        self.assertEqual([item.rule_id for item in report.enabled_items], ['base/base_alpha'])
        self.assertEqual([item.rule_id for item in report.dependencies], ['base/base_shared'])
        self.assertEqual(report.subset_rule_ids, ('base/base_shared', 'base/base_alpha'))

    def test_missing_dependency_approval_names_the_dependency(self):
        """Check that an unapproved dependency blocks its root and is named exactly."""
        manifest = DeploymentManifest(
            'alpha-only',
            groups=('base',),
            selectors={'deploy': {'windows'}},
            enabled_rules=('base_alpha',),
        )
        report = resolve_deployment(
            manifest,
            self.base,
            [Approval('APR-ALPHA', rule='base_alpha')],
        )

        self.assertFalse(report.reviewable)
        missing = report.missing_for('base/base_shared')
        self.assertIsNotNone(missing)
        self.assertEqual(missing.reason, 'no_approval')
        self.assertEqual(missing.required_by, 'base/base_alpha')
        self.assertEqual(report.subset_rule_ids, ())
        self.assertIn(
            'blocked_by_dependency:base/base_shared',
            report.item('base/base_alpha').reasons,
        )

    def test_imports_are_emitted_once_and_dependencies_are_ordered_first(self):
        """Verify that the subset is self-contained enough to parse and resolve references."""
        group = parse_file_group('imports', '''
import "math"

rule import_base
{
    condition:
        true
}

rule import_user
{
    condition:
        math.entropy(0, filesize) > 0.0 and import_base
}
''')
        manifest = DeploymentManifest(
            'imports-combo',
            groups=('imports',),
            enabled_rules=('import_user',),
        )
        approvals = [
            Approval('APR-IMPORT-USER', rule='import_user'),
            Approval('APR-IMPORT-BASE', rule='import_base'),
        ]

        report = resolve_deployment(manifest, group, approvals)

        self.assertTrue(report.reviewable)
        self.assertEqual(report.subset_imports, ('math',))
        self.assertEqual(report.subset_rule_ids, ('imports/import_base', 'imports/import_user'))
        self.assertTrue(report.subset_text.startswith('import "math"'))
        self.assertEqual(report.subset_text.count('import "math"'), 1)

    def test_optional_group_upgrade_makes_one_combination_reviewable(self):
        """Check that after the optional pack upgrade only the approved combination passes."""
        upgraded = load_manifest(DATA / 'manifest_upgraded.json')
        legacy = load_manifest(DATA / 'manifest_legacy.json')
        approvals = self.approvals()

        before = review_combinations(
            [upgraded, legacy],
            {'base': self.base, 'extras': self.extras_v1},
            approvals,
        )
        self.assertFalse(before['upgraded'].reviewable)
        self.assertEqual(
            before['upgraded'].missing_for('extras_upgraded').reason,
            'rule_not_installed',
        )
        self.assertFalse(before['legacy'].reviewable)

        upgraded_group = upgrade_file_group(
            self.extras_v1, DATA / 'extras_v2.yar', version='2.0'
        )
        after = review_combinations(
            [upgraded, legacy],
            {'base': self.base, 'extras': upgraded_group},
            approvals,
        )

        self.assertEqual(upgraded_group.version, '2.0')
        self.assertTrue(upgraded_group.optional)
        self.assertTrue(after['upgraded'].reviewable)
        self.assertEqual(
            after['upgraded'].subset_rule_ids,
            ('base/base_shared', 'base/base_alpha', 'extras/extras_upgraded'),
        )
        self.assertIn('extras_upgraded', after['upgraded'].subset_text)

        legacy_report = after['legacy']
        self.assertFalse(legacy_report.reviewable)
        missing = legacy_report.missing_for('extras/extras_legacy')
        self.assertIsNotNone(missing)
        self.assertEqual(missing.reason, 'inactive_approval')
        self.assertEqual(
            [trace.approval_id for trace in missing.rejected_approvals],
            ['APR-LEGACY'],
        )
        self.assertIn('APR-LEGACY', missing.message)
        self.assertNotIn('extras_legacy', legacy_report.subset_text)

    def test_missing_optional_group_is_reported_precisely(self):
        """Verify that a manifest can mark the absent optional group as the blocker."""
        manifest = DeploymentManifest(
            'needs-extras',
            groups=('base', 'extras'),
            optional_groups=('extras',),
            required_rules=('extras_upgraded',),
        )
        report = resolve_deployment(manifest, self.base, self.approvals())

        self.assertFalse(report.reviewable)
        missing_group = report.missing_for('group/extras')
        self.assertIsNotNone(missing_group)
        self.assertEqual(missing_group.reason, 'optional_group_not_installed')

    def test_external_variable_can_be_declared_in_the_manifest(self):
        """Verify that declared external variables do not create false misses."""
        group = parse_file_group(
            'external',
            'rule external_rule { condition: external_flag and true }',
        )
        manifest = DeploymentManifest(
            'external-combo',
            groups=('external',),
            required_rules=('external_rule',),
            external_variables=('external_flag',),
        )

        report = resolve_deployment(
            manifest,
            group,
            [Approval('APR-EXTERNAL', rule='external_rule')],
        )

        self.assertTrue(report.reviewable)
        self.assertEqual(report.verification_issues, ())

    def test_same_named_rules_are_collapsed_only_when_identical(self):
        """Verify that duplicate names either collapse safely or block the subset."""
        first = parse_file_group('first', 'rule duplicate_name { condition: true }')
        same = parse_file_group('same', 'rule duplicate_name { condition: true }')
        different = parse_file_group('different', 'rule duplicate_name { condition: false }')
        approvals = [Approval('APR-DUPLICATE', rule='duplicate_name')]

        merged = resolve_deployment(
            DeploymentManifest('merged', groups=('first', 'same'), required_rules=('duplicate_name',)),
            {'first': first, 'same': same},
            approvals,
        )
        self.assertTrue(merged.reviewable)
        self.assertEqual(merged.subset_rule_ids, ('first/duplicate_name',))
        self.assertIn('duplicate_rule_deduplicated', [item.kind for item in merged.findings])

        conflict = resolve_deployment(
            DeploymentManifest('conflict', groups=('first', 'different'), required_rules=('duplicate_name',)),
            {'first': first, 'different': different},
            approvals,
        )
        self.assertFalse(conflict.reviewable)
        self.assertEqual(conflict.subset_rule_ids, ())
        self.assertIn('duplicate_rule_name', [item.kind for item in conflict.findings])


if __name__ == '__main__':
    unittest.main()
