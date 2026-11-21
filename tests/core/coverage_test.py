import json
import os
import shutil
import sys

import pytest

from detect_secrets.core import coverage
from detect_secrets.settings import default_settings


DEMO_ROOT = os.path.join('test_data', 'coverage_demo')
PROJECTS = ('project_alpha', 'project_beta', 'project_gamma')
MIN_GROUP_SIZE = 3


def scan(*paths, root=''):
    with default_settings():
        return coverage.scan_coverage(*paths, should_scan_all_files=True, root=root)


def export(*paths, root='', min_group_size=MIN_GROUP_SIZE):
    return scan(*paths, root=root).export(min_group_size)


class TestExport:
    def test_contains_no_per_finding_fingerprints(self):
        report = export(DEMO_ROOT)

        coverage.assert_report_anonymized(report)
        blob = json.dumps(report)
        for fragment in ('hashed_secret', 'line_number', 'config.py', 'locked.env'):
            assert fragment not in blob

    def test_file_outcomes_are_distinguished(self):
        report = export(DEMO_ROOT)

        # 6 readable text files, 1 non-text file (logo.png) legitimately
        # skipped by the default filters, and nothing failed.
        assert report['coverage'] == {
            'scanned_files': 6,
            'skipped_files': 1,
            'failed_files': 0,
        }

    @pytest.mark.skipif(
        sys.platform == 'win32'
        or (hasattr(os, 'geteuid') and os.geteuid() == 0),
        reason='chmod-based unreadable files require a non-root posix user',
    )
    def test_unreadable_file_is_reported_as_failed(self, tmp_path):
        shutil.copytree(DEMO_ROOT, tmp_path / 'workspace', dirs_exist_ok=True)
        locked = tmp_path / 'workspace' / 'project_gamma' / 'locked.env'
        locked.chmod(0)
        try:
            report = export(str(tmp_path / 'workspace'), root=str(tmp_path / 'workspace'))
        finally:
            locked.chmod(0o644)

        assert report['coverage']['failed_files'] == 1
        assert report['coverage']['scanned_files'] == 5

    def test_small_groups_are_merged(self):
        report = export(DEMO_ROOT)

        groups = {group['group']: group for group in report['groups']}
        assert groups['Base64 High Entropy String']['findings'] == 4
        assert groups['Hex High Entropy String']['findings'] == 3

        merged = groups[coverage.MERGED_GROUP]
        assert merged['kind'] == 'merged'
        assert merged['detectors'] == [
            'Basic Auth Credentials',
            'Private Key',
            'Secret Keyword',
        ]
        assert merged['findings'] == 4

    def test_pool_below_minimum_size_is_suppressed(self):
        # Only one private key finding exists under certs/, which is below
        # the approved minimum group size, so no counts may be exported.
        report = export(os.path.join(DEMO_ROOT, 'project_gamma', 'certs'))

        assert report['groups'] == [{
            'group': coverage.SUPPRESSED_GROUP,
            'kind': 'suppressed',
            'detectors': ['Private Key'],
            'findings': None,
            'files': None,
            'reason': f'combined findings below min_group_size={MIN_GROUP_SIZE}',
        }]
        assert report['totals']['findings_known'] == 0
        assert report['totals']['findings_hidden_max'] == MIN_GROUP_SIZE - 1

    def test_invalid_min_group_size(self):
        with pytest.raises(ValueError):
            scan(DEMO_ROOT).export(0)

    def test_plugins_used_proves_rule_capability(self):
        report = export(DEMO_ROOT)

        assert 'Base64HighEntropyString' in report['plugins_used']
        assert 'PrivateKeyDetector' in report['plugins_used']


class TestCombine:
    def test_split_scope_reaggregates_to_monolithic_export(self):
        monolithic = export(DEMO_ROOT)

        combined = coverage.CoverageReport()
        for project in PROJECTS:
            combined.combine(scan(os.path.join(DEMO_ROOT, project)))
        split = combined.export(MIN_GROUP_SIZE)

        for key in ('coverage', 'groups', 'totals', 'plugins_used'):
            assert monolithic[key] == split[key]


class TestReconcile:
    def test_consistent_across_generations(self):
        gen1 = export(DEMO_ROOT)

        combined = coverage.CoverageReport()
        for project in PROJECTS:
            combined.combine(scan(os.path.join(DEMO_ROOT, project)))
        gen2 = combined.export(MIN_GROUP_SIZE)

        result = coverage.reconcile_reports(gen1, gen2)
        assert result['coverage_consistent'] is True
        assert result['requires_fresh_review'] is False
        assert result['individual_findings_actionable'] is False

    def test_disappearing_alert_is_only_an_aggregate_delta(self, tmp_path):
        gen1 = export(DEMO_ROOT)

        shutil.copytree(DEMO_ROOT, tmp_path / 'workspace', dirs_exist_ok=True)
        token_py = tmp_path / 'workspace' / 'project_gamma' / 'src' / 'token.py'
        token_py.write_text(
            ''.join(
                line
                for line in token_py.read_text().splitlines(keepends=True)
                if 'refresh_token' not in line
            ),
        )
        gen2 = export(str(tmp_path / 'workspace'), root=str(tmp_path / 'workspace'))

        result = coverage.reconcile_reports(gen1, gen2)
        assert result['coverage_consistent'] is False
        assert result['requires_fresh_review'] is True
        assert result['individual_findings_actionable'] is False
        assert result['detector_groups']['changed'] == [{
            'detector': 'Base64 High Entropy String',
            'old': 4,
            'new': 3,
            'delta': -1,
        }]

        # The reconciliation must not identify which candidate disappeared:
        # there is nothing below group granularity to act on.
        blob = json.dumps(result)
        for fragment in ('token.py', 'hashed_secret', 'line_number'):
            assert fragment not in blob

    def test_pool_membership_change_is_unattributable(self):
        gen1 = export(DEMO_ROOT)

        # A second generation where one detector graduates out of the merged
        # pool: membership differs, so counts must not be subtracted.
        gen2 = json.loads(json.dumps(gen1))
        gen2['groups'] = [
            group
            for group in gen2['groups']
            if group['kind'] != 'merged'
        ] + [
            {
                'group': 'Private Key',
                'kind': 'detector',
                'findings': MIN_GROUP_SIZE,
                'files': MIN_GROUP_SIZE,
            },
            {
                'group': coverage.MERGED_GROUP,
                'kind': 'merged',
                'detectors': ['Basic Auth Credentials', 'Secret Keyword'],
                'findings': 3,
                'files': 3,
            },
        ]

        result = coverage.reconcile_reports(gen1, gen2)
        assert result['pooled_groups']['membership_changed'] is True
        assert result['pooled_groups']['unattributable'] is True
        assert 'merged_findings' not in result['pooled_groups']

    def test_rejects_non_coverage_reports(self):
        with pytest.raises(ValueError):
            coverage.reconcile_reports({'results': {}}, export(DEMO_ROOT))

    def test_rejects_reports_with_fingerprints(self):
        report = export(DEMO_ROOT)
        poisoned = {**report, 'results': {'config.py': [{'hashed_secret': 'x'}]}}

        with pytest.raises(ValueError):
            coverage.assert_report_anonymized(poisoned)
        with pytest.raises(ValueError):
            coverage.reconcile_reports(report, poisoned)
