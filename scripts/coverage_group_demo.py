#!/usr/bin/env python3
"""
Demonstrates the anonymized group-coverage export path on three synthetic
projects (test_data/coverage_demo).

The demo shows that:

    1. A monolithic scan and a split scan (per-project scans, combined
       before export) produce reconcilable coverage -- proving scan scope
       and detector capability are sufficient across two generations of a
       build, without persisting any per-finding fingerprint.
    2. Files are classified as scanned / legitimately skipped / failed.
    3. Small detector groups are merged or suppressed according to the
       caller-approved minimum group size.
    4. When an individual alert disappears between generations, the delta
       is only visible as an aggregate: the specific candidate cannot be
       identified, carried over, or closed from the exported reports.

Run from the repository root:

    python scripts/coverage_group_demo.py
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detect_secrets.core import coverage         # noqa: E402
from detect_secrets.settings import default_settings  # noqa: E402


DEMO_ROOT = os.path.join('test_data', 'coverage_demo')
PROJECTS = ['project_alpha', 'project_beta', 'project_gamma']
MIN_GROUP_SIZE = 3


def print_section(title):
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)


def scan_scope(*paths, root=''):
    with default_settings():
        return coverage.scan_coverage(*paths, should_scan_all_files=True, root=root)


def main():
    print_section('1. Generation 1: monolithic scan of all three projects')
    gen1 = scan_scope(DEMO_ROOT).export(MIN_GROUP_SIZE)
    print(json.dumps(gen1['coverage'], indent=2))
    print(json.dumps(gen1['groups'], indent=2))

    print_section('2. Generation 2: the scope splits into per-project scans')
    combined = coverage.CoverageReport()
    for project in PROJECTS:
        combined.combine(scan_scope(os.path.join(DEMO_ROOT, project)))
    gen2 = combined.export(MIN_GROUP_SIZE)

    reconciliation = coverage.reconcile_reports(gen1, gen2)
    print(json.dumps(reconciliation, indent=2))
    assert reconciliation['coverage_consistent'], \
        'split scans must reconcile with the monolithic scan'
    print('OK: split groups re-aggregate; coverage reconciles across generations.')

    print_section('3. A detector cannot complete (unreadable file)')
    with tempfile.TemporaryDirectory() as tmpdir:
        broken_copy = os.path.join(tmpdir, 'workspace')
        shutil.copytree(DEMO_ROOT, broken_copy)
        locked = os.path.join(broken_copy, 'project_gamma', 'locked.env')
        os.chmod(locked, 0)
        try:
            gen3 = scan_scope(broken_copy, root=broken_copy).export(MIN_GROUP_SIZE)
        finally:
            os.chmod(locked, 0o644)

    reconciliation = coverage.reconcile_reports(gen1, gen3)
    print(json.dumps(reconciliation['coverage'], indent=2))
    assert reconciliation['coverage']['failed_files']['new'] == 1
    assert not reconciliation['coverage_consistent']
    print('OK: failed file is visible in coverage, without naming the file.')

    print_section('4. An individual alert disappears between generations')
    with tempfile.TemporaryDirectory() as tmpdir:
        changed_copy = os.path.join(tmpdir, 'workspace')
        shutil.copytree(DEMO_ROOT, changed_copy)
        token_py = os.path.join(changed_copy, 'project_gamma', 'src', 'token.py')
        with open(token_py) as f:
            lines = f.readlines()
        with open(token_py, 'w') as f:
            f.writelines(line for line in lines if 'refresh_token' not in line)
        gen4 = scan_scope(changed_copy, root=changed_copy).export(MIN_GROUP_SIZE)

    reconciliation = coverage.reconcile_reports(gen1, gen4)
    print(json.dumps(reconciliation['detector_groups'], indent=2))
    assert reconciliation['detector_groups']['changed'], \
        'the removed alert must surface as an aggregate delta'
    assert reconciliation['individual_findings_actionable'] is False
    assert reconciliation['requires_fresh_review'] is True
    print(
        'OK: the delta is only visible as an aggregate count. There is no '
        'fingerprint to carry the old verdict over, and no way to close the '
        'specific alert -- a fresh review is required.',
    )

    print_section('5. Groups below the approved minimum size are suppressed')
    tiny = scan_scope(os.path.join(DEMO_ROOT, 'project_gamma', 'certs'))
    tiny_report = tiny.export(MIN_GROUP_SIZE)
    print(json.dumps(tiny_report['groups'], indent=2))
    suppressed = tiny_report['groups'][0]
    assert suppressed['kind'] == 'suppressed'
    assert suppressed['findings'] is None
    print('OK: sub-minimum group exports no counts at all.')

    print_section('6. Anonymity contract holds for every export')
    for name, report in [
        ('gen1', gen1),
        ('gen2', gen2),
        ('gen3', gen3),
        ('gen4', gen4),
        ('tiny', tiny_report),
    ]:
        coverage.assert_report_anonymized(report)
        blob = json.dumps(report)
        assert 'hashed_secret' not in blob
        assert 'locked.env' not in blob and 'config.py' not in blob
        print(f'OK: {name} contains no fingerprints, filenames, or line numbers.')

    print('\nAll demo checks passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
