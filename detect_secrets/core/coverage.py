"""
Group-coverage reports: an export path that proves scan coverage and rule
capability without persisting any per-finding fingerprint.

Unlike a baseline (which stores `hashed_secret` values so that individual
candidates can be tracked across scans), a coverage report only contains
aggregate, k-anonymized counts:

    * files are tallied by scan outcome (scanned / skipped / failed),
    * findings are tallied per detector, and
    * detector groups smaller than the caller-approved `min_group_size`
      are either merged into a combined bucket or explicitly suppressed.

Because no stable fingerprint, filename, or line number is ever exported,
two reports from different builds cannot be differenced to recover the
status of any specific candidate. `reconcile_reports` only ever compares
aggregate groups, and flags anything that cannot be matched at group level
as requiring a fresh review.
"""
import os
import time
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set

from ..__version__ import VERSION
from ..settings import get_settings
from . import scan
from .potential_secret import PotentialSecret
from .scan import _is_filtered_out
from .scan import get_files_to_scan


REPORT_TYPE = 'detect-secrets/coverage-report'

SCANNED = 'scanned'
SKIPPED = 'skipped'
FAILED = 'failed'
FILE_OUTCOMES = (SCANNED, SKIPPED, FAILED)

#: Group names used in exported reports for k-anonymity pooling.
MERGED_GROUP = '__merged_small_groups__'
SUPPRESSED_GROUP = '__suppressed_small_groups__'

#: Keys that would re-introduce per-candidate state. Their presence anywhere
#: in an exported report is a violation of the anonymity contract.
FORBIDDEN_EXPORT_KEYS = {
    'hashed_secret',
    'secret',
    'filename',
    'line_number',
    'is_secret',
    'is_verified',
    'results',
}


class CoverageReport:
    """
    In-memory tallies of a scan. Filenames may be held in memory while
    scanning, but `export` reduces everything to aggregate counts.
    """

    def __init__(self) -> None:
        self.file_outcomes: Dict[str, int] = {
            outcome: 0
            for outcome in FILE_OUTCOMES
        }
        self.detector_findings: Dict[str, int] = defaultdict(int)

        # Only used to compute per-detector file counts at export time.
        self._detector_files: Dict[str, Set[str]] = defaultdict(set)

        self.plugins_used: List[str] = []

    def record_outcome(self, outcome: str) -> None:
        if outcome not in self.file_outcomes:
            raise ValueError(f'Unknown file outcome: {outcome}')
        self.file_outcomes[outcome] += 1

    def record_findings(self, filename: str, secrets: Iterable[PotentialSecret]) -> None:
        for secret in secrets:
            self.detector_findings[secret.type] += 1
            self._detector_files[secret.type].add(filename)

    def combine(self, other: 'CoverageReport') -> 'CoverageReport':
        """
        Merges another report's tallies into this one. This is how a scope
        that was split into several independently-scanned parts (e.g. a
        monorepo broken into per-project scans) is re-aggregated *before*
        k-anonymity is applied, so that small groups are evaluated against
        `min_group_size` only once, on the combined totals.
        """
        for outcome in FILE_OUTCOMES:
            self.file_outcomes[outcome] += other.file_outcomes[outcome]

        for detector, count in other.detector_findings.items():
            self.detector_findings[detector] += count
        for detector, files in other._detector_files.items():
            self._detector_files[detector] |= files

        self.plugins_used = sorted(set(self.plugins_used) | set(other.plugins_used))
        return self

    @property
    def total_findings(self) -> int:
        return sum(self.detector_findings.values())

    def export(self, min_group_size: int) -> Dict[str, Any]:
        """
        Produces the anonymized, exportable report.

        :param min_group_size: caller-approved minimum group size. Detector
            groups with fewer findings than this are pooled together; if the
            pool itself is still too small, its counts are suppressed
            entirely so that no small group can be isolated by differencing
            two exports.
        """
        if min_group_size < 1:
            raise ValueError('min_group_size must be a positive integer.')

        groups: List[Dict[str, Any]] = []
        small: Dict[str, int] = {}
        for detector in sorted(self.detector_findings):
            count = self.detector_findings[detector]
            if count >= min_group_size:
                groups.append({
                    'group': detector,
                    'kind': 'detector',
                    'findings': count,
                    'files': len(self._detector_files[detector]),
                })
            else:
                small[detector] = count

        suppressed = False
        if small:
            combined = sum(small.values())
            if combined >= min_group_size:
                groups.append({
                    'group': MERGED_GROUP,
                    'kind': 'merged',
                    'detectors': sorted(small),
                    'findings': combined,
                    # Sum of per-detector file counts; a file flagged by two
                    # small detectors is counted once per detector.
                    'files': sum(len(self._detector_files[d]) for d in small),
                })
            else:
                suppressed = True
                groups.append({
                    'group': SUPPRESSED_GROUP,
                    'kind': 'suppressed',
                    'detectors': sorted(small),
                    # Counts are intentionally absent: the pool is below the
                    # approved minimum group size, so exporting any number
                    # would make its members isolable across two exports.
                    'findings': None,
                    'files': None,
                    'reason': (
                        f'combined findings below min_group_size={min_group_size}'
                    ),
                })

        report = {
            'version': VERSION,
            'report_type': REPORT_TYPE,
            'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'min_group_size': min_group_size,
            'plugins_used': sorted(self.plugins_used),
            'coverage': {
                f'{outcome}_files': self.file_outcomes[outcome]
                for outcome in FILE_OUTCOMES
            },
            'groups': groups,
            'totals': {
                'findings_known': sum(
                    group['findings']
                    for group in groups
                    if group['findings'] is not None
                ),
                # Upper bound of findings hidden by suppression, derivable
                # from the approved group size alone.
                'findings_hidden_max': (min_group_size - 1) if suppressed else 0,
            },
        }

        assert_report_anonymized(report)
        return report


def scan_coverage(
    *paths: str,
    root: str = '',
    should_scan_all_files: bool = False,
    report: Optional[CoverageReport] = None,
) -> CoverageReport:
    """
    Scans paths just like a baseline scan would, but only records aggregate
    coverage tallies. Every file in scope is classified as:

        * scanned: fully processed by all configured detectors,
        * skipped: legitimately excluded by configured filters
          (e.g. non-text files), or
        * failed:  selected for scanning, but the detectors could not
          complete (e.g. unreadable file).
    """
    if report is None:
        report = CoverageReport()

    report.plugins_used = sorted(get_settings().plugins)

    for filename in get_files_to_scan(
        *paths,
        should_scan_all_files=should_scan_all_files,
        root=root,
    ):
        full_path = os.path.join(root, filename) if root else filename

        if _is_filtered_out(required_filter_parameters=['filename'], filename=full_path):
            report.record_outcome(SKIPPED)
            continue

        if not _is_readable(full_path):
            report.record_outcome(FAILED)
            continue

        try:
            secrets = list(scan.scan_file(full_path))
        except Exception:   # pragma: no cover
            report.record_outcome(FAILED)
            continue

        report.record_outcome(SCANNED)
        report.record_findings(filename, secrets)

    return report


def reconcile_reports(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reconciles two exported coverage reports (e.g. two generations of a
    build) at group level only.

    The reconciliation proves that scan scope and detector capability are
    consistent between the two runs, but it deliberately provides no way to
    map an old finding onto a new one: any group that cannot be matched
    exactly (same detector, same count) is reported as requiring a fresh
    review, and may not be used to carry over or close individual alerts.
    """
    for report in (old, new):
        if report.get('report_type') != REPORT_TYPE:
            raise ValueError('Can only reconcile coverage reports.')
        assert_report_anonymized(report)

    coverage = {}
    for key in ('scanned_files', 'skipped_files', 'failed_files'):
        old_value = old['coverage'][key]
        new_value = new['coverage'][key]
        coverage[key] = {
            'old': old_value,
            'new': new_value,
            'delta': new_value - old_value,
        }

    old_groups = _exact_groups(old)
    new_groups = _exact_groups(new)

    stable = sorted(
        detector
        for detector in old_groups.keys() & new_groups.keys()
        if old_groups[detector] == new_groups[detector]
    )
    changed = sorted(
        (
            {
                'detector': detector,
                'old': old_groups[detector],
                'new': new_groups[detector],
                'delta': new_groups[detector] - old_groups[detector],
            }
            for detector in old_groups.keys() & new_groups.keys()
            if old_groups[detector] != new_groups[detector]
        ),
        key=lambda item: item['detector'],
    )
    appeared = sorted(new_groups.keys() - old_groups.keys())
    disappeared = sorted(old_groups.keys() - new_groups.keys())

    pools = _reconcile_pools(old, new)

    totals = {
        'findings_known': {
            'old': old['totals']['findings_known'],
            'new': new['totals']['findings_known'],
            'delta': (
                new['totals']['findings_known'] - old['totals']['findings_known']
            ),
        },
        'findings_hidden_max': {
            'old': old['totals']['findings_hidden_max'],
            'new': new['totals']['findings_hidden_max'],
        },
    }

    consistent = (
        not changed
        and not appeared
        and not disappeared
        and pools['membership_changed'] is False
        and all(value['delta'] == 0 for value in coverage.values())
    )

    return {
        'coverage': coverage,
        'detector_groups': {
            'stable': stable,
            'changed': changed,
            'appeared': appeared,
            'disappeared': disappeared,
        },
        'pooled_groups': pools,
        'totals': totals,
        'coverage_consistent': consistent,
        # Hard rule of this export path: without per-finding fingerprints,
        # nothing below group granularity can be carried between versions.
        'individual_findings_actionable': False,
        'requires_fresh_review': not consistent,
        'policy': (
            'Coverage reports contain no per-finding fingerprints. Individual '
            'alerts cannot be carried over or closed from these reports; any '
            'group that is not stable must be re-scanned and reviewed afresh.'
        ),
    }


def assert_report_anonymized(report: Dict[str, Any]) -> None:
    """
    :raises ValueError: if any per-candidate state is found in the report.
    """
    stack: List[Any] = [report]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            offending = FORBIDDEN_EXPORT_KEYS & set(item.keys())
            if offending:
                raise ValueError(
                    'Coverage report must not contain per-candidate keys: '
                    f'{sorted(offending)}',
                )
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _exact_groups(report: Dict[str, Any]) -> Dict[str, int]:
    """Detector groups that were large enough to be exported individually."""
    return {
        group['group']: group['findings']
        for group in report['groups']
        if group['kind'] == 'detector'
    }


def _pooled_groups(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        group['group']: group
        for group in report['groups']
        if group['kind'] in ('merged', 'suppressed')
    }


def _reconcile_pools(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares merged/suppressed pools by membership only. When membership
    changes between versions (e.g. a detector graduates out of the pool, or
    a group splits), the pools are flagged unattributable: subtracting one
    from the other would leak sub-minimum group sizes, so no derived counts
    are computed.
    """
    old_pools = _pooled_groups(old)
    new_pools = _pooled_groups(new)

    old_members = {
        kind: set(pool['detectors'])
        for kind, pool in old_pools.items()
    }
    new_members = {
        kind: set(pool['detectors'])
        for kind, pool in new_pools.items()
    }

    membership_changed = old_members != new_members
    result: Dict[str, Any] = {
        'membership_changed': membership_changed,
        'old_membership': {kind: sorted(m) for kind, m in old_members.items()},
        'new_membership': {kind: sorted(m) for kind, m in new_members.items()},
    }

    if not membership_changed and MERGED_GROUP in old_pools:
        result['merged_findings'] = {
            'old': old_pools[MERGED_GROUP]['findings'],
            'new': new_pools[MERGED_GROUP]['findings'],
            'delta': (
                new_pools[MERGED_GROUP]['findings']
                - old_pools[MERGED_GROUP]['findings']
            ),
        }

    if membership_changed:
        result['unattributable'] = True
        result['note'] = (
            'Pooled group membership changed between versions; counts are not '
            'comparable and individual findings cannot be attributed.'
        )

    return result


def _is_readable(filename: str) -> bool:
    try:
        with open(filename, 'rb'):
            return True
    except OSError:
        return False
