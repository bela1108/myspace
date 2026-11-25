# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Human-readable reporting for reconciliation audits."""

from typing import Iterable, List

from .model import (
    ArchiveOnlyFinding,
    AuditDiff,
    AuditResult,
    ComponentOnlyFinding,
    ContentDigest,
    ExcludedRecord,
)

_LIST_SEPARATOR = ', '
_EMPTY = '-'


def _yes_no(value: bool) -> str:
    return 'yes' if value else 'no'


def _digests(digests: Iterable[ContentDigest]) -> str:
    rendered = [str(digest) for digest in digests]
    return ', '.join(rendered) if rendered else '-'


def _locations(locations: Iterable[object]) -> str:
    rendered = [str(location) for location in locations]
    return ', '.join(rendered) if rendered else '-'


def _render_archive_finding(finding: ArchiveOnlyFinding, lines: List[str]) -> None:
    lines.append(f'  - [{finding.entry_id}] {finding.location}')
    lines.append(f'      reason: {finding.reason}')
    lines.append(f'      hashes: {_digests(finding.hashes)}')
    if finding.digest_fanout_locations:
        lines.append(f'      same digest also at: {_locations(finding.digest_fanout_locations)}')
    if finding.ignored_decision_ids:
        lines.append(f'      non-approved decisions considered: {_LIST_SEPARATOR.join(finding.ignored_decision_ids)}')


def _render_component_finding(finding: ComponentOnlyFinding, lines: List[str]) -> None:
    version = f'@{finding.version}' if finding.version else ''
    lines.append(f'  - [{finding.component_ref}] {finding.name}{version}')
    lines.append(f'      reason: {finding.reason}')
    lines.append(f'      declared locations: {_locations(finding.declared_locations)}')
    lines.append(f'      declared hashes: {_digests(finding.hashes)}')
    if finding.purl:
        lines.append(f'      purl: {finding.purl}')
    if finding.ignored_decision_ids:
        lines.append(f'      non-approved decisions considered: {_LIST_SEPARATOR.join(finding.ignored_decision_ids)}')


def _render_excluded(record: ExcludedRecord, lines: List[str]) -> None:
    target = record.location if record.location is not None else record.component_ref or '-'
    lines.append(f'  - [{record.record_kind.value}] {record.record_id}  {target}')
    lines.append(f'      reason: {record.reason}')
    lines.append(f'      hashes: {_digests(record.hashes)}')
    for decision in record.decisions:
        lines.append(
            f'      decision: {decision.decision_id} rev {decision.revision} '
            f'({decision.status.value}) by {decision.decided_by} at {decision.decided_at}'
        )
        lines.append(f'        rationale: {decision.rationale}')
    if record.ignored_decision_ids:
        lines.append(f'      non-approved decisions considered: {_LIST_SEPARATOR.join(record.ignored_decision_ids)}')


def render_audit(result: AuditResult) -> str:
    """Render an :class:`AuditResult` as deterministic plain text."""
    summary = result.summary
    lines = [
        'CycloneDX archive reconciliation',
        f'  archive:      {result.manifest_label}',
        f'  manifest:     {result.fingerprints.manifest}',
        f'  declarations: {result.fingerprints.declarations}',
        f'  policy:       {result.fingerprints.policy}',
        f'  audit:        {result.fingerprints.audit}',
        '',
        'Summary',
        f'  archive records:               {summary.archive_entries}',
        f'  component declarations:        {summary.component_declarations}',
        f'  matched archive records:       {summary.matched_archive_entries}',
        f'  matched declarations:          {summary.matched_component_declarations}',
        f'  archive-only:                  {summary.archive_only}',
        f'  declaration-only:              {summary.component_only}',
        f'  confirmed exclusions:          {summary.excluded}',
        f'  unresolved ambiguities:        {summary.ambiguous}',
        f'  content conflicts:             {summary.conflicts}',
        f'  digest fan-out findings:       {summary.digest_fanout}',
        f'  location contention findings:  {summary.location_contention}',
        '',
        f'Ambiguity: one digest at multiple archive paths ({summary.digest_fanout})',
    ]
    if result.digest_fanout:
        for fanout in result.digest_fanout:
            lines.append(f'  - {fanout.digest}')
            lines.append(f'      entries: {_LIST_SEPARATOR.join(fanout.entry_ids)}')
            lines.append(f'      locations: {_locations(fanout.locations)}')
            declared_by = (_LIST_SEPARATOR.join(fanout.declared_by)
                           if fanout.declared_by else _EMPTY)
            lines.append(f'      declared by: {declared_by}')
    else:
        lines.append('  (none)')

    lines.append('')
    lines.append(f'Ambiguity: one location claimed by multiple declarations ({summary.location_contention})')
    if result.location_contention:
        for contention in result.location_contention:
            lines.append(f'  - {contention.location}')
            entry_ids = (_LIST_SEPARATOR.join(contention.entry_ids)
                         if contention.entry_ids else _EMPTY)
            lines.append(f'      entries: {entry_ids}')
            lines.append(f'      components: {_LIST_SEPARATOR.join(contention.component_refs)}')
    else:
        lines.append('  (none)')

    lines.append('')
    lines.append(f'Unresolved ambiguous declarations ({len(result.ambiguous)})')
    if result.ambiguous:
        for finding in result.ambiguous:
            lines.append(f'  - [{finding.component_ref}] {finding.name}')
            lines.append(f'      reason: {finding.reason}')
            lines.append(f'      declared hashes: {_digests(finding.hashes)}')
            lines.append(
                '      candidates: ' + ', '.join(
                    f'{candidate.entry_id}={candidate.location}' for candidate in finding.candidate_entries
                )
            )
    else:
        lines.append('  (none)')

    lines.append('')
    lines.append(f'Content conflicts ({len(result.conflicts)})')
    if result.conflicts:
        for conflict in result.conflicts:
            lines.append(f'  - [{conflict.component_ref}] {conflict.location}')
            lines.append(f'      entry: {conflict.entry_id}')
            lines.append(f'      declared hashes: {_digests(conflict.component_hashes)}')
            lines.append(f'      archive hashes:  {_digests(conflict.entry_hashes)}')
    else:
        lines.append('  (none)')

    lines.append('')
    lines.append(f'Archive records without declaration ({len(result.archive_only)})')
    if result.archive_only:
        for finding in result.archive_only:
            _render_archive_finding(finding, lines)
    else:
        lines.append('  (none)')

    lines.append('')
    lines.append(f'Declarations without archive record ({len(result.component_only)})')
    if result.component_only:
        for finding in result.component_only:
            _render_component_finding(finding, lines)
    else:
        lines.append('  (none)')

    lines.append('')
    lines.append(f'Confirmed exclusions ({len(result.excluded)})')
    if result.excluded:
        for record in result.excluded:
            _render_excluded(record, lines)
    else:
        lines.append('  (none)')

    return '\n'.join(lines) + '\n'


def render_diff(diff: AuditDiff) -> str:
    """Render an :class:`AuditDiff` as deterministic plain text."""
    lines = [
        'Audit diff',
        f'  manifest changed:     {_yes_no(diff.manifest_changed)}',
        f'  declarations changed: {_yes_no(diff.declarations_changed)}',
        f'  policy changed:       {_yes_no(diff.policy_changed)}',
        f'  record changes:       {len(diff.changes)}',
    ]
    for change in diff.changes:
        before = ','.join(change.decision_ids_before) or '-'
        after = ','.join(change.decision_ids_after) or '-'
        lines.append(
            f'  - [{change.record_kind.value}] {change.record_id}: '
            f'{change.before} ({before}) -> {change.after} ({after})'
        )
    return '\n'.join(lines) + '\n'
