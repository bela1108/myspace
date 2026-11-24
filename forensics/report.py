"""Render the crosscheck report as JSON or Markdown.

The JSON format is the machine-readable one and is used for archive
evidence; the Markdown format is the human-readable summary used in the
demo. Both are produced from the same CrosscheckReport so the two views
can never disagree.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from forensics.models import (
    CONFLICT,
    CONSISTENT,
    UNDECIDED,
    CrosscheckReport,
    TargetVerdict,
)

_STATUS = {
    CONFLICT: 'CONFLICT',
    CONSISTENT: 'consistent',
    UNDECIDED: 'UNDECIDED',
}


def render_json(report: CrosscheckReport) -> str:
    """Return the stable, indented JSON serialization of report."""

    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + '\n'


def _evidence_line(label: str, verdict: TargetVerdict, party: str) -> str:
    statement = verdict.statements.get(party)
    if statement is None:
        return f'- {label}: no verified statement'
    evidence = statement.evidence
    hashes = ', '.join(
        f'{name}={value}'
        for name, value in sorted(statement.hashes.items())
    )
    return (
        f'- {label}: {evidence.metadata_file}'
        f' (role {evidence.role} v{evidence.metadata_version},'
        f' sha256 {evidence.metadata_sha256[:16]}...,'
        f' length {statement.length}; {hashes})'
    )


def _render_verdict(verdict: TargetVerdict) -> list[str]:
    parties = sorted(verdict.statements)
    lines = [
        f'### {verdict.target_path} -- {_STATUS[verdict.verdict]}',
        '',
    ]
    if verdict.reasons:
        lines.append('Reasons: ' + ', '.join(verdict.reasons))
        lines.append('')
    for party in parties:
        lines.append(_evidence_line(f'party {party}', verdict, party))
    if len(parties) < 2 and verdict.verdict == UNDECIDED:
        lines.append('- the other party provided no verifiable statement')
    lines.append('')
    return lines


def _section(title: str, verdicts: Iterable[TargetVerdict]) -> list[str]:
    lines = [f'## {title}', '']
    bucket = list(verdicts)
    if not bucket:
        lines.extend(['(none)', ''])
        return lines
    for verdict in bucket:
        lines.extend(_render_verdict(verdict))
    return lines


def render_markdown(report: CrosscheckReport) -> str:
    """Return a human-readable Markdown summary of report."""

    data = report.to_dict()
    summary = data['summary']
    lines = [
        '# TUF release-statement cross-check',
        '',
        'Read-only offline comparison. Every statement was verified',
        'independently against the root vouched for by that party.',
        '',
        '## Summary',
        '',
        f"- parties compared: {summary['parties']}",
        "- targets in the joint observation scope: "
        f"{summary['targets_compared']}",
        f"- proven conflicts: {summary['conflicts']}",
        "- undecided (missing or unverifiable evidence): "
        f"{summary['undecided']}",
        f"- consistent: {summary['consistent']}",
        '',
    ]
    for party, result in sorted(data['parties'].items()):
        lines.extend([
            f'## Party {party}',
            '',
            f"- root: {result['root_file']}",
            f"- bundle fully verified: {result['verified']}",
            '- verified roles: ' + ', '.join(result['verified_roles']),
            f"- verified statements: {result['statement_count']}",
        ])
        if result['errors']:
            lines.append('- errors: ' + '; '.join(result['errors']))
        if result['warnings']:
            lines.append('- warnings: ' + '; '.join(result['warnings']))
        lines.append('')
    lines.extend(_section('Proven conflicts', report.conflicts))
    lines.extend(_section('Undecided', report.undecided))
    lines.extend(_section('Consistent', report.consistent))
    return '\n'.join(lines)
