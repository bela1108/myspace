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

# Command line entry point for the offline timeline audit.

import argparse
import json
import sys
from typing import Any, Optional, Sequence

from .audit import AuditReport, audit_timelines
from .constraints import ConstraintError, parse_constraints
from .loader import LoadError
from .model import OrderConstraint


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='python -m cyclonedx.timeline',
        description='Offline CycloneDX lifecycle/component timeline audit.',
    )
    parser.add_argument('paths', nargs='+', metavar='BOM', help='BOM file or directory')
    parser.add_argument(
        '-c', '--constraints', action='append', default=[], metavar='FILE_OR_CLAIM',
        help='constraint JSON/text file, or an inline claim such as a.json < b.json',
    )
    parser.add_argument(
        '--claim', action='append', default=[], metavar='CLAIM',
        help='inline ordering claim: A before B, A<B, A after B, ...',
    )
    parser.add_argument('--phase-order', action='store_true', help='also enforce standard lifecycle phase order')
    parser.add_argument('--max-order-evidence', type=int, default=40, metavar='N', help='pairwise order limit')
    parser.add_argument('--format', choices=('json', 'text'), default='json')
    parser.add_argument('--compact', action='store_true', help='compact JSON output')
    parser.add_argument('-o', '--output', metavar='FILE', help='write the report to FILE')
    parser.add_argument('--fail-on-conflict', action='store_true', help='exit 1 when a conflict is found')
    return parser


def _format_claim(constraint: dict[str, Any]) -> str:
    before = constraint.get('before')
    relation = constraint.get('relation')
    after = constraint.get('after')
    return f'{before} {relation} {after}'


def _render_text(report: AuditReport) -> str:  # noqa: C901
    lines: list[str] = []
    status = 'CONSISTENT' if report.consistent else 'INCONSISTENT'
    bom_ids = sorted({item.bom_id for item in report.evidence})
    lines.append(f'Timeline audit: {status}')
    lines.append(f'Evidence: {len(report.evidence)} items from {len(bom_ids)} BOM(s)')
    if report.entailed:
        lines.append('Entailed order:')
        for before, after in report.entailed:
            lines.append(f'  {before} -> {after}')
    if report.ambiguous:
        lines.append('Ambiguous order (both directions are legal):')
        for left, right in report.ambiguous:
            lines.append(f'  {left} ? {right}')
    if report.legal_orders is not None and len(report.legal_orders) > 1:
        lines.append('Legal stage orders:')
        for order in report.legal_orders[:8]:
            lines.append('  ' + ' -> '.join(order))
        if report.legal_orders_truncated or len(report.legal_orders) > 8:
            lines.append('  ...')
    for conflict in report.conflicts:
        lines.append('Minimal conflict:')
        for constraint in conflict.constraints:
            identifier = constraint.get('id')
            lines.append(f'  {identifier}: {_format_claim(constraint)}')
        lines.append('  evidence: ' + ', '.join(conflict.evidence_ids))
        lines.append('  BOMs: ' + ', '.join(conflict.bom_ids))
        lines.append('  reason: ' + conflict.reason)
    if report.errors:
        lines.append('Warnings:')
        for error in report.errors:
            lines.append('  ' + str(error.get('message', error)))
    return '\n'.join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        constraints: list[OrderConstraint] = []
        for value in list(args.constraints) + list(args.claim):
            constraints.extend(parse_constraints(value))
        report = audit_timelines(
            args.paths,
            constraints or None,
            include_phase_order=args.phase_order,
            order_limit=args.max_order_evidence,
        )
    except (LoadError, ConstraintError, OSError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2

    if args.format == 'text':
        rendered = _render_text(report)
    else:
        rendered = json.dumps(
            report.to_json(),
            indent=None if args.compact else 2,
            separators=(',', ':') if args.compact else None,
            ensure_ascii=False,
        )
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as stream:
            stream.write(rendered + '\n')
    else:
        print(rendered)
    if args.fail_on_conflict and not report.consistent:
        return 1
    return 0
