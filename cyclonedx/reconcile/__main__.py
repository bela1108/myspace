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

"""Command line entry point for archive reconciliation."""

import json
import sys
from argparse import ArgumentParser, Namespace
from typing import Dict, Optional, Sequence

from ..exception.reconcile import ReconciliationError
from .engine import Reconciler, diff_audits
from .loaders import decisions_from_file, load_inputs
from .model import AuditDiff, AuditResult
from .report import render_diff


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog='python -m cyclonedx.reconcile',
        description='Reconcile a read-only archive manifest against CycloneDX component declarations.',
    )
    parser.add_argument('--manifest', required=True, help='JSON archive file manifest')
    declarations = parser.add_mutually_exclusive_group(required=True)
    declarations.add_argument('--bom', help='CycloneDX BOM in JSON or XML')
    declarations.add_argument('--components', help='JSON component-declaration file')
    parser.add_argument('--decisions', required=True, help='JSON exclusion decisions (current revision)')
    parser.add_argument('--baseline-decisions', help='earlier decision revision to diff against')
    parser.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    parser.add_argument(
        '--fail-on-unexplained',
        action='store_true',
        help='exit 2 if any archive-only, declaration-only, ambiguous, or conflicting record remains',
    )
    return parser


def _render_json(audit: AuditResult, diff: Optional[AuditDiff] = None) -> str:
    payload: Dict[str, object] = {'audit': audit.as_dict()}
    if diff is not None:
        payload['diff'] = diff.as_dict()
    return json.dumps(payload, indent=2, sort_keys=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = _parser()
    args: Namespace = parser.parse_args(argv)
    try:
        manifest, declarations, decisions = load_inputs(
            args.manifest,
            args.decisions,
            bom_file=args.bom,
            declarations_file=args.components,
        )
        reconciler = Reconciler(manifest, declarations)
        audit = reconciler.audit(decisions)
        diff: Optional[AuditDiff] = None
        if args.baseline_decisions:
            baseline = reconciler.audit(decisions_from_file(args.baseline_decisions))
            diff = diff_audits(baseline, audit)
    except (OSError, ReconciliationError, ValueError) as error:
        print(f'reconcile: {error}', file=sys.stderr)
        return 2

    if args.json:
        print(_render_json(audit, diff))
    else:
        print(audit.render_text(), end='')
        if diff is not None:
            print()
            print(render_diff(diff), end='')

    if args.fail_on_unexplained and (
        audit.summary.archive_only
        or audit.summary.component_only
        or audit.summary.ambiguous
        or audit.summary.conflicts
    ):
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
