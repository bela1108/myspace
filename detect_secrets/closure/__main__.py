import argparse
import json
import sys
from typing import List
from typing import Optional
from typing import Tuple

from .engine import ClosureEngine
from .engine import ClosureReport
from .engine import diff_reports
from .engine import ReportDiff
from .io import diff_to_dict
from .io import fingerprints_from_baseline
from .io import load_case
from .io import parse_datetime
from .io import report_to_dict
from .io import save_case


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog='detect-secrets-closure',
        description=(
            'Offline closure judgement for historical secret findings. '
            'Only credential fingerprints are handled, never secret plaintext.'
        ),
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    evaluate_parser = subparsers.add_parser(
        'evaluate',
        help='decide, per branch, whether the alert can be closed',
    )
    evaluate_parser.add_argument('case', help='path to the JSON case file')
    evaluate_parser.add_argument('--fingerprint', help='override the case fingerprint')
    evaluate_parser.add_argument('--as-of', help='override the evaluation moment (ISO 8601)')
    evaluate_parser.add_argument('--json', action='store_true', help='emit JSON')

    revoke_parser = subparsers.add_parser(
        'revoke',
        help='revoke a receipt, persist the new evidence version, and show the diff',
    )
    revoke_parser.add_argument('case', help='path to the JSON case file')
    revoke_parser.add_argument('receipt_id', help='id of the receipt to revoke')
    revoke_parser.add_argument(
        '--out',
        help='where to write the updated case (defaults to overwriting the case file)',
    )
    revoke_parser.add_argument('--json', action='store_true', help='emit JSON')

    fingerprints_parser = subparsers.add_parser(
        'fingerprints',
        help='list the hashed secrets of a detect-secrets baseline',
    )
    fingerprints_parser.add_argument('baseline', help='path to a .secrets.baseline file')
    fingerprints_parser.add_argument('--json', action='store_true', help='emit JSON')

    args = parser.parse_args(argv)
    if args.command == 'evaluate':
        return _evaluate(args)
    if args.command == 'revoke':
        return _revoke(args)
    return _fingerprints(args)


def _evaluate(args: argparse.Namespace) -> int:
    engine = ClosureEngine(load_case(args.case))
    report = engine.evaluate(
        fingerprint=args.fingerprint,
        as_of=parse_datetime(args.as_of) if args.as_of else None,
    )
    if args.json:
        print(json.dumps(report_to_dict(report), indent=2, sort_keys=True))
    else:
        print(_render_report(report))
    return 0


def _revoke(args: argparse.Namespace) -> int:
    engine = ClosureEngine(load_case(args.case))
    original = engine.evaluate()
    try:
        engine.revoke(args.receipt_id)
    except KeyError:
        print('no receipt named {!r} in this case'.format(args.receipt_id), file=sys.stderr)
        return 1
    save_case(engine.bundle, args.out or args.case)
    current = engine.evaluate()
    diff = diff_reports(original, current)
    if args.json:
        print(json.dumps(diff_to_dict(diff), indent=2, sort_keys=True))
    else:
        print(_render_diff(diff))
    return 0


def _fingerprints(args: argparse.Namespace) -> int:
    fingerprints = fingerprints_from_baseline(args.baseline)
    if args.json:
        print(json.dumps(fingerprints, indent=2))
    else:
        for fingerprint in fingerprints:
            print(fingerprint)
    return 0


def _render_report(report: ClosureReport) -> str:
    lines = [
        'fingerprint: {}'.format(report.fingerprint),
        'environment: {}'.format(report.environment),
        'evidence version: {}'.format(report.evidence_version),
        'evaluated at: {}'.format(report.evaluated_at.isoformat()),
    ]
    for decision in report.decisions:
        lines.append('branch {}: {}'.format(decision.branch, decision.status.value.upper()))
        for receipt_id in decision.supporting_receipts:
            lines.append('  supported by receipt {}'.format(receipt_id))
        for reason in decision.reasons:
            lines.append('  - {}'.format(reason))
    return '\n'.join(lines)


def _render_diff(diff: ReportDiff) -> str:
    def render(label: str, branches: Tuple[str, ...]) -> str:
        return '{}: {}'.format(label, ', '.join(branches) if branches else '(none)')

    return '\n'.join([
        'original decision held under evidence version {}'.format(
            diff.original_evidence_version,
        ),
        'current evidence version: {}'.format(diff.current_evidence_version),
        render('reopened branches', diff.reopened),
        render('still closable', diff.still_closable),
        render('newly closable', diff.newly_closable),
        render('still open', diff.still_open),
    ])


if __name__ == '__main__':
    sys.exit(main())
