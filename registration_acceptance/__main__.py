# coding: utf-8
"""Command-line entry point for local registration acceptance checks."""

from __future__ import print_function

import argparse
import json
import sys
from pathlib import Path

from .core import (
    ApprovedNameChanges,
    ArchiveRecord,
    compare_archive_csr,
    compare_csr_pair,
)


def _read_archive_record(path, application_id):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    records = data.get('records', [data] if 'application_id' in data else [])
    for record in records:
        if record['application_id'] == application_id:
            return ArchiveRecord.from_dict(record), record
    raise SystemExit('application_id not found in archive: %s' % application_id)


def _print_decision(decision):
    print(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if decision.accepted else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compare archive coordinates and CSR Names.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    archive_parser = subparsers.add_parser('archive')
    archive_parser.add_argument('--archive', required=True)
    archive_parser.add_argument('--application-id', required=True)
    archive_parser.add_argument('--csr')
    archive_parser.add_argument('--declarations', required=True)
    archive_parser.add_argument('--as-of')

    pair_parser = subparsers.add_parser('pair')
    pair_parser.add_argument('--legacy-csr', required=True)
    pair_parser.add_argument('--current-csr', required=True)
    pair_parser.add_argument('--declarations', required=True)
    pair_parser.add_argument('--archive')
    pair_parser.add_argument('--application-id')
    pair_parser.add_argument('--as-of')

    args = parser.parse_args(argv)

    if args.command == 'archive':
        record, raw_record = _read_archive_record(args.archive, args.application_id)
        csr_path = args.csr or raw_record.get('current_csr')
        if not csr_path:
            raise SystemExit('--csr is required when the archive has no current_csr')
        csr_candidate = Path(csr_path)
        if not csr_candidate.exists():
            csr_candidate = Path(args.archive).resolve().parent / csr_path
        decision = compare_archive_csr(
            record,
            str(csr_candidate),
            ApprovedNameChanges.load(args.declarations),
            as_of=args.as_of,
        )
        return _print_decision(decision)

    archive_record = None
    if args.archive:
        if not args.application_id:
            raise SystemExit('--application-id is required with --archive')
        archive_record, _ = _read_archive_record(args.archive, args.application_id)

    decision = compare_csr_pair(
        args.legacy_csr,
        args.current_csr,
        ApprovedNameChanges.load(args.declarations),
        as_of=args.as_of,
        archive_record=archive_record,
    )
    return _print_decision(decision)


if __name__ == '__main__':
    sys.exit(main())
