import glob
import json
from itertools import chain
from os.path import isfile

import filetype


def guess(path):
    kind = filetype.guess(path)
    if kind is None:
        print('{}: File type determination failure.'.format(path))
    else:
        print('{}: {} ({})'.format(path, kind.extension, kind.mime))


def _load_json(path):
    with open(path, 'r') as fp:
        return json.load(fp)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog='filetype', description='Determine type of FILEs.'
    )
    parser.add_argument(
        'file', nargs='*',
        help='files, wildcard is supported'
    )
    parser.add_argument(
        '--capabilities', action='store_true',
        help='print the handler capability manifest as JSON and exit'
    )
    parser.add_argument(
        '--audit', metavar='FILE',
        help='audit saved determinations from a JSON ledger and exit'
    )
    parser.add_argument(
        '--manifest', metavar='FILE',
        help='JSON capability manifest used by --capabilities or --audit'
    )
    parser.add_argument(
        '-v', '--version', action='version',
        version=f'%(prog)s {filetype.version}',
        help='output version information and exit'
    )

    args = parser.parse_args()

    if args.capabilities:
        overrides = _load_json(args.manifest) if args.manifest else None
        manifest = filetype.capabilities(overrides=overrides)
        print(json.dumps(manifest.to_dict(), indent=2))
        return

    if args.audit:
        records = _load_json(args.audit)
        supplied = _load_json(args.manifest) if args.manifest else None
        report = filetype.audit(records, capabilities=supplied)
        print(json.dumps(report.to_dict(), indent=2))
        return

    if not args.file:
        parser.error('at least one file is required')

    items = chain.from_iterable(map(glob.iglob, args.file))
    files = filter(isfile, items)

    for file in files:
        guess(file)


if __name__ == '__main__':
    main()
