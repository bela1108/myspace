#!/usr/bin/env python
#-------------------------------------------------------------------------------
# scripts/tls_info.py
#
# Print a static loading description of an ELF file's thread-local storage.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import json
import sys
import traceback
from typing import IO, Sequence

# For running from the development directory.
sys.path.insert(0, '.')

from elftools import __version__
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.tls import (
    compare_tls,
    describe_tls,
    format_tls_comparison,
    format_tls_description,
)


def _read_description(
    path: str,
    *,
    verify: bool,
    include_bytes: bool,
) -> dict[str, object]:
    with open(path, 'rb') as stream:
        report = describe_tls(
            ELFFile(stream), verify=verify, include_bytes=include_bytes)
    report['file'] = path
    return report


def _write_text(
    output: IO[str],
    reports: Sequence[dict[str, object]],
    *,
    compare: bool,
) -> None:
    for index, report in enumerate(reports):
        if len(reports) > 1:
            if index:
                output.write('\n')
            output.write(f"=== {report['file']} ===\n")
        output.write(format_tls_description(report))
        output.write('\n')
    if compare and len(reports) >= 2:
        output.write('\n')
        output.write(format_tls_comparison(compare_tls(reports[0], reports[1])))
        output.write('\n')


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='tls_info.py',
        description=(
            'Describe the static file/memory layout of ELF thread-local '
            'storage using PT_TLS, SHF_TLS sections, and STT_TLS symbols'))
    parser.add_argument(
        'files', nargs='+', metavar='ELF',
        help='ELF file to inspect; two files are compared when two are given')
    parser.add_argument(
        '-j', '--json', action='store_true', dest='as_json',
        help='emit machine-readable JSON')
    parser.add_argument(
        '--no-verify', action='store_true', dest='no_verify',
        help='do not read file-backed ranges or compute SHA-256 digests')
    parser.add_argument(
        '--bytes', action='store_true', dest='include_bytes',
        help='include a hex preview of the PT_TLS initialization template')
    parser.add_argument(
        '--compare', action='store_true', dest='compare',
        help='compare the first two files (the default with multiple files)')
    parser.add_argument(
        '--traceback', action='store_true', dest='show_traceback',
        help='dump the Python traceback on ELF errors')
    parser.add_argument(
        '-v', '--version', action='version',
        version=f'%(prog)s: based on pyelftools {__version__}')
    args = parser.parse_args(argv)

    # A comparison is most useful when there is more than one file, so make
    # it the default in that case.  --compare remains available to make the
    # intent explicit.
    args.compare = len(args.files) >= 2

    try:
        reports = [
            _read_description(
                path,
                verify=not args.no_verify,
                include_bytes=args.include_bytes)
            for path in args.files
        ]
    except (ELFError, OSError) as error:
        sys.stderr.write(f'ELF error: {error}\n')
        if args.show_traceback:
            traceback.print_exc()
        return 1

    comparison = None
    if args.compare:
        comparison = compare_tls(reports[0], reports[1])

    if args.as_json:
        payload: dict[str, object]
        if len(reports) == 1:
            payload = reports[0]
        else:
            payload = {'files': reports}
            if comparison is not None:
                payload['comparison'] = comparison
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write('\n')
        return 0

    _write_text(sys.stdout, reports, compare=args.compare)
    return 0


if __name__ == '__main__':
    sys.exit(main())
