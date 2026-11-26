#-------------------------------------------------------------------------------
# elftools example: dwarf_interval_witness.py
#
# Re-check address-to-source testimony from two DWARF debug files for the same
# module version.  The caller supplies the module load interval(s); the report
# splits them into unchanged, changed and unconfirmed address segments rather
# than repeating an old report's single continuous interval.
#
# Each debug file is read locally with pyelftools.  Compile units supply the
# source root (DW_AT_comp_dir) and code ranges.  Line-table rows supply source
# positions; DW_LNE.end_sequence closes each sequence instead of letting its
# last row leak into the gap before the next sequence.  An internal gap with a
# source position on both sides is reported separately as a line-table hole.
#
# Run from the repository root:
#     PYTHONPATH=. python examples/dwarf_interval_witness.py \
#         old.debug new.debug --load 0x400400-0x4005b9
#
# The two inputs may use different link-time bases.  Use --left-bias and
# --right-bias to move each debug file's addresses into the caller's load
# address space.  If --load is omitted, one span covering all declared CU code
# in both files is used; gaps between CUs then appear as unconfirmed ranges.
#
# Repository labels default to DW_AT_comp_dir, so different build roots are
# reported as different testimony.  Supply --repo-prefix PREFIX=LABEL (or just
# a prefix, using its basename as the label) to map checkout roots explicitly.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import argparse
import json
import posixpath
import re
import sys

from elftools.common.exceptions import DWARFError, ELFError
from elftools.dwarf.source_intervals import (
    AddressInterval,
    compare_witnesses,
    format_report,
    read_source_index,
    report_to_dict,
)


def parse_interval(text):
    """Parse BEGIN-END (also BEGIN:END, BEGIN,END or BEGIN..END) as hex."""
    parts = re.split(r'\s*(?:-|:|,|\.\.)\s*', text, maxsplit=1)
    if len(parts) != 2:
        raise ValueError(f'expected BEGIN-END, got {text!r}')
    begin = int(parts[0], 0)
    end = int(parts[1], 0)
    try:
        return AddressInterval(begin, end)
    except ValueError as error:
        raise ValueError(f'invalid load interval {text!r}: {error}') from error


def parse_repo_prefix(text):
    """Parse PREFIX=LABEL, or use the prefix basename as the label."""
    if '=' in text:
        prefix, label = text.split('=', 1)
    else:
        prefix = text
        label = posixpath.basename(posixpath.normpath(prefix))
    if not prefix or not label:
        raise ValueError(f'expected PREFIX or PREFIX=LABEL, got {text!r}')
    return prefix, label


def build_parser():
    parser = argparse.ArgumentParser(
        description='Compare DWARF source testimony from two debug files.')
    parser.add_argument('left', help='first/old ELF or .debug file')
    parser.add_argument('right', nargs='?', help='second/new ELF or .debug file')
    parser.add_argument(
        '--load', action='append', default=[], metavar='BEGIN-END',
        help='caller-provided module load interval; may be repeated')
    parser.add_argument(
        '--repo-prefix', action='append', default=[], metavar='PREFIX[=LABEL]',
        help='map a source path prefix to a repository label')
    parser.add_argument(
        '--attribution', choices=('repo', 'file', 'location'), default='repo',
        help='what must match for a segment to be unchanged (default: repo)')
    parser.add_argument(
        '--left-bias', type=lambda value: int(value, 0), default=0,
        metavar='ADDR', help='add ADDR to every left DWARF address')
    parser.add_argument(
        '--right-bias', type=lambda value: int(value, 0), default=0,
        metavar='ADDR', help='add ADDR to every right DWARF address')
    parser.add_argument('--json', action='store_true', help='emit JSON')
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # The repository's example test harness invokes every example as
    # `--test ./examples/sample_exe64.elf`.  Compare the file with itself so the
    # reference output stays deterministic.
    if argv[:1] == ['--test']:
        if len(argv) != 2:
            sys.exit('Usage: dwarf_interval_witness.py --test <elf-file>')
        filename = argv[1]
        args = argparse.Namespace(
            left=filename, right=filename, load=[], repo_prefix=[],
            attribution='repo', left_bias=0, right_bias=0, json=False)
    else:
        parser = build_parser()
        args = parser.parse_args(argv)
        if args.right is None:
            parser.error('two debug files are required')

    try:
        loads = [parse_interval(text) for text in args.load]
        repo_roots = [parse_repo_prefix(text) for text in args.repo_prefix]
        left = read_source_index(
            args.left, repo_roots=repo_roots, address_bias=args.left_bias)
        right = read_source_index(
            args.right, repo_roots=repo_roots, address_bias=args.right_bias)
        report = compare_witnesses(
            left, right, loads or None, attribution=args.attribution)
    except (OSError, ValueError, ELFError, DWARFError) as error:
        sys.exit(f'error: {error}')

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print(format_report(report))

    for side, index in (('left', left), ('right', right)):
        for diagnostic in index.diagnostics:
            print(f'{side}: {diagnostic}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
