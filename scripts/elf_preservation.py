#!/usr/bin/env python
#-------------------------------------------------------------------------------
# scripts/elf_preservation.py
#
# Read-only page-preservation planning for ELF note claims.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')

from elftools.common.exceptions import ELFError
from elftools.elf.preservation import PreservationError, PreservationRequest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=('Compute the smallest set of ELF file pages that keeps '
                     'specified note-backed claims independently verifiable. '
                     'The ELF is opened read-only.'))
    parser.add_argument('elf', help='ELF file to analyze (never modified)')
    parser.add_argument('--claims', required=True, metavar='FILE',
                        help='JSON claim/provenance manifest')
    parser.add_argument('--page-size', type=int, default=None,
                        help='override the manifest page size (default 4096)')
    parser.add_argument('--budget', type=int, default=None,
                        help='override the manifest page budget')
    parser.add_argument('--json', action='store_true',
                        help='emit the receipt as JSON')
    args = parser.parse_args(argv)

    try:
        request = PreservationRequest.from_json(args.claims)
        if args.page_size is not None:
            request = replace(request, page_size=args.page_size)
        if args.budget is not None:
            request = replace(request, budget=args.budget)
        plan = request.plan(args.elf)
    except (OSError, ELFError, PreservationError, ValueError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        print(plan.format_receipt())
    return 0


if __name__ == '__main__':
    sys.exit(main())
