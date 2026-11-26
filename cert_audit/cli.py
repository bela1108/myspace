# coding: utf-8
"""
Command line interface for public-material-only certificate archive review.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import argparse
import json
import sys

from .archive import load_archive
from .manifest import load_manifest
from .report import build_comparison, build_report, render_text


def _build_parser():
    parser = argparse.ArgumentParser(
        prog='python -m cert_audit',
        description='Review PKCS#12/X.509 certificate archives without exporting private keys.',
    )
    parser.add_argument('archives', nargs='+', help='PKCS#12 (.p12/.pfx) or X.509 PEM/DER archive(s)')
    parser.add_argument('-m', '--manifest', required=True, help='Credential manifest (JSON/YAML)')
    parser.add_argument('-o', '--output', help='Write machine-readable JSON report to this path')
    parser.add_argument(
        '--no-signature-verification',
        action='store_true',
        help='Confirm chains structurally only; do not verify signatures',
    )
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    if len(args.archives) > 2:
        parser.error('at most two archives may be compared')

    manifest = load_manifest(args.manifest)
    verify_signatures = not args.no_signature_verification
    reviews = [
        build_report(load_archive(path), manifest, verify_signatures)
        for path in args.archives
    ]

    result = {'reports': reviews}
    if len(reviews) == 2:
        result['comparison'] = build_comparison(reviews[0], reviews[1])
        text = render_text(reviews[0], reviews[1], result['comparison'])
    else:
        text = render_text(reviews[0])

    if args.output:
        with open(args.output, 'w') as file_handle:
            json.dump(result, file_handle, indent=2, sort_keys=True)
    else:
        sys.stdout.write(text + '\n')
        sys.stdout.write('\n(JSON report available with -o/--output)\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
