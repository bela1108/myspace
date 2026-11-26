# coding: utf-8
"""
Build two small, private-key-free PKCS#12 archives and compare them.

Run with::

    python -m cert_audit.demo /tmp/cert-audit-demo

The script writes batch-a.p12, batch-b.p12 and manifest.json, then prints the
review. The .p12 files contain certificate bags only; the RSA keys generated
in memory stay in the process and are never written to disk.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import json
import os
import sys

from .archive import load_archive
from .manifest import load_manifest
from .report import build_comparison, build_report, render_text

# Imported lazily so the rest of cert_audit works without cryptography.
try:
    from tests.cert_audit_fixtures import build_test_material
except ImportError:  # pragma: no cover
    build_test_material = None


def main(output_dir):
    if build_test_material is None:
        raise SystemExit('cryptography is required to generate demo certificates')
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    material = build_test_material()
    batch_a_path = os.path.join(output_dir, 'batch-a.p12')
    batch_b_path = os.path.join(output_dir, 'batch-b.p12')
    manifest_path = os.path.join(output_dir, 'manifest.json')
    report_path = os.path.join(output_dir, 'review-report.json')

    with open(batch_a_path, 'wb') as handle:
        handle.write(material['batch_a_pfx'])
    with open(batch_b_path, 'wb') as handle:
        handle.write(material['batch_b_pfx'])
    with open(manifest_path, 'w') as handle:
        json.dump(material['manifest'], handle, indent=2, sort_keys=True)

    manifest = load_manifest(material['manifest'])
    review_a = build_report(load_archive(batch_a_path), manifest)
    review_b = build_report(load_archive(batch_b_path), manifest)
    comparison = build_comparison(review_a, review_b)

    with open(report_path, 'w') as handle:
        json.dump({'reports': [review_a, review_b], 'comparison': comparison},
                  handle, indent=2, sort_keys=True)

    print(render_text(review_a, review_b, comparison))
    print('\nWrote:')
    for path in (batch_a_path, batch_b_path, manifest_path, report_path):
        print(' - %s' % path)


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.environ.get('TMPDIR', '/tmp'), 'cert-audit-demo'
    )
    main(target)
