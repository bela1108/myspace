#!/usr/bin/env python
# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asn1crypto.handoff import (
    LocalSignoff,
    VerificationRequired,
    VerifiableMaterial,
    create_cms_handoff,
)


def main():
    fixture = ROOT / 'tests' / 'fixtures' / 'cms-signed.der'
    der = fixture.read_bytes()
    scope = {'case': 'CMS-PRINT-42', 'checked': ['content_type', 'signer_infos']}
    material = VerifiableMaterial(der, spec='cms')
    receipt = LocalSignoff.sign_off(
        material.evidence_identity(scope),
        signed_by='front-desk',
        secret='local-demo',
    )
    bundle = create_cms_handoff(
        der,
        scope=scope,
        receipt=receipt,
        receipt_secret='local-demo',
    )

    print('identity:', bundle.evidence_id)
    print('initial:', bundle.status, 'needs_reverification=', bundle.needs_reverification)
    for _ in range(2):
        view = bundle.view_report()
    print('report:', str(view).replace('\n', ' | '))
    print('views:', bundle.view_count, 'status:', bundle.status)

    transferred = bundle.from_bytes(bundle.to_bytes())
    cloned = transferred.clone().reencode()
    print('clone/reencode:', cloned.status, 'same_identity=', cloned.evidence_id == bundle.evidence_id)

    wider_scope = dict(scope)
    wider_scope['checked'] = scope['checked'] + ['certificates']
    wider = bundle.with_scope(wider_scope)
    print('same_display_text=', wider.view_report() == bundle.view_report())
    print('wider_scope:', wider.status, 'needs_reverification=', wider.needs_reverification)
    try:
        wider.require_current_receipt()
    except VerificationRequired:
        print('gate: VerificationRequired')

    wider.attach_receipt(LocalSignoff.sign_off(
        wider.identity,
        signed_by='certificate-reviewer',
        secret='local-demo',
    ))
    print('new_receipt:', wider.status)


if __name__ == '__main__':
    main()
