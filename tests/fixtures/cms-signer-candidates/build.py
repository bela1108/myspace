# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

from asn1crypto import cms, x509


HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.abspath(os.path.join(HERE, '..', 'keys'))


def load_certificate(name):
    with open(os.path.join(KEYS, name), 'rb') as f:
        return x509.Certificate.load(f.read())


def make_signer(sid, signature=b'\x01\x02\x03\x04'):
    return cms.SignerInfo({
        'version': 'v1',
        'sid': sid,
        'digest_algorithm': {'algorithm': 'sha256'},
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': signature,
    })


def make_signed_data(certificates, signers):
    fields = {
        'version': 'v1',
        'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {
            'content_type': 'data',
            'content': b'cms signer candidate fixture\n',
        },
        'signer_infos': signers,
    }
    if certificates is not None:
        fields['certificates'] = certificates
    return cms.SignedData(fields)


def write_content_info(name, signed_data):
    content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })
    with open(os.path.join(HERE, name), 'wb') as f:
        f.write(content_info.dump())


def build_issuer_serial_duplicate():
    certificate = load_certificate('test-der.crt')
    sid = {
        'issuer_and_serial_number': {
            'issuer': certificate.issuer,
            'serial_number': certificate.serial_number,
        }
    }
    signed_data = make_signed_data(
        [certificate, certificate],
        [make_signer(sid)]
    )
    write_content_info('issuer-serial-duplicate.der', signed_data)


def build_ski_conflict():
    certificate_a = load_certificate('test-der.crt')
    certificate_b = load_certificate('test-der.crt')
    certificate_b['tbs_certificate']['serial_number'] = certificate_a.serial_number + 1
    sid = {'subject_key_identifier': certificate_a.key_identifier}
    signed_data = make_signed_data(
        [certificate_a, certificate_b],
        [make_signer(sid)]
    )
    write_content_info('ski-conflict.der', signed_data)


def build_nested_missing():
    certificate = load_certificate('test-der.crt')
    outer_sid = {
        'issuer_and_serial_number': {
            'issuer': certificate.issuer,
            'serial_number': certificate.serial_number,
        }
    }
    outer_signer = make_signer(outer_sid)

    nested_sid = {
        'issuer_and_serial_number': {
            'issuer': certificate.issuer,
            'serial_number': certificate.serial_number + 1,
        }
    }
    nested_signed_data = make_signed_data(None, [make_signer(nested_sid)])
    nested_content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': nested_signed_data,
    })
    outer_signer['unsigned_attrs'] = cms.CMSAttributes([
        cms.CMSAttribute({
            'type': 'microsoft_nested_signature',
            'values': [nested_content_info],
        })
    ])

    signed_data = make_signed_data([certificate], [outer_signer])
    write_content_info('nested-missing.der', signed_data)


if __name__ == '__main__':
    build_issuer_serial_duplicate()
    build_ski_conflict()
    build_nested_missing()
    print('Generated CMS signer candidate fixtures in %s' % HERE)
