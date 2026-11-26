# coding: utf-8
"""
In-memory CMS samples for the RFC 6211 algorithm-protection review.

Every builder returns a cms.ContentInfo object.  Calling ``.dump()`` on the
object produces the DER used by the review code; no binary fixture files are
needed and the samples can be rebuilt in a test process or a review notebook.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import collections

from asn1crypto import algos, cms, core, x509
from asn1crypto._types import chr_cls


NULL = b'\x05\x00'


def _der_length(length):
    if length < 128:
        return chr_cls(length)
    encoded = []
    while length:
        encoded.insert(0, length & 0xff)
        length >>= 8
    return chr_cls(0x80 | len(encoded)) + b''.join(chr_cls(value) for value in encoded)


def _tlv(tag, contents):
    return chr_cls(tag) + _der_length(len(contents)) + contents


def _seq(*parts):
    return _tlv(0x30, b''.join(parts))


def _oid(oid):
    return core.ObjectIdentifier(oid).dump()


def algorithm_der(oid, parameters='null'):
    """
    Builds an AlgorithmIdentifier DER blob.

    ``parameters`` may be "absent", "null", or a raw DER TLV byte string.
    """

    parts = [_oid(oid)]
    if parameters == 'null':
        parts.append(NULL)
    elif parameters != 'absent':
        parts.append(parameters)
    return _seq(*parts)


def digest_algorithm(oid, parameters='null'):
    return algos.DigestAlgorithm.load(algorithm_der(oid, parameters))


def signature_algorithm(oid, parameters='null'):
    return algos.SignedDigestAlgorithm.load(algorithm_der(oid, parameters))


def mac_algorithm(oid, parameters='absent'):
    return algos.HmacAlgorithm.load(algorithm_der(oid, parameters))


def pss_parameters(hash_name='sha256', mgf_hash_name='sha256', salt_length=32, absent_defaults=False):
    if absent_defaults:
        return 'absent'
    if hash_name is None:
        hash_name = 'sha256'
    params = algos.RSASSAPSSParams.load(_seq())
    if not (hash_name == 'sha1' and mgf_hash_name == 'sha1' and salt_length == 20):
        params = algos.RSASSAPSSParams({
            'hash_algorithm': {'algorithm': hash_name},
            'mask_gen_algorithm': {
                'algorithm': 'mgf1',
                'parameters': {'algorithm': mgf_hash_name},
            },
            'salt_length': salt_length,
        })
    return params.dump()


def identity(common_name='Alice', serial_number=1):
    return {
        'issuer_and_serial_number': {
            'issuer': x509.Name.build({'common_name': common_name}),
            'serial_number': serial_number,
        }
    }


def protection_value(digest, signature=None, mac=None):
    value = {'digest_algorithm': digest}
    if signature is not None:
        value['signature_algorithm'] = signature
    if mac is not None:
        value['mac_algorithm'] = mac
    return cms.CMSAlgorithmProtection(value)


def protection_attribute(value):
    return {'type': 'cms_algorithm_protection', 'values': [value]}


def _other_signed_attributes():
    return [
        {'type': 'content_type', 'values': ['data']},
        {'type': 'message_digest', 'values': [b'\x00' * 32]},
    ]


def signer_info(
        digest,
        signature,
        protection=None,
        signed=True,
        unsigned=False,
        common_name='Alice',
        serial_number=1,
        extra_signed_attrs=None,
        extra_unsigned_attrs=None):
    """
    Builds a SignerInfo.  ``protection`` may be a CMSAlgorithmProtection
    object, a list of values (to create duplicate values) or None.
    """

    signed_attrs = _other_signed_attributes()
    unsigned_attrs = None

    if protection is not None:
        if not isinstance(protection, list):
            protection = [protection]
        attribute = {'type': 'cms_algorithm_protection', 'values': protection}
        if signed:
            signed_attrs.append(attribute)
        if unsigned:
            unsigned_attrs = [attribute]

    if extra_signed_attrs:
        signed_attrs.extend(extra_signed_attrs)
    if extra_unsigned_attrs:
        unsigned_attrs = extra_unsigned_attrs

    values = {
        'version': 'v1',
        'sid': identity(common_name, serial_number),
        'digest_algorithm': digest,
        'signed_attrs': signed_attrs,
        'signature_algorithm': signature,
        'signature': b'\x01' * 32,
    }
    if unsigned_attrs:
        values['unsigned_attrs'] = unsigned_attrs
    return cms.SignerInfo(values)


def signed_data(signers, digest=None, content=b'hello'):
    digest_algorithms = []
    if digest is not None:
        digest_algorithms.append(digest)
    for signer in signers:
        signer_digest = signer['digest_algorithm']
        signer_digest_oid = signer_digest['algorithm'].dotted
        if not any(algorithm['algorithm'].dotted == signer_digest_oid for algorithm in digest_algorithms):
            digest_algorithms.append(signer_digest)
    if not digest_algorithms:
        digest_algorithms.append(digest_algorithm('2.16.840.1.101.3.4.2.1'))
    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': cms.SignedData({
            'version': 'v1',
            'digest_algorithms': digest_algorithms,
            'encap_content_info': {'content_type': 'data', 'content': content},
            'signer_infos': signers,
        }),
    })


def _recipient_info():
    return cms.RecipientInfo({
        'ktri': {
            'version': 'v0',
            'rid': {
                'issuer_and_serial_number': {
                    'issuer': x509.Name.build({'common_name': 'Recipient'}),
                    'serial_number': 7,
                },
            },
            'key_encryption_algorithm': {'algorithm': 'rsaes_pkcs1v15'},
            'encrypted_key': b'\x00' * 8,
        },
    })


def authenticated_data(
        digest,
        mac,
        protection=None,
        authenticated=True,
        unauthenticated=False,
        content=b'hello'):
    auth_attrs = None
    unauth_attrs = None
    if protection is not None:
        if not isinstance(protection, list):
            protection = [protection]
        attribute = {'type': 'cms_algorithm_protection', 'values': protection}
        if authenticated:
            auth_attrs = [attribute]
        if unauthenticated:
            unauth_attrs = [attribute]

    values = {
        'version': 'v0',
        'recipient_infos': [_recipient_info()],
        'mac_algorithm': mac,
        'digest_algorithm': digest,
        'encap_content_info': {'content_type': 'data', 'content': content},
        'mac': b'\x11' * 32,
    }
    if auth_attrs:
        values['auth_attrs'] = auth_attrs
    if unauth_attrs:
        values['unauth_attrs'] = unauth_attrs
    return cms.ContentInfo({
        'content_type': 'authenticated_data',
        'content': cms.AuthenticatedData(values),
    })


def sample_set():
    """
    Returns an OrderedDict of scenario name -> cms.ContentInfo.  Each sample
    is independent and can be dumped and reloaded in memory.
    """

    sha256 = '2.16.840.1.101.3.4.2.1'
    sha256_rsa = '1.2.840.113549.1.1.11'
    sha384_rsa = '1.2.840.113549.1.1.12'
    pss = '1.2.840.113549.1.1.10'
    hmac_sha256 = '1.2.840.113549.2.9'
    hmac_sha384 = '1.2.840.113549.2.10'

    good_digest = digest_algorithm(sha256)
    good_signature = signature_algorithm(sha256_rsa)
    good_protection = protection_value(good_digest, signature=good_signature)

    samples = collections.OrderedDict()

    samples['signed_protected'] = signed_data([
        signer_info(good_digest, good_signature, good_protection, common_name='Alice', serial_number=1),
    ])

    samples['signed_legacy_unprotected'] = signed_data([
        signer_info(good_digest, good_signature, None, common_name='Bob', serial_number=2),
    ])

    samples['signed_unsigned_only'] = signed_data([
        signer_info(
            good_digest,
            good_signature,
            good_protection,
            signed=False,
            unsigned=True,
            common_name='Carol',
            serial_number=3,
        ),
    ])

    samples['signed_duplicate_attribute'] = signed_data([
        signer_info(
            good_digest,
            good_signature,
            good_protection,
            common_name='Dave',
            serial_number=4,
            extra_signed_attrs=[
                {'type': 'cms_algorithm_protection', 'values': [good_protection]},
            ],
        ),
    ])

    samples['signed_duplicate_value'] = signed_data([
        signer_info(
            good_digest,
            good_signature,
            [good_protection, good_protection],
            common_name='Dave2',
            serial_number=5,
        ),
    ])

    samples['signed_protected_unauth_copy'] = signed_data([
        signer_info(
            good_digest,
            good_signature,
            good_protection,
            unsigned=True,
            common_name='Dave3',
            serial_number=12,
        ),
    ])

    samples['signed_algorithm_mismatch'] = signed_data([
        signer_info(
            good_digest,
            signature_algorithm(sha384_rsa),
            good_protection,
            common_name='Eve',
            serial_number=6,
        ),
    ])

    pss_signer = signature_algorithm(pss, pss_parameters(hash_name='sha256', salt_length=32))
    pss_protection = protection_value(
        digest_algorithm(sha256),
        signature=signature_algorithm(pss, pss_parameters(hash_name='sha256', salt_length=20)),
    )
    samples['signed_parameter_mismatch'] = signed_data([
        signer_info(good_digest, pss_signer, pss_protection, common_name='Frank', serial_number=7),
    ])

    samples['signed_missing_signature_component'] = signed_data([
        signer_info(
            good_digest,
            good_signature,
            protection_value(good_digest),
            common_name='Frank2',
            serial_number=16,
        ),
    ])

    opaque_pss_der = _seq(_oid(pss), _tlv(0x04, b'ab'))
    opaque_pss = algos.SignedDigestAlgorithm.load(opaque_pss_der)
    samples['signed_unsupported_parameters'] = signed_data([
        signer_info(
            good_digest,
            opaque_pss,
            protection_value(good_digest, signature=opaque_pss),
            common_name='Grace',
            serial_number=8,
        ),
    ])

    absent_digest = digest_algorithm(sha256, parameters='absent')
    absent_signature = signature_algorithm(sha256_rsa, parameters='absent')
    samples['signed_null_vs_absent'] = signed_data([
        signer_info(
            absent_digest,
            absent_signature,
            protection_value(digest_algorithm(sha256), signature=signature_algorithm(sha256_rsa)),
            common_name='Helen',
            serial_number=9,
        ),
    ])

    samples['signed_alias_equivalent'] = signed_data([
        signer_info(
            digest_algorithm('1.3.14.3.2.26'),
            signature_algorithm('1.3.14.3.2.27', parameters='absent'),
            protection_value(
                digest_algorithm('1.3.14.3.2.26'),
                signature=signature_algorithm('1.2.840.10040.4.3', parameters='null'),
            ),
            common_name='Helen2',
            serial_number=13,
        ),
    ])

    samples['signed_generic_rsa_equivalent'] = signed_data([
        signer_info(
            digest_algorithm(sha256),
            signature_algorithm('1.2.840.113549.1.1.1'),
            protection_value(digest_algorithm(sha256), signature=signature_algorithm(sha256_rsa)),
            common_name='Helen4',
            serial_number=15,
        ),
    ])

    samples['signed_pss_defaults_equivalent'] = signed_data([
        signer_info(
            digest_algorithm('1.3.14.3.2.26'),
            signature_algorithm(
                pss,
                pss_parameters(hash_name='sha1', mgf_hash_name='sha1', salt_length=20, absent_defaults=True),
            ),
            protection_value(
                digest_algorithm('1.3.14.3.2.26'),
                signature=signature_algorithm(
                    pss,
                    pss_parameters(hash_name='sha1', mgf_hash_name='sha1', salt_length=20),
                ),
            ),
            common_name='Helen3',
            serial_number=14,
        ),
    ])

    samples['signed_mixed_ledger'] = signed_data([
        signer_info(good_digest, good_signature, good_protection, common_name='Ivan', serial_number=10),
        signer_info(good_digest, good_signature, None, common_name='Judy', serial_number=11),
    ])

    hmac = mac_algorithm(hmac_sha256)
    samples['authenticated_data_protected'] = authenticated_data(
        digest_algorithm(sha256),
        hmac,
        protection_value(digest_algorithm(sha256), mac=mac_algorithm(hmac_sha256)),
    )

    samples['authenticated_data_unauth_only'] = authenticated_data(
        digest_algorithm(sha256),
        hmac,
        protection_value(digest_algorithm(sha256), mac=mac_algorithm(hmac_sha256)),
        authenticated=False,
        unauthenticated=True,
    )

    samples['authenticated_data_mac_mismatch'] = authenticated_data(
        digest_algorithm(sha256),
        mac_algorithm(hmac_sha384),
        protection_value(digest_algorithm(sha256), mac=mac_algorithm(hmac_sha256)),
    )

    return samples


def sample_reviews():
    """Returns scenario name -> CMSAlgorithmProtectionReview for the sample set."""

    from asn1crypto import cms_algorithm_protection

    return collections.OrderedDict(
        (name, cms_algorithm_protection.review(content_info))
        for name, content_info in sample_set().items()
    )


def render_sample_ledger():
    """Renders every sample as a reviewer-facing text report."""

    chunks = []
    for name, review in sample_reviews().items():
        chunks.append('%s\n%s' % (name, review.format_text()))
    return '\n\n'.join(chunks)


if __name__ == '__main__':
    print(render_sample_ledger())
