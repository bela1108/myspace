# coding: utf-8
"""
Deterministic, private-key-free test fixtures for cert_audit.

cryptography is used only to generate short-lived test certificates in
memory. The returned PKCS#12 archives are built from public certificate DER
only and never embed the generated private keys.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import datetime

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from asn1crypto.x509 import Certificate
from cert_audit.pfx_builder import build_cert_only_pfx


CRYPTOGRAPHY_AVAILABLE = True

_NOT_BEFORE = datetime.datetime(2026, 1, 1, 0, 0, 0)
_NOT_AFTER = datetime.datetime(2031, 1, 1, 0, 0, 0)


def _name(common_name, organization='Certificate Audit Test'):
    return crypto_x509.Name([
        crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


class GeneratedCert(object):
    def __init__(self, cert):
        self._cert = cert
        self.der = cert.public_bytes(serialization.Encoding.DER)
        self.asn1 = Certificate.load(self.der)
        self.fingerprint = self.asn1.sha256.hex().upper()
        self.ski = self.asn1.key_identifier.hex().upper()


def _issue(subject_cn, issuer_cert, issuer_key, ca=False, eku=None, key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = crypto_x509.CertificateBuilder().subject_name(
        _name(subject_cn)
    ).issuer_name(
        issuer_cert.subject if issuer_cert else _name(subject_cn)
    ).public_key(
        key.public_key()
    ).serial_number(
        crypto_x509.random_serial_number()
    ).not_valid_before(
        _NOT_BEFORE
    ).not_valid_after(
        _NOT_AFTER
    ).add_extension(
        crypto_x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )

    if ca:
        builder = builder.add_extension(
            crypto_x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            crypto_x509.KeyUsage(
                digital_signature=False, key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            crypto_x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            crypto_x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        if eku:
            builder = builder.add_extension(
                crypto_x509.ExtendedKeyUsage(eku), critical=False
            )

    if issuer_cert is not None:
        builder = builder.add_extension(
            crypto_x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        signed = builder.sign(issuer_key, hashes.SHA256())
    else:
        builder = builder.add_extension(
            crypto_x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        signed = builder.sign(key, hashes.SHA256())
    return GeneratedCert(signed)


def build_test_material():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _issue('Audit Test Root CA', None, root_key, ca=True, key=root_key)

    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate = _issue('Audit Test Intermediate CA', root._cert, root_key, ca=True,
                          key=intermediate_key)

    leaf_server = _issue(
        'server.example.com', intermediate._cert, intermediate_key,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    leaf_client = _issue(
        'client.example.com', intermediate._cert, intermediate_key,
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    leaf_server_renewed = _issue(
        'server.example.com', intermediate._cert, intermediate_key,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    external_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    external_ca = _issue('External Root CA', None, external_ca_key, ca=True, key=external_ca_key)
    leaf_orphan = _issue(
        'orphan.example.com', external_ca._cert, external_ca_key,
        eku=[ExtendedKeyUsageOID.CODE_SIGNING],
    )

    batch_a = build_cert_only_pfx([
        {'certificate': root.der, 'friendly_name': 'root-ca', 'local_key_id': b'\x01root'},
        {'certificate': intermediate.der, 'friendly_name': 'intermediate-ca',
         'local_key_id': b'\x02inter'},
        {'certificate': leaf_server.der, 'friendly_name': 'display-cert',
         'local_key_id': b'\x03leaf'},
        {'certificate': leaf_orphan.der, 'friendly_name': 'display-cert',
         'local_key_id': b'\x04orphan'},
    ])
    batch_b = build_cert_only_pfx([
        {'certificate': root.der, 'friendly_name': 'root-ca', 'local_key_id': b'\x01root'},
        {'certificate': intermediate.der, 'friendly_name': 'intermediate-ca',
         'local_key_id': b'\x02inter'},
        {'certificate': leaf_server.der, 'friendly_name': 'display-cert',
         'local_key_id': b'\x03leaf'},
        {'certificate': leaf_server_renewed.der, 'friendly_name': 'display-cert',
         'local_key_id': b'\x06renewed'},
        {'certificate': leaf_client.der, 'friendly_name': 'client-cert',
         'local_key_id': b'\x05client'},
    ])

    manifest = {
        'allowed_usage': ['server_auth', 'client_auth'],
        'intermediates': [
            {'subject_key_identifier': intermediate.ski},
        ],
        'leaves': [
            {
                'sha256_fingerprint': leaf_server.fingerprint,
                'usage': ['server_auth'],
                'allowed_issuers': [{'subject_key_identifier': intermediate.ski}],
            },
            {
                'sha256_fingerprint': leaf_server_renewed.fingerprint,
                'usage': ['server_auth'],
                'allowed_issuers': [{'subject_key_identifier': intermediate.ski}],
            },
            {
                'sha256_fingerprint': leaf_client.fingerprint,
                'usage': ['client_auth'],
                'allowed_issuers': [{'subject_key_identifier': intermediate.ski}],
            },
        ],
    }

    return {
        'root': root,
        'intermediate': intermediate,
        'leaf_server': leaf_server,
        'leaf_server_renewed': leaf_server_renewed,
        'leaf_client': leaf_client,
        'leaf_orphan': leaf_orphan,
        'batch_a_pfx': batch_a,
        'batch_b_pfx': batch_b,
        'manifest': manifest,
    }
