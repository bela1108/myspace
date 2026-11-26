# coding: utf-8
"""Regenerate legal, self-consistent synthetic CSR fixtures for acceptance tests."""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


FIXTURE_DIR = Path(__file__).resolve().parent
REPO_ROOT = FIXTURE_DIR.parents[2]
DEFAULT_KEY = REPO_ROOT / 'tests' / 'fixtures' / 'keys' / 'test.key'


def load_private_key():
    if DEFAULT_KEY.exists():
        return serialization.load_pem_private_key(DEFAULT_KEY.read_bytes(), password=None)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write_csr(filename, key, name):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .sign(key, hashes.SHA256())
    )
    if not csr.is_signature_valid:
        raise AssertionError('generated CSR signature is invalid: %s' % filename)
    path = FIXTURE_DIR / filename
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return path


def main():
    key = load_private_key()

    same_text_a = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Shared Service Desk'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Procurement'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Agency'),
    ])

    same_text_b = x509.Name([
        x509.RelativeDistinguishedName([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Shared Service Desk'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Procurement'),
        ]),
        x509.RelativeDistinguishedName([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Agency'),
        ]),
    ])

    same_text_order_swap = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Procurement'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'Shared Service Desk'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Agency'),
    ])

    legacy_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'procurement-desk-092'),
        x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            'General Affairs Department',
        ),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Legacy Example Bureau'),
    ])

    current_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'procurement-portal.example.test'),
        x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            'Central Procurement Office',
        ),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Public Agency'),
        x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, 'OLD-DEPT-092'),
    ])

    extra_attribute_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'procurement-portal.example.test'),
        x509.NameAttribute(NameOID.TITLE, 'Procurement Operator'),
        x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            'Central Procurement Office',
        ),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Public Agency'),
        x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, 'OLD-DEPT-092'),
    ])

    write_csr('same-text-hierarchy-a.csr', key, same_text_a)
    write_csr('same-text-hierarchy-b.csr', key, same_text_b)
    write_csr('same-text-order-swap.csr', key, same_text_order_swap)
    write_csr('procurement-legacy.csr', key, legacy_name)
    write_csr('procurement-current.csr', key, current_name)
    write_csr('procurement-current-extra-attribute.csr', key, extra_attribute_name)


if __name__ == '__main__':
    main()
