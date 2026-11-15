# Copyright (C) 2026  JWCrypto Project Contributors - see LICENSE file

import base64
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from jwcrypto import jwk, jws
from jwcrypto.common import base64url_encode, json_decode, json_encode


def _name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'JWCrypto Tests'),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _make_certificate(subject_key, subject_name, issuer_key, issuer_name,
                      ca=False):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA256(), default_backend())


def _cert_b64(cert):
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return base64.b64encode(der).decode('ascii')


def _int_b64(value):
    size = max(1, (value.bit_length() + 7) // 8)
    return base64url_encode(value.to_bytes(size, 'big'))


def _rsa_jwk(key, **params):
    numbers = key.public_key().public_numbers()
    values = {
        'kty': 'RSA',
        'n': _int_b64(numbers.n),
        'e': _int_b64(numbers.e),
    }
    values.update(params)
    return values


def _ec_jwk(key, **params):
    numbers = key.public_key().public_numbers()
    values = {
        'kty': 'EC',
        'crv': 'P-256',
        'x': _int_b64(numbers.x),
        'y': _int_b64(numbers.y),
    }
    values.update(params)
    return values


class TestX5C(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.root_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        cls.intermediate_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        cls.leaf_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())

        root_name = _name('Test Root')
        intermediate_name = _name('Test Intermediate')
        leaf_name = _name('tenant-a.example')
        cls.root_name = root_name
        cls.intermediate_name = intermediate_name
        cls.leaf_name = leaf_name

        cls.root_cert = _make_certificate(
            cls.root_key, root_name, cls.root_key, root_name, ca=True)
        cls.intermediate_cert = _make_certificate(
            cls.intermediate_key, intermediate_name,
            cls.root_key, root_name, ca=True)
        cls.leaf_cert = _make_certificate(
            cls.leaf_key, leaf_name,
            cls.intermediate_key, intermediate_name)
        cls.chain = [
            _cert_b64(cls.leaf_cert),
            _cert_b64(cls.intermediate_cert),
            _cert_b64(cls.root_cert),
        ]

        cls.ec_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend())
        ec_name = _name('tenant-ec.example')
        cls.ec_cert = _make_certificate(
            cls.ec_key, ec_name, cls.ec_key, ec_name)
        cls.ec_chain = [_cert_b64(cls.ec_cert)]

    def test_valid_rsa_chain_import(self):
        key = jwk.JWK(**_rsa_jwk(self.leaf_key, kid='old-key',
                                 use='sig', x5c=self.chain))
        self.assertEqual(key['x5c'], self.chain)
        self.assertTrue(key.get_op_key('verify'))

    def test_valid_ec_certificate_import(self):
        key = jwk.JWK(**_ec_jwk(self.ec_key, kid='ec-key',
                                use='sig', x5c=self.ec_chain))
        self.assertEqual(key['kty'], 'EC')

    def test_leaf_rsa_key_mismatch_rejected(self):
        other_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        values = _rsa_jwk(other_key, kid='old-key', x5c=self.chain)
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(**values)

        values = _rsa_jwk(self.leaf_key, kid='old-key', x5c=self.chain)
        values['e'] = _int_b64(3)
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(**values)

    def test_leaf_ec_key_mismatch_rejected(self):
        other_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend())
        values = _ec_jwk(other_key, kid='ec-key', x5c=self.ec_chain)
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(**values)

        wrong_curve = ec.generate_private_key(
            ec.SECP384R1(), default_backend())
        numbers = wrong_curve.public_key().public_numbers()
        values = {
            'kty': 'EC',
            'crv': 'P-384',
            'x': _int_b64(numbers.x),
            'y': _int_b64(numbers.y),
            'x5c': self.ec_chain,
        }
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(**values)

    def test_malformed_x5c_rejected(self):
        values = _rsa_jwk(self.leaf_key, kid='old-key')
        for bad_chain in (
                'not-an-array',
                [],
                [1],
                [''],
                ['not base64!'],
                [base64.b64encode(b'not a certificate').decode('ascii')],
        ):
            values['x5c'] = bad_chain
            with self.assertRaises(jwk.InvalidJWKValue):
                jwk.JWK(**values)

    def test_broken_chain_name_rejected(self):
        unrelated_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        unrelated_name = _name('Unrelated CA')
        unrelated_cert = _make_certificate(
            unrelated_key, unrelated_name, unrelated_key, unrelated_name,
            ca=True)
        values = _rsa_jwk(
            self.leaf_key, kid='old-key',
            x5c=[_cert_b64(self.leaf_cert), _cert_b64(unrelated_cert)])
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(**values)

    def test_broken_chain_signature_rejected(self):
        rogue_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        # Same subject as the real intermediate, but signed by a rogue key.
        rogue_cert = _make_certificate(
            rogue_key, self.intermediate_name,
            self.root_key, self.root_name, ca=True)
        values = _rsa_jwk(
            self.leaf_key, kid='old-key',
            x5c=[_cert_b64(self.leaf_cert), _cert_b64(rogue_cert)])
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(**values)

    def test_chain_length_limit(self):
        values = _rsa_jwk(
            self.leaf_key, kid='old-key',
            x5c=[_cert_b64(self.leaf_cert)] *
            (jwk.MAX_X5C_CHAIN_LENGTH + 1))
        with self.assertRaises(jwk.InvalidJWKValue):
            jwk.JWK(**values)

    def test_certificate_size_limit(self):
        old_limit = jwk.MAX_X5C_CERTIFICATE_SIZE
        der = self.leaf_cert.public_bytes(
            encoding=serialization.Encoding.DER)
        try:
            jwk.MAX_X5C_CERTIFICATE_SIZE = len(der) - 1
            values = _rsa_jwk(
                self.leaf_key, kid='old-key', x5c=self.chain)
            with self.assertRaises(jwk.InvalidJWKValue):
                jwk.JWK(**values)
        finally:
            jwk.MAX_X5C_CERTIFICATE_SIZE = old_limit

    def test_use_and_key_ops_filter_candidates(self):
        old_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        old_key = jwk.JWK.from_pyca(old_private)
        old_key['kid'] = 'shared'
        old_key['use'] = 'sig'
        enc_key = jwk.JWK(**_rsa_jwk(self.leaf_key, kid='shared',
                                     use='enc', x5c=self.chain))
        keyset = jwk.JWKSet()
        keyset.add(enc_key)
        keyset.add(old_key)

        candidates = keyset.get_keys(
            'shared', use='sig', operation='verify')
        self.assertEqual(candidates, {old_key})
        self.assertEqual(
            keyset.get_key('shared', use='sig', operation='verify'),
            old_key)

        bad_ops_key = jwk.JWK(**_rsa_jwk(self.leaf_key, kid='ops-only',
                                         key_ops=['encrypt'],
                                         x5c=self.chain))
        bad_ops_set = jwk.JWKSet()
        bad_ops_set.add(bad_ops_key)
        self.assertIsNone(
            bad_ops_set.get_key('ops-only', use='sig',
                                operation='verify'))

    def test_duplicate_kid_requires_thumbprint(self):
        other_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        key_a = jwk.JWK(**_rsa_jwk(self.leaf_key, kid='shared', use='sig'))
        key_b = jwk.JWK(**_rsa_jwk(other_key, kid='shared', use='sig'))
        keyset = jwk.JWKSet()
        keyset.add(key_a)
        keyset.add(key_b)

        with self.assertRaises(jwk.InvalidJWKValue):
            keyset.get_key('shared', use='sig', operation='verify')

        selected = keyset.get_key(
            'shared', thumbprint=key_b.thumbprint(),
            use='sig', operation='verify')
        self.assertEqual(selected, key_b)

    def test_forged_x5c_excluded_during_rotation(self):
        old_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        unrelated_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        old_key = jwk.JWK.from_pyca(old_private)
        old_key['kid'] = 'rotating'
        old_key['use'] = 'sig'

        # Simulate a key that was imported with a valid certificate binding
        # and then altered.  It is not equal to the old key, so both remain
        # in the set.
        forged = jwk.JWK(**_rsa_jwk(self.leaf_key, kid='rotating',
                                    use='sig', x5c=self.chain))
        forged['n'] = _rsa_jwk(unrelated_private)['n']
        forged['e'] = _rsa_jwk(unrelated_private)['e']

        keyset = jwk.JWKSet()
        keyset.add(forged)
        keyset.add(old_key)

        selected = keyset.get_key(
            'rotating', use='sig', operation='verify')
        self.assertEqual(selected, old_key)

        token = jws.JWS(b'tenant payload')
        token.add_signature(old_key, protected={'alg': 'RS256',
                                                'kid': 'rotating'})
        verifier = jws.JWS()
        verifier.deserialize(token.serialize(), keyset)
        self.assertTrue(verifier.is_valid)
        self.assertEqual(verifier.payload, b'tenant payload')

    def test_keyset_import_excludes_forged_x5c(self):
        old_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        old_key = _rsa_jwk(old_private, kid='rotating', use='sig')
        forged = _rsa_jwk(self.leaf_key, kid='rotating', use='sig',
                          x5c=self.chain)
        forged['n'] = old_key['n']
        forged['e'] = old_key['e']

        keyset = jwk.JWKSet.from_json(
            json_encode({'keys': [old_key, forged]}))
        self.assertEqual(len(keyset['keys']), 1)
        selected = keyset.get_key('rotating', use='sig',
                                  operation='verify')
        self.assertEqual(selected.thumbprint(),
                         jwk.JWK(**old_key).thumbprint())

    def test_tenant_keysets_verify_separately(self):
        tenant_b_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        tenant_a_private = jwk.JWK.from_pyca(self.leaf_key)
        tenant_a_private['kid'] = 'shared-rotation'
        tenant_a_private['use'] = 'sig'
        tenant_b_private = jwk.JWK.from_pyca(tenant_b_key)
        tenant_b_private['kid'] = 'shared-rotation'
        tenant_b_private['use'] = 'sig'

        keyset_a = jwk.JWKSet()
        keyset_a.add(tenant_a_private)
        keyset_b = jwk.JWKSet()
        keyset_b.add(tenant_b_private)

        token_a = jws.JWS(b'tenant a')
        token_a.add_signature(tenant_a_private,
                              protected={'alg': 'RS256',
                                         'kid': 'shared-rotation'})
        token_b = jws.JWS(b'tenant b')
        token_b.add_signature(tenant_b_private,
                              protected={'alg': 'RS256',
                                         'kid': 'shared-rotation'})

        verifier_a = jws.JWS()
        verifier_a.deserialize(token_a.serialize(), keyset_a)
        self.assertEqual(verifier_a.payload, b'tenant a')

        verifier_b = jws.JWS()
        verifier_b.deserialize(token_b.serialize(), keyset_b)
        self.assertEqual(verifier_b.payload, b'tenant b')

    def test_export_preserves_validated_x5c(self):
        key = jwk.JWK(**_rsa_jwk(self.leaf_key, kid='old-key',
                                 use='sig', x5c=self.chain))
        exported = json_decode(key.export_public())
        self.assertEqual(exported['x5c'], self.chain)


if __name__ == '__main__':
    unittest.main()
