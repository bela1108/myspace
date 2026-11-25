#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""Tests for explicit single-entry key-to-certificate verification.

All keystores in this module are generated synthetically at runtime so that
the tests can deterministically produce the three relevant situations:
a matching key/certificate pair, a mismatched pair (a re-pasted foreign
certificate chain), and a complete entry whose algorithm the local verifier
does not support.
"""

from __future__ import print_function
import unittest

from Cryptodome.PublicKey import RSA, DSA
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, char, useful
from pyasn1_modules import rfc2459, rfc5208

import jks
from jks import util


STORE_PASSWORD = "archiving-password"
WRONG_PASSWORD = "not-the-password"


def _algorithm_identifier(oid, params=None):
    alg_id = rfc2459.AlgorithmIdentifier()
    alg_id.setComponentByName("algorithm", oid)
    if params is not None:
        alg_id.setComponentByName("parameters", params)
    else:
        alg_id.setComponentByName("parameters", univ.Null())
    return alg_id


def _rsa_material(bits=1024):
    key = RSA.generate(bits)
    pkcs8 = key.export_key("DER", pkcs=8)
    spki_der = key.publickey().export_key("DER")
    return pkcs8, spki_der, util.RSA_ENCRYPTION_OID


def _dsa_material(bits=1024):
    key = DSA.generate(bits)

    params = univ.Sequence()
    for idx, value in enumerate((key.p, key.q, key.g)):
        params.setComponentByPosition(idx, univ.Integer(value))

    private_key_info = rfc5208.PrivateKeyInfo()
    private_key_info.setComponentByName("version", "v1")
    private_key_info.setComponentByName("privateKeyAlgorithm", _algorithm_identifier(util.DSA_OID, params))
    private_key_info.setComponentByName("privateKey", univ.OctetString(encoder.encode(univ.Integer(key.x))))
    pkcs8 = encoder.encode(private_key_info)

    public_integer = encoder.encode(univ.Integer(key.y))
    spki = rfc2459.SubjectPublicKeyInfo()
    spki.setComponentByName("algorithm", _algorithm_identifier(util.DSA_OID, params))
    spki.setComponentByName("subjectPublicKey", univ.BitString.fromOctetString(bytearray(public_integer)))
    spki_der = encoder.encode(spki)
    return pkcs8, spki_der, util.DSA_OID


def _make_certificate(spki_der, subject_cn, serial):
    """Build a minimal self-issued X.509 certificate; signature bytes are
    placeholders because verification only compares public-key material."""
    spki, _ = decoder.decode(spki_der, asn1Spec=rfc2459.SubjectPublicKeyInfo())

    rdn_sequence = rfc2459.RDNSequence()
    rdn = rfc2459.RelativeDistinguishedName()
    atv = rfc2459.AttributeTypeAndValue()
    atv.setComponentByName("type", rfc2459.id_at_commonName)
    atv.setComponentByName("value", char.UTF8String(subject_cn))
    rdn.setComponentByPosition(0, atv)
    rdn_sequence.setComponentByPosition(0, rdn)
    name = rfc2459.Name()
    name.setComponentByName("", rdn_sequence)

    validity = rfc2459.Validity()
    for field, value in (("notBefore", "200101000000Z"), ("notAfter", "491231235959Z")):
        time_choice = rfc2459.Time()
        time_choice.setComponentByName("utcTime", useful.UTCTime(value))
        validity.setComponentByName(field, time_choice)

    tbs = rfc2459.TBSCertificate()
    tbs.setComponentByName("serialNumber", univ.Integer(serial))
    tbs.setComponentByName("signature", _algorithm_identifier(util.DSA_WITH_SHA1_OID))
    tbs.setComponentByName("issuer", name)
    tbs.setComponentByName("subject", name)
    tbs.setComponentByName("validity", validity)
    tbs.setComponentByName("subjectPublicKeyInfo", spki)

    certificate = rfc2459.Certificate()
    certificate.setComponentByName("tbsCertificate", tbs)
    certificate.setComponentByName("signatureAlgorithm", _algorithm_identifier(util.DSA_WITH_SHA1_OID))
    certificate.setComponentByName("signatureValue", univ.BitString.fromBinaryString("0" * 160))
    return encoder.encode(certificate)


class RsaOnlyVerifier(util.LocalCertificateVerifier):
    """Reference local verifier: reconstructs the SubjectPublicKeyInfo from an
    RSA private key and compares it byte-for-byte with the public key carried
    in the leaf certificate."""

    def supports_algorithm(self, algorithm_oid):
        return algorithm_oid == util.RSA_ENCRYPTION_OID

    def verify(self, private_key_pkcs8, leaf_certificate, algorithm_oid):
        if not self.supports_algorithm(algorithm_oid):
            raise util.UnsupportedKeyAlgorithmException("Unsupported algorithm OID %r" % (algorithm_oid,))
        private_key_info, _ = decoder.decode(private_key_pkcs8, asn1Spec=rfc5208.PrivateKeyInfo())
        rsa_private_key = RSA.import_key(encoder.encode(private_key_info))
        expected_spki = rsa_private_key.publickey().export_key("DER")
        certificate, _ = decoder.decode(leaf_certificate, asn1Spec=rfc2459.Certificate())
        actual_spki = encoder.encode(certificate["tbsCertificate"]["subjectPublicKeyInfo"])
        return expected_spki == actual_spki


class AlwaysFalseVerifier(RsaOnlyVerifier):
    def verify(self, private_key_pkcs8, leaf_certificate, algorithm_oid):
        return False


def _build_jks(private_key_pkcs8, leaf_certificate, alias="archived"):
    entry = jks.PrivateKeyEntry.new(alias, [leaf_certificate], private_key_pkcs8)
    store = jks.KeyStore.new("jks", [entry])
    return store.saves(STORE_PASSWORD)


class CertificateVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = RsaOnlyVerifier()

        matching_pkcs8, matching_spki, _ = _rsa_material()
        matching_cert = _make_certificate(matching_spki, "matching identity", serial=101)
        cls.matching_bytes = _build_jks(matching_pkcs8, matching_cert, alias="matching")
        cls.matching_cert = matching_cert

        key_pkcs8, key_spki, _ = _rsa_material()
        _, foreign_spki, _ = _rsa_material()
        foreign_cert = _make_certificate(foreign_spki, "foreign re-pasted identity", serial=202)
        cls.mismatched_bytes = _build_jks(key_pkcs8, foreign_cert, alias="mismatched")
        cls.foreign_cert = foreign_cert

        dsa_pkcs8, dsa_spki, _ = _dsa_material()
        dsa_cert = _make_certificate(dsa_spki, "dsa identity", serial=303)
        cls.unsupported_bytes = _build_jks(dsa_pkcs8, dsa_cert, alias="unsupported")
        cls.dsa_cert = dsa_cert


    def _load(self, data):
        return jks.KeyStore.loads(data, STORE_PASSWORD, try_decrypt_keys=False)

    def test_read_only_inventory_only_exposes_public_cert_data(self):
        """Read-only inventory can show the declared leaf certificate and its
        public identity, but cannot itself prove any key/certificate relationship."""
        for data in (self.matching_bytes, self.mismatched_bytes, self.unsupported_bytes):
            store = self._load(data)
            entry = list(store.private_keys.values())[0]
            self.assertFalse(entry.is_decrypted())
            self.assertRaises(jks.NotYetDecryptedException, lambda: entry.pkey)
            self.assertRaises(jks.NotYetDecryptedException, lambda: entry.pkey_pkcs8)
            self.assertRaises(jks.NotYetDecryptedException, lambda: entry.algorithm_oid)
            self.assertTrue(entry.cert_chain[0][1])
            subject_dn, serial = jks.jks._read_leaf_identity(entry.cert_chain[0][1])
            self.assertTrue(subject_dn.startswith("CN="))
            self.assertTrue(serial)

    def test_matching_material_verifies_as_matched(self):
        store = self._load(self.matching_bytes)
        result = store.verify_entry("matching", STORE_PASSWORD, self.verifier)
        self.assertEqual(result.status, jks.CertificateVerificationResult.MATCHED)
        self.assertTrue(result.matched)
        self.assertEqual(result.alias, "matching")
        self.assertEqual(result.leaf_certificate, self.matching_cert)
        self.assertEqual(result.subject_dn, "CN=matching identity")
        self.assertEqual(result.serial_number, "65")
        self.assertEqual(len(result.sha1_fingerprint), 40)
        self.assertEqual(len(result.sha256_fingerprint), 64)
        self.assertEqual(result.sha1_fingerprint, util.as_hex(jks.jks.hashlib.sha1(self.matching_cert).digest()).upper())

    def test_mismatched_material_verifies_as_mismatched(self):
        store = self._load(self.mismatched_bytes)
        result = store.verify_entry("mismatched", STORE_PASSWORD, self.verifier)
        self.assertEqual(result.status, jks.CertificateVerificationResult.MISMATCHED)
        self.assertFalse(result.matched)
        self.assertEqual(result.leaf_certificate, self.foreign_cert)
        self.assertEqual(result.subject_dn, "CN=foreign re-pasted identity")
        self.assertEqual(result.serial_number, "CA")

    def test_unsupported_algorithm_is_distinct_from_mismatch(self):
        store = self._load(self.unsupported_bytes)
        with self.assertRaises(jks.UnsupportedKeyAlgorithmException) as cm:
            store.verify_entry("unsupported", STORE_PASSWORD, self.verifier)
        message = str(cm.exception)
        self.assertNotIn(STORE_PASSWORD, message)
        self.assertNotIn(WRONG_PASSWORD, message)
        self.assertIn("1.2.840.10040.4.1", message)

    def test_wrong_password_is_distinct_from_unsupported_and_mismatch(self):
        store = self._load(self.matching_bytes)
        self.assertRaises(jks.DecryptionFailureException, store.verify_entry, "matching", WRONG_PASSWORD, self.verifier)
        store2 = self._load(self.unsupported_bytes)
        self.assertRaises(jks.DecryptionFailureException, store2.verify_entry, "unsupported", WRONG_PASSWORD, self.verifier)


    def test_verifier_failure_verdict_is_passed_through(self):
        store = self._load(self.matching_bytes)
        result = store.verify_entry("matching", STORE_PASSWORD, AlwaysFalseVerifier())
        self.assertEqual(result.status, jks.CertificateVerificationResult.MISMATCHED)

    def test_unknown_alias_and_wrong_entry_type(self):
        store = self._load(self.matching_bytes)
        self.assertRaises(KeyError, store.verify_entry, "missing", STORE_PASSWORD, self.verifier)
        trusted = jks.TrustedCertEntry.new("trusted", self.matching_cert)
        mixed = jks.KeyStore.new("jks", [trusted])
        self.assertRaises(jks.UnsupportedKeystoreEntryTypeException, mixed.verify_entry, "trusted", STORE_PASSWORD, self.verifier)

    def test_empty_certificate_chain_is_reported(self):
        matching_pkcs8, matching_spki, _ = _rsa_material()
        entry = jks.PrivateKeyEntry(cert_chain=[], encrypted=None, pkey=b"x",
                                    pkey_pkcs8=matching_pkcs8,
                                    algorithm_oid=util.RSA_ENCRYPTION_OID,
                                    store_type="jks", alias="empty")
        self.assertRaises(jks.EmptyCertificateChainException, entry.verify_certificate, STORE_PASSWORD, self.verifier)

    def test_results_and_exceptions_never_contain_secrets(self):
        store = self._load(self.matching_bytes)
        result = store.verify_entry("matching", STORE_PASSWORD, self.verifier)
        public_text = repr(result) + str(result.__dict__)
        self.assertNotIn(STORE_PASSWORD, public_text)
        self.assertNotIn(WRONG_PASSWORD, public_text)
        entry = store.entries["matching"]
        secret_markers = [entry.pkey, entry.pkey_pkcs8]
        for marker in secret_markers:
            self.assertNotIn(marker.decode("latin-1"), repr(result))
            self.assertNotIn(marker.decode("latin-1"), str(result.__dict__))


if __name__ == "__main__":
    unittest.main()
