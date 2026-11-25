"""Builders for in-memory synthetic X.509 data and JKS keystores (test/demo only).

These helpers deliberately avoid any cryptographic dependency: they produce
well-formed DER that pyjks stores and the retention auditor parses, but the
signatures are placeholders. They are intended purely for offline retention
decision exercises, never for real PKI.
"""

from __future__ import print_function

import datetime

from pyasn1.codec.der import encoder
from pyasn1.type import char, univ, useful
from pyasn1_modules import rfc2459, rfc5208

from .jks import PrivateKeyEntry, TrustedCertEntry, KeyStore


COMMON_NAME_OID = univ.ObjectIdentifier("2.5.4.3")
SHA256_WITH_RSA_OID = univ.ObjectIdentifier("1.2.840.113549.1.1.11")
RSA_KEY_OID = univ.ObjectIdentifier("1.2.840.113549.1.1.1")


def _dn(common_name):
    rdn = rfc2459.RelativeDistinguishedName()
    atv = rfc2459.AttributeTypeAndValue()
    atv.setComponentByName("type", COMMON_NAME_OID)
    atv.setComponentByName("value", char.UTF8String(common_name))
    rdn.setComponentByPosition(0, atv)
    seq = rfc2459.RDNSequence()
    seq.setComponentByPosition(0, rdn)
    name = rfc2459.Name()
    name.setComponentByPosition(0, seq)
    return name


def _algorithm_identifier(oid=SHA256_WITH_RSA_OID):
    algo = rfc2459.AlgorithmIdentifier()
    algo.setComponentByName("algorithm", oid)
    algo.setComponentByName("parameters", univ.Null(""))
    return algo


def _dummy_spki(seed):
    """A structurally valid but non-functional SubjectPublicKeyInfo."""
    spki = rfc2459.SubjectPublicKeyInfo()
    algo = rfc2459.AlgorithmIdentifier()
    algo.setComponentByName("algorithm", RSA_KEY_OID)
    algo.setComponentByName("parameters", univ.Null(""))
    spki.setComponentByName("algorithm", algo)
    bits = "".join("{:08b}".format(b) for b in b"SYNTHETIC-" + seed)
    spki.setComponentByName("subjectPublicKey",
                            univ.BitString.fromBinaryString(bits))
    return spki


def build_cert(common_name, issuer_name=None, serial=1,
               not_before=None, not_after=None):
    """Build a self-contained synthetic X.509 DER certificate.

    The signature is a fixed placeholder byte string; the DER is still valid
    enough for pyasn1 and the retention auditor, which only read structure.
    """
    not_before = not_before or datetime.datetime(2024, 1, 1)
    not_after = not_after or datetime.datetime(2026, 1, 1)
    subject = _dn(common_name)
    issuer = issuer_name if issuer_name is not None else subject

    tbs = rfc2459.TBSCertificate()
    version_type = tbs.componentType.getTypeByPosition(0)
    tbs.setComponentByName("version", version_type.clone(value="v3"))
    tbs.setComponentByName("serialNumber",
                           rfc2459.CertificateSerialNumber(serial))
    tbs.setComponentByName("signature", _algorithm_identifier())
    tbs.setComponentByName("issuer", issuer)

    validity = rfc2459.Validity()
    start = rfc2459.Time()
    start.setComponentByName(
        "utcTime", useful.UTCTime(not_before.strftime("%y%m%d%H%M%SZ")))
    end = rfc2459.Time()
    end.setComponentByName(
        "utcTime", useful.UTCTime(not_after.strftime("%y%m%d%H%M%SZ")))
    validity.setComponentByName("notBefore", start)
    validity.setComponentByName("notAfter", end)
    tbs.setComponentByName("validity", validity)

    tbs.setComponentByName("subject", subject)
    tbs.setComponentByName("subjectPublicKeyInfo",
                           _dummy_spki(common_name.encode("utf-8")))

    cert = rfc2459.Certificate()
    cert.setComponentByName("tbsCertificate", tbs)
    cert.setComponentByName("signatureAlgorithm", _algorithm_identifier())
    cert.setComponentByName("signatureValue",
                            univ.BitString.fromBinaryString("0" * 256))
    return encoder.encode(cert)


def _placeholder_pkcs8():
    """A structurally valid but non-functional PKCS#8 PrivateKeyInfo."""
    pki = rfc5208.PrivateKeyInfo()
    pki["version"] = 0
    algo = rfc2459.AlgorithmIdentifier()
    algo["algorithm"] = RSA_KEY_OID
    algo["parameters"] = univ.Null("")
    pki["privateKeyAlgorithm"] = algo
    pki["privateKey"] = univ.OctetString(
        b"SYNTHETIC-PRIVATE-KEY-PLACEHOLDER-NOT-A-REAL-KEY")
    return encoder.encode(pki)


DUMMY_PRIVATE_KEY_PKCS8 = _placeholder_pkcs8()


def build_private_key_entry(alias, chain_der):
    """Create a PrivateKeyEntry carrying the supplied public cert chain.

    The embedded PKCS#8 blob is a placeholder; pyjks only needs a structurally
    decodable PrivateKeyInfo for round-tripping, and the retention auditor never
    reads the private key itself.
    """
    return PrivateKeyEntry.new(alias, list(chain_der),
                               DUMMY_PRIVATE_KEY_PKCS8, key_format="pkcs8")


def build_trusted_cert_entry(alias, cert_der):
    """Create a TrustedCertEntry holding one public certificate."""
    return TrustedCertEntry.new(alias, cert_der)


def build_keystore(entries, store_password="retention-demo"):
    """Assemble an in-memory JKS KeyStore from synthetic entries."""
    store = KeyStore.new("jks", list(entries))
    return store, store_password
