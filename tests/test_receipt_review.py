from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pycose.algorithms import Es256
from pycose.exceptions import CoseInvalidCertificate
from pycose.extensions.x509 import X5Chain
from pycose.headers import Algorithm, X5chain
from pycose.keys import CoseKey
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.messages import Sign1Message
from pycose.receipts import (
    CONFIRMED_SIGNING_TIME,
    TIMESTAMP_BINDING,
    DeliveryReceipt,
    DispatchStatus,
    EvidenceStatus,
    LocalIdentityStore,
    SigningTimeEvidence,
    TransferAuthorization,
    TransferReviewer,
    review_delivery_receipts,
)


UTC = timezone.utc
SIGNED_AT = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
REVIEWED_AT = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
REVOKED_AT = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _der(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)


def _key_usage(leaf):
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=not leaf,
        crl_sign=not leaf,
        encipher_only=False,
        decipher_only=False,
    )


def _build_ca(common_name='Delivery Root'):
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(common_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _build_leaf(root_key, root_name, common_name, serial, not_after):
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(root_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(True), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    return key, certificate


@dataclass
class Material:
    root_der: bytes
    first_key: object
    first_der: bytes
    second_key: object
    second_der: bytes
    crl_der: bytes


@pytest.fixture(scope='module')
def material():
    root_key, root = _build_ca()
    first_key, first = _build_leaf(
        root_key, root.subject, 'Delivery Issuer A', 1001,
        datetime(2026, 6, 1, tzinfo=UTC),
    )
    second_key, second = _build_leaf(
        root_key, root.subject, 'Delivery Issuer B', 1002,
        datetime(2026, 6, 1, tzinfo=UTC),
    )

    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(1002)
        .revocation_date(REVOKED_AT)
        .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.subject)
        .last_update(datetime(2026, 11, 1, tzinfo=UTC))
        .next_update(datetime(2027, 1, 1, tzinfo=UTC))
        .add_revoked_certificate(revoked)
        .sign(root_key, hashes.SHA256())
    )
    return Material(
        root_der=_der(root),
        first_key=first_key,
        first_der=_der(first),
        second_key=second_key,
        second_der=_der(second),
        crl_der=_der(crl),
    )


def _cose_key(private_key):
    return CoseKey._from_cryptography_key(
        private_key,
        optional_params={KpAlg: Es256, KpKeyOps: [SignOp, VerifyOp]},
    )


def _signed_receipt(private_key, certificate_der, payload):
    message = Sign1Message(
        phdr={Algorithm: Es256},
        uhdr={X5chain: [certificate_der]},
        payload=payload,
    )
    message.key = _cose_key(private_key)
    return message.encode()


def _time_evidence(encoded, source='delivery log'):
    return SigningTimeEvidence(
        SIGNED_AT,
        source=source,
        message_digest=sha256(encoded).digest(),
    )


def _receipt(receipt_id, encoded, signing_time=None, **kwargs):
    return DeliveryReceipt(
        receipt_id,
        encoded,
        recipient='archive',
        purpose='device_delivery',
        signing_time=signing_time,
        encoded_receipt=encoded,
        **kwargs,
    )


def _permit(permit_id, receipt_id, revoked_at=None):
    return TransferAuthorization(
        permit_id,
        recipient='archive',
        purpose='device_delivery',
        receipt_ids=frozenset({receipt_id}),
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        revoked_at=revoked_at,
    )


def _first_two_receipts(material):
    first_encoded = _signed_receipt(
        material.first_key, material.first_der, b'device delivery one')
    second_encoded = _signed_receipt(
        material.second_key, material.second_der, b'device delivery two')
    return (
        _receipt('receipt-one', first_encoded, _time_evidence(first_encoded)),
        _receipt('receipt-two', second_encoded, _time_evidence(second_encoded)),
    )


def test_same_day_receipts_keep_history_but_revoked_permit_shrinks_dispatch(material):
    first, second = _first_two_receipts(material)
    store = LocalIdentityStore(
        trust_roots=[material.root_der],
        authorizations=[_permit('permit-one', 'receipt-one'),
                        _permit('permit-two', 'receipt-two')],
    )

    before = TransferReviewer(store, now=REVIEWED_AT).review([first, second])
    assert before.historical_evidence_ids == ('receipt-one', 'receipt-two')
    assert before.dispatchable_ids == ('receipt-one', 'receipt-two')
    assert all(review.signature_valid for review in before)

    after_store = store.with_revoked_authorization('permit-two', REVOKED_AT)
    after = TransferReviewer(after_store, now=REVIEWED_AT).review([first, second])

    assert after.historical_evidence_ids == ('receipt-one', 'receipt-two')
    assert after.dispatchable_ids == ('receipt-one',)
    assert after.by_id('receipt-two').dispatch_status is DispatchStatus.REVOKED
    assert after.by_id('receipt-two').certificate_valid_now is False
    assert after.by_id('receipt-one').certificate_valid_now is False
    assert all(review.historical_status is EvidenceStatus.HISTORICAL for review in after)


def test_missing_confirmed_time_is_reported_instead_of_using_claim(material):
    encoded = _signed_receipt(material.first_key, material.first_der, b'no trusted time')
    receipt = _receipt(
        'receipt-claim',
        encoded,
        signing_time=None,
        claimed_signing_time=SIGNED_AT,
    )
    store = LocalIdentityStore(
        trust_roots=[material.root_der],
        authorizations=[_permit('permit-claim', 'receipt-claim')],
    )

    review = TransferReviewer(store, now=REVIEWED_AT).review([receipt])[0]

    assert review.signature_valid
    assert review.historical_evidence is False
    assert review.historical_status is EvidenceStatus.NEEDS_TIME_EVIDENCE
    assert review.missing_time_evidence == (CONFIRMED_SIGNING_TIME,)
    assert review.dispatchable is True


def test_time_evidence_must_be_bound_to_the_receipt(material):
    encoded = _signed_receipt(material.first_key, material.first_der, b'bound evidence')
    wrong_digest = SigningTimeEvidence(
        SIGNED_AT,
        message_digest=sha256(b'another receipt').digest(),
    )
    review = TransferReviewer(
        LocalIdentityStore(trust_roots=[material.root_der]),
        now=REVIEWED_AT,
    ).review([_receipt('receipt-bound', encoded, wrong_digest)])[0]

    assert review.historical_evidence is False
    assert review.missing_time_evidence == (TIMESTAMP_BINDING,)


def test_late_certificate_revocation_keeps_history_but_blocks_dispatch(material):
    encoded = _signed_receipt(material.second_key, material.second_der, b'late revocation')
    receipt = _receipt('receipt-revoked-cert', encoded, _time_evidence(encoded))
    store = LocalIdentityStore(
        trust_roots=[material.root_der],
        crls=[material.crl_der],
        authorizations=[_permit('permit-revoked-cert', 'receipt-revoked-cert')],
    )

    review = TransferReviewer(store, now=REVIEWED_AT).review([receipt])[0]

    assert review.historical_evidence is True
    assert review.certificate_revoked_at_signing_time is False
    assert review.certificate_revoked_now is True
    assert review.dispatchable is False
    assert review.dispatch_status is DispatchStatus.REVOKED


def test_tampered_receipt_cannot_be_evidence_or_dispatchable(material):
    encoded = _signed_receipt(material.first_key, material.first_der, b'original payload')
    decoded = Sign1Message.decode(encoded)
    decoded.payload = b'tampered payload'
    tampered = decoded.encode(sign=False)
    receipt = _receipt(
        'receipt-tampered',
        tampered,
        SigningTimeEvidence(SIGNED_AT),
    )
    store = LocalIdentityStore(
        trust_roots=[material.root_der],
        authorizations=[_permit('permit-tampered', 'receipt-tampered')],
    )

    review = TransferReviewer(store, now=REVIEWED_AT).review([receipt])[0]

    assert review.signature_valid is False
    assert review.historical_evidence is False
    assert review.historical_status is EvidenceStatus.SIGNATURE_INVALID
    assert review.dispatchable is False
    assert review.dispatch_status is DispatchStatus.SIGNATURE_INVALID


def test_certificate_not_yet_valid_at_signing_time_is_not_history(material):
    encoded = _signed_receipt(material.first_key, material.first_der, b'too early')
    early = datetime(2025, 12, 1, tzinfo=UTC)
    receipt = _receipt(
        'receipt-early',
        encoded,
        SigningTimeEvidence(early, source='bad archive clock'),
    )

    review = TransferReviewer(
        LocalIdentityStore(trust_roots=[material.root_der]),
        now=REVIEWED_AT,
    ).review([receipt])[0]

    assert review.signature_valid is True
    assert review.historical_evidence is False
    assert review.certificate_valid_at_signing_time is False
    assert any('not valid until' in reason for reason in review.historical_reasons)


def test_x5chain_local_validation_and_moment(material):
    cose_key = _cose_key(material.first_key)
    chain = X5Chain([material.first_der])

    assert chain.public_key_matches(cose_key)
    chain.validate(
        cose_key=cose_key,
        trust_roots=[material.root_der],
        key_ops=[VerifyOp],
        moment=SIGNED_AT,
    )

    with pytest.raises(CoseInvalidCertificate, match='expired'):
        chain.validate(
            cose_key=cose_key,
            trust_roots=[material.root_der],
            key_ops=[VerifyOp],
            moment=REVIEWED_AT,
        )

    wrong_key = _cose_key(material.second_key)
    assert chain.public_key_matches(wrong_key) is False
    with pytest.raises(CoseInvalidCertificate, match='does not match the CoseKey'):
        chain.validate(cose_key=wrong_key, trust_roots=[material.root_der])


def test_convenience_entry_point(material):
    encoded = _signed_receipt(material.first_key, material.first_der, b'convenience')
    report = review_delivery_receipts(
        [_receipt('receipt-shortcut', encoded, _time_evidence(encoded))],
        trust_roots=[material.root_der],
        authorizations=[_permit('permit-shortcut', 'receipt-shortcut')],
        now=REVIEWED_AT,
    )

    assert report.historical_evidence_ids == ('receipt-shortcut',)
    assert report.dispatchable_ids == ('receipt-shortcut',)
