from hashlib import sha256

import pytest

from pycose.exceptions import CoseException
from pycose.keys import EC2Key
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.messages.evidence import (
    EVIDENCE_FIELDS,
    EvidenceView,
    FieldPolicy,
    MessageEvidenceProjection,
)
from pycose.messages.sign1message import Sign1Message

KID = b'kid-forensics-01'
EXTERNAL_AAD = b'case-file-42-chain-of-custody'
PAYLOAD = b'evidence bundle digest manifest'
EVIDENCE_TIME = '2026-11-26T10:00:00+00:00'


@pytest.fixture
def signed_message():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    key.key_ops = [SignOp, VerifyOp]

    msg = Sign1Message(
        phdr={'ALG': 'ES256'},
        uhdr={'KID': KID},
        payload=PAYLOAD,
        external_aad=EXTERNAL_AAD,
    )
    msg.key = key
    msg.signature = msg.compute_signature()
    return msg


def test_forensic_handover_discloses_only_public_fields(signed_message):
    record = MessageEvidenceProjection.project(
        signed_message, FieldPolicy.FORENSIC_HANDOVER, evidence_time=EVIDENCE_TIME)

    view = record.view
    assert view.verify()
    assert set(view.public_fields()) == {'alg', 'time', 'payload_digest'}
    assert set(view.hidden_fields()) == {'kid', 'external_aad'}

    public = view.public_fields()
    assert public['alg'] == 'ES256'
    assert public['time'] == EVIDENCE_TIME
    assert public['payload_digest'] == sha256(PAYLOAD).digest()


def test_handover_view_does_not_leak_hidden_values(signed_message):
    record = MessageEvidenceProjection.project(
        signed_message, FieldPolicy.FORENSIC_HANDOVER, evidence_time=EVIDENCE_TIME)

    blob = record.handover()
    assert KID not in blob
    assert EXTERNAL_AAD not in blob
    assert record.salt not in blob

    decoded = EvidenceView.decode(blob)
    assert decoded.verify()
    assert decoded.get_field('kid').value is None
    assert decoded.get_field('external_aad').value is None


def test_two_policies_yield_different_verifiable_views(signed_message):
    salt = b'\x01' * 32
    forensic = MessageEvidenceProjection.project(
        signed_message, FieldPolicy.FORENSIC_HANDOVER, evidence_time=EVIDENCE_TIME, salt=salt)
    internal = MessageEvidenceProjection.project(
        signed_message, FieldPolicy.INTERNAL_ARCHIVE, evidence_time=EVIDENCE_TIME, salt=salt)

    assert forensic.view.verify()
    assert internal.view.verify()

    # same signature binds both views, but the views themselves differ
    assert forensic.view.signature_digest == internal.view.signature_digest
    assert forensic.view.signature_digest == sha256(signed_message.signature).digest()
    assert forensic.view.root != internal.view.root
    assert forensic.handover() != internal.handover()

    # the internal view discloses everything
    public = internal.view.public_fields()
    assert set(public) == set(EVIDENCE_FIELDS)
    assert public['kid'] == KID
    assert public['external_aad'] == EXTERNAL_AAD
    assert internal.view.hidden_fields() == ()


def test_tampered_view_fails_verification(signed_message):
    record = MessageEvidenceProjection.project(
        signed_message, FieldPolicy.FORENSIC_HANDOVER, evidence_time=EVIDENCE_TIME)

    view = record.view
    view.get_field('alg').value = 'ES512'
    assert not view.verify()


def test_internal_record_opens_hidden_commitments(signed_message):
    record = MessageEvidenceProjection.project(
        signed_message, FieldPolicy.FORENSIC_HANDOVER, evidence_time=EVIDENCE_TIME)

    assert record.prove('kid')
    assert record.prove('external_aad')
    assert record.reveal('kid') == KID
    assert record.reveal('external_aad') == EXTERNAL_AAD

    # wrong values or wrong salt must not open the commitments
    assert not record.view.open_commitment('kid', b'other-kid', record.salt)
    assert not record.view.open_commitment('kid', KID, b'\x00' * 32)

    with pytest.raises(KeyError):
        record.reveal('alg')


def test_view_roundtrip_through_cbor(signed_message):
    record = MessageEvidenceProjection.project(
        signed_message, FieldPolicy.FORENSIC_HANDOVER, evidence_time=EVIDENCE_TIME)

    decoded = EvidenceView.decode(record.handover())
    assert decoded.verify()
    assert decoded.root == record.view.root
    assert decoded.public_fields() == record.view.public_fields()
    assert decoded.hidden_fields() == record.view.hidden_fields()


def test_policy_must_partition_evidence_fields():
    with pytest.raises(CoseException):
        FieldPolicy('overlap', disclosed=['alg'], redacted=['alg', 'kid'])

    with pytest.raises(CoseException):
        FieldPolicy('unknown', disclosed=['alg', 'nonce'], redacted=['kid'])

    with pytest.raises(CoseException):
        FieldPolicy('incomplete', disclosed=['alg'], redacted=['kid'])


def test_projection_requires_signed_message():
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=PAYLOAD)
    with pytest.raises(CoseException):
        MessageEvidenceProjection.project(msg, FieldPolicy.FORENSIC_HANDOVER)


def test_projection_rejects_non_sign1_message(signed_message):
    with pytest.raises(TypeError):
        MessageEvidenceProjection.project(b'not-a-message', FieldPolicy.FORENSIC_HANDOVER)
