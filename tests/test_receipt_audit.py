from datetime import date

import pytest

from pycose.exceptions import CoseReceiptAuditError
from pycose.keys import EC2Key
from pycose.messages import SignMessage
from pycose.messages.signer import CoseSignature
from pycose.receipts import (
    BUILDER_ROLE,
    REVIEWER_ROLE,
    IndependentWitness,
    OfflineReceiptAuditor,
    SignatureAttestation,
)


PAYLOAD = b"security configuration receipt"
RECEIPT_DATE = date(2026, 11, 27)


def _signed_material(material_id, builder_key, reviewer_key):
    builder = CoseSignature(phdr={"ALG": "ES256"}, uhdr={"KID": f"{material_id}-builder".encode()})
    reviewer = CoseSignature(phdr={"ALG": "ES256"}, uhdr={"KID": f"{material_id}-reviewer".encode()})
    builder.key = builder_key
    reviewer.key = reviewer_key

    message = SignMessage(payload=PAYLOAD, signers=[builder, reviewer])
    decoded = SignMessage.decode(message.encode())
    decoded.signers[0].key = builder_key
    decoded.signers[1].key = reviewer_key

    assert decoded.signers[0].verify_signature()
    assert decoded.signers[1].verify_signature()
    return decoded


def _attestation(message, index, key_id, person_id, role, effective_date=RECEIPT_DATE):
    return SignatureAttestation(
        key_id=key_id,
        signature_valid=message.signers[index].verify_signature(),
        person_id=person_id,
        role=role,
        effective_date=effective_date,
    )


def test_two_part_time_people_can_fulfill_both_duties_across_materials():
    alice_builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    alice_reviewer_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    bob_builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    bob_reviewer_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})

    first_material = _signed_material("receipt-1", alice_builder_key, bob_reviewer_key)
    second_material = _signed_material("receipt-2", bob_builder_key, alice_reviewer_key)

    witnesses = [
        IndependentWitness(
            "receipt-1",
            [
                _attestation(first_material, 0, "alice-builder-key", "alice", BUILDER_ROLE),
                _attestation(first_material, 1, "bob-reviewer-key", "bob", REVIEWER_ROLE),
            ],
        ),
        IndependentWitness(
            "receipt-2",
            [
                _attestation(second_material, 0, "bob-builder-key", "bob", BUILDER_ROLE),
                _attestation(second_material, 1, "alice-reviewer-key", "alice", REVIEWER_ROLE),
            ],
        ),
    ]

    result = OfflineReceiptAuditor(RECEIPT_DATE).audit(witnesses)

    assert result.valid
    assert result.missing_responsibilities == {}


def test_one_person_with_two_keys_lacks_independent_natural_person():
    builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    reviewer_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    material = _signed_material("receipt-1", builder_key, reviewer_key)

    witness = IndependentWitness(
        "receipt-1",
        [
            _attestation(material, 0, "person-a-builder-key", "person-a", BUILDER_ROLE),
            _attestation(material, 1, "person-a-reviewer-key", "person-a", REVIEWER_ROLE),
        ],
    )

    result = OfflineReceiptAuditor(RECEIPT_DATE).audit([witness])

    assert not result.valid
    assert result.missing_responsibilities == {
        "receipt-1": ["independent natural person for builder and reviewer duties"]
    }


def test_missing_reviewer_duty_is_reported_for_signed_material():
    builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    second_builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    material = _signed_material("receipt-1", builder_key, second_builder_key)

    witness = IndependentWitness(
        "receipt-1",
        [_attestation(material, 0, "builder-key", "alice", BUILDER_ROLE)],
    )

    result = OfflineReceiptAuditor(RECEIPT_DATE).audit([witness])

    assert not result.valid
    assert result.missing_responsibilities == {"receipt-1": ["independent reviewer duty"]}


def test_signed_material_without_witness_lacks_both_independent_duties():
    result = OfflineReceiptAuditor(RECEIPT_DATE).audit([IndependentWitness("receipt-1", [])])

    assert not result.valid
    assert result.missing_responsibilities == {
        "receipt-1": ["independent builder duty", "independent reviewer duty"]
    }


def test_equivalent_active_reviewer_attestation_can_replace_future_choice():
    builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    reviewer_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    material = _signed_material("receipt-1", builder_key, reviewer_key)

    witness = IndependentWitness(
        "receipt-1",
        [
            _attestation(material, 0, "builder-key", "alice", BUILDER_ROLE),
            _attestation(
                material,
                1,
                "future-reviewer-key",
                "carol",
                REVIEWER_ROLE,
                effective_date=date(2026, 11, 28),
            ),
            _attestation(material, 1, "active-reviewer-key", "bob", REVIEWER_ROLE),
        ],
    )

    result = OfflineReceiptAuditor(RECEIPT_DATE).audit([witness])

    assert result.valid
    assert result.missing_responsibilities == {}


def test_failed_cryptographic_verification_cannot_satisfy_reviewer_duty():
    builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    reviewer_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    material = _signed_material("receipt-1", builder_key, reviewer_key)

    failed_reviewer = SignatureAttestation(
        key_id="invalid-reviewer-key",
        signature_valid=False,
        person_id="bob",
        role=REVIEWER_ROLE,
        effective_date=RECEIPT_DATE,
    )
    witness = IndependentWitness(
        "receipt-1",
        [_attestation(material, 0, "builder-key", "alice", BUILDER_ROLE), failed_reviewer],
    )

    result = OfflineReceiptAuditor(RECEIPT_DATE).audit([witness])

    assert not result.valid
    assert result.missing_responsibilities == {"receipt-1": ["independent reviewer duty"]}


def test_same_key_cannot_be_claimed_for_both_independent_duties():
    builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    material = _signed_material("receipt-1", builder_key, builder_key)

    witness = IndependentWitness(
        "receipt-1",
        [
            _attestation(material, 0, "shared-key", "alice", BUILDER_ROLE),
            _attestation(material, 1, "shared-key", "bob", REVIEWER_ROLE),
        ],
    )

    with pytest.raises(CoseReceiptAuditError, match="Duplicate key attestation"):
        OfflineReceiptAuditor(RECEIPT_DATE).audit([witness])


def test_future_effective_date_is_not_an_active_key_attribution():
    builder_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    reviewer_key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})
    material = _signed_material("receipt-1", builder_key, reviewer_key)

    witness = IndependentWitness(
        "receipt-1",
        [
            _attestation(material, 0, "builder-key", "alice", BUILDER_ROLE),
            _attestation(
                material,
                1,
                "future-reviewer-key",
                "bob",
                REVIEWER_ROLE,
                effective_date=date(2026, 11, 28),
            ),
        ],
    )

    result = OfflineReceiptAuditor(RECEIPT_DATE).audit([witness])

    assert not result.valid
    assert result.missing_responsibilities == {"receipt-1": ["independent reviewer duty"]}
