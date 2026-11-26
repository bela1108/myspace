"""Tests for layer-aware Strict Critical extension acceptance.

The fixtures generate their own small ES256 keys and signatures locally; no
external COSE test vectors are required.
"""

import cbor2
import pytest

from pycose.critical import (
    CriticalExtensionRegistry,
    SignStrictVerificationResult,
    StrictVerificationResult,
)
from pycose.keys import EC2Key
from pycose.messages import Sign1Message, SignMessage
from pycose.messages.signer import CoseSignature


TIME_WINDOW_LABEL = 1700
NOW = 1000
VALID_WINDOW = {"not_before": 900, "not_after": 1100}
EXPIRED_WINDOW = {"not_before": 100, "not_after": 200}


def _check_time_window(value, context):
    return value["not_before"] <= context.now <= value["not_after"]


def _new_key():
    return EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256"})


def _make_sign1(window=VALID_WINDOW, protected_critical=True):
    key = _new_key()
    phdr = {"ALG": "ES256", TIME_WINDOW_LABEL: window}
    uhdr = {}
    if protected_critical:
        phdr["CRITICAL"] = [TIME_WINDOW_LABEL]
    else:
        # A Critical declaration here is not authenticated and must be ignored
        # by strict acceptance.
        uhdr = {"CRITICAL": [TIME_WINDOW_LABEL]}

    msg = Sign1Message(phdr=phdr, uhdr=uhdr, payload=b"purchase-order")
    msg.key = key

    decoded = Sign1Message.decode(msg.encode())
    decoded.key = key
    return decoded


def _make_sign_message(top_window=VALID_WINDOW, signer_windows=(VALID_WINDOW, VALID_WINDOW)):
    keys = [_new_key() for _ in signer_windows]
    signers = [
        CoseSignature(
            phdr={
                "ALG": "ES256",
                TIME_WINDOW_LABEL: window,
                "CRITICAL": [TIME_WINDOW_LABEL],
            },
            key=key,
        )
        for key, window in zip(keys, signer_windows)
    ]

    msg = SignMessage(
        phdr={
            TIME_WINDOW_LABEL: top_window,
            "CRITICAL": [TIME_WINDOW_LABEL],
        },
        payload=b"purchase-order",
        signers=signers,
    )

    decoded = SignMessage.decode(msg.encode())
    for key, signer in zip(keys, decoded.signers):
        signer.key = key
    return decoded


def test_sign1_strict_critical_accepted_and_old_entry_point_still_works():
    msg = _make_sign1()

    result = msg.verify_strict({TIME_WINDOW_LABEL: _check_time_window}, now=NOW)

    assert isinstance(result, StrictVerificationResult)
    assert result.accepted
    assert result.signature_valid
    assert result.critical[TIME_WINDOW_LABEL].status == "passed"
    assert result.critical[TIME_WINDOW_LABEL].value == VALID_WINDOW

    # The legacy entry point deliberately does not apply Critical policy.
    assert msg.verify_signature()


def test_sign1_unregistered_critical_rejected_although_crypto_is_valid():
    msg = _make_sign1()

    result = msg.verify_strict({}, now=NOW)

    assert not result.accepted
    assert result.signature_valid
    assert result.critical[TIME_WINDOW_LABEL].status == "unsupported"
    assert not result.critical[TIME_WINDOW_LABEL].supported


def test_sign1_expired_window_is_rejected_although_crypto_is_valid():
    msg = _make_sign1(window=EXPIRED_WINDOW)

    result = msg.verify_strict({TIME_WINDOW_LABEL: _check_time_window}, now=NOW)

    assert not result.accepted
    assert result.signature_valid
    assert result.critical[TIME_WINDOW_LABEL].status == "failed"


def test_sign1_unprotected_critical_is_not_trusted():
    msg = _make_sign1(protected_critical=False)

    result = msg.verify_strict({TIME_WINDOW_LABEL: _check_time_window}, now=NOW)

    assert not result.accepted
    assert result.signature_valid
    assert "must be in the protected header" in " ".join(result.errors)


def test_sign1_without_any_critical_declaration_still_passes_strict_crypto():
    key = _new_key()
    msg = Sign1Message(phdr={"ALG": "ES256"}, payload=b"plain")
    msg.key = key
    msg = Sign1Message.decode(msg.encode())
    msg.key = key

    result = msg.verify_strict({}, now=NOW)

    assert result.accepted
    assert result.signature_valid
    assert result.critical_results == []


def test_handler_can_request_now_by_parameter_name():
    msg = _make_sign1()

    def check(value, now):
        return value["not_before"] <= now <= value["not_after"]

    result = msg.verify_strict({TIME_WINDOW_LABEL: check}, now=NOW)

    assert result.accepted
    assert result.critical[TIME_WINDOW_LABEL].accepted


def test_label_only_registration_is_treated_as_understood():
    msg = _make_sign1()

    result = msg.verify_strict([TIME_WINDOW_LABEL], now=NOW)

    assert result.accepted
    assert result.critical[TIME_WINDOW_LABEL].accepted
    assert result.critical[TIME_WINDOW_LABEL].result is True


def test_message_layer_accepts_time_window_but_unregistered_signers_do_not():
    msg = _make_sign_message()

    # Only the message layer is registered.  The same-named extension is valid
    # there, but that handling evidence must not leak into signer layers.
    result = msg.verify_strict({TIME_WINDOW_LABEL: _check_time_window}, now=NOW)

    assert isinstance(result, SignStrictVerificationResult)
    assert result.message.accepted
    assert result.message.critical[TIME_WINDOW_LABEL].status == "passed"

    assert not result.accepted
    assert result.signature_valid  # every signer is still cryptographically valid
    assert len(result.signers) == 2
    for signer in result.signers:
        assert signer.signature_valid
        assert not signer.accepted
        assert signer.critical[TIME_WINDOW_LABEL].status == "unsupported"

    assert result.unsupported == [TIME_WINDOW_LABEL]
    assert set(result.unsupported_at) == {"signer:0", "signer:1"}


def test_one_unsupported_signer_keeps_other_crypto_results_available():
    msg = _make_sign_message()

    result = msg.verify_strict(
        {TIME_WINDOW_LABEL: _check_time_window},
        signer_critical_extensions=[
            {TIME_WINDOW_LABEL: _check_time_window},
            {},
        ],
        now=NOW,
    )

    assert result.signers[0].accepted
    assert not result.signers[1].accepted
    assert result.signers[1].critical[TIME_WINDOW_LABEL].status == "unsupported"
    assert result.crypto_results == [True, True]
    assert not result.accepted


def test_all_layers_registered_accepts_the_message():
    msg = _make_sign_message()

    result = msg.verify_strict(
        {TIME_WINDOW_LABEL: _check_time_window},
        signer_critical_extensions=[
            {TIME_WINDOW_LABEL: _check_time_window},
            {TIME_WINDOW_LABEL: _check_time_window},
        ],
        now=NOW,
    )

    assert result.accepted
    assert result.signature_valid
    assert all(signer.accepted for signer in result.signers)


def test_expired_signer_window_rejects_only_that_signer_layer():
    msg = _make_sign_message(signer_windows=(VALID_WINDOW, EXPIRED_WINDOW))
    registry = CriticalExtensionRegistry({TIME_WINDOW_LABEL: _check_time_window})

    result = msg.verify_strict(
        registry,
        signer_critical_extensions=registry,
        now=NOW,
    )

    assert result.message.accepted
    assert result.signers[0].accepted
    assert not result.signers[1].accepted
    assert result.signers[0].signature_valid
    assert result.signers[1].signature_valid
    assert result.signers[1].critical[TIME_WINDOW_LABEL].status == "failed"
    assert not result.accepted
