# SPDX-License-Identifier: Apache-2.0

# Tests for the replayable quota ledger state machine.

import json

import pytest

from quota_ledger import Credential
from quota_ledger import Ledger
from quota_ledger.credentials import ENTITLEMENT_TYPE
from quota_ledger.credentials import HOLD_TYPE
from quota_ledger.credentials import RELEASE_TYPE
from quota_ledger.credentials import REVOKE_TYPE
from quota_ledger.exceptions import DuplicateCredentialError
from quota_ledger.exceptions import InvalidTransitionError
from quota_ledger.exceptions import PendingCredentialError
from tests.conftest import CHANNELS
from tests.conftest import DIGEST


@pytest.fixture()
def ledger(tmp_path):
    return Ledger(tmp_path / "ledger")


def _cred(signers, channel, ctype, cid, payload=None, digest=DIGEST):
    signer = signers[channel]
    credential = Credential.create(
        signer, ctype, cid, channel, digest, payload or {}
    )
    credential.verify_signature({signer.public_key.keyid: signer.public_key})
    return credential


def _import(ledger, signers, evidence, channel, ctype, cid, payload=None):
    credential = _cred(signers, channel, ctype, cid, payload)
    return ledger.import_credential(credential, evidence[channel])


def test_entitlement_open_line(ledger, keys, evidence):
    receipt = _import(
        ledger, keys["signers"], evidence, "channel-a",
        ENTITLEMENT_TYPE, "ent-a", {"amount": 5}
    )
    assert receipt.state_before is None
    assert receipt.state_after == "open"
    assert receipt.available_after == 5
    assert ledger.available_quota("channel-a", DIGEST) == 5


def test_hold_release_lifecycle(ledger, keys, evidence):
    _import(ledger, keys["signers"], evidence, "channel-a",
            ENTITLEMENT_TYPE, "ent-a", {"amount": 5})
    hold = _import(ledger, keys["signers"], evidence, "channel-a",
                   HOLD_TYPE, "hold-a", {"amount": 2})
    assert hold.state_after == "held" and hold.available_after == 3
    release = _import(ledger, keys["signers"], evidence, "channel-a",
                      RELEASE_TYPE, "rel-a", {"amount": 2})
    assert release.state_after == "released"
    assert ledger.available_quota("channel-a", DIGEST) == 3


def test_release_cannot_exceed_hold(ledger, keys, evidence):
    _import(ledger, keys["signers"], evidence, "channel-a",
            ENTITLEMENT_TYPE, "ent-a", {"amount": 5})
    _import(ledger, keys["signers"], evidence, "channel-a",
            HOLD_TYPE, "hold-a", {"amount": 1})
    with pytest.raises(InvalidTransitionError):
        _import(ledger, keys["signers"], evidence, "channel-a",
                RELEASE_TYPE, "rel-a", {"amount": 4})


def test_missing_entitlement_is_pending_without_side_effect(ledger, keys):
    credential = _cred(keys["signers"], "channel-a", HOLD_TYPE, "early")
    with pytest.raises(PendingCredentialError):
        ledger.import_credential(credential)
    assert len(ledger.state.receipts) == 0
    assert not ledger.event_log.exists()
    assert ledger.available_quota("channel-a", DIGEST) == 0


def test_parked_credential_succeeds_after_entitlement(ledger, keys, evidence):
    early = _cred(keys["signers"], "channel-a", HOLD_TYPE, "early")
    with pytest.raises(PendingCredentialError):
        ledger.import_credential(early)
    _import(ledger, keys["signers"], evidence, "channel-a",
            ENTITLEMENT_TYPE, "ent-a", {"amount": 2})
    receipt = ledger.import_credential(early, evidence["channel-a"])
    assert receipt.state_after == "held"
    assert receipt.available_after == 1


def test_revoke_isolates_channels(ledger, keys, evidence):
    for channel in CHANNELS:
        _import(ledger, keys["signers"], evidence, channel,
                ENTITLEMENT_TYPE, f"ent-{channel}", {"amount": 4})
    revoke = _import(ledger, keys["signers"], evidence, "channel-b",
                     REVOKE_TYPE, "revoke-b")
    assert revoke.state_after == "revoked"
    assert ledger.available_quota("channel-b", DIGEST) == 0
    # Channel A keeps its full quota and its own receipt trail.
    assert ledger.available_quota("channel-a", DIGEST) == 4
    receipts_a = ledger.receipts_for_channel("channel-a")
    assert [r.credential_id for r in receipts_a] == ["ent-channel-a"]
    receipts_b = ledger.receipts_for_channel("channel-b")
    assert receipts_b[-1].state_after == "revoked"


def test_repeated_import_is_idempotent(ledger, keys, evidence):
    credential = _cred(keys["signers"], "channel-a", ENTITLEMENT_TYPE,
                       "ent-a", {"amount": 2})
    first = ledger.import_credential(credential, evidence["channel-a"])
    second = ledger.import_credential(credential, evidence["channel-a"])
    assert first.event_seq == second.event_seq
    assert len(ledger.state.receipts) == 1


def test_conflicting_credential_id_rejected(ledger, keys, evidence):
    first = _cred(keys["signers"], "channel-a", ENTITLEMENT_TYPE,
                  "same-id", {"amount": 2})
    ledger.import_credential(first, evidence["channel-a"])
    conflicting = _cred(keys["signers"], "channel-a", ENTITLEMENT_TYPE,
                        "same-id", {"amount": 9})
    with pytest.raises(DuplicateCredentialError):
        ledger.import_credential(conflicting, evidence["channel-a"])


def test_replay_reconstructs_identical_state(ledger, keys, evidence, tmp_path):
    _import(ledger, keys["signers"], evidence, "channel-a",
            ENTITLEMENT_TYPE, "ent-a", {"amount": 5})
    _import(ledger, keys["signers"], evidence, "channel-a",
            HOLD_TYPE, "hold-a", {"amount": 2})
    _import(ledger, keys["signers"], evidence, "channel-b",
            ENTITLEMENT_TYPE, "ent-b", {"amount": 3})
    _import(ledger, keys["signers"], evidence, "channel-b",
            REVOKE_TYPE, "revoke-b")
    replayed = Ledger(tmp_path / "ledger")
    assert replayed.snapshot() == ledger.snapshot()
    persisted = sorted(p.name for p in replayed.receipts_dir.glob("*.json"))
    assert len(persisted) == len(replayed.state.receipts)
    assert persisted[0].startswith("000001-")


def test_tampered_event_log_detected(ledger, keys, evidence, tmp_path):
    _import(ledger, keys["signers"], evidence, "channel-a",
            ENTITLEMENT_TYPE, "ent-a", {"amount": 5})
    log = ledger.event_log
    record = json.loads(log.read_text().splitlines()[0])
    record["body"]["payload"]["amount"] = 500
    log.write_text(json.dumps(record) + "\n")
    with pytest.raises(InvalidTransitionError):
        Ledger(tmp_path / "ledger")


def test_evidence_channel_mismatch_is_pending(ledger, keys, evidence):
    credential = _cred(keys["signers"], "channel-a", ENTITLEMENT_TYPE,
                       "ent-a", {"amount": 1})
    with pytest.raises(PendingCredentialError):
        ledger.import_credential(credential, evidence["channel-b"])


def test_evidence_digest_mismatch_is_pending(ledger, keys, evidence):
    credential = _cred(
        keys["signers"], "channel-a", ENTITLEMENT_TYPE, "ent-a",
        {"amount": 1}, digest="ff" * 32
    )
    with pytest.raises(PendingCredentialError):
        ledger.import_credential(credential, evidence["channel-a"])


def test_credential_requires_authorized_signer(keys):
    from quota_ledger.exceptions import SignatureError
    victim = keys["signers"]["channel-a"]
    outsider = keys["signers"]["channel-b"]
    credential = Credential.create(
        outsider, ENTITLEMENT_TYPE, "forged", "channel-a", DIGEST,
        {"amount": 1}
    )
    with pytest.raises(SignatureError):
        credential.verify_signature({
            victim.public_key.keyid: victim.public_key
        })


def test_revoked_line_rejects_further_holds(ledger, keys, evidence):
    _import(ledger, keys["signers"], evidence, "channel-a",
            ENTITLEMENT_TYPE, "ent-a", {"amount": 2})
    _import(ledger, keys["signers"], evidence, "channel-a",
            REVOKE_TYPE, "revoke-a")
    with pytest.raises(InvalidTransitionError):
        _import(ledger, keys["signers"], evidence, "channel-a",
                HOLD_TYPE, "hold-a", {"amount": 1})


def test_reimport_after_reopen_is_still_idempotent(ledger, keys, evidence,
                                              tmp_path):
    credential = _cred(keys["signers"], "channel-a", ENTITLEMENT_TYPE,
                       "ent-a", {"amount": 2})
    ledger.import_credential(credential, evidence["channel-a"])
    reopened = Ledger(tmp_path / "ledger")
    receipt = reopened.import_credential(credential, evidence["channel-a"])
    assert receipt.event_seq == 1
    assert len(reopened.state.receipts) == 1
    assert len(reopened.event_log.read_text().splitlines()) == 1
