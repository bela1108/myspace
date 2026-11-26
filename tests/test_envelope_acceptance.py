import json
import os
from hashlib import sha256

import pytest

from pycose import (
    EnvelopeAcceptor,
    LocalTestKey,
    PolicyConflictError,
    ReceiptError,
    accept_envelope,
    check_envelope,
    require_publication_receipt,
)
from pycose import headers
from pycose.algorithms import A128GCM, A128KW
from pycose.keys import SymmetricKey
from pycose.keys.keyops import UnwrapOp, WrapOp
from pycose.keys.keyparam import KpAlg, KpKid, KpKeyOps
from pycose.messages import Enc0Message, EncMessage
from pycose.messages.recipient import KeyWrap


PLAINTEXT = b"SYNTHETIC-EVIDENCE-PLAINTEXT-MUST-NOT-LEAK"

MANIFEST = {
    "recipients": {
        "auditor": {
            "purposes": ["audit"],
            "attachment_groups": ["exhibits", "chain-of-custody"],
        },
        "counsel": {
            "purposes": ["litigation"],
            "attachment_groups": ["exhibits", "privileged"],
        },
    }
}

BOTH_REQUESTS = {
    "recipient_requests": {
        "auditor": {"purpose": "audit", "attachment_groups": ["exhibits"]},
        "counsel": {"purpose": "litigation", "attachment_groups": ["privileged"]},
    }
}


def _kek(node, seed):
    return SymmetricKey(
        k=bytes([seed]) * 16,
        optional_params={
            KpAlg: A128KW,
            KpKid: node.encode("utf-8"),
            KpKeyOps: [WrapOp, UnwrapOp],
        },
    )


def _synthetic_envelope(nodes=("auditor", "counsel"), payload=PLAINTEXT):
    keys = {node: _kek(node, index + 1) for index, node in enumerate(nodes)}
    recipients = [
        KeyWrap(
            uhdr={headers.Algorithm: A128KW, headers.KID: node.encode("utf-8")},
            key=keys[node],
        )
        for node in nodes
    ]
    message = EncMessage(
        phdr={headers.Algorithm: A128GCM, headers.IV: os.urandom(12)},
        uhdr={headers.KID: b"evidence-envelope-1"},
        payload=payload,
        recipients=recipients,
    )
    return message.encode(), keys


def _canonical_digest(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return sha256(encoded.encode("utf-8")).hexdigest()


def test_two_recipient_groups_have_distinct_scopes_and_no_plaintext():
    envelope, keys = _synthetic_envelope()

    report = accept_envelope(envelope, MANIFEST, keys, BOTH_REQUESTS)

    assert report.accepted is True
    assert report.receipt is not None
    assert report.receipt.verified_recipients == ("auditor", "counsel")

    by_node = {recipient.node: recipient for recipient in report.recipients}
    assert by_node["auditor"].allowed_purposes == ("audit",)
    assert by_node["auditor"].allowed_attachment_groups == (
        "chain-of-custody",
        "exhibits",
    )
    assert by_node["auditor"].requested_purpose == "audit"
    assert by_node["auditor"].requested_attachment_groups == ("exhibits",)

    assert by_node["counsel"].allowed_purposes == ("litigation",)
    assert by_node["counsel"].allowed_attachment_groups == ("exhibits", "privileged")
    assert by_node["counsel"].requested_purpose == "litigation"
    assert by_node["counsel"].requested_attachment_groups == ("privileged",)

    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert "plaintext" not in report.__dict__
    assert not hasattr(report, "plaintext")
    assert PLAINTEXT.decode("utf-8") not in rendered
    assert PLAINTEXT.decode("utf-8") not in json.dumps(
        report.receipt.to_dict(), sort_keys=True
    )


def test_each_group_can_be_checked_with_only_its_authorized_local_key():
    envelope, keys = _synthetic_envelope()

    auditor_report = accept_envelope(
        envelope,
        MANIFEST,
        {"auditor": keys["auditor"]},
        {
            "recipient_requests": {
                "auditor": {"purpose": "audit", "attachment_groups": ["exhibits"]}
            }
        },
    )
    counsel_report = accept_envelope(
        envelope,
        MANIFEST,
        {"counsel": keys["counsel"]},
        {
            "recipient_requests": {
                "counsel": {
                    "purpose": "litigation",
                    "attachment_groups": ["privileged"],
                }
            }
        },
    )

    assert auditor_report.verified_recipients == ("auditor",)
    assert counsel_report.verified_recipients == ("counsel",)
    auditor_scope = {item.node: item for item in auditor_report.recipients}["auditor"]
    counsel_scope = {item.node: item for item in counsel_report.recipients}["counsel"]
    assert auditor_scope.allowed_purposes == ("audit",)
    assert counsel_scope.allowed_purposes == ("litigation",)
    assert (
        auditor_scope.allowed_attachment_groups
        != counsel_scope.allowed_attachment_groups
    )

    rejected = check_envelope(
        envelope,
        MANIFEST,
        {"auditor": keys["auditor"]},
        {
            "recipient_requests": {
                "auditor": {
                    "purpose": "litigation",
                    "attachment_groups": ["privileged"],
                }
            }
        },
    )
    assert rejected.accepted is False
    assert rejected.receipt is None
    assert rejected.error_type == "ScopeViolationError"
    assert "auditor" in rejected.errors[0]


def test_one_node_bound_to_two_commitments_is_a_policy_conflict():
    envelope, keys = _synthetic_envelope()
    conflicting_manifest = [
        {
            "node": "auditor",
            "purposes": ["audit"],
            "attachment_groups": ["chain-of-custody"],
        },
        {
            "node": "auditor",
            "purposes": ["litigation"],
            "attachment_groups": ["privileged"],
        },
        {
            "node": "counsel",
            "purposes": ["litigation"],
            "attachment_groups": ["privileged"],
        },
    ]

    report = check_envelope(envelope, conflicting_manifest, keys, BOTH_REQUESTS)
    assert report.accepted is False
    assert report.receipt is None
    assert report.error_type == "PolicyConflictError"
    assert "policy conflict" in report.errors[0]
    assert "auditor" in report.errors[0]
    assert len(report.conflicts) == 2
    assert {item["purposes"][0] for item in report.conflicts} == {"audit", "litigation"}

    with pytest.raises(PolicyConflictError) as raised:
        accept_envelope(envelope, conflicting_manifest, keys, BOTH_REQUESTS)
    assert raised.value.node == "auditor"
    assert len(raised.value.commitments) == 2


def test_duplicate_recipient_node_in_envelope_is_a_policy_conflict():
    keys = [_kek("auditor", 1), _kek("auditor", 2)]
    recipients = [
        KeyWrap(
            uhdr={headers.Algorithm: A128KW, headers.KID: b"auditor"},
            key=key,
        )
        for key in keys
    ]
    message = EncMessage(
        phdr={headers.Algorithm: A128GCM, headers.IV: os.urandom(12)},
        payload=PLAINTEXT,
        recipients=recipients,
    )

    report = check_envelope(
        message.encode(),
        {"auditor": {"purposes": ["audit"], "attachment_groups": ["exhibits"]}},
        {"auditor": keys[0]},
        {"purpose": "audit", "attachment_groups": ["exhibits"]},
    )

    assert report.accepted is False
    assert report.receipt is None
    assert report.error_type == "PolicyConflictError"
    assert len(report.conflicts) == 2


def test_failure_midway_never_issues_a_receipt_for_later_publication():
    envelope, keys = _synthetic_envelope()
    accepted = accept_envelope(envelope, MANIFEST, keys, BOTH_REQUESTS)
    assert accepted.receipt is not None
    require_publication_receipt(accepted, envelope, MANIFEST, BOTH_REQUESTS)

    tampered = bytearray(envelope)
    tampered[-1] ^= 0x01
    rejected = check_envelope(bytes(tampered), MANIFEST, keys, BOTH_REQUESTS)

    assert rejected.accepted is False
    assert rejected.receipt is None
    assert rejected.error_type == "TestKeyVerificationError"
    with pytest.raises(ReceiptError):
        require_publication_receipt(rejected)

    # An old receipt cannot authorize a different envelope either.
    with pytest.raises(ReceiptError):
        require_publication_receipt(
            accepted.receipt, bytes(tampered), MANIFEST, BOTH_REQUESTS
        )


def test_failure_after_one_recipient_verified_still_yields_no_receipt():
    envelope, keys = _synthetic_envelope()
    wrong_counsel_key = _kek("counsel", 99)

    report = check_envelope(
        envelope,
        MANIFEST,
        {"auditor": keys["auditor"], "counsel": wrong_counsel_key},
        BOTH_REQUESTS,
    )

    assert report.accepted is False
    assert report.receipt is None
    assert report.error_type == "TestKeyVerificationError"
    with pytest.raises(ReceiptError):
        require_publication_receipt(report)


def test_unauthorized_or_narrower_local_test_key_is_rejected():
    envelope, keys = _synthetic_envelope()

    intruder_key = _kek("intruder", 9)
    report = check_envelope(
        envelope,
        MANIFEST,
        dict(keys, intruder=intruder_key),
        BOTH_REQUESTS,
    )
    assert report.accepted is False
    assert report.receipt is None
    assert report.error_type == "UnauthorizedTestKeyError"

    narrow_key = LocalTestKey(
        node="auditor",
        key=keys["auditor"],
        purposes={"audit"},
        attachment_groups={"exhibits"},
    )
    report = check_envelope(
        envelope,
        MANIFEST,
        {"auditor": narrow_key},
        {
            "recipient_requests": {
                "auditor": {
                    "purpose": "audit",
                    "attachment_groups": ["chain-of-custody"],
                }
            }
        },
    )
    assert report.accepted is False
    assert report.receipt is None
    assert report.error_type == "UnauthorizedTestKeyError"


def test_verified_metadata_digest_is_required_to_bind():
    envelope, keys = _synthetic_envelope()
    metadata = {"case": "SYNTH-CASE-1", "manifest_version": 3}
    good = dict(
        BOTH_REQUESTS, metadata=metadata, metadata_digest=_canonical_digest(metadata)
    )
    bad = dict(BOTH_REQUESTS, metadata=metadata, metadata_digest="0" * 64)

    accepted = accept_envelope(envelope, MANIFEST, keys, good)
    assert accepted.accepted is True
    assert accepted.receipt.metadata_digest == _canonical_digest(metadata)

    rejected = check_envelope(envelope, MANIFEST, keys, bad)
    assert rejected.accepted is False
    assert rejected.receipt is None
    assert rejected.error_type == "MetadataConstraintError"
    assert "metadata digest" in rejected.errors[0]


def test_manifest_recipient_set_must_match_envelope():
    envelope, keys = _synthetic_envelope()
    wider_manifest = {
        "recipients": {
            **MANIFEST["recipients"],
            "reviewer": {"purposes": ["review"], "attachment_groups": ["exhibits"]},
        }
    }

    report = check_envelope(envelope, wider_manifest, keys, BOTH_REQUESTS)
    assert report.accepted is False
    assert report.receipt is None
    assert report.error_type == "RecipientSetError"
    assert "reviewer" in report.errors[0]


def test_decoded_message_and_reusable_acceptor_paths_do_not_return_plaintext():
    envelope, keys = _synthetic_envelope()
    message = EncMessage.decode(envelope)

    report = message.accept(MANIFEST, keys, BOTH_REQUESTS)
    assert report.accepted is True
    assert PLAINTEXT not in repr(report).encode("utf-8")

    acceptor = EnvelopeAcceptor(MANIFEST, keys, BOTH_REQUESTS)
    assert acceptor.check(envelope).accepted is True
    assert acceptor.accept(envelope).receipt is not None


def test_encrypt0_single_node_is_supported_without_plaintext_exposure():
    node = "sole-custodian"
    key = SymmetricKey(
        k=b"\x11" * 16, optional_params={KpAlg: A128GCM, KpKid: node.encode("utf-8")}
    )
    message = Enc0Message(
        phdr={headers.Algorithm: A128GCM, headers.IV: os.urandom(12)},
        uhdr={headers.KID: node.encode("utf-8")},
        payload=PLAINTEXT,
        key=key,
    )
    envelope = message.encode()

    report = accept_envelope(
        envelope,
        {node: {"purposes": ["audit"], "attachment_groups": ["exhibits"]}},
        {node: key},
        {"purpose": "audit", "attachment_groups": ["exhibits"]},
    )
    assert report.accepted is True
    assert report.verified_recipients == (node,)
    assert PLAINTEXT.decode("utf-8") not in json.dumps(report.to_dict())
