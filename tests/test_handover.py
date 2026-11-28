import cbor2
from datetime import datetime, timedelta, timezone

from pycose import headers
from pycose.algorithms import A128GCM, A128KW
from pycose.handover import (
    ELIGIBLE,
    INELIGIBLE,
    INFORMATION_INCOMPLETE,
    HandoverMaterial,
    RosterEntry,
    assess_handover,
)
from pycose.messages.encmessage import EncMessage
from pycose.messages.recipient import KeyWrap


NOW = datetime(2026, 11, 28, tzinfo=timezone.utc)
NEW_ARCHIVE = b"new-archive"
OLD_ARCHIVE = b"old-archive"
PAYLOAD = b"encrypted document payload"


def _recipient(kid, group=NEW_ARCHIVE, recipients=None):
    return KeyWrap(
        uhdr={
            headers.Algorithm: A128KW,
            headers.KID: kid,
            "HANDOVER_GROUP": group,
        },
        payload=b"wrapped key",
        recipients=recipients,
    )


def _message(recipients):
    return EncMessage(
        phdr={headers.Algorithm: A128GCM},
        uhdr={headers.IV: b"0123456789ab"},
        payload=PAYLOAD,
        recipients=recipients,
    )


def _encoded(message):
    def recipient_structure(recipient):
        structure = [recipient.phdr_encoded, recipient.uhdr_encoded, recipient.payload]
        if recipient.recipients:
            structure.append([recipient_structure(child) for child in recipient.recipients])
        return structure

    return cbor2.dumps(cbor2.CBORTag(
        96,
        [
            message.phdr_encoded,
            message.uhdr_encoded,
            message.payload,
            [recipient_structure(recipient) for recipient in message.recipients],
        ]
    ), default=message._custom_cbor_encoder)


def _material(expires_at=None):
    return HandoverMaterial(
        NEW_ARCHIVE,
        [
            {
                "holder_group": OLD_ARCHIVE,
                "recipient_kid": b"old-concurrent",
                "recipient_path": (b"old-concurrent",),
                "expires_at": expires_at or NOW + timedelta(days=1),
            }
        ],
        now=NOW,
    )


def test_handover_assessment_classifies_recipients_without_decoding():
    message = _message([
        _recipient(b"new-recipient"),
        _recipient(b"revoked-recipient"),
        _recipient(b"old-concurrent", OLD_ARCHIVE),
    ])
    roster = {
        b"new-recipient": True,
        b"old-concurrent": True,
        b"revoked-recipient": False,
    }

    result = assess_handover(message, roster, _material())

    assert result.status == INELIGIBLE
    assert [item.status for item in result.recipients] == [ELIGIBLE, INELIGIBLE, ELIGIBLE]
    assert message.payload == PAYLOAD
    assert result.active_concurrent_paths[0].holder_group == OLD_ARCHIVE
    assert result.active_concurrent_paths[0].recipient_kid == b"old-concurrent"


def test_handover_assessment_marks_information_incomplete_for_missing_roster_entry():
    message = _message([_recipient(b"new-recipient"), _recipient(b"unknown-recipient")])
    roster = {b"new-recipient": {"eligible": True}}

    result = assess_handover(message, roster, _material())

    assert result.status == INFORMATION_INCOMPLETE
    assert [item.status for item in result.recipients] == [ELIGIBLE, INFORMATION_INCOMPLETE]
    assert "absent from the caller's offline roster" in result.recipients[1].reason


def test_handover_assessment_accepts_roster_entry_objects():
    message = _message([_recipient(b"new-recipient")])

    result = assess_handover(message, {b"new-recipient": RosterEntry(eligible=True)}, _material())

    assert result.status == ELIGIBLE
    assert result.recipients[0].status == ELIGIBLE


def test_nested_recipient_inherits_unexpired_old_group_concurrent_path():
    nested = _recipient(b"nested-old-recipient", OLD_ARCHIVE)
    old_root = _recipient(b"old-concurrent", OLD_ARCHIVE, recipients=[nested])
    message = _message([_recipient(b"new-recipient"), old_root])
    roster = {
        b"new-recipient": True,
        b"old-concurrent": True,
        b"nested-old-recipient": True,
    }

    result = assess_handover(message, roster, _material())

    assert result.status == ELIGIBLE
    nested_result = result.recipients[-1]
    assert nested_result.is_nested is True
    assert nested_result.parent_path == (b"old-concurrent",)
    assert nested_result.group == OLD_ARCHIVE
    assert nested_result.status == ELIGIBLE
    assert result.active_concurrent_paths[0].holder_group == OLD_ARCHIVE


def test_concurrent_path_exposes_specific_old_group_holder():
    recipient = KeyWrap(
        uhdr={
            headers.Algorithm: A128KW,
            headers.KID: b"old-concurrent",
            "OLD_GROUP_HOLDER": OLD_ARCHIVE,
        },
        payload=b"wrapped key",
    )
    result = assess_handover(
        _message([recipient]),
        {b"old-concurrent": True},
        _material()
    )

    assert result.status == ELIGIBLE
    assert result.recipients[0].group == OLD_ARCHIVE
    active_path = result.active_concurrent_paths[0]
    assert active_path.holder_group == OLD_ARCHIVE
    assert active_path.recipient_kid == b"old-concurrent"
    assert active_path.recipient_path == (b"old-concurrent",)
    assert active_path.expires_at == NOW + timedelta(days=1)


def test_expired_concurrent_path_makes_old_group_subtree_ineligible():
    nested = _recipient(b"nested-old-recipient", OLD_ARCHIVE)
    old_root = _recipient(b"old-concurrent", OLD_ARCHIVE, recipients=[nested])
    message = _message([old_root])
    roster = {b"old-concurrent": True, b"nested-old-recipient": True}
    material = _material(expires_at=NOW - timedelta(minutes=1))

    result = assess_handover(message, roster, material)

    assert result.status == INELIGIBLE
    assert all(item.status == INELIGIBLE for item in result.recipients)
    assert result.active_concurrent_paths == ()
    assert all("no active concurrent path" in item.reason for item in result.recipients)


def test_concurrent_path_is_inactive_at_its_expiry_instant():
    message = _message([_recipient(b"old-concurrent", OLD_ARCHIVE)])
    material = _material(expires_at=NOW)

    result = assess_handover(message, {b"old-concurrent": True}, material)

    assert result.status == INELIGIBLE
    assert result.active_concurrent_paths == ()


def test_nested_recipient_can_be_replaced_under_new_archive_group():
    replaced_nested = _recipient(b"replaced-recipient", NEW_ARCHIVE)
    old_root = _recipient(b"old-concurrent", OLD_ARCHIVE, recipients=[replaced_nested])
    message = _message([old_root])
    roster = {b"old-concurrent": True, b"replaced-recipient": True}

    result = assess_handover(message, roster, _material())

    assert result.status == ELIGIBLE
    assert result.recipients[1].group == NEW_ARCHIVE
    assert result.recipients[1].status == ELIGIBLE
    assert "new archive group" in result.nested_recipient_handling


def test_assessment_accepts_encoded_message_without_calling_decrypt(monkeypatch):
    nested = _recipient(b"nested-old-recipient", OLD_ARCHIVE)
    message = _message([
        _recipient(b"new-recipient"),
        _recipient(b"old-concurrent", OLD_ARCHIVE, recipients=[nested]),
    ])
    roster = {
        b"new-recipient": True,
        b"old-concurrent": True,
        b"nested-old-recipient": True,
    }

    def fail_decrypt(*args, **kwargs):
        raise AssertionError("decrypt must not be called")

    monkeypatch.setattr(EncMessage, "decrypt", fail_decrypt)
    result = assess_handover(_encoded(message), roster, _material())

    assert result.status == ELIGIBLE
    assert len(result.recipients) == 3


def test_encoded_nested_recipients_remain_available_after_decoding():
    nested = _recipient(b"nested-old-recipient", OLD_ARCHIVE)
    message = _message([
        _recipient(b"old-concurrent", OLD_ARCHIVE, recipients=[nested]),
    ])
    decoded = EncMessage.decode(_encoded(message))

    assert len(decoded.recipients) == 1
    assert len(decoded.recipients[0].recipients) == 1
    assert decoded.recipients[0].recipients[0].get_attr(headers.KID) == b"nested-old-recipient"


def test_encrypted_package_without_recipients_is_information_incomplete():
    result = assess_handover(_message([]), {}, _material())

    assert result.status == INFORMATION_INCOMPLETE
    assert result.recipients == ()
