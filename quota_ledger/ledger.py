# SPDX-License-Identifier: Apache-2.0

"""Append-only, replayable release-quota ledger.

The ledger state is entirely derived from an ordered JSON event log. Every
event is the projection of a signed quota credential; importing the same
credential twice is a no-op (the credential id and canonical bytes are used
for idempotent de-duplication). Replaying the log from an empty state
reconstructs identical quota lines and receipts, which makes auditing and
re-processing a credential directory reproducible.
"""

import hashlib
import json
from pathlib import Path

import attr

from quota_ledger.credentials import ENTITLEMENT_TYPE
from quota_ledger.credentials import HOLD_TYPE
from quota_ledger.credentials import RELEASE_TYPE
from quota_ledger.credentials import REVOKE_TYPE
from quota_ledger.credentials import check_duplicate
from quota_ledger.exceptions import InvalidTransitionError
from quota_ledger.exceptions import PendingCredentialError

STATE_OPEN = "open"
STATE_HELD = "held"
STATE_RELEASED = "released"
STATE_REVOKED = "revoked"

EVENT_LOG = "events.log"
RECEIPTS_DIR = "receipts"


@attr.s
class QuotaLine:
    """One signed release entitlement and its current lifecycle state."""

    line_id = attr.ib()
    channel = attr.ib()
    artifact_sha256 = attr.ib()
    amount = attr.ib()
    state = attr.ib()
    held = attr.ib(default=0)
    released = attr.ib(default=0)
    credential_ids = attr.ib(factory=tuple)

    @property
    def available(self):
        """Quota still consumable: nothing held, released or revoked."""
        if self.state == STATE_REVOKED:
            return 0
        return self.amount - self.held - self.released

    def to_dict(self):
        return attr.asdict(self)


@attr.s(frozen=True)
class Receipt:
    """Per-event receipt proving how a credential changed the ledger."""

    event_seq = attr.ib()
    event_hash = attr.ib()
    credential_id = attr.ib()
    credential_type = attr.ib()
    channel = attr.ib()
    line_id = attr.ib()
    artifact_sha256 = attr.ib()
    state_before = attr.ib()
    state_after = attr.ib()
    available_after = attr.ib()

    def to_dict(self):
        return attr.asdict(self)


@attr.s
class LedgerState:
    """In-memory projection of the event log."""

    lines = attr.ib(factory=dict)
    seen_credentials = attr.ib(factory=dict)
    receipts = attr.ib(factory=list)
    channel_index = attr.ib(factory=dict)

    def line_for(self, channel, artifact_sha256, credential_id=None):
        key = (channel, artifact_sha256)
        ids = self.channel_index.get(key, {})
        if credential_id is not None:
            return self.lines.get(ids.get(credential_id))
        unique = {line_id: self.lines[line_id] for line_id in ids.values()}
        return list(unique.values())


class Ledger:
    """Append-only quota ledger backed by a JSON-lines event log."""

    def __init__(self, store_dir):
        self.store_dir = Path(store_dir)
        self.event_log = self.store_dir / EVENT_LOG
        self.receipts_dir = self.store_dir / RECEIPTS_DIR
        self.state = LedgerState()
        self._last_hash = ""
        if self.event_log.exists():
            self.replay()

    # -- persistence -----------------------------------------------------

    @staticmethod
    def _hash_event(prev_hash, event_body):
        body = json.dumps(event_body, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(prev_hash.encode() + body.encode()).hexdigest()
        return digest

    def _append_event(self, event_body):
        self.store_dir.mkdir(parents=True, exist_ok=True)
        event_hash = self._hash_event(self._last_hash, event_body)
        record = {"hash": event_hash, "body": event_body}
        with self.event_log.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(record, sort_keys=True) + "\n")
        self._last_hash = event_hash
        return event_hash


    def replay(self):
        """Rebuild the projection from the event log and verify hashes."""
        self.state = LedgerState()
        prev_hash = ""
        receipts = []
        if not self.event_log.exists():
            self._last_hash = ""
            return
        for seq, raw in enumerate(self.event_log.read_text().splitlines(), 1):
            if not raw.strip():
                continue
            record = json.loads(raw)
            expected = self._hash_event(prev_hash, record["body"])
            if record["hash"] != expected:
                raise InvalidTransitionError(
                    f"event log tampered at sequence {seq}"
                )
            body = record["body"]
            receipt = self._apply_guarded(body, seq, expected, persist=False)
            receipts.append(receipt)
            # Rebuild the idempotency index so re-importing a credential
            # after reopening the ledger is still a no-op.
            self.state.seen_credentials[body["credential_id"]] = (
                bytes.fromhex(body["canonical"])
            )
            prev_hash = expected
        self._last_hash = prev_hash
        self.state.receipts = receipts


    def import_credential(self, credential, verified_release=None):
        # Verify idempotency first: identical re-import is a no-op.
        if check_duplicate(self.state.seen_credentials, credential):
            return self._receipt_for(credential.credential_id)

        artifact = credential.artifact_sha256
        if verified_release is not None:
            self._check_evidence(credential, verified_release)

        seq = len(self.state.receipts) + 1
        event_body = {
            "credential_id": credential.credential_id,
            "credential_type": credential.credential_type,
            "channel": credential.channel,
            "artifact_sha256": artifact,
            "payload": credential.payload,
            "signer_keyid": credential.signer_keyid,
            "canonical": credential.canonical_bytes().hex(),
        }
        # Apply in memory first: an invalid transition must never touch
        # the append-only log, so a parked credential leaves no side effects.
        event_hash = self._hash_event(self._last_hash, event_body)
        receipt = self._apply_guarded(event_body, seq, event_hash, persist=False)
        self._append_event(event_body)
        self._persist_receipt(receipt)
        self.state.seen_credentials[credential.credential_id] = (
            credential.canonical_bytes()
        )
        return receipt


    @staticmethod
    def _check_evidence(credential, evidence):
        if evidence.channel != credential.channel:
            raise PendingCredentialError(
                "evidence channel does not match credential channel"
            )
        if evidence.artifact_sha256 != credential.artifact_sha256:
            raise PendingCredentialError(
                "verified artifact digest does not match credential digest"
            )


    def _apply(self, event, seq, event_hash, persist):
        ctype = event["credential_type"]
        line_id = self._line_id(event)
        line = self.state.lines.get(line_id)
        before = line.state if line else None

        if ctype == ENTITLEMENT_TYPE:
            line = self._apply_entitlement(event, line_id, line)
        elif ctype == HOLD_TYPE:
            line = self._apply_hold(event, line)
        elif ctype == RELEASE_TYPE:
            line = self._apply_release(event, line)
        elif ctype == REVOKE_TYPE:
            line = self._apply_revoke(event, line)

        line.credential_ids = tuple(sorted(set(line.credential_ids + (
            event["credential_id"],
        ))))
        self.state.lines[line_id] = line
        self.state.channel_index.setdefault(
            (line.channel, line.artifact_sha256), {}
        )[event["credential_id"]] = line_id

        receipt = Receipt(
            event_seq=seq,
            event_hash=event_hash,
            credential_id=event["credential_id"],
            credential_type=ctype,
            channel=event["channel"],
            line_id=line_id,
            artifact_sha256=event["artifact_sha256"],
            state_before=before,
            state_after=line.state,
            available_after=line.available,
        )
        self.state.receipts.append(receipt)
        if persist:
            self._persist_receipt(receipt)
        return receipt

    def _apply_guarded(self, event, seq, event_hash, persist):
        # Transition failures must not leave partial projection state behind,
        # otherwise replaying the event log would diverge from the live ledger.
        lines_snapshot = dict(self.state.lines)
        index_snapshot = {
            key: dict(ids) for key, ids in self.state.channel_index.items()
        }
        receipts_before = len(self.state.receipts)
        try:
            return self._apply(event, seq, event_hash, persist)
        except Exception:
            self.state.lines = lines_snapshot
            self.state.channel_index = index_snapshot
            del self.state.receipts[receipts_before:]
            raise


    @staticmethod
    def _line_id(event):
        digest = event["artifact_sha256"]
        return event['channel'] + ':' + digest[:12]


    def _apply_entitlement(self, event, line_id, line):
        amount = event["payload"].get("amount")
        if not isinstance(amount, int) or amount <= 0:
            raise InvalidTransitionError(
                f"entitlement {event['credential_id']!r} needs positive amount"
            )
        if line is not None:
            raise InvalidTransitionError(
                f"quota line {line_id!r} already exists"
            )
        return QuotaLine(
            line_id=line_id,
            channel=event["channel"],
            artifact_sha256=event["artifact_sha256"],
            amount=amount,
            state=STATE_OPEN,
        )


    def _require_line(self, event, line):
        if line is None:
            msg = 'no entitlement for credential ' + repr(event['credential_id'])
            raise PendingCredentialError(
                msg + '; park it until the entitlement is imported'
            )
        return line


    def _apply_hold(self, event, line):
        line = self._require_line(event, line)
        if line.state == STATE_REVOKED:
            raise InvalidTransitionError(
                f"cannot hold revoked line {line.line_id!r}"
            )
        amount = event["payload"].get("amount", 1)
        if line.available < amount:
            raise InvalidTransitionError(
                f"line {line.line_id!r} has {line.available} available, "
                f"hold requested {amount}"
            )
        line.held += amount
        line.state = STATE_HELD
        return line


    def _apply_release(self, event, line):
        line = self._require_line(event, line)
        if line.state == STATE_REVOKED:
            raise InvalidTransitionError(
                f"cannot release revoked line {line.line_id!r}"
            )
        amount = event["payload"].get("amount", line.held)
        if amount > line.held:
            raise InvalidTransitionError(
                f"release of {amount} exceeds held {line.held} on "
                f"line {line.line_id!r}"
            )
        line.held -= amount
        line.released += amount
        line.state = STATE_RELEASED
        return line


    def _apply_revoke(self, event, line):
        line = self._require_line(event, line)
        if line.state == STATE_REVOKED:
            raise InvalidTransitionError(
                f"line {line.line_id!r} already revoked"
            )
        line.state = STATE_REVOKED
        line.held = 0
        return line


    def _persist_receipt(self, receipt):
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        name = f"{receipt.event_seq:06d}-{receipt.credential_id}.json"
        path = self.receipts_dir / name
        path.write_text(json.dumps(receipt.to_dict(), sort_keys=True, indent=2))


    def _receipt_for(self, credential_id):
        for receipt in reversed(self.state.receipts):
            if receipt.credential_id == credential_id:
                return receipt
        return None


    def lines_for_channel(self, channel):
        return [
            line for line in self.state.lines.values() if line.channel == channel
        ]


    def available_quota(self, channel, artifact_sha256):
        # Sum of still-consumable quota across all lines of a channel.
        lines = self.state.line_for(channel, artifact_sha256)
        return sum(line.available for line in lines)


    def receipts_for_channel(self, channel):
        return [
            receipt for receipt in self.state.receipts
            if receipt.channel == channel
        ]


    def snapshot(self):
        # Serializable projection used by tests and the CLI.
        return {
            "last_event_hash": self._last_hash,
            "lines": [line.to_dict() for line in self.state.lines.values()],
            "receipts": [r.to_dict() for r in self.state.receipts],
        }
