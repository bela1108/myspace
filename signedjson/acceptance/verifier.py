"""Chain-level acceptance over a finite set of signed delivery events.

The verifier is deliberately offline: every signature is re-checked against a
fixed registry of verify keys, and every acceptance decision is recomputed
from the whole admitted event set so that events delivered out of order can
be recovered once their predecessor finally arrives.
"""

from typing import Any, Dict, List, Optional, Set

from signedjson.acceptance import status as event_status
from signedjson.acceptance.materials import canonical_digest, signature_fingerprint
from signedjson.key import decode_verify_key_base64
from signedjson.sign import SignatureVerifyException, verify_signed_json
from signedjson.types import VerifyKey


class UnknownSigner(Exception):
    """An event was signed by an entity not present in the key registry."""


class DuplicateEvent(Exception):
    """The same signed acknowledgement was presented more than once.

    A replay must never advance the chain a second time.
    """


class AcceptanceReport:
    """Outcome of ingesting one batch of events."""

    def __init__(
        self,
        accepted: List[str],
        duplicates: List[str],
        invalid_signatures: List[str],
        unknown_signers: List[str],
    ) -> None:
        self.accepted = accepted
        self.duplicates = duplicates
        self.invalid_signatures = invalid_signatures
        self.unknown_signers = unknown_signers

    @property
    def replay_count(self) -> int:
        return len(self.duplicates)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "accepted": list(self.accepted),
            "duplicates": list(self.duplicates),
            "invalid_signatures": list(self.invalid_signatures),
            "unknown_signers": list(self.unknown_signers),
        }


class AcceptanceVerifier:
    """Recompute acceptance decisions for a finite, signed event set.

    Args:
        materials: Registry mapping material id -> payload. Used to decide
            which original each event actually acknowledges and to detect
            bindings that do not match the declared digest.
        keys: Mapping ``signer -> ed25519 verify key``.
    """

    def __init__(
        self,
        materials: Optional[Dict[str, Dict[str, Any]]] = None,
        keys: Optional[Dict[str, VerifyKey]] = None,
    ) -> None:
        self.materials: Dict[str, Dict[str, Any]] = dict(materials or {})
        self.keys: Dict[str, VerifyKey] = dict(keys or {})
        self.events: Dict[str, Dict[str, Any]] = {}
        self._fingerprints: Dict[str, str] = {}
        self._seen_fingerprints: Set[str] = set()
        self._status_cache: Dict[str, str] = {}
        self._active_paths: Set[str] = set()
        self._frozen: Set[str] = set()

    @classmethod
    def from_key_config(
        cls,
        materials: Dict[str, Dict[str, Any]],
        key_config: Dict[str, Dict[str, str]],
    ) -> "AcceptanceVerifier":
        """Build a verifier from serialisable ``{signer: {key_id, key}}``."""

        keys: Dict[str, VerifyKey] = {}
        for signer, entry in key_config.items():
            algorithm, version = entry["key_id"].split(":", 1)
            keys[signer] = decode_verify_key_base64(
                algorithm, version, entry["key"]
            )
        return cls(materials=materials, keys=keys)

    def ingest(self, batch: List[Dict[str, Any]]) -> AcceptanceReport:
        """Admit the validly signed, non-duplicate events from ``batch``.

        Ingestion never mutates chain decisions: call :meth:`recompute`
        afterwards (or read :meth:`snapshot`, which does it for you).
        """

        accepted: List[str] = []
        duplicates: List[str] = []
        invalid: List[str] = []
        unknown: List[str] = []
        for event in batch:
            event_id = str(event.get("event_id", "<unknown>"))
            signer = event.get("signer")
            if signer not in self.keys:
                unknown.append(event_id)
                continue
            try:
                verify_signed_json(event, signer, self.keys[signer])
            except (SignatureVerifyException, KeyError):
                invalid.append(event_id)
                continue
            fingerprint = signature_fingerprint(event)
            if (
                event_id in self.events
                or fingerprint in self._seen_fingerprints
            ):
                duplicates.append(event_id)
                continue
            self.events[event_id] = event
            self._fingerprints[event_id] = fingerprint
            self._seen_fingerprints.add(fingerprint)
            accepted.append(event_id)
        return AcceptanceReport(accepted, duplicates, invalid, unknown)

    def recompute(self) -> Dict[str, str]:
        """Recompute every event's status from the full admitted event set.

        Recomputing from scratch is what lets late predecessors restore
        previously pending confirmations without keeping fragile incremental
        state.
        """

        self._status_cache = {}
        self._active_paths = set()
        self._frozen = set()
        return {
            event_id: self._status(event_id) for event_id in sorted(self.events)
        }

    def _status(self, event_id: str) -> str:
        if event_id in self._status_cache:
            return self._status_cache[event_id]
        if event_id in self._active_paths:
            # A predecessor loop cannot confirm anything: freeze the cycle
            # entry as a broken, human-reviewed chain. The frozen flag stops
            # the unwind from overwriting it with ``blocked``.
            self._status_cache[event_id] = event_status.MISBOUND
            self._frozen.add(event_id)
            return event_status.MISBOUND
        event = self.events[event_id]
        self._active_paths.add(event_id)
        try:
            candidate = self._compute_status(event_id, event)
        finally:
            self._active_paths.discard(event_id)
        if event_id not in self._frozen:
            self._status_cache[event_id] = candidate
        return self._status_cache[event_id]

    def _compute_status(
        self, event_id: str, event: Dict[str, Any]
    ) -> str:
        if self._is_misbound(event):
            return event_status.MISBOUND
        predecessor = event.get("predecessor")
        if predecessor is None:
            base = event_status.CONFIRMED
        elif predecessor not in self.events:
            base = event_status.AWAITING_PREDECESSOR
        else:
            parent_status = self._status(predecessor)
            if parent_status == event_status.AWAITING_PREDECESSOR:
                base = event_status.AWAITING_PREDECESSOR
            elif parent_status == event_status.CONFIRMED:
                base = event_status.CONFIRMED
            else:
                # The predecessor is itself disputed (fork) or misbound, so
                # every later acknowledgement hangs until a human reviews it.
                base = event_status.BLOCKED
        if self._is_fork(event):
            base = self._higher_precedence(base, event_status.FORK)
        return base

    @staticmethod
    def _higher_precedence(left: str, right: str) -> str:
        return left if event_status.ORDER.index(left) < event_status.ORDER.index(
            right
        ) else right

    def _is_misbound(self, event: Dict[str, Any]) -> bool:
        actual = self._material_for_digest(event.get("material_digest"))
        if actual is None:
            # The digest matches no registered original, so the
            # acknowledgement cannot be bound to any known material.
            return True
        declared = event.get("material_id")
        if declared is None:
            # No main-archive binding was recorded; the digest alone is
            # enough to know which original was actually acknowledged.
            return False
        return declared != actual

    def _fork_events(self) -> Set[str]:
        """Events that compete with a sibling for the same predecessor.

        Only the competing successors themselves are disputed; the events
        further down each branch keep their own status so both mutually
        exclusive branches stay on record.
        """

        successors: Dict[str, List[str]] = {}
        for event_id, event in self.events.items():
            predecessor = event.get("predecessor")
            if predecessor is not None:
                successors.setdefault(predecessor, []).append(event_id)
        disputed: Set[str] = set()
        for group in successors.values():
            if len(group) > 1:
                disputed.update(group)
        return disputed

    def _is_fork(self, event: Dict[str, Any]) -> bool:
        return event.get("event_id") in self._fork_events()

    def branches(self) -> Dict[str, List[str]]:
        """Return the acknowledged chains grouped by branch label.

        A branch label is the chain root's event id; a fork appends the
        successor's own event id so the two mutually exclusive branches stay
        distinguishable while both remain on record.
        """

        labels: Dict[str, str] = {}
        for event_id in sorted(self.events):
            labels[event_id] = self._branch_label(event_id, labels)
        branches: Dict[str, List[str]] = {}
        for event_id in sorted(self.events, key=lambda item: (labels[item], item)):
            branches.setdefault(labels[event_id], []).append(event_id)
        return branches

    def _branch_label(self, event_id: str, labels: Dict[str, str]) -> str:
        event = self.events[event_id]
        predecessor = event.get("predecessor")
        if predecessor is None or predecessor not in self.events:
            return event_id
        parent_label = labels.get(predecessor) or self._branch_label(
            predecessor, labels
        )
        if self._is_fork(event):
            return parent_label + ">" + event_id
        return parent_label

    def chain_audit(self) -> List[Dict[str, Any]]:
        """Walk every confirmed step and name the original it acknowledges."""

        statuses = self.recompute()
        audit: List[Dict[str, Any]] = []
        for event_id in sorted(self.events):
            event = self.events[event_id]
            audit.append(
                {
                    "event_id": event_id,
                    "status": statuses[event_id],
                    "signer": event.get("signer"),
                    "predecessor": event.get("predecessor"),
                    "material_digest": event.get("material_digest"),
                    "acknowledged_material": self._material_for_digest(
                        event.get("material_digest")
                    ),
                    "declared_material": event.get("material_id"),
                }
            )
        return audit

    def _material_for_digest(self, digest: Optional[str]) -> Optional[str]:
        for material_id, payload in self.materials.items():
            if canonical_digest(payload) == digest:
                return material_id
        return None

    def review_queue(self) -> List[Dict[str, str]]:
        """Events a human must inspect, grouped by reason."""

        statuses = self.recompute()
        queue: List[Dict[str, str]] = []
        for event_id in sorted(self.events):
            state = statuses[event_id]
            if state in event_status.NEEDS_REVIEW:
                queue.append({"event_id": event_id, "reason": state})
        return queue

    def snapshot(self, run: int) -> Dict[str, Any]:
        """Node summary for one acceptance run."""

        statuses = self.recompute()
        labels: Dict[str, str] = {}
        for event_id in sorted(self.events):
            labels[event_id] = self._branch_label(event_id, labels)
        nodes = [
            {
                "event_id": event_id,
                "status": statuses[event_id],
                "branch": labels[event_id],
                "predecessor": self.events[event_id].get("predecessor"),
                "material_digest": self.events[event_id].get("material_digest"),
                "acknowledged_material": self._material_for_digest(
                    self.events[event_id].get("material_digest")
                ),
            }
            for event_id in sorted(self.events)
        ]
        counts: Dict[str, int] = {}
        for state in statuses.values():
            counts[state] = counts.get(state, 0) + 1
        return {
            "run": run,
            "event_count": len(self.events),
            "status_counts": counts,
            "review_queue": self.review_queue(),
            "nodes": nodes,
        }
