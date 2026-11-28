"""Optional receipt protocol for delegated signing services.

When a release pipeline delegates signing to a remote service, a timed-out
request is ambiguous: the service may never have accepted the request, or it
may already have produced a signature whose response was lost in transit.

This module defines an *optional* protocol that signers may implement to make
that ambiguity resolvable. The pipeline persists a small piece of correlation
evidence locally (a "receipt") before and during the remote call, so a later
retry can ask the service what actually happened and act accordingly:

* NOT_ACCEPTED: the service confirmed it never accepted the request.
  Retrying must re-submit the payload for signing.
* SIGNED_PENDING_PICKUP: the service already produced a signature that is
  waiting to be picked up. Retrying may collect that exact signature without
  re-signing.
* LOCALLY_UNCONFIRMED: the request was submitted (or attempted) but the
  outcome is not known locally, typically after a timeout. The next retry
  must query the service to resolve the state.

Signers that do not implement ReceiptSigner keep working unchanged:
sign_with_receipt() falls back to a plain Signer.sign() call.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import tempfile
from abc import abstractmethod
from dataclasses import dataclass, replace
from enum import StrEnum, unique
from pathlib import Path
from typing import Any

from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import Signer

logger = logging.getLogger(__name__)

# Errors after which the remote state is unknown and a retry is meaningful.
RECEIPT_RETRYABLE_ERRORS = (TimeoutError, ConnectionError)


@unique
class ReceiptState(StrEnum):
    """State of a delegated signing request, as tracked by a receipt."""

    #: The service confirmed it never accepted the request: safe to re-submit.
    NOT_ACCEPTED = "not_accepted"

    #: The service produced a signature that is waiting to be picked up.
    SIGNED_PENDING_PICKUP = "signed_pending_pickup"

    #: The request was submitted but the outcome is not known locally.
    LOCALLY_UNCONFIRMED = "locally_unconfirmed"


@dataclass(frozen=True)
class SigningReceipt:
    """Locally persistable correlation evidence for a signing request.

    Attributes:
        request_id: Client-generated idempotency key correlating all remote
            calls for one logical signing request.
        payload_digest: SHA256 hex digest of the payload to be signed.
        state: Last known ReceiptState of the request.
    """

    request_id: str
    payload_digest: str
    state: ReceiptState

    @classmethod
    def new(cls, payload: bytes) -> SigningReceipt:
        """Creates a fresh receipt for a payload that was never submitted."""
        return cls(
            request_id=secrets.token_hex(16),
            payload_digest=hashlib.sha256(payload).hexdigest(),
            state=ReceiptState.NOT_ACCEPTED,
        )

    def with_state(self, state: ReceiptState) -> SigningReceipt:
        """Returns a copy of the receipt with an updated state."""
        return replace(self, state=state)

    @classmethod
    def from_dict(cls, receipt_dict: dict[str, Any]) -> SigningReceipt:
        """Creates a SigningReceipt from its JSON/dict representation."""
        return cls(
            request_id=receipt_dict["request_id"],
            payload_digest=receipt_dict["payload_digest"],
            state=ReceiptState(receipt_dict["state"]),
        )

    def to_dict(self) -> dict[str, Any]:
        """Returns the JSON-serializable dict representation of self."""
        return {
            "request_id": self.request_id,
            "payload_digest": self.payload_digest,
            "state": self.state.value,
        }


class ReceiptStore:
    """JSON-file backed persistence for signing receipts.

    Receipts are keyed by payload digest: a pipeline retrying the same
    payload after a failure finds the evidence left by the previous attempt.
    Every mutation is written to disk immediately and atomically.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {"receipts": {}}
        with open(self._path, encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=self._path.name
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self._path)
        except BaseException:
            os.unlink(tmp_path)
            raise

    def get(self, payload_digest: str) -> SigningReceipt | None:
        """Returns the receipt for a payload digest, or None."""
        receipt_dict = self._load()["receipts"].get(payload_digest)
        if receipt_dict is None:
            return None
        return SigningReceipt.from_dict(receipt_dict)

    def put(self, receipt: SigningReceipt) -> None:
        """Persists a receipt, replacing any receipt for the same payload."""
        data = self._load()
        data["receipts"][receipt.payload_digest] = receipt.to_dict()
        self._save(data)

    def remove(self, payload_digest: str) -> None:
        """Drops the receipt for a payload digest, if one exists."""
        data = self._load()
        if data["receipts"].pop(payload_digest, None) is not None:
            self._save(data)


class ReceiptSigner(Signer):
    """Optional signer interface for delegated signing with receipts.

    Implementations talk to a remote signing service that correlates
    requests by SigningReceipt.request_id. All remote operations for one
    logical request must use the same request_id, and submit() must be
    idempotent with respect to it.
    """

    @abstractmethod
    def submit(self, receipt: SigningReceipt, payload: bytes) -> SigningReceipt:
        """Submits payload for signing under receipt.request_id.

        Returns a receipt updated with the remotely confirmed state
        (typically SIGNED_PENDING_PICKUP). Raises one of
        RECEIPT_RETRYABLE_ERRORS if the outcome is unknown.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def query(self, receipt: SigningReceipt) -> SigningReceipt:
        """Asks the service for the current state of receipt.

        Returns a receipt updated with the remotely confirmed state.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def collect(self, receipt: SigningReceipt) -> Signature:
        """Picks up the signature for a SIGNED_PENDING_PICKUP receipt."""
        raise NotImplementedError  # pragma: no cover

    def sign(self, payload: bytes) -> Signature:
        """One-shot sign without local persistence.

        A timeout leaves no local evidence: use sign_with_receipt() with a
        ReceiptStore if retries must be able to recover the outcome.
        """
        receipt = self.submit(SigningReceipt.new(payload), payload)
        return self.collect(receipt)


def sign_with_receipt(signer: Signer, payload: bytes, store: ReceiptStore) -> Signature:
    """Signs payload, tracking progress with a locally persisted receipt.

    If signer does not implement the receipt protocol, falls back to a
    plain signer.sign() call and the store is left untouched.

    On a retryable error the receipt is persisted and the error re-raised:
    calling this function again with the same payload and store resumes the
    request. A request the service never accepted is re-submitted; a request
    the service already signed is completed by picking up the existing
    signature. Once a signature is returned, the receipt is discarded.
    """
    if not isinstance(signer, ReceiptSigner):
        return signer.sign(payload)

    digest = hashlib.sha256(payload).hexdigest()
    receipt = store.get(digest)
    if receipt is None:
        receipt = SigningReceipt.new(payload)
        store.put(receipt)

    if receipt.state is ReceiptState.LOCALLY_UNCONFIRMED:
        try:
            receipt = signer.query(receipt)
        except RECEIPT_RETRYABLE_ERRORS:
            store.put(receipt)
            raise
        store.put(receipt)

    if receipt.state is ReceiptState.NOT_ACCEPTED:
        try:
            receipt = signer.submit(receipt, payload)
        except RECEIPT_RETRYABLE_ERRORS:
            store.put(receipt.with_state(ReceiptState.LOCALLY_UNCONFIRMED))
            raise
        store.put(receipt)

    try:
        signature = signer.collect(receipt)
    except RECEIPT_RETRYABLE_ERRORS:
        store.put(receipt)
        raise

    store.remove(digest)
    return signature
