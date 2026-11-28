"""Key generation rotation boundary.

This module supports maintenance-group handovers: a signing service can be
reconfigured with a successor key generation while signatures made under the
previous generation remain verifiable for historical review.

The design guarantees that every signing operation pins the generation that is
active when the operation starts. A rotation performed while an operation is in
flight therefore never changes the key used by that operation, while all
subsequent operations use the successor generation. Older generations are kept
("archived") for verification only and can no longer produce new signatures.

The building blocks are:

* :class:`LocalSigner`: a small self-contained "fake" signer that needs no
  external cryptographic library and is easy to use in tests or prototypes.
* :class:`KeyGeneration`: a named key generation holding a signer and the
  verifier used to validate its signatures.
* :class:`SigningConfig`: injectable, thread-safe registry of generations and
  the currently active key id.
* :class:`RotationBoundary`: a :class:`~securesystemslib.signer.Signer` that
  pins the active generation at operation start.
* :func:`review_records`: classifies persisted records into archived valid,
  authorized new and unverifiable samples.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer._signature import Signature
from securesystemslib.signer._signer import SecretsHandler, Signer

# A sync point is an optional callback invoked by RotationBoundary at a known
# point in the signing lifecycle. Tests use it to deterministically force a
# rotation to happen while a signing operation is in flight.
SyncPoint = Callable[[], None]


@runtime_checkable
class Verifier(Protocol):
    """Anything able to verify a :class:`Signature` over a payload."""

    def verify(self, payload: bytes, signature: Signature) -> None:
        """Raise on an invalid signature, return otherwise."""


class LocalSigner(Signer):
    """Local, dependency-free "fake" signer for tests and prototyping.

    Signatures are deterministic HMAC-SHA256 tags keyed by a shared secret.
    The same instance (or another instance created with the same secret) can
    verify the signatures. The key id is derived from the secret so that two
    generations never collide unless they share a secret.

    This signer intentionally does not implement :meth:`from_priv_key_uri`:
    instances are constructed directly with the secret material.
    """

    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes):
            raise TypeError("secret must be bytes")
        if not secret:
            raise ValueError("secret must not be empty")
        self._secret = secret
        self._keyid = hashlib.sha256(secret).hexdigest()

    @property
    def keyid(self) -> str:
        """HEX string uniquely identifying this signer's key."""
        return self._keyid

    @property
    def public_key(self) -> None:  # type: ignore[override]
        """Symmetric fake signer has no asymmetric public key object."""
        return None

    def sign(self, payload: bytes) -> Signature:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        tag = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return Signature(self._keyid, tag)

    def verify(self, payload: bytes, signature: Signature) -> None:
        """Verify a signature previously created by an equivalent signer.

        Raises:
            VerificationError: The signature references a different key id.
            UnverifiedSignatureError: The signature tag does not match.
        """
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if signature.keyid != self._keyid:
            raise VerificationError(
                f"key id {signature.keyid!r} does not match {self._keyid!r}"
            )
        expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.signature):
            raise UnverifiedSignatureError("signature is invalid")

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: object,
        secrets_handler: SecretsHandler | None = None,
    ) -> LocalSigner:
        raise NotImplementedError(
            "LocalSigner is constructed directly, not from a private key URI"
        )


@dataclass(frozen=True)
class KeyGeneration:
    """A named key generation inside a :class:`SigningConfig`.

    Args:
        generation: Monotonic generation identifier (e.g. ``1``, ``2``).
        signer: The signer holding the private key material.
        verifier: Object able to verify this generation's signatures.
            Use the signer itself when it can also verify, as
            :meth:`for_local` does for :class:`LocalSigner`.

    Attributes:
        keyid: HEX string identifying the generation's key, read from the
            signer.
    """

    generation: int
    signer: Signer
    verifier: Verifier
    keyid: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.generation, int) or self.generation < 1:
            raise ValueError("generation must be a positive integer")
        if not isinstance(self.verifier, Verifier):
            raise TypeError("verifier must provide verify(payload, signature)")
        object.__setattr__(
            self,
            "keyid",
            self.signer.keyid,  # type: ignore[attr-defined]
        )

    @classmethod
    def for_local(cls, generation: int, secret: bytes) -> KeyGeneration:
        """Create a generation backed by a :class:`LocalSigner`."""
        signer = LocalSigner(secret)
        return cls(generation, signer, signer)

    def verify(self, payload: bytes, signature: Signature) -> None:
        """Verify a signature with this generation's verifier."""
        self.verifier.verify(payload, signature)


class SigningConfig:
    """Injectable configuration holding key generations and the active key.

    The config is the single source of truth shared between signing and review
    code. All access is guarded by a re-entrant lock so that a rotation can be
    applied from any thread without corrupting in-flight signing operations.

    A rotation installs a successor generation and archives the previously
    active one: archived generations remain available for verification but can
    no longer be used for new signatures.
    """

    def __init__(self, initial_generation: KeyGeneration):
        self._lock = threading.RLock()
        self._generations: dict[int, KeyGeneration] = {}
        self._keyids: dict[str, KeyGeneration] = {}
        self._archived_keyids: set[str] = set()
        self._active_keyid: str | None = None
        self.rotate(initial_generation)

    @property
    def lock(self) -> threading.RLock:
        """Re-entrant lock guarding this config's state."""
        return self._lock

    @property
    def active_keyid(self) -> str | None:
        """Key id that new signatures must use, or ``None`` if retired."""
        with self._lock:
            return self._active_keyid

    def rotate(self, successor: KeyGeneration) -> None:
        """Install ``successor`` and archive the current active generation.

        Raises:
            ValueError: The generation id is not strictly greater than the
                current one, or its key id is already registered.
        """
        with self._lock:
            if successor.keyid in self._keyids:
                raise ValueError(f"key id {successor.keyid!r} is already registered")
            if self._generations:
                current_max = max(self._generations)
                if successor.generation <= current_max:
                    raise ValueError(
                        f"generation {successor.generation} must be greater "
                        f"than current generation {current_max}"
                    )
            if self._active_keyid is not None:
                self._archived_keyids.add(self._active_keyid)
            self._generations[successor.generation] = successor
            self._keyids[successor.keyid] = successor
            self._active_keyid = successor.keyid

    def retire_active(self) -> None:
        """Archive the active generation and allow no new signatures."""
        with self._lock:
            if self._active_keyid is None:
                return
            self._archived_keyids.add(self._active_keyid)
            self._active_keyid = None

    def get_active_generation(self) -> KeyGeneration:
        """Return the generation that new signatures must use.

        Raises:
            ValueError: No active generation exists.
        """
        with self._lock:
            if self._active_keyid is None:
                raise ValueError("no active key generation")
            return self._keyids[self._active_keyid]

    def get_generation(self, generation: int) -> KeyGeneration:
        """Return a generation by id."""
        with self._lock:
            return self._generations[generation]

    def get_generation_for_keyid(self, keyid: str) -> KeyGeneration:
        """Resolve a key id to its generation.

        Raises:
            KeyError: No registered generation owns the key id.
        """
        with self._lock:
            return self._keyids[keyid]

    def is_active_key(self, keyid: str) -> bool:
        """Whether ``keyid`` identifies the currently active generation."""
        with self._lock:
            return keyid == self._active_keyid

    def is_archived_key(self, keyid: str) -> bool:
        """Whether ``keyid`` identifies an archived verify-only generation."""
        with self._lock:
            return keyid in self._archived_keyids

    def is_known_key(self, keyid: str) -> bool:
        """Whether any generation (active or archived) owns the key id."""
        with self._lock:
            return keyid in self._keyids


class RotationBoundary(Signer):
    """Signer that pins the generation active when ``sign()`` starts.

    The boundary takes an injectable :class:`SigningConfig`. Each signing
    operation captures the active generation at start time and keeps using it
    for the whole operation, even if the config is rotated in the meantime.
    Operations that start after a rotation automatically use the successor
    generation.

    Optional sync points can be injected to observe or control the signing
    lifecycle, which makes rotation races deterministic in tests:

    * ``before_capture`` runs before the active generation is captured.
    * ``after_capture`` runs after the generation is pinned but before the
      actual signing call.
    """

    def __init__(
        self,
        config: SigningConfig,
        before_capture: SyncPoint | None = None,
        after_capture: SyncPoint | None = None,
    ):
        self._config = config
        self._before_capture = before_capture
        self._after_capture = after_capture

    @property
    def config(self) -> SigningConfig:
        """The injected signing configuration."""
        return self._config

    @property
    def public_key(self) -> None:  # type: ignore[override]
        """The active key is owned by the config, not by the boundary."""
        return None

    def sign(self, payload: bytes) -> Signature:
        if self._before_capture is not None:
            self._before_capture()

        with self._config.lock:
            generation = self._config.get_active_generation()
            signer = generation.signer

        if self._after_capture is not None:
            self._after_capture()

        return signer.sign(payload)

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: object,
        secrets_handler: SecretsHandler | None = None,
    ) -> RotationBoundary:
        raise NotImplementedError(
            "RotationBoundary is constructed with a SigningConfig, "
            "not from a private key URI"
        )


@dataclass(frozen=True)
class SignedRecord:
    """Persisted payload plus the signature over it.

    The persisted representation only carries the key id (inside the
    signature); the generation that produced it is intentionally not stored.
    Review code reconstructs the generation by looking the key id up in the
    current :class:`SigningConfig`.
    """

    payload: bytes
    signature: Signature

    def to_dict(self) -> dict:
        """JSON-serializable representation (key id and signature only)."""
        return {
            "payload": self.payload.hex(),
            "signature": self.signature.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> SignedRecord:
        """Rebuild a record from its key-id-only representation."""
        return cls(
            bytes.fromhex(data["payload"]),
            Signature.from_dict(dict(data["signature"])),
        )


@dataclass(frozen=True)
class ReviewedSample:
    """A record whose signature verified against a known generation."""

    record: SignedRecord
    keyid: str
    generation: int


@dataclass(frozen=True)
class UnverifiableSample:
    """A record that could not be verified, with the reason."""

    record: SignedRecord
    reason: str


@dataclass(frozen=True)
class ReviewReport:
    """Classification result of :func:`review_records`.

    Attributes:
        archived_valid: Records verified with an archived generation.
        authorized_new: Records verified with the currently active generation.
        unverifiable: Records whose key id is unknown, or whose signature did
            not verify.
    """

    archived_valid: list[ReviewedSample] = field(default_factory=list)
    authorized_new: list[ReviewedSample] = field(default_factory=list)
    unverifiable: list[UnverifiableSample] = field(default_factory=list)


def review_records(records: list[SignedRecord], config: SigningConfig) -> ReviewReport:
    """Classify persisted records for historical review.

    Each record carries only a key id. The key id is resolved against the
    injected config to find the generation that owns it:

    * a valid signature under the active generation is "authorized new";
    * a valid signature under an archived generation is "archived valid";
    * unknown key ids and invalid signatures are "unverifiable".
    """
    archived_valid: list[ReviewedSample] = []
    authorized_new: list[ReviewedSample] = []
    unverifiable: list[UnverifiableSample] = []

    for record in records:
        keyid = record.signature.keyid
        try:
            with config.lock:
                generation = config.get_generation_for_keyid(keyid)
                generation.verify(record.payload, record.signature)
        except KeyError:
            unverifiable.append(UnverifiableSample(record, f"unknown key id {keyid!r}"))
            continue
        except (UnverifiedSignatureError, VerificationError) as error:
            unverifiable.append(UnverifiableSample(record, str(error)))
            continue

        sample = ReviewedSample(record, keyid, generation.generation)
        if config.is_active_key(keyid):
            authorized_new.append(sample)
        else:
            archived_valid.append(sample)

    return ReviewReport(archived_valid, authorized_new, unverifiable)
