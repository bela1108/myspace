"""Statements and seal registrations used for ownership reconciliation.

A :class:`Registration` binds a public key (as serialized by
``securesystemslib``) to the organization that filed it. A :class:`Statement`
is a signed envelope whose payload is canonicalized to deterministic JSON
before the existing signature machinery verifies it.

Two statement purposes are supported:

* ``authorization`` -- an organization claims ownership of the key material
  for a purpose, an interval and a jurisdiction, and
* ``handoff`` -- the key holder documents a transfer between two
  organizations at a point in time.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from securesystemslib._internal.utils import make_hashable
from securesystemslib.signer import Key, Signature, SSlibKey

AUTHORIZATION = "authorization"
HANDOFF = "handoff"

STATEMENT_TYPES = (AUTHORIZATION, HANDOFF)


def canonical_payload(payload: dict[str, Any]) -> bytes:
    """Return the deterministic byte representation of a statement payload.

    Signatures are created and verified over these bytes so that the result is
    independent of dictionary insertion order and whitespace.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def material_id(fingerprint: tuple[Any, Any, Any]) -> str:
    """Stable short identifier for a key material fingerprint."""
    rendered = canonical_payload(
        {
            "keytype": fingerprint[0],
            "scheme": fingerprint[1],
            "keyval": dict(fingerprint[2]),
        }
    )
    return hashlib.sha256(rendered).hexdigest()[:16]


@dataclass
class Registration:
    """A seal registration filed by an organization for a public key.

    Two registrations may describe the *same key material* while carrying
    different keyids or organizations. Key material equality is decided from
    the serialized key content, not from the keyid.
    """

    organization: str
    key: Key

    @property
    def material_fingerprint(self) -> tuple[str, str, Any]:
        """Identity of the underlying key material (type, scheme and keyval)."""
        return (
            self.key.keytype,
            self.key.scheme,
            make_hashable(self.key.keyval),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Registration:
        """Create a registration from a JSON-serializable dictionary."""
        organization = data["organization"]
        keyid = data.get("keyid")
        key = SSlibKey.from_dict(
            keyid if keyid is not None else data["key"].get("keyid", ""),
            dict(data["key"]),
        )
        return cls(organization=organization, key=key)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of the registration."""
        return {
            "organization": self.organization,
            "keyid": self.key.keyid,
            "key": self.key.to_dict(),
        }


@dataclass
class Statement:
    """A signed authorization or handoff statement.

    The payload carries the business claims; ``signature`` is verified over
    :func:`canonical_payload` using the key referenced by ``signature.keyid``.
    """

    payload: dict[str, Any]
    signature: Signature

    def __post_init__(self) -> None:
        statement_type = self.payload.get("type")
        if statement_type not in STATEMENT_TYPES:
            raise ValueError(
                f"statement type must be one of {STATEMENT_TYPES}, "
                f"got {statement_type!r}"
            )

    @property
    def statement_id(self) -> str:
        """Stable identity of the (unsigned) payload.

        Statements with identical payloads share the same identity and are
        merged during reconciliation even if they were filed more than once.
        """
        return canonical_payload(self.payload).hex()

    @property
    def statement_type(self) -> str:
        return self.payload["type"]

    @property
    def purpose(self) -> str:
        return self.payload["purpose"]

    @property
    def jurisdiction(self) -> str:
        return self.payload["jurisdiction"]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Statement:
        """Create a statement from a JSON-serializable dictionary."""
        payload = dict(data["payload"])
        signature = Signature.from_dict(dict(data["signature"]))
        return cls(payload=payload, signature=signature)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of the statement."""
        return {
            "payload": dict(self.payload),
            "signature": self.signature.to_dict(),
        }


@dataclass
class Authorization:
    """Business claims of an authorization statement."""

    organization: str
    purpose: str
    jurisdiction: str
    valid_from: str
    valid_to: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Authorization:
        return cls(
            organization=payload["organization"],
            purpose=payload["purpose"],
            jurisdiction=payload["jurisdiction"],
            valid_from=payload["valid_from"],
            valid_to=payload["valid_to"],
        )


@dataclass
class Handoff:
    """Business claims of a handoff statement.

    A handoff is a point-in-time event: the key material is transferred from
    ``from_organization`` to ``to_organization`` at ``effective_at``.
    """

    from_organization: str
    to_organization: str
    purpose: str
    jurisdiction: str
    effective_at: str
    witnesses: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Handoff:
        return cls(
            from_organization=payload["from_organization"],
            to_organization=payload["to_organization"],
            purpose=payload["purpose"],
            jurisdiction=payload["jurisdiction"],
            effective_at=payload["effective_at"],
            witnesses=tuple(payload.get("witnesses", ())),
        )
