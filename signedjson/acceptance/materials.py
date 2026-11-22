"""Canonical fingerprints for original materials and signed events."""

import hashlib
from typing import Any, Dict

from canonicaljson import encode_canonical_json


def canonical_digest(payload: Dict[str, Any]) -> str:
    """Return the hex sha256 of the canonical JSON encoding of ``payload``."""

    return hashlib.sha256(encode_canonical_json(payload)).hexdigest()


def material_id(payload: Dict[str, Any]) -> str:
    """Compute the self-certifying identifier of an original material."""

    return "sha256:" + canonical_digest(payload)


def signature_fingerprint(event: Dict[str, Any]) -> str:
    """Stable fingerprint of every signature attached to an event.

    Re-delivering the same signed event produces the same fingerprint, which
    lets the verifier reject replays even if the client invents a new event id.
    """

    return canonical_digest(event.get("signatures", {}))
