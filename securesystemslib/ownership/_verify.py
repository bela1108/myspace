"""Offline signature verification for ownership statements.

Verification reuses the existing ``securesystemslib`` signature machinery:
every statement must be signed by a keyid that is registered, and the
signature is checked against the canonical payload with that registered key.
No network access is performed.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.ownership._model import (
    Registration,
    Statement,
    canonical_payload,
)
from securesystemslib.signer import Signature, Signer

VerificationResult = tuple[
    list[tuple[Statement, Registration]],
    list[tuple[Statement, "StatementVerificationError"]],
]


class StatementVerificationError(Exception):
    """Raised when a statement cannot be verified against a registered key."""


def make_statement(signer: Signer, payload: dict[str, Any]) -> Statement:
    """Sign a canonicalized payload and return the resulting Statement.

    This is a convenience helper for the parties that author statements.
    Verification of the returned envelope uses the exact same canonical
    representation.
    """
    payload = dict(payload)
    signature: Signature = signer.sign(canonical_payload(payload))
    return Statement(payload=payload, signature=signature)


class StatementVerifier:
    """Verify statements offline against the filed seal registrations."""

    def __init__(self, registrations: Iterable[Registration]) -> None:
        self._keys_by_id: dict[str, Registration] = {}
        self._materials: dict[tuple[Any, Any, Any], list[Registration]] = {}

        for registration in registrations:
            self._keys_by_id.setdefault(registration.key.keyid, registration)
            self._materials.setdefault(registration.material_fingerprint, []).append(
                registration
            )

    @property
    def materials(self) -> dict[tuple[Any, Any, Any], list[Registration]]:
        """Registrations grouped by the fingerprint of the key material."""
        return self._materials

    def verify(self, statement: Statement) -> Registration:
        """Verify one statement and return the registration that signed it.

        Raises:
            StatementVerificationError: the keyid is unregistered or the
                existing signature does not verify.
        """
        keyid = statement.signature.keyid
        registration = self._keys_by_id.get(keyid)
        if registration is None:
            raise StatementVerificationError(
                f"no registration found for signature keyid {keyid!r}"
            )

        try:
            registration.key.verify_signature(
                statement.signature, canonical_payload(statement.payload)
            )
        except (UnverifiedSignatureError, VerificationError) as error:
            raise StatementVerificationError(
                f"signature for statement {statement.statement_id[:12]}... "
                f"failed to verify with keyid {keyid!r}: {error}"
            ) from error

        return registration

    def verify_all(self, statements: Iterable[Statement]) -> VerificationResult:
        """Verify all statements.

        Returns a tuple of verified ``(statement, registration)`` pairs and
        rejected ``(statement, error)`` pairs. Verification failures never
        abort the run, so a single bad statement cannot suppress the others.
        """
        verified: list[tuple[Statement, Registration]] = []
        rejected: list[tuple[Statement, StatementVerificationError]] = []

        for statement in statements:
            try:
                registration = self.verify(statement)
            except StatementVerificationError as error:
                rejected.append((statement, error))
            else:
                verified.append((statement, registration))

        return verified, rejected
