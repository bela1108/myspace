"""Signing helpers for offline seal statements."""

from __future__ import annotations

from securesystemslib.hash import digest
from securesystemslib.signer import CryptoSigner

from seal_reconciliation.models import (
    SealStatement,
    SourceLocation,
    build_canonical_payload,
)


def digest_material(content: bytes) -> str:
    """Return the sha256 digest of the signed material content."""
    digest_object = digest(algorithm="sha256")
    digest_object.update(content)
    return digest_object.hexdigest()


def issue_statement(
    signer: CryptoSigner,
    statement_id: str,
    category: str,
    seal_number: int,
    content: bytes,
    source: SourceLocation,
) -> SealStatement:
    """Create a cryptographically signed seal statement offline."""
    material_digest = digest_material(content)
    keyid = signer.public_key.keyid
    payload = build_canonical_payload(
        statement_id, category, seal_number, material_digest, keyid
    )
    return SealStatement(
        statement_id=statement_id,
        category=category,
        seal_number=seal_number,
        material_digest=material_digest,
        keyid=keyid,
        signature=signer.sign(payload),
        source=source,
    )
