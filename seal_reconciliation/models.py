"""Data model for seal-number authorization and signed statements.

The model deliberately keeps the signed payload independent of the archive
location: the same signed material may re-appear in a backup volume without
producing a different statement, which is what makes backup de-duplication
possible during reconciliation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from securesystemslib.signer import Key, Signature, SSlibKey


def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"'{field_name}' must be a non-empty string")
    return value


def _require_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"'{field_name}' must be an integer")
    return value


@dataclass(frozen=True)
class SourceLocation:
    """Where an archived seal impression can physically be found.

    Attributes:
        archive: Archive volume, e.g. the primary archive or a backup tape.
        page: Page or folio number inside the archive volume.
        entry: Entry index on the page.
    """

    archive: str
    page: str
    entry: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive": self.archive,
            "page": self.page,
            "entry": self.entry,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceLocation:
        return cls(
            archive=_require_str(data.get("archive"), "archive"),
            page=_require_str(data.get("page"), "page"),
            entry=_require_int(data.get("entry"), "entry"),
        )

    def __str__(self) -> str:
        return f"{self.archive} / {self.page} / #{self.entry}"


@dataclass(frozen=True)
class Authorization:
    """One contiguous seal-number interval granted to an officer.

    A leave hand-over is represented by two adjacent authorizations sharing
    the same interval bounds' split point: the original officer keeps the
    first half and the substitute officer receives the second half.

    Attributes:
        officer_id: Officer who may settle numbers in the interval.
        keyid: Key id whose signatures prove the officer's seal usage.
        start: First seal number of the authorized interval (inclusive).
        end: Last seal number of the authorized interval (inclusive).
        category: Statement category the interval is valid for.
        note: Human-readable context, e.g. "delegated half-segment".
    """

    officer_id: str
    keyid: str
    start: int
    end: int
    category: str
    note: str = ""

    def __post_init__(self) -> None:
        _require_str(self.officer_id, "officer_id")
        _require_str(self.keyid, "keyid")
        _require_str(self.category, "category")
        if self.start > self.end:
            raise ValueError(
                f"authorization interval [{self.start}, {self.end}] is empty"
            )
        if self.start < 0:
            raise ValueError("seal numbers must be non-negative")

    def contains(self, number: int) -> bool:
        return self.start <= number <= self.end

    @property
    def interval(self) -> str:
        return f"[{self.start}, {self.end}]"

    def to_dict(self) -> dict[str, Any]:
        data = {
            "officer_id": self.officer_id,
            "keyid": self.keyid,
            "start": self.start,
            "end": self.end,
            "category": self.category,
        }
        if self.note:
            data["note"] = self.note
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Authorization:
        return cls(
            officer_id=_require_str(data.get("officer_id"), "officer_id"),
            keyid=_require_str(data.get("keyid"), "keyid"),
            start=_require_int(data.get("start"), "start"),
            end=_require_int(data.get("end"), "end"),
            category=_require_str(data.get("category"), "category"),
            note=str(data.get("note", "")),
        )


@dataclass(frozen=True)
class SealStatement:
    """A signed record of one seal impression on a piece of material.

    Attributes:
        statement_id: Stable identifier of the signed statement.
        category: Statement category; numbers may repeat across categories.
        seal_number: Seal number stamped on the material.
        material_digest: sha256 digest of the signed material's content.
        keyid: Key id of the officer who produced the impression.
        signature: securesystemslib signature over the canonical payload.
        source: Location of the original paper impression.
    """

    statement_id: str
    category: str
    seal_number: int
    material_digest: str
    keyid: str
    signature: Signature
    source: SourceLocation
    unrecognized_fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_str(self.statement_id, "statement_id")
        _require_str(self.category, "category")
        _require_int(self.seal_number, "seal_number")
        _require_str(self.material_digest, "material_digest")
        _require_str(self.keyid, "keyid")
        if self.seal_number < 0:
            raise ValueError("seal numbers must be non-negative")
        if not isinstance(self.signature, Signature):
            raise ValueError("'signature' must be a securesystemslib Signature")
        if not isinstance(self.source, SourceLocation):
            raise ValueError("'source' must be a SourceLocation")

    def canonical_payload(self) -> bytes:
        """Return the deterministic bytes that are signed.

        The archive location is intentionally excluded so a backup copy of
        the same material yields byte-identical signed payloads.
        """
        return build_canonical_payload(
            self.statement_id,
            self.category,
            self.seal_number,
            self.material_digest,
            self.keyid,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement_id": self.statement_id,
            "category": self.category,
            "seal_number": self.seal_number,
            "material_digest": self.material_digest,
            "keyid": self.keyid,
            "signature": self.signature.to_dict(),
            "source": self.source.to_dict(),
            **self.unrecognized_fields,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SealStatement:
        managed = {
            "statement_id",
            "category",
            "seal_number",
            "material_digest",
            "keyid",
            "signature",
            "source",
        }
        signature_data = data.get("signature")
        if not isinstance(signature_data, dict):
            raise ValueError("'signature' must be an object")
        source_data = data.get("source")
        if not isinstance(source_data, dict):
            raise ValueError("'source' must be an object")
        return cls(
            statement_id=_require_str(data.get("statement_id"), "statement_id"),
            category=_require_str(data.get("category"), "category"),
            seal_number=_require_int(data.get("seal_number"), "seal_number"),
            material_digest=_require_str(
                data.get("material_digest"), "material_digest"
            ),
            keyid=_require_str(data.get("keyid"), "keyid"),
            signature=Signature.from_dict(signature_data),
            source=SourceLocation.from_dict(source_data),
            unrecognized_fields={
                key: value
                for key, value in data.items()
                if key not in managed
            },
        )


def build_canonical_payload(
    statement_id: str,
    category: str,
    seal_number: int,
    material_digest: str,
    keyid: str,
) -> bytes:
    """Deterministic signed bytes; archive location is excluded."""
    payload = {
        "statement_id": statement_id,
        "category": category,
        "seal_number": seal_number,
        "material_digest": material_digest,
        "keyid": keyid,
    }
    return json_dumps(payload).encode("utf-8")
def json_dumps(payload: dict[str, Any]) -> str:
    """Stable JSON encoding shared by signer and verifier."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def public_key_to_dict(key: Key) -> dict[str, Any]:
    """Serialize a public key together with its keyid for offline use."""
    return {"keyid": key.keyid, "key": key.to_dict()}


def public_key_from_dict(data: dict[str, Any]) -> Key:
    """Rebuild a securesystemslib public key from a serialized key dict."""
    keyid = _require_str(data.get("keyid"), "keyid")
    key_data = data.get("key")
    if not isinstance(key_data, dict):
        raise ValueError("key payload must be an object")
    return SSlibKey.from_dict(keyid, key_data)
