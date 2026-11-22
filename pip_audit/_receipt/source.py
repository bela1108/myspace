"""
Loading and validation for the three evidence sources reconciled by
`pip_audit._receipt`.

Each source is a JSON document whose entries describe distribution files
(wheels or sdists). Entries that only carry a package name and version, as
produced by legacy pip-audit reports, are accepted but flagged as lacking an
artifact identity so that downstream reconciliation keeps them open as
"needs review" rather than rejecting the whole document.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from pip_audit._receipt.model import (
    ArtifactIdentity,
    EvidenceRecord,
    HandoffStage,
    PackageCoordinate,
    ReceiptSourceError,
)

_NAME_ALIASES = ("name", "package", "project")
_VERSION_ALIASES = ("version", "resolved_version", "package_version")
_FILE_ALIASES = ("filename", "file", "artifact", "wheel", "dist_file", "distribution_file")
_DIGEST_FIELD_ALIASES = ("digests", "digest", "hashes", "hash", "sha256", "sha256_digest", "checksum")
_PROVIDER_ALIASES = ("provided_by", "provider", "source_provider", "emitted_by", "reporter")
_ENTRY_KEYS = ("entries", "records", "dependencies", "artifacts", "items")


def _first_present(payload: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for alias in aliases:
        value = payload.get(alias)
        if value is not None:
            return value
    return None


class ReceiptDocument:
    """
    A parsed evidence document from one of the three handoff stages.

    Documents are intentionally permissive: records without a distribution
    filename or digest are kept so that legacy reports remain openable. Use
    `EvidenceRecord.has_identity` to detect those records.
    """

    def __init__(
        self,
        stage: HandoffStage,
        records: list[EvidenceRecord],
        *,
        source_document: str,
    ) -> None:
        self.stage = stage
        self.records = records
        self.source_document = source_document

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        stage: HandoffStage,
        *,
        default_provider: str | None = None,
    ) -> "ReceiptDocument":
        """Load and parse a JSON evidence document from disk."""

        document_path = Path(path)
        try:
            text = document_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReceiptSourceError(f"unable to read {document_path}: {exc}") from exc
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ReceiptSourceError(f"{document_path} is not valid JSON: {exc}") from exc
        return cls.from_dict(
            payload,
            stage,
            default_provider=default_provider,
            source_document=str(document_path),
        )

    @classmethod
    def from_dict(
        cls,
        payload: Any,
        stage: HandoffStage,
        *,
        default_provider: str | None = None,
        source_document: str | None = None,
    ) -> "ReceiptDocument":
        """
        Build a document from an in-memory JSON mapping or entry list.

        The payload may be a bare list of entries or a mapping containing an
        `entries`/`records`/`dependencies` list. A document-level provider (or
        `default_provider`) is attributed to records that name no provider.
        """

        location = source_document or f"{stage.value} document"
        entries = cls._extract_entries(payload, location)
        document_provider = cls._document_provider(payload) or default_provider

        records: list[EvidenceRecord] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ReceiptSourceError(f"{location}: entry {index} is not an object")
            context = f"{location} entry {index}"
            records.append(
                cls._parse_entry(
                    entry,
                    stage,
                    context=context,
                    document_provider=document_provider,
                    source_document=location,
                )
            )
        return cls(stage=stage, records=records, source_document=location)

    @classmethod
    def _parse_entry(
        cls,
        entry: dict[str, Any],
        stage: HandoffStage,
        *,
        context: str,
        document_provider: str | None,
        source_document: str,
    ) -> EvidenceRecord:
        name = _first_present(entry, _NAME_ALIASES)
        if not name:
            raise ReceiptSourceError(f"{context}: missing package name")
        raw_version = _first_present(entry, _VERSION_ALIASES)
        if raw_version is None:
            raise ReceiptSourceError(f"{context}: missing package version")
        try:
            version = str(Version(str(raw_version)))
        except InvalidVersion as exc:
            raise ReceiptSourceError(
                f"{context}: invalid version {raw_version!r}: {exc}"
            ) from exc

        filename = _first_present(entry, _FILE_ALIASES)
        digest = cls._extract_digest(entry)
        identity = ArtifactIdentity.create(
            str(filename) if filename is not None else None,
            digest,
        )
        provider = _first_present(entry, _PROVIDER_ALIASES) or document_provider
        if provider is None:
            provider = f"unknown-provider:{stage.value}"
        return EvidenceRecord(
            stage=stage,
            coordinate=PackageCoordinate(name=str(name), version=version),
            identity=identity,
            provided_by=str(provider),
            source_document=source_document,
        )

    @staticmethod
    def _extract_digest(entry: dict[str, Any]) -> str | None:
        raw = _first_present(entry, _DIGEST_FIELD_ALIASES)
        if isinstance(raw, dict):
            for algorithm in ("sha256", "sha512", "sha384", "sha224", "md5"):
                if raw.get(algorithm):
                    return str(raw[algorithm])
            nested = next(iter(raw.values()), None)
            return str(nested) if nested is not None else None
        if raw is not None:
            return str(raw)
        return None

    @staticmethod
    def _document_provider(payload: Any) -> str | None:
        if not isinstance(payload, dict):
            return None
        source = payload.get("source")
        if isinstance(source, dict):
            for key in ("provider", "provided_by", "name"):
                if source.get(key):
                    return str(source[key])
        return _first_present(payload, _PROVIDER_ALIASES)

    @staticmethod
    def _extract_entries(payload: Any, location: str) -> list[Any]:
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            raise ReceiptSourceError(
                f"{location}: top-level JSON must be an object or array"
            )
        for key in _ENTRY_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return value
        expected = ", ".join(_ENTRY_KEYS)
        raise ReceiptSourceError(
            f"{location}: no entries list found (expected one of {expected})"
        )

    def __len__(self) -> int:
        return len(self.records)

    def __repr__(self) -> str:
        return (
            f"ReceiptDocument(stage={self.stage!r}, "
            f"records={len(self.records)}, source_document={self.source_document!r})"
        )
