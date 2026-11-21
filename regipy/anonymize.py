"""
Case-scoped anonymization export for regipy plugin results.

This module is the callable export gate for handing plugin output to external
parties. The caller declares, per field, how the data is sourced
(``AnonymizationPolicy``); anything not declared is dropped (default-deny).

Guarantees:

- Pseudonyms are deterministic HMAC tokens keyed by a per-case secret, so
  evidence correlates within one case but never across cases - two cases
  sharing the same username produce unrelated tokens and cannot be merged
  from the external results.
- The public export contains only one-way tokens; the reversible token ->
  original mapping is kept separately for internal review
  (``export_internal_mapping``) and is never part of the public output.
- Updating a case's anonymized material is done by re-instantiating with the
  same case secret (persisted in the internal mapping), which keeps existing
  tokens stable while leaving other cases untouched.
"""

import hashlib
import hmac
import json
import logging
import re
import secrets
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

logger = logging.getLogger(__name__)

#: Length (hex chars) of the truncated HMAC used for pseudonym tokens.
TOKEN_HEX_LENGTH = 24

_SECRET_BYTES = 32

_PATH_SEGMENT_SPLIT = re.compile(r"[\\/]")

_PLUGIN_ENTRIES = Union[list[dict[str, Any]], dict[str, Any]]


class FieldKind(str, Enum):
    """How the values of a declared field are sourced and must be handled."""

    #: Non-identifying data, passed through unchanged.
    KEEP = "keep"
    #: Identity inside a value (username, e-mail, SID, ...). Pseudonymized.
    IDENTITY = "identity"
    #: Object identifier derived by a plugin (GUID, hash, ...). Pseudonymized.
    OBJECT_ID = "object_id"
    #: Registry key path; segments matching a known identity are pseudonymized.
    KEY_PATH = "key_path"


_TOKEN_PREFIXES = {
    FieldKind.IDENTITY: "USR",
    FieldKind.OBJECT_ID: "OBJ",
}


class AnonymizationPolicy:
    """
    Caller-supplied declaration of field sources.

    :param fields: Mapping of field name -> FieldKind (or its string value).
        Fields not declared here are dropped from the output.
    """

    def __init__(self, fields: Mapping[str, Union[FieldKind, str]]):
        self._fields: dict[str, FieldKind] = {}
        for name, kind in fields.items():
            try:
                self._fields[name] = FieldKind(kind)
            except ValueError:
                raise ValueError(f"Unknown field kind for {name!r}: {kind!r}") from None

    def kind_for(self, field_name: str) -> Optional[FieldKind]:
        return self._fields.get(field_name)


class CaseAnonymizer:
    """
    Anonymizes plugin results for a single case.

    :param case_id: Identifier of the case; recorded in the internal mapping.
    :param policy: The field-source declaration to apply.
    :param secret: Per-case secret (hex string or bytes). Generated randomly
        when omitted. Persist it (it is stored in the internal mapping export)
        to keep tokens stable when updating the case's anonymized material.
    :param identity_aliases: Mapping of alias -> canonical identity. Aliases
        resolve to the same pseudonym as the canonical identity, so evidence
        of the same subject correlates under one token.
    """

    def __init__(
        self,
        case_id: str,
        policy: AnonymizationPolicy,
        secret: Union[str, bytes, None] = None,
        identity_aliases: Optional[Mapping[str, str]] = None,
    ):
        self.case_id = case_id
        self.policy = policy
        if secret is None:
            self._secret = secrets.token_bytes(_SECRET_BYTES)
        elif isinstance(secret, str):
            self._secret = bytes.fromhex(secret)
        else:
            self._secret = bytes(secret)

        self._aliases = {
            self._normalize(alias): self._normalize(canonical) for alias, canonical in (identity_aliases or {}).items()
        }
        # token -> {"kind": FieldKind, "value": original} - internal review only.
        self._mapping: dict[str, dict[str, str]] = {}
        # (kind, normalized value) -> token, for deterministic reuse.
        self._token_by_value: dict[tuple, str] = {}
        # normalized identity -> token, used to pseudonymize key path segments.
        self._known_identities: dict[str, str] = {}

    @property
    def secret(self) -> str:
        """The case secret as hex. Handle like a key: internal use only."""
        return self._secret.hex()

    @staticmethod
    def _normalize(value: str) -> str:
        return value.strip().casefold()

    def _canonicalize(self, normalized: str) -> str:
        return self._aliases.get(normalized, normalized)

    def _derive_token(self, kind: FieldKind, normalized_value: str) -> str:
        prefix = _TOKEN_PREFIXES[kind]
        digest = hmac.new(
            self._secret,
            f"{kind.value}\x00{normalized_value}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{prefix}-{digest[:TOKEN_HEX_LENGTH]}"

    def _pseudonymize(self, kind: FieldKind, value: str, original: str) -> str:
        normalized = self._canonicalize(self._normalize(value))
        key = (kind, normalized)
        token = self._token_by_value.get(key)
        if token is None:
            token = self._derive_token(kind, normalized)
            self._token_by_value[key] = token
        # Keep the first-seen original for a token; aliases share the token.
        self._mapping.setdefault(token, {"kind": kind.value, "value": original})
        if kind == FieldKind.IDENTITY:
            self._known_identities.setdefault(self._normalize(value), token)
        return token

    def register_identity(self, value: str) -> str:
        """
        Declare an identity known to appear in the case's evidence (e.g. inside
        key paths) even if no IDENTITY field carries it. Returns its token.
        """
        return self._pseudonymize(FieldKind.IDENTITY, value, value)

    def _anonymize_identity(self, value: Any) -> Optional[str]:
        if not isinstance(value, str):
            logger.warning("Dropping identity value of unexpected type: %r", type(value).__name__)
            return None
        if not value.strip():
            return value
        return self._pseudonymize(FieldKind.IDENTITY, value, value)

    def _anonymize_object_id(self, value: Any) -> Optional[str]:
        if not isinstance(value, str):
            logger.warning("Dropping object identifier of unexpected type: %r", type(value).__name__)
            return None
        if not value.strip():
            return value
        return self._pseudonymize(FieldKind.OBJECT_ID, value, value)

    def _anonymize_key_path(self, value: Any) -> Optional[str]:
        if not isinstance(value, str):
            logger.warning("Dropping key path of unexpected type: %r", type(value).__name__)
            return None
        segments = _PATH_SEGMENT_SPLIT.split(value)
        anonymized = [self._known_identities.get(self._normalize(segment), segment) for segment in segments]
        return "\\".join(anonymized)

    def _collect_identities(self, node: Any) -> None:
        """First pass: learn identities so key paths can be pseudonymized."""
        if isinstance(node, dict):
            for field_name, value in node.items():
                if self.policy.kind_for(field_name) == FieldKind.IDENTITY:
                    if isinstance(value, str) and value.strip():
                        self._pseudonymize(FieldKind.IDENTITY, value, value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and item.strip():
                                self._pseudonymize(FieldKind.IDENTITY, item, item)
                else:
                    self._collect_identities(value)
        elif isinstance(node, list):
            for item in node:
                self._collect_identities(item)

    def _transform_field_value(self, kind: FieldKind, value: Any) -> Any:
        if value is None:
            return None
        if kind == FieldKind.KEEP:
            return self._transform_node(value)
        if isinstance(value, list):
            transform = {
                FieldKind.IDENTITY: self._anonymize_identity,
                FieldKind.OBJECT_ID: self._anonymize_object_id,
                FieldKind.KEY_PATH: self._anonymize_key_path,
            }[kind]
            return [transform(item) for item in value]
        if kind == FieldKind.IDENTITY:
            return self._anonymize_identity(value)
        if kind == FieldKind.OBJECT_ID:
            return self._anonymize_object_id(value)
        return self._anonymize_key_path(value)

    def _transform_node(self, node: Any) -> Any:
        if isinstance(node, dict):
            result: dict[str, Any] = {}
            for field_name, value in node.items():
                kind = self.policy.kind_for(field_name)
                if kind is None:
                    # Default-deny: undeclared data is not exported.
                    logger.debug("Dropping undeclared field %r", field_name)
                    continue
                transformed = self._transform_field_value(kind, value)
                if transformed is None and value is not None:
                    # Declared but unprocessable: drop rather than leak.
                    continue
                result[field_name] = transformed
            return result
        if isinstance(node, list):
            return [self._transform_node(item) for item in node]
        return node

    def anonymize_entries(self, entries: _PLUGIN_ENTRIES) -> _PLUGIN_ENTRIES:
        """
        Anonymize plugin results for external disclosure.

        Accepts the shapes plugins produce (list of entry dicts, or a dict
        holding nested entry lists) and returns the same shape with declared
        fields pseudonymized and undeclared fields removed.
        """
        self._collect_identities(entries)
        return self._transform_node(entries)

    def export_public(self, entries: _PLUGIN_ENTRIES, output_path: Union[str, Path, None] = None) -> _PLUGIN_ENTRIES:
        """
        Anonymize and optionally write the public (non-reversible) export.

        The output contains only one-way pseudonym tokens; the real identities
        cannot be looked up from it.
        """
        anonymized = self.anonymize_entries(entries)
        if output_path is not None:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(anonymized, f, indent=2, ensure_ascii=False)
        return anonymized

    def export_internal_mapping(self, output_path: Union[str, Path]) -> dict[str, Any]:
        """
        Export the reversible token -> original mapping for internal review.

        This file (which includes the case secret, so the case's material can
        be updated later with stable tokens) is what lets reviewers go back to
        the originals. It must never leave the case file.
        """
        mapping = {
            "case_id": self.case_id,
            "secret": self.secret,
            "tokens": [
                {"token": token, "kind": record["kind"], "value": record["value"]}
                for token, record in sorted(self._mapping.items())
            ],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2, ensure_ascii=False)
        return mapping

    @classmethod
    def from_internal_mapping(
        cls,
        mapping_path: Union[str, Path],
        policy: AnonymizationPolicy,
        identity_aliases: Optional[Mapping[str, str]] = None,
    ) -> "CaseAnonymizer":
        """
        Resume a case from its internal mapping export, e.g. to update the
        case's anonymized material with stable tokens.
        """
        with open(mapping_path, encoding="utf-8") as f:
            mapping = json.load(f)
        anonymizer = cls(
            case_id=mapping["case_id"],
            policy=policy,
            secret=mapping["secret"],
            identity_aliases=identity_aliases,
        )
        for record in mapping.get("tokens", []):
            kind = FieldKind(record["kind"])
            if kind in _TOKEN_PREFIXES:
                anonymizer._pseudonymize(kind, record["value"], record["value"])
        return anonymizer
