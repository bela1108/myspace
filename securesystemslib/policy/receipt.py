"""Signed material receipts that remain readable without verification power.

A receipt records *what* was signed, *which key and scheme* signed it, and
*for what material purpose*. Parsing a receipt never requires a verifier
backend or even a locally registered key implementation: receipts created
with algorithms that the current environment cannot verify are represented
by an :class:`UnsupportedKey` placeholder so that auditors can still inspect
every field and policy checks can attribute the gap correctly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from securesystemslib.exceptions import FormatError
from securesystemslib.policy.policy import MaterialPurpose
from securesystemslib.policy.verifier import VerifierCapabilityError
from securesystemslib.signer import Key, Signature

RECEIPT_SCHEMA_VERSION = "1"


class ReceiptParseError(FormatError):
    """A receipt envelope is malformed and cannot be interpreted at all."""


class UnsupportedKey(Key):
    """Placeholder for a key whose scheme the local environment cannot verify.

    The original key dictionary is preserved verbatim, so the receipt stays
    fully readable and serializable. Attempting actual verification raises a
    capability error rather than pretending the signature is invalid.
    """

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: dict[str, Any],
        unrecognized_fields: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(keyid, keytype, scheme, keyval, unrecognized_fields)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> UnsupportedKey:
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict[str, Any]:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        raise VerifierCapabilityError(
            f"no verifier registered for scheme {self.scheme!r} "
            f"(keytype {self.keytype!r})"
        )


@dataclass
class Receipt:
    """A signed material receipt.

    Args:
        purpose: Whether the material is new or under historical review.
        payload: Raw signed bytes.
        key: Public key claimed by the receipt. May be an
            :class:`UnsupportedKey` when the scheme is not verifiable here.
        signature: Signature container.
        schema_version: Receipt envelope version.
        unrecognized_fields: Forward-compatible extra envelope fields.
    """

    purpose: MaterialPurpose
    payload: bytes
    key: Key
    signature: Signature
    schema_version: str = RECEIPT_SCHEMA_VERSION
    unrecognized_fields: dict[str, Any] = field(default_factory=dict)

    @property
    def scheme(self) -> str:
        """Signature scheme claimed by the receipt's key."""
        return self.key.scheme

    @property
    def verifiable_in_environment(self) -> bool:
        """Whether the current environment knows a verifier for the scheme."""
        return not isinstance(self.key, UnsupportedKey)

    @classmethod
    def from_dict(cls, receipt_dict: dict[str, Any]) -> Receipt:
        """Parse a receipt dictionary without requiring any backend.

        Unknown schemes degrade to :class:`UnsupportedKey`; malformed
        envelopes raise :class:`ReceiptParseError`.
        """
        if not isinstance(receipt_dict, dict):
            raise ReceiptParseError("receipt must be a dictionary")

        data = dict(receipt_dict)
        try:
            purpose_value = data.pop("purpose")
            payload_hex = data.pop("payload")
            key_dict = data.pop("key")
            signature_dict = data.pop("signature")
        except KeyError as error:
            raise ReceiptParseError(
                f"receipt is missing required field {error.args[0]!r}"
            ) from error

        try:
            purpose = MaterialPurpose(purpose_value)
        except ValueError as error:
            raise ReceiptParseError(
                f"unknown material purpose {purpose_value!r}"
            ) from error

        if not isinstance(payload_hex, str):
            raise ReceiptParseError("payload must be a hex string")
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError as error:
            raise ReceiptParseError("payload is not valid hex") from error

        if not isinstance(key_dict, dict):
            raise ReceiptParseError("key must be a dictionary")
        if not isinstance(signature_dict, dict):
            raise ReceiptParseError("signature must be a dictionary")

        signature = Signature.from_dict(dict(signature_dict))
        key = cls._parse_key(signature.keyid, key_dict)

        schema_version = data.pop("schema_version", RECEIPT_SCHEMA_VERSION)
        if not isinstance(schema_version, str):
            raise ReceiptParseError("schema_version must be a string")

        return cls(
            purpose=purpose,
            payload=payload,
            key=key,
            signature=signature,
            schema_version=schema_version,
            unrecognized_fields=data,
        )

    @staticmethod
    def _parse_key(keyid: str, key_dict: dict[str, Any]) -> Key:
        try:
            return Key.from_dict(keyid, dict(key_dict))
        except (KeyError, TypeError, ValueError):
            # The scheme is not registered in this environment (for example an
            # optional dependency is missing): keep the raw key so historical
            # receipts stay readable.
            return UnsupportedKey.from_dict(keyid, dict(key_dict))

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable dictionary representation."""
        return {
            "schema_version": self.schema_version,
            "purpose": self.purpose.value,
            "payload": self.payload.hex(),
            "key": self.key.to_dict(),
            "signature": self.signature.to_dict(),
            **self.unrecognized_fields,
        }


def make_receipt(
    purpose: MaterialPurpose,
    payload: bytes,
    key: Key,
    signature: Signature,
) -> Receipt:
    """Convenience constructor for producing a receipt after signing."""
    return Receipt(
        purpose=purpose,
        payload=payload,
        key=key,
        signature=signature,
    )
