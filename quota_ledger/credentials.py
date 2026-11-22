# SPDX-License-Identifier: Apache-2.0

"""Signed release credentials carried in in-toto link metadata.

A credential reuses the standard in-toto :class:`Metablock` container with a
:class:`Link` payload. The business data lives in ``Link.byproducts`` and the
artifact digest the credential refers to lives in ``Link.products`` so that
the digest is covered by the same canonical-JSON signature as the rest of the
credential. No new signature code is introduced: signing and verification go
through ``Metablock.create_signature`` / ``verify_signature``.
"""

import json

from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.exceptions import SignatureVerificationError

from quota_ledger.exceptions import CredentialError
from quota_ledger.exceptions import DuplicateCredentialError
from quota_ledger.exceptions import SignatureError

ENTITLEMENT_TYPE = "entitlement"
HOLD_TYPE = "hold"
RELEASE_TYPE = "release"
REVOKE_TYPE = "revoke"

CREDENTIAL_TYPES = frozenset(
    [ENTITLEMENT_TYPE, HOLD_TYPE, RELEASE_TYPE, REVOKE_TYPE]
)

ARTIFACT_PATH = "release-artifact"
PAYLOAD_KEY = "quota-ledger"


def _default_byproducts():
    return {"stdout": "", "stderr": "", "return-value": 0}


class Credential:
    """A signed quota credential wrapped in in-toto link metadata.

    Attributes:
      credential_id: Stable identifier used for idempotent de-duplication.
      credential_type: One of the ``*_TYPE`` module constants.
      channel: Delivery channel this credential belongs to.
      artifact_sha256: SHA-256 digest of the shared build artifact.
      payload: Type-specific business data (e.g. quota amount).
      signer_keyid: Key id of the signing functionary (after verification).
    """

    def __init__(self, metadata, payload):
        self._metadata = metadata
        link = metadata.signed
        self.credential_id = payload["credential_id"]
        self.credential_type = payload["credential_type"]
        self.channel = payload["channel"]
        self.artifact_sha256 = link.products[ARTIFACT_PATH]["sha256"]
        self.payload = payload
        self.signer_keyid = None

    # -- constructors -----------------------------------------------------

    @classmethod
    def create(cls, signer, credential_type, credential_id, channel,
               artifact_sha256, payload=None):
        """Build and sign a credential with the supplied in-toto signer."""
        if credential_type not in CREDENTIAL_TYPES:
            raise CredentialError(f"unknown credential type {credential_type!r}")

        body = dict(payload or {})
        body.update(
            {
                "credential_id": credential_id,
                "credential_type": credential_type,
                "channel": channel,
            }
        )
        byproducts = _default_byproducts()
        byproducts[PAYLOAD_KEY] = body

        link = Link(
            name=f"quota-{credential_type}",
            materials={},
            products={ARTIFACT_PATH: {"sha256": artifact_sha256}},
            byproducts=byproducts,
            command=[],
            environment={},
        )
        metadata = Metablock(signed=link)
        metadata.create_signature(signer)
        return cls(metadata, body)

    @classmethod
    def load(cls, path):
        """Load a credential from a JSON metadata file on disk."""
        metadata = Metablock.load(path)
        payload = cls._extract_payload(metadata)
        return cls(metadata, payload)

    @classmethod
    def from_dict(cls, data):
        """Load a credential from its JSON/dict representation."""
        metadata = Metablock.from_dict(data)
        payload = cls._extract_payload(metadata)
        return cls(metadata, payload)

    @staticmethod
    def _extract_payload(metadata):
        link = metadata.signed
        if not isinstance(link, Link):
            raise CredentialError("credential payload must be an in-toto link")
        try:
            payload = link.byproducts[PAYLOAD_KEY]
        except (KeyError, TypeError) as exc:
            raise CredentialError("credential is missing quota payload") from exc

        for field in ("credential_id", "credential_type", "channel"):
            if field not in payload:
                raise CredentialError(f"credential payload missing {field!r}")
        if payload["credential_type"] not in CREDENTIAL_TYPES:
            raise CredentialError(
                f"unknown credential type {payload['credential_type']!r}"
            )
        if ARTIFACT_PATH not in link.products or "sha256" not in \
                link.products[ARTIFACT_PATH]:
            raise CredentialError("credential is missing artifact sha256")
        return payload

    # -- signing / serialization -----------------------------------------

    def verify_signature(self, authorized_keys):
        """Verify the credential signature against authorized channel keys.

        ``authorized_keys`` maps key ids to securesystemslib ``Key`` objects.
        The signer must be one of the authorized keys. The matching key id is
        recorded on the credential and returned.
        """
        signatures = {sig["keyid"]: sig for sig in self._metadata.signatures}
        normalized = {}
        for keyid, key in authorized_keys.items():
            normalized[keyid] = key.to_dict() if hasattr(key, "to_dict") else key
            normalized[keyid].setdefault("keyid", keyid)
        for keyid, key in normalized.items():
            if keyid not in signatures:
                continue
            try:
                self._metadata.verify_signature(key)
            except SignatureVerificationError as exc:
                raise SignatureError(
                    f"credential {self.credential_id!r} signature invalid"
                ) from exc
            self.signer_keyid = keyid
            return keyid
        raise SignatureError(
            f"credential {self.credential_id!r} was not signed by an "
            "authorized key"
        )

    def canonical_bytes(self):
        """Deterministic bytes used for idempotent duplicate detection."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def to_dict(self):
        return self._metadata.to_dict()

    def dump(self, path):
        self._metadata.dump(path)


def check_duplicate(seen, credential):
    """Reject a credential id reused with conflicting content.

    Exact re-imports are silently accepted (idempotent); a changed body with
    a known id raises :class:`DuplicateCredentialError`.
    """
    previous = seen.get(credential.credential_id)
    if previous is None:
        return False
    if previous != credential.canonical_bytes():
        raise DuplicateCredentialError(
            f"credential id {credential.credential_id!r} reused with "
            "different content"
        )
    return True
