# vim: set et ai ts=4 sts=4 sw=4:
"""Selective disclosure proofs for JKS snapshots.

The public half of a proof is limited to approved certificate identities and
archive-bound commitments. The internal half is a complete manifest of the
parsed entries, including duplicate certificate occurrences and entries that
could not be interpreted. It never relies on the mutable state of a loaded
``KeyStore``; the snapshot digest is always taken over the exact input bytes.
"""

from __future__ import print_function

import base64
import binascii
import hashlib
import json
import os
import struct

from .util import (
    AbstractKeystore,
    BadKeystoreFormatException,
    DisclosureProofException,
    KeystoreException,
    UnknownDisclosureScopeException,
    UnsupportedKeystoreVersionException,
    b2,
    b4,
    b8,
)


DISCLOSURE_FORMAT = "pyjks-disclosure-v1"
_COMMITMENT_DOMAIN = b"pyjks-jks-disclosure-v1\x00"
_HEX_DIGITS = frozenset("0123456789abcdef")


class _Record(dict):
    """A JSON-serializable record that also supports attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def to_dict(self):
        return _json_clone(self)

    def to_json(self, **kwargs):
        if "sort_keys" not in kwargs:
            kwargs["sort_keys"] = True
        return json.dumps(self, **kwargs)


class PublicDisclosureBundle(_Record):
    """The portion of a proof that may be shown to an external verifier."""

    pass


class InternalAuditAttachment(_Record):
    """The complete snapshot manifest retained by the archive custodian."""

    pass


class DisclosureProof(object):
    """A public bundle paired with its internal audit attachment."""

    def __init__(self, public_bundle, internal_attachment):
        self.public_bundle = public_bundle
        self.internal_attachment = internal_attachment

    @property
    def external_bundle(self):
        return self.public_bundle

    @property
    def internal_manifest(self):
        return self.internal_attachment

    @property
    def public(self):
        return self.public_bundle

    @property
    def internal(self):
        return self.internal_attachment

    def __getitem__(self, key):
        aliases = {
            "public": self.public_bundle,
            "external": self.public_bundle,
            "public_bundle": self.public_bundle,
            "external_bundle": self.public_bundle,
            "internal": self.internal_attachment,
            "internal_attachment": self.internal_attachment,
            "internal_manifest": self.internal_attachment,
        }
        try:
            return aliases[key]
        except KeyError:
            raise KeyError(key)

    def to_dict(self):
        return {
            "public_bundle": _json_clone(self.public_bundle),
            "internal_attachment": _json_clone(self.internal_attachment),
        }

    def to_json(self, **kwargs):
        if "sort_keys" not in kwargs:
            kwargs["sort_keys"] = True
        return json.dumps(self.to_dict(), **kwargs)

    def verify(self, source_data=None):
        return verify_disclosure_proof(
            self.public_bundle,
            self.internal_attachment,
            source_data=source_data,
        )

    @classmethod
    def from_bytes(cls, data, scope, store_password=None):
        """Build a proof directly from exact JKS bytes.

        Parsing is intentionally tolerant after the store header: a malformed
        or unsupported entry is retained as an unreadable manifest entry rather
        than being omitted from the audit attachment.
        """
        data = _as_bytes(data, "snapshot")
        entries, scan_info = _scan_snapshot(data)
        if store_password is not None:
            from .jks import KeyStore

            store = KeyStore.loads(
                data, store_password, try_decrypt_keys=False
            )
            return cls.from_keystore(store, data, scope)
        return _build_proof(data, entries, scan_info, scope)

    @classmethod
    def from_file(cls, filename, scope, store_password=None):
        with open(filename, "rb") as source_file:
            data = source_file.read()
        return cls.from_bytes(data, scope, store_password=store_password)

    create = from_bytes

    @classmethod
    def from_keystore(cls, store, source_data=None, scope=None):
        """Build a proof only if ``source_data`` matches the loaded entries."""
        if scope is None:
            scope = source_data
            source_data = getattr(store, "_source_bytes", None)
        if source_data is None:
            raise DisclosureProofException(
                "This keystore has no source bytes; load it through KeyStore.load or loads"
            )
        data = _as_bytes(source_data, "snapshot")
        entries, scan_info = _scan_snapshot(data)

        store_entries = [
            _loaded_entry_signature(alias, entry)
            for alias, entry in store.entries.items()
        ]
        snapshot_entries = [
            _snapshot_entry_signature(entry)
            for entry in entries
            if entry.get("readable")
        ]
        if store_entries != snapshot_entries:
            raise DisclosureProofException(
                "The loaded keystore entries do not match the supplied snapshot bytes"
            )

        return _build_proof(data, entries, scan_info, scope)


def certificate_identity(certificate):
    """Return the stable SHA-256 identity of a DER certificate."""
    return hashlib.sha256(_as_bytes(certificate, "certificate")).hexdigest()


def _loaded_entry_signature(alias, entry):
    entry_type = type(entry).__name__
    certificates = []
    if entry_type in ("TrustedCertEntry", "BksTrustedCertEntry"):
        kind = "trusted_cert"
        certificates.append(entry.cert)
    elif entry_type == "PrivateKeyEntry":
        kind = "private_key"
        certificates.extend(certificate[1] for certificate in entry.cert_chain)
    elif entry_type == "SecretKeyEntry":
        kind = "secret_key"
    else:
        kind = "unknown"
    return (
        alias,
        kind,
        entry.timestamp,
        tuple(certificate_identity(cert) for cert in certificates),
    )


def _snapshot_entry_signature(entry):
    return (
        entry.get("alias"),
        entry.get("kind"),
        entry.get("timestamp"),
        tuple(
            certificate["identity"]
            for certificate in entry.get("certificates", [])
        ),
    )


def snapshot_digest(data):
    """Return the SHA-256 digest of the exact snapshot bytes."""
    return hashlib.sha256(_as_bytes(data, "snapshot")).hexdigest()


def snapshot_manifest(data):
    """Return the complete internal manifest for a snapshot without openings."""
    data = _as_bytes(data, "snapshot")
    entries, scan_info = _scan_snapshot(data)
    return _internal_attachment(data, entries, scan_info, [])


def create_disclosure_proof(source, scope, store_password=None):
    """Create a disclosure proof from bytes, a path, or a loaded ``KeyStore``.

    ``scope`` accepts aliases, SHA-256 certificate identity strings, raw DER
    certificate bytes, or objects with a ``cert`` attribute. Selecting any
    identity includes every occurrence of that exact certificate in the
    archive, including duplicates under other aliases and certificate-chain
    slots.
    """
    if isinstance(source, AbstractKeystore):
        source_data = getattr(source, "_source_bytes", None)
        if source_data is None:
            raise DisclosureProofException(
                "This keystore has no source bytes; load it through KeyStore.load or loads"
            )
        return DisclosureProof.from_keystore(source, source_data, scope)

    if isinstance(source, (bytes, bytearray)):
        data = source
    elif hasattr(source, "read"):
        data = source.read()
    else:
        path = os.fspath(source)
        with open(path, "rb") as source_file:
            data = source_file.read()

    if store_password is not None:
        from .jks import KeyStore

        store = KeyStore.loads(data, store_password, try_decrypt_keys=False)
        return DisclosureProof.from_keystore(store, data, scope)

    return DisclosureProof.from_bytes(data, scope)


def load_disclosure_proof(filename, store_password, scope):
    """Read and prove a JKS file without decrypting any private key entry."""
    with open(filename, "rb") as source_file:
        data = source_file.read()
    return DisclosureProof.from_bytes(data, scope, store_password=store_password)


def verify_disclosure_proof(public_bundle, internal_attachment=None, source_data=None):
    """Verify a public bundle, optionally against its attachment and snapshot."""
    if isinstance(public_bundle, DisclosureProof):
        proof = public_bundle
        public_bundle = proof.public_bundle
        if internal_attachment is None:
            internal_attachment = proof.internal_attachment

    if (
        internal_attachment is not None
        and not isinstance(internal_attachment, dict)
        and source_data is None
    ):
        source_data = internal_attachment
        internal_attachment = None

    if not _verify_public_bundle(public_bundle):
        return False

    try:
        if internal_attachment is None:
            if source_data is None:
                return True
            return _verify_public_against_source(public_bundle, source_data)

        return _verify_internal_attachment(
            internal_attachment,
            public_bundle=public_bundle,
            source_data=source_data,
        )
    except (TypeError, ValueError, KeystoreException):
        return False


def verify_public_bundle(public_bundle):
    """Verify only the self-contained, public portion of a proof."""
    return _verify_public_bundle(public_bundle)


def verify_internal_attachment(internal_attachment, source_data=None):
    """Verify an internal manifest, optionally by reparsing the snapshot."""
    try:
        return _verify_internal_attachment(
            internal_attachment,
            source_data=source_data,
        )
    except (TypeError, ValueError, KeystoreException):
        return False


def _build_proof(data, entries, scan_info, scope):
    digest = hashlib.sha256(data).hexdigest()
    approved_ids = _resolve_scope(entries, scope)

    certificate_records = []
    openings = []
    occurrence_counts = dict((identity, 0) for identity in approved_ids)

    for entry in entries:
        for certificate in entry.get("certificates", []):
            identity = certificate["identity"]
            if identity not in approved_ids:
                continue

            occurrence_counts[identity] += 1
            commitment = _make_commitment(
                digest,
                entry["position"],
                entry["offset"],
                entry["kind"],
                certificate["slot"],
                entry["entry_digest"],
                identity,
            )
            certificate_records.append({
                "identity": identity,
                "sha256": identity,
                "fingerprint": identity,
                "commitment": commitment,
            })
            openings.append({
                "identity": identity,
                "commitment": commitment,
                "entry_position": entry["position"],
                "entry_offset": entry["offset"],
                "entry_digest": entry["entry_digest"],
                "entry_kind": entry["kind"],
                "certificate_slot": certificate["slot"],
            })

    public_bundle = PublicDisclosureBundle({
        "format": DISCLOSURE_FORMAT,
        "snapshot_digest_algorithm": "sha256",
        "snapshot_digest": digest,
        "scope": sorted(approved_ids),
        "certificate_count": len(certificate_records),
        "occurrence_counts": occurrence_counts,
        "certificates": certificate_records,
        "commitments": [record["commitment"] for record in certificate_records],
    })
    internal_attachment = _internal_attachment(data, entries, scan_info, openings)
    return DisclosureProof(public_bundle, internal_attachment)


def _internal_attachment(data, entries, scan_info, openings):
    return InternalAuditAttachment({
        "format": DISCLOSURE_FORMAT,
        "snapshot_digest_algorithm": "sha256",
        "snapshot_digest": hashlib.sha256(data).hexdigest(),
        "snapshot_size": len(data),
        "store_type": scan_info["store_type"],
        "version": scan_info["version"],
        "declared_entry_count": scan_info["declared_entry_count"],
        "entry_count": len(entries),
        "unparsed_entry_count": max(
            0, scan_info["declared_entry_count"] - len(entries)
        ),
        "unreadable_entry_count": sum(
            1 for entry in entries if not entry.get("readable")
        ),
        "complete": len(entries) == scan_info["declared_entry_count"],
        "entries": entries,
        "certificate_count": sum(
            len(entry.get("certificates", [])) for entry in entries
        ),
        "openings": openings,
    })


def _resolve_scope(entries, scope):
    selectors = _scope_selectors(scope)
    identities = set()
    aliases = {}

    for entry in entries:
        entry_identities = [
            cert["identity"] for cert in entry.get("certificates", [])
        ]
        if entry.get("alias") is not None:
            aliases[entry["alias"]] = entry_identities

    for selector in selectors:
        identity = _identity_selector(selector)
        if identity is not None:
            if not _identity_present(entries, identity):
                raise UnknownDisclosureScopeException(
                    "Certificate identity is not present in the snapshot: %s" % selector
                )
            identities.add(identity)
            continue

        if not isinstance(selector, str):
            raise UnknownDisclosureScopeException(
                "Unsupported disclosure scope selector: %r" % (selector,)
            )
        if selector not in aliases:
            raise UnknownDisclosureScopeException(
                "Alias is not present in the snapshot: %s" % selector
            )
        if not aliases[selector]:
            raise UnknownDisclosureScopeException(
                "Alias does not contain a certificate: %s" % selector
            )
        identities.update(aliases[selector])

    if not identities:
        raise UnknownDisclosureScopeException(
            "The disclosure scope must select at least one certificate"
        )
    return identities


def _scope_selectors(scope):
    if scope is None:
        raise UnknownDisclosureScopeException("A disclosure scope is required")
    if isinstance(scope, (str, bytes, bytearray)):
        return [scope]
    if hasattr(scope, "cert") and not hasattr(scope, "__iter__"):
        return [scope]
    try:
        selectors = list(scope)
    except TypeError:
        raise UnknownDisclosureScopeException(
            "Unsupported disclosure scope: %r" % (scope,)
        )
    if not selectors:
        raise UnknownDisclosureScopeException(
            "The disclosure scope must select at least one certificate"
        )
    return selectors


def _identity_selector(selector):
    if isinstance(selector, (bytes, bytearray)):
        if len(selector) == 32:
            return binascii.hexlify(bytes(selector)).decode("ascii")
        try:
            text = bytes(selector).decode("ascii").lower()
            if _is_sha256_hex(text):
                return text
            if text.startswith("sha256:") and _is_sha256_hex(text[7:]):
                return text[7:]
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
        return certificate_identity(selector)
    if hasattr(selector, "cert") and not isinstance(selector, str):
        return certificate_identity(selector.cert)
    if not isinstance(selector, str):
        return None

    candidate = selector.lower()
    if candidate.startswith("sha256:") or candidate.startswith("sha256="):
        candidate = candidate[7:]
    if _is_sha256_hex(candidate):
        return candidate
    if candidate.startswith("base64:"):
        try:
            der = base64.b64decode(selector[7:].encode("ascii"))
        except (TypeError, ValueError, binascii.Error):
            return None
        return certificate_identity(der)
    return None


def _identity_present(entries, identity):
    for entry in entries:
        for certificate in entry.get("certificates", []):
            if certificate["identity"] == identity:
                return True
    return False


def _make_commitment(
    digest, entry_position, entry_offset, entry_kind, certificate_slot,
    entry_digest, identity,
):
    kind_tag = {
        "private_key": 1,
        "trusted_cert": 2,
        "secret_key": 3,
    }.get(entry_kind, 0)
    commitment = hashlib.sha256()
    commitment.update(_COMMITMENT_DOMAIN)
    commitment.update(binascii.unhexlify(digest))
    commitment.update(b8.pack(entry_position))
    commitment.update(b8.pack(entry_offset))
    commitment.update(b4.pack(kind_tag))
    commitment.update(b4.pack(certificate_slot))
    commitment.update(binascii.unhexlify(entry_digest))
    commitment.update(binascii.unhexlify(identity))
    return commitment.hexdigest()


def _verify_public_bundle(public_bundle):
    if not isinstance(public_bundle, dict):
        return False
    if public_bundle.get("format") != DISCLOSURE_FORMAT:
        return False
    digest = public_bundle.get("snapshot_digest")
    if not _is_sha256_hex(digest):
        return False
    if public_bundle.get("snapshot_digest_algorithm") != "sha256":
        return False

    certificates = public_bundle.get("certificates")
    scope = public_bundle.get("scope")
    if not isinstance(certificates, list) or not isinstance(scope, list):
        return False
    if not certificates or not scope:
        return False
    if public_bundle.get("certificate_count") != len(certificates):
        return False

    scope_ids = set()
    for identity in scope:
        if not _is_sha256_hex(identity) or identity in scope_ids:
            return False
        scope_ids.add(identity)

    record_ids = set()
    commitments = []
    for record in certificates:
        if not isinstance(record, dict):
            return False
        identity = record.get("identity")
        commitment = record.get("commitment")
        if not _is_sha256_hex(identity) or not _is_sha256_hex(commitment):
            return False
        if identity not in scope_ids:
            return False
        if record.get("sha256") not in (None, identity):
            return False
        if record.get("fingerprint") not in (None, identity):
            return False
        record_ids.add(identity)
        commitments.append(commitment)

    if record_ids != scope_ids:
        return False
    if len(commitments) != len(set(commitments)):
        return False
    if public_bundle.get("commitments") not in (None, commitments):
        return False

    counts = public_bundle.get("occurrence_counts")
    expected_counts = dict((identity, 0) for identity in scope_ids)
    for identity in [record["identity"] for record in certificates]:
        expected_counts[identity] += 1
    if counts not in (None, expected_counts):
        return False
    return True


def _verify_internal_attachment(
    internal_attachment, public_bundle=None, source_data=None,
):
    if not isinstance(internal_attachment, dict):
        return False
    if internal_attachment.get("format") != DISCLOSURE_FORMAT:
        return False
    digest = internal_attachment.get("snapshot_digest")
    if not _is_sha256_hex(digest):
        return False
    if internal_attachment.get("snapshot_digest_algorithm") != "sha256":
        return False

    entries = internal_attachment.get("entries")
    if not isinstance(entries, list):
        return False
    if internal_attachment.get("entry_count") != len(entries):
        return False
    if internal_attachment.get("snapshot_size") is not None:
        if not isinstance(internal_attachment["snapshot_size"], int):
            return False
        if internal_attachment["snapshot_size"] < 0:
            return False
    if internal_attachment.get("declared_entry_count") is not None:
        if not isinstance(internal_attachment["declared_entry_count"], int):
            return False
        if internal_attachment["declared_entry_count"] < 0:
            return False
    if internal_attachment.get("unparsed_entry_count") is not None:
        expected_unparsed = max(
            0,
            (internal_attachment.get("declared_entry_count") or 0)
            - len(entries),
        )
        if internal_attachment["unparsed_entry_count"] != expected_unparsed:
            return False
    certificate_count = 0
    unreadable_entry_count = 0
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return False
        if entry.get("position") != position:
            return False
        if not isinstance(entry.get("offset"), int) or entry["offset"] < 0:
            return False
        if not _is_sha256_hex(entry.get("entry_digest")):
            return False
        if not isinstance(entry.get("readable"), bool):
            return False
        if not entry["readable"]:
            unreadable_entry_count += 1
        certificates = entry.get("certificates")
        if not isinstance(certificates, list):
            return False
        certificate_count += len(certificates)
        slots = set()
        for certificate in certificates:
            if not isinstance(certificate, dict):
                return False
            slot = certificate.get("slot")
            if not isinstance(slot, int) or slot < 0 or slot in slots:
                return False
            if not _is_sha256_hex(certificate.get("identity")):
                return False
            slots.add(slot)
    if internal_attachment.get("certificate_count") not in (None, certificate_count):
        return False
    if internal_attachment.get("unreadable_entry_count") not in (
        None, unreadable_entry_count,
    ):
        return False

    if public_bundle is not None:
        if not _verify_public_bundle(public_bundle):
            return False
        if public_bundle.get("snapshot_digest") != digest:
            return False
        if not _verify_openings(public_bundle, internal_attachment):
            return False
    elif not _verify_openings(None, internal_attachment):
        return False

    if source_data is not None:
        source_data = _as_bytes(source_data, "snapshot")
        if hashlib.sha256(source_data).hexdigest() != digest:
            return False
        scanned_entries, scan_info = _scan_snapshot(source_data)
        if internal_attachment.get("snapshot_size") != len(source_data):
            return False
        if internal_attachment.get("store_type") != scan_info["store_type"]:
            return False
        if internal_attachment.get("version") != scan_info["version"]:
            return False
        if internal_attachment.get("declared_entry_count") != scan_info["declared_entry_count"]:
            return False
        if entries != scanned_entries:
            return False

    return True


def _verify_openings(public_bundle, internal_attachment):
    entries = internal_attachment["entries"]
    openings = internal_attachment.get("openings")
    if not isinstance(openings, list):
        return False

    all_occurrences = {}
    for entry in entries:
        for certificate in entry["certificates"]:
            key = (entry["position"], certificate["slot"])
            all_occurrences[key] = certificate["identity"]

    approved_ids = None
    if public_bundle is not None:
        approved_ids = set(public_bundle["scope"])
    seen_occurrences = set()
    derived_records = []
    for opening in openings:
        if not isinstance(opening, dict):
            return False
        identity = opening.get("identity")
        commitment = opening.get("commitment")
        position = opening.get("entry_position")
        slot = opening.get("certificate_slot")
        if not _is_sha256_hex(identity) or not _is_sha256_hex(commitment):
            return False
        if not isinstance(position, int) or not isinstance(slot, int):
            return False
        if position < 0 or position >= len(entries) or slot < 0:
            return False
        if approved_ids is not None and identity not in approved_ids:
            return False

        entry = entries[position]
        occurrence_key = (position, slot)
        if occurrence_key in seen_occurrences:
            return False
        seen_occurrences.add(occurrence_key)
        if all_occurrences.get(occurrence_key) != identity:
            return False
        if opening.get("entry_offset") != entry.get("offset"):
            return False
        if opening.get("entry_digest") != entry.get("entry_digest"):
            return False
        if opening.get("entry_kind") != entry.get("kind"):
            return False

        expected_commitment = _make_commitment(
            internal_attachment["snapshot_digest"],
            position,
            entry["offset"],
            entry["kind"],
            slot,
            entry["entry_digest"],
            identity,
        )
        if commitment != expected_commitment:
            return False
        derived_records.append({
            "identity": identity,
            "sha256": identity,
            "fingerprint": identity,
            "commitment": commitment,
        })

    if public_bundle is None:
        return True

    public_records = public_bundle["certificates"]
    if public_records != derived_records:
        return False
    expected_occurrences = set(
        key for key, identity in all_occurrences.items()
        if identity in approved_ids
    )
    if seen_occurrences != expected_occurrences:
        return False
    expected_counts = dict((identity, 0) for identity in approved_ids)
    for identity in all_occurrences.values():
        if identity in approved_ids:
            expected_counts[identity] += 1
    if public_bundle.get("occurrence_counts") not in (None, expected_counts):
        return False
    return True


def _verify_public_against_source(public_bundle, source_data):
    source_data = _as_bytes(source_data, "snapshot")
    if hashlib.sha256(source_data).hexdigest() != public_bundle["snapshot_digest"]:
        return False
    entries, _ = _scan_snapshot(source_data)

    expected_records = []
    scope_ids = set(public_bundle["scope"])
    for entry in entries:
        for certificate in entry.get("certificates", []):
            identity = certificate["identity"]
            if identity not in scope_ids:
                continue
            expected_records.append({
                "identity": identity,
                "sha256": identity,
                "fingerprint": identity,
                "commitment": _make_commitment(
                    public_bundle["snapshot_digest"],
                    entry["position"],
                    entry["offset"],
                    entry["kind"],
                    certificate["slot"],
                    entry["entry_digest"],
                    identity,
                ),
            })
    return public_bundle["certificates"] == expected_records


def _scan_snapshot(data):
    if len(data) < 12:
        raise BadKeystoreFormatException("Insufficient keystore header bytes")

    magic = data[:4]
    if magic == b"\xfe\xed\xfe\xed":
        store_type = "jks"
    elif magic == b"\xce\xce\xce\xce":
        store_type = "jceks"
    else:
        raise BadKeystoreFormatException(
            "Not a JKS or JCEKS keystore"
        )

    version = _unpack(b4, data, 4, "keystore version")
    if version != 2:
        raise UnsupportedKeystoreVersionException(
            "Unsupported keystore version; expected v2, found v%r" % version
        )
    declared_entry_count = _unpack(b4, data, 8, "entry count")

    entries = []
    pos = 12
    for position in range(declared_entry_count):
        start = pos
        try:
            tag = _unpack(b4, data, pos, "entry tag")
            pos += 4
            alias, pos = _read_utf_strict(data, pos, "entry alias")
            timestamp = _unpack(b8, data, pos, "entry timestamp")
            pos += 8

            if tag == 1:
                _key_blob, pos = _read_data_strict(data, pos, "private key data")
                chain_len = _unpack(b4, data, pos, "certificate chain length")
                pos += 4
                certificates = []
                for slot in range(chain_len):
                    cert_type, pos = _read_utf_strict(
                        data, pos, "certificate type"
                    )
                    cert_data, pos = _read_data_strict(
                        data, pos, "certificate data"
                    )
                    certificates.append(_certificate_record(
                        slot, cert_type, cert_data
                    ))
                kind = "private_key"
            elif tag == 2:
                cert_type, pos = _read_utf_strict(data, pos, "certificate type")
                cert_data, pos = _read_data_strict(data, pos, "certificate data")
                certificates = [_certificate_record(0, cert_type, cert_data)]
                kind = "trusted_cert"
            elif tag == 3 and store_type == "jceks":
                from .jks import KeyStore

                _sealed, pos = KeyStore._read_java_obj(
                    data, pos, ignore_remaining_data=True
                )
                certificates = []
                kind = "secret_key"
            else:
                raise BadKeystoreFormatException(
                    "Unsupported keystore entry tag %d" % tag
                )

            entries.append({
                "position": position,
                "entry_index": position,
                "offset": start,
                "entry_offset": start,
                "end_offset": pos,
                "kind": kind,
                "readable": True,
                "alias": alias,
                "timestamp": timestamp,
                "entry_digest": hashlib.sha256(data[start:pos]).hexdigest(),
                "certificates": certificates,
            })
        except Exception as error:
            alias = None
            tag = None
            timestamp = None
            try:
                if start + 4 <= len(data):
                    tag = b4.unpack_from(data, start)[0]
                alias, _ = _read_utf_strict(data, start + 4, "entry alias")
                timestamp = b8.unpack_from(data, start + 12)[0]
            except Exception:
                pass
            entries.append({
                "position": position,
                "entry_index": position,
                "offset": start,
                "entry_offset": start,
                "end_offset": None,
                "kind": "unreadable",
                "readable": False,
                "alias": alias,
                "timestamp": timestamp,
                "tag": tag,
                "error": str(error),
                "entry_digest": hashlib.sha256(data[start:]).hexdigest(),
                "certificates": [],
            })
            break

    return entries, {
        "store_type": store_type,
        "version": version,
        "declared_entry_count": declared_entry_count,
    }


def _certificate_record(slot, cert_type, cert_data):
    return {
        "slot": slot,
        "type": cert_type,
        "identity": certificate_identity(cert_data),
    }


def _read_utf_strict(data, pos, kind):
    size = _unpack(b2, data, pos, kind + " length")
    pos += 2
    end = pos + size
    if end > len(data):
        raise BadKeystoreFormatException("Truncated %s" % kind)
    try:
        return data[pos:end].decode("utf-8"), end
    except (UnicodeDecodeError, UnicodeEncodeError) as error:
        raise BadKeystoreFormatException("Failed to read %s: %s" % (kind, error))


def _read_data_strict(data, pos, kind):
    size = _unpack(b4, data, pos, kind + " length")
    pos += 4
    end = pos + size
    if end > len(data):
        raise BadKeystoreFormatException("Truncated %s" % kind)
    return data[pos:end], end


def _unpack(unpacker, data, pos, kind):
    try:
        return unpacker.unpack_from(data, pos)[0]
    except struct.error:
        raise BadKeystoreFormatException("Truncated %s" % kind)


def _is_sha256_hex(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in _HEX_DIGITS for character in value)


def _as_bytes(value, label):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    raise TypeError("%s must be a byte string" % label)


def _json_clone(value):
    return json.loads(json.dumps(value, sort_keys=True))


__all__ = [
    "DISCLOSURE_FORMAT",
    "DisclosureProof",
    "InternalAttachment",
    "InternalAuditAttachment",
    "JksDisclosureProof",
    "PublicBundle",
    "PublicDisclosureBundle",
    "SelectiveDisclosureProof",
    "certificate_identity",
    "create_disclosure_proof",
    "generate_disclosure_proof",
    "load_disclosure_proof",
    "make_disclosure_proof",
    "prove_disclosure",
    "verify_proof",
    "snapshot_digest",
    "snapshot_manifest",
    "verify_disclosure_proof",
    "verify_internal_attachment",
    "verify_public_bundle",
]


# Common spellings used by callers that treat the proof as a generated artifact.
generate_disclosure_proof = create_disclosure_proof
make_disclosure_proof = create_disclosure_proof
prove_disclosure = create_disclosure_proof
verify_proof = verify_disclosure_proof

PublicBundle = PublicDisclosureBundle
InternalAttachment = InternalAuditAttachment
SelectiveDisclosureProof = DisclosureProof
JksDisclosureProof = DisclosureProof
