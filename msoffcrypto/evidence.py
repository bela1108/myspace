"""Offline format evidence for encrypted Microsoft Office containers.

The reader in this module deliberately stays on the protection wrapper.  It
reads the OLE directory, the ``EncryptionInfo`` stream, and the format-specific
encryption headers, but it never loads a password, decrypts an ``EncryptedPackage``
or ``Workbook`` payload, or evaluates a macro.  The resulting evidence is stable
enough to be used as a receipt in an offline verification plan.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import zipfile
from collections import namedtuple
from dataclasses import dataclass, field
from pathlib import Path
from struct import unpack
from typing import Any, BinaryIO, ClassVar, Mapping
from xml.dom.minidom import parseString

import olefile

from msoffcrypto.format.common import (
    _parse_encryptionheader,
    _parse_encryptionverifier,
)

EVIDENCE_SCHEMA = "msoffcrypto.offline-format-evidence/v1"


def _canonical_json(value: Any) -> bytes:
    """Return a deterministic JSON representation used for digests."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_parts(*parts: Any) -> str:
    """Hash a sequence of byte/string parts without exposing the parts."""
    digest = hashlib.sha256()
    for part in parts:
        if part is None:
            continue
        if isinstance(part, str):
            part = part.encode("utf-8")
        digest.update(part)
        digest.update(b"\x00")
    return digest.hexdigest()


def _sha256_stream(stream: BinaryIO) -> tuple[str, int]:
    """Return ``(sha256, size)`` for a file-like object and restore its offset."""
    position = None
    try:
        position = stream.tell()
    except (AttributeError, OSError):
        pass
    stream.seek(0)
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    if position is not None:
        stream.seek(position)
    else:
        stream.seek(0)
    return digest.hexdigest(), size


def _uint32_pair(data: bytes) -> tuple[int, int]:
    if len(data) < 8:
        raise ValueError("encryption header is truncated")
    return unpack("<II", data[:8])


def _strip_utf16(value: str) -> str:
    return value.replace("\x00", "").strip()


def _cipher_for_alg_id(alg_id: int) -> tuple[str | None, int | None]:
    return {
        0x0000660E: ("AES", 128),
        0x0000660F: ("AES", 192),
        0x00006610: ("AES", 256),
        0x00006801: ("RC4", None),
        0x0000681A: ("RC4", None),
    }.get(alg_id, (None, None))


def _hash_for_alg_id(alg_id: int) -> str | None:
    return {
        0x00008004: "SHA1",
        0x0000800C: "SHA256",
        0x0000800D: "SHA384",
        0x0000800E: "SHA512",
        0x00008002: "MD5",
    }.get(alg_id)


def _parse_rc4_cryptoapi_header(data: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse flags/header/verifier without running the password verifier."""
    if len(data) < 8:
        raise ValueError("RC4 CryptoAPI header is truncated")
    flags, header_size = _uint32_pair(data)
    if len(data) < 8 + header_size:
        raise ValueError("RC4 CryptoAPI header size exceeds the available data")
    header = _parse_encryptionheader(io.BytesIO(data[8 : 8 + header_size]))
    verifier = _parse_encryptionverifier(io.BytesIO(data[8 + header_size :]), "RC4")
    header = dict(header)
    header["flags"] = flags
    header["headerSize"] = header_size
    return header, verifier


def _verifier_digest(verifier: Mapping[str, Any]) -> str:
    return _digest_parts(
        verifier.get("salt"),
        verifier.get("encryptedVerifier"),
        verifier.get("encryptedVerifierHash"),
    )


@dataclass(frozen=True)
class FormatEvidence:
    """A stable, JSON-safe description of an Office protection wrapper.

    ``details`` contains format-specific parse results.  Secrets are not copied
    into the evidence; salts and verifier blobs are represented by
    ``verifier_sha256`` instead.  ``file_sha256`` binds the evidence to the
    exact file bytes and is therefore suitable for a sealed receipt.
    """

    schema: ClassVar[str] = EVIDENCE_SCHEMA

    format: str
    container: str
    encrypted: bool
    scheme: str | None = None
    cipher: str | None = None
    key_bits: int | None = None
    hash_algorithm: str | None = None
    spin_count: int | None = None
    key_types: tuple[str, ...] = ()
    protected_streams: tuple[str, ...] = ()
    file_size: int | None = None
    file_sha256: str | None = None
    verifier_sha256: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    supported: bool = True
    error: str | None = None

    def _identity(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "container": self.container,
            "encrypted": self.encrypted,
            "scheme": self.scheme,
            "cipher": self.cipher,
            "key_bits": self.key_bits,
            "hash_algorithm": self.hash_algorithm,
            "spin_count": self.spin_count,
            "key_types": list(self.key_types),
            "protected_streams": list(self.protected_streams),
            "file_size": self.file_size,
            "file_sha256": self.file_sha256,
            "verifier_sha256": self.verifier_sha256,
            "details": dict(self.details),
            "supported": self.supported,
            "error": self.error,
        }

    @property
    def evidence_digest(self) -> str:
        return hashlib.sha256(_canonical_json(self._identity())).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        result = {"schema": EVIDENCE_SCHEMA}
        result.update(self._identity())
        result["evidence_digest"] = self.evidence_digest
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FormatEvidence":
        def optional_tuple(name: str) -> tuple[str, ...]:
            raw = value.get(name) or ()
            return tuple(str(item) for item in raw)

        details = value.get("details") or {}
        return cls(
            format=str(value.get("format", "unknown")),
            container=str(value.get("container", "unknown")),
            encrypted=bool(value.get("encrypted", False)),
            scheme=value.get("scheme"),
            cipher=value.get("cipher"),
            key_bits=value.get("key_bits"),
            hash_algorithm=value.get("hash_algorithm"),
            spin_count=value.get("spin_count"),
            key_types=optional_tuple("key_types"),
            protected_streams=optional_tuple("protected_streams"),
            file_size=value.get("file_size"),
            file_sha256=value.get("file_sha256"),
            verifier_sha256=value.get("verifier_sha256"),
            details=dict(details),
            supported=bool(value.get("supported", True)),
            error=value.get("error"),
        )


def _ooxml_version(data: bytes) -> tuple[int, int]:
    if len(data) < 4:
        raise ValueError("EncryptionInfo stream is truncated")
    return unpack("<HH", data[:4])


def _inspect_ooxml_standard(data: bytes, stream_names: tuple[str, ...]) -> FormatEvidence:
    from msoffcrypto.format.ooxml import _parseinfo_standard

    info = _parseinfo_standard(io.BytesIO(data[4:]))
    header = info["header"]
    verifier = info["verifier"]
    cipher, default_bits = _cipher_for_alg_id(header["algId"])
    key_bits = header["keySize"] or default_bits
    hash_algorithm = _hash_for_alg_id(header["algIdHash"])
    return FormatEvidence(
        format="ooxml",
        container="ole",
        encrypted=True,
        scheme="standard",
        cipher=cipher,
        key_bits=key_bits,
        hash_algorithm=hash_algorithm,
        key_types=("password", "secret_key"),
        protected_streams=stream_names,
        verifier_sha256=_verifier_digest(verifier),
        details={
            "flags": header["flags"],
            "alg_id": header["algId"],
            "alg_id_hash": header["algIdHash"],
            "provider_type": header["providerType"],
            "csp_name": _strip_utf16(header.get("cspName", "")),
            "verifier_hash_size": verifier["verifierHashSize"],
        },
    )


def _xml_first(xml: Any, tag: str) -> Any | None:
    nodes = xml.getElementsByTagName(tag)
    return nodes[0] if nodes else None


def _xml_int(node: Any | None, attribute: str) -> int | None:
    if node is None or not node.hasAttribute(attribute):
        return None
    try:
        return int(node.getAttribute(attribute))
    except (TypeError, ValueError):
        return None


def _inspect_ooxml_agile(data: bytes, stream_names: tuple[str, ...]) -> FormatEvidence:
    xml = parseString(data[8:])
    key_data = _xml_first(xml, "keyData")
    encrypted_key_nodes = xml.getElementsByTagNameNS(
        "http://schemas.microsoft.com/office/2006/keyEncryptor/password",
        "encryptedKey",
    )
    if not encrypted_key_nodes:
        encrypted_key_nodes = [node for node in xml.getElementsByTagName("*") if node.localName == "encryptedKey"]
    encrypted_key = encrypted_key_nodes[0] if encrypted_key_nodes else None
    key_encryptors = xml.getElementsByTagName("keyEncryptor")
    spin_count = _xml_int(encrypted_key, "spinCount")
    key_bits = _xml_int(key_data, "keyBits")
    block_size = _xml_int(key_data, "blockSize")
    key_data_hash = key_data.getAttribute("hashAlgorithm") if key_data is not None else None
    password_hash = encrypted_key.getAttribute("hashAlgorithm") if encrypted_key is not None else None
    password_key_bits = _xml_int(encrypted_key, "keyBits")
    cipher = key_data.getAttribute("cipherAlgorithm") if key_data is not None else None
    cipher_chaining = key_data.getAttribute("cipherChaining") if key_data is not None else None
    salt_value = key_data.getAttribute("saltValue") if key_data is not None else ""
    encrypted_key_value = encrypted_key.getAttribute("encryptedKeyValue") if encrypted_key is not None else ""
    verifier_input = encrypted_key.getAttribute("encryptedVerifierHashInput") if encrypted_key is not None else ""
    verifier_value = encrypted_key.getAttribute("encryptedVerifierHashValue") if encrypted_key is not None else ""
    verifier = {
        "salt": base64.b64decode(salt_value) if salt_value else b"",
        "encryptedVerifier": base64.b64decode(verifier_input) if verifier_input else b"",
        "encryptedVerifierHash": base64.b64decode(verifier_value) if verifier_value else b"",
    }
    has_integrity = bool(_xml_first(xml, "dataIntegrity"))
    supported = True
    error = None
    if spin_count is not None and not 0 <= spin_count <= 10_000_000:
        supported = False
        error = "Agile spinCount is outside the supported range (0..10000000)"
    return FormatEvidence(
        format="ooxml",
        container="ole",
        encrypted=True,
        scheme="agile",
        cipher=cipher,
        key_bits=key_bits,
        hash_algorithm=key_data_hash,
        spin_count=spin_count,
        key_types=("password", "private_key", "secret_key"),
        protected_streams=stream_names,
        verifier_sha256=_verifier_digest(verifier),
        details={
            "cipher_chaining": cipher_chaining,
            "block_size": block_size,
            "key_data_hash_algorithm": key_data_hash,
            "password_hash_algorithm": password_hash,
            "password_key_bits": password_key_bits,
            "key_encryptor_count": len(key_encryptors),
            "data_integrity": has_integrity,
            "encrypted_key_value_sha256": _digest_text(encrypted_key_value),
        },
        supported=supported,
        error=error,
    )


def _inspect_ooxml(ole: Any) -> FormatEvidence:
    streams = ["EncryptionInfo"]
    if ole.exists("EncryptedPackage"):
        streams.append("EncryptedPackage")
    with ole.openstream("EncryptionInfo") as stream:
        data = stream.read()
    major, minor = _ooxml_version(data)
    if major == 4 and minor == 4:
        return _inspect_ooxml_agile(data, tuple(streams))
    if major in (2, 3, 4) and minor == 2:
        return _inspect_ooxml_standard(data, tuple(streams))
    if major in (3, 4) and minor == 3:
        return FormatEvidence(
            format="ooxml",
            container="ole",
            encrypted=True,
            scheme="extensible",
            protected_streams=tuple(streams),
            details={"encryption_info_version": [major, minor]},
            supported=False,
            error="Extensible encryption is not supported by the offline evidence reader",
        )
    return FormatEvidence(
        format="ooxml",
        container="ole",
        encrypted=True,
        scheme="unknown",
        protected_streams=tuple(streams),
        details={"encryption_info_version": [major, minor]},
        supported=False,
        error="Unsupported EncryptionInfo version {}:{}".format(major, minor),
    )


def _inspect_doc(ole: Any) -> FormatEvidence:
    from msoffcrypto.format.doc97 import _parseFib, _parse_header_RC4

    with ole.openstream("wordDocument") as stream:
        fib = _parseFib(stream)
    base = fib.base
    table_name = "1Table" if base.fWhichTblStm == 1 else "0Table"
    protected = ("wordDocument", table_name)
    if not base.fEncrypted:
        return FormatEvidence(
            format="doc97",
            container="ole",
            encrypted=False,
            scheme="plain",
            protected_streams=protected,
            details={"nFib": base.nFib, "fWhichTblStm": base.fWhichTblStm},
        )
    if base.fObfuscation:
        return FormatEvidence(
            format="doc97",
            container="ole",
            encrypted=True,
            scheme="xor",
            cipher="XOR",
            key_bits=16,
            key_types=("password",),
            protected_streams=protected,
            details={"iKey": base.IKey},
        )
    with ole.openstream(table_name) as stream:
        version = stream.read(4)
        if len(version) < 4:
            raise ValueError("DOC table stream is truncated")
        major, minor = unpack("<HH", version)
        if major == 1 and minor == 1:
            body = stream.read(48)
        elif major in (2, 3, 4) and minor == 2:
            prefix = stream.read(8)
            if len(prefix) < 8:
                raise ValueError("RC4 CryptoAPI header is truncated")
            _, header_size = _uint32_pair(prefix)
            body = prefix + stream.read(header_size) + stream.read(64)
        else:
            body = b""
    if len(version) < 4:
        raise ValueError("DOC table stream is truncated")
    if major == 1 and minor == 1:
        info = _parse_header_RC4(io.BytesIO(body))
        return FormatEvidence(
            format="doc97",
            container="ole",
            encrypted=True,
            scheme="rc4",
            cipher="RC4",
            key_bits=128,
            hash_algorithm="MD5",
            key_types=("password",),
            protected_streams=protected,
            verifier_sha256=_verifier_digest(info),
            details={"encryption_version": [major, minor]},
        )
    if major in (2, 3, 4) and minor == 2:
        header, verifier = _parse_rc4_cryptoapi_header(body)
        key_bits = header["keySize"] or 40
        return FormatEvidence(
            format="doc97",
            container="ole",
            encrypted=True,
            scheme="rc4_cryptoapi",
            cipher="RC4",
            key_bits=key_bits,
            hash_algorithm="SHA1",
            key_types=("password",),
            protected_streams=protected,
            verifier_sha256=_verifier_digest(verifier),
            details={
                "encryption_version": [major, minor],
                "alg_id": header["algId"],
                "provider_type": header["providerType"],
            },
        )
    return FormatEvidence(
        format="doc97",
        container="ole",
        encrypted=True,
        scheme="unknown",
        protected_streams=protected,
        details={"encryption_version": [major, minor]},
        supported=False,
        error="Unsupported DOC encryption version {}:{}".format(major, minor),
    )


def _inspect_xls(ole: Any) -> FormatEvidence:
    from msoffcrypto.format.xls97 import recordNameNum
    from msoffcrypto.format.doc97 import _parse_header_RC4

    with ole.openstream("Workbook") as stream:
        header = stream.read(4)
        if len(header) < 4:
            raise ValueError("Workbook stream is truncated")
        record_id, record_size = unpack("<HH", header)
        if record_id != recordNameNum["BOF"]:
            raise ValueError("Workbook stream does not start with a BOF record")
        stream.seek(record_size, os.SEEK_CUR)
        payload = None
        while True:
            record_header = stream.read(4)
            if len(record_header) < 4:
                break
            record_id, record_size = unpack("<HH", record_header)
            if record_id == recordNameNum["FilePass"]:
                payload = stream.read(record_size)
                break
            if record_id == recordNameNum["EOF"]:
                break
            stream.seek(record_size, os.SEEK_CUR)
    if payload is None:
        return FormatEvidence(
            format="xls97",
            container="ole",
            encrypted=False,
            scheme="plain",
            protected_streams=("Workbook",),
        )
    if len(payload) < 2:
        raise ValueError("FilePass record is truncated")
    encryption_type = unpack("<H", payload[:2])[0]
    if encryption_type == 0:
        return FormatEvidence(
            format="xls97",
            container="ole",
            encrypted=True,
            scheme="xor",
            cipher="XOR",
            key_bits=16,
            key_types=("password",),
            protected_streams=("Workbook",),
        )
    if encryption_type != 1 or len(payload) < 6:
        return FormatEvidence(
            format="xls97",
            container="ole",
            encrypted=True,
            scheme="unknown",
            protected_streams=("Workbook",),
            supported=False,
            error="Unsupported XLS FilePass encryption type {}".format(encryption_type),
        )
    major, minor = unpack("<HH", payload[2:6])
    body = payload[6:]
    if major == 1 and minor == 1:
        info = _parse_header_RC4(io.BytesIO(body))
        return FormatEvidence(
            format="xls97",
            container="ole",
            encrypted=True,
            scheme="rc4",
            cipher="RC4",
            key_bits=128,
            hash_algorithm="MD5",
            key_types=("password",),
            protected_streams=("Workbook",),
            verifier_sha256=_verifier_digest(info),
            details={"encryption_version": [major, minor]},
        )
    if major in (2, 3, 4) and minor == 2:
        header, verifier = _parse_rc4_cryptoapi_header(body)
        return FormatEvidence(
            format="xls97",
            container="ole",
            encrypted=True,
            scheme="rc4_cryptoapi",
            cipher="RC4",
            key_bits=header["keySize"] or 40,
            hash_algorithm="SHA1",
            key_types=("password",),
            protected_streams=("Workbook",),
            verifier_sha256=_verifier_digest(verifier),
            details={
                "encryption_version": [major, minor],
                "alg_id": header["algId"],
                "provider_type": header["providerType"],
            },
        )
    return FormatEvidence(
        format="xls97",
        container="ole",
        encrypted=True,
        scheme="unknown",
        protected_streams=("Workbook",),
        details={"encryption_version": [major, minor]},
        supported=False,
        error="Unsupported XLS encryption version {}:{}".format(major, minor),
    )


def _inspect_ppt(ole: Any) -> FormatEvidence:
    from msoffcrypto.format.ppt97 import (
        _parseCryptSession10Container,
        _parseCurrentUser,
        _parseUserEditAtom,
        construct_persistobjectdirectory,
    )

    with ole.openstream("Current User") as current_user_stream, ole.openstream("PowerPoint Document") as presentation_stream:
        current_user = _parseCurrentUser(current_user_stream)
        presentation_stream.seek(current_user.currentuseratom.offsetToCurrentEdit)
        user_edit = _parseUserEditAtom(presentation_stream)
        if user_edit.rh.recLen != 0x20:
            return FormatEvidence(
                format="ppt97",
                container="ole",
                encrypted=False,
                scheme="plain",
                protected_streams=("Current User", "PowerPoint Document"),
            )
        Data = namedtuple("Data", ["currentuser", "powerpointdocument"])
        data = Data(currentuser=current_user_stream, powerpointdocument=presentation_stream)
        persist_directory = construct_persistobjectdirectory(data)
        offset = persist_directory[user_edit.encryptSessionPersistIdRef]
        presentation_stream.seek(offset)
        crypt_session = _parseCryptSession10Container(presentation_stream)
    payload = crypt_session.data
    if len(payload) < 4:
        raise ValueError("PowerPoint CryptSession10Container is truncated")
    major, minor = unpack("<HH", payload[:4])
    if major in (2, 3, 4) and minor == 2:
        header, verifier = _parse_rc4_cryptoapi_header(payload[4:])
        return FormatEvidence(
            format="ppt97",
            container="ole",
            encrypted=True,
            scheme="rc4_cryptoapi",
            cipher="RC4",
            key_bits=header["keySize"] or 40,
            hash_algorithm="SHA1",
            key_types=("password",),
            protected_streams=("Current User", "PowerPoint Document"),
            verifier_sha256=_verifier_digest(verifier),
            details={
                "encryption_version": [major, minor],
                "alg_id": header["algId"],
                "provider_type": header["providerType"],
            },
        )
    return FormatEvidence(
        format="ppt97",
        container="ole",
        encrypted=True,
        scheme="unknown",
        protected_streams=("Current User", "PowerPoint Document"),
        details={"encryption_version": [major, minor]},
        supported=False,
        error="Unsupported PPT encryption version {}:{}".format(major, minor),
    )


def _inspect_ole(ole: Any) -> FormatEvidence:
    if ole.exists("EncryptionInfo"):
        return _inspect_ooxml(ole)
    if ole.exists("wordDocument"):
        return _inspect_doc(ole)
    if ole.exists("Workbook"):
        return _inspect_xls(ole)
    if ole.exists("PowerPoint Document"):
        return _inspect_ppt(ole)
    return FormatEvidence(
        format="ole",
        container="ole",
        encrypted=False,
        scheme="unknown",
        supported=False,
        error="OLE container has no recognized Office document stream",
    )


def _inspect_open_file(handle: BinaryIO, *, include_file_digest: bool) -> FormatEvidence:
    file_sha256 = None
    file_size = None
    if include_file_digest:
        file_sha256, file_size = _sha256_stream(handle)
    handle.seek(0)
    container = "unknown"
    try:
        if olefile.isOleFile(handle):
            container = "ole"
            ole = olefile.OleFileIO(handle)
            try:
                evidence = _inspect_ole(ole)
            finally:
                ole.close()
        elif zipfile.is_zipfile(handle):
            container = "zip"
            from msoffcrypto.format.ooxml import _is_ooxml

            handle.seek(0)
            if _is_ooxml(handle):
                evidence = FormatEvidence(
                    format="ooxml",
                    container="zip",
                    encrypted=False,
                    scheme="plain",
                    supported=True,
                )
            else:
                evidence = FormatEvidence(
                    format="zip",
                    container="zip",
                    encrypted=False,
                    scheme="unknown",
                    supported=False,
                    error="ZIP container is not an OOXML package",
                )
        else:
            evidence = FormatEvidence(
                format="unknown",
                container="unknown",
                encrypted=False,
                scheme="unknown",
                supported=False,
                error="Unsupported file format",
            )
    except Exception as exc:  # malformed evidence must not abort a whole batch
        evidence = FormatEvidence(
            format="unknown",
            container=container,
            encrypted=False,
            scheme="unknown",
            supported=False,
            error="{}: {}".format(type(exc).__name__, exc),
        )
    if file_size is None:
        try:
            position = handle.tell()
            handle.seek(0, os.SEEK_END)
            file_size = handle.tell()
            handle.seek(position)
        except (AttributeError, OSError):
            file_size = None
    if include_file_digest and evidence.file_sha256 is None:
        evidence = FormatEvidence(**{**evidence._identity(), "file_sha256": file_sha256, "file_size": file_size})
    elif evidence.file_size is None and file_size is not None:
        evidence = FormatEvidence(**{**evidence._identity(), "file_size": file_size})
    return evidence


def inspect_file(source: str | os.PathLike[str] | bytes | BinaryIO, *, include_file_digest: bool = True) -> FormatEvidence:
    """Read offline protection evidence from a path, bytes, or file handle.

    The file handle is not closed and its original position is restored.  The
    function never calls ``load_key`` or ``decrypt`` and never opens an encrypted
    payload as a document.
    """
    if isinstance(source, (str, os.PathLike, Path)):
        with open(source, "rb") as handle:
            return _inspect_open_file(handle, include_file_digest=include_file_digest)
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _inspect_open_file(io.BytesIO(bytes(source)), include_file_digest=include_file_digest)
    position = None
    try:
        position = source.tell()
    except (AttributeError, OSError):
        pass
    try:
        return _inspect_open_file(source, include_file_digest=include_file_digest)
    finally:
        if position is not None:
            try:
                source.seek(position)
            except (AttributeError, OSError):
                pass


def inspect_offline(source: str | os.PathLike[str] | bytes | BinaryIO, **kwargs: Any) -> FormatEvidence:
    """Alias for :func:`inspect_file`."""
    return inspect_file(source, **kwargs)


def format_evidence(source: str | os.PathLike[str] | bytes | BinaryIO, **kwargs: Any) -> FormatEvidence:
    """Alias for :func:`inspect_file`."""
    return inspect_file(source, **kwargs)


__all__ = [
    "EVIDENCE_SCHEMA",
    "FormatEvidence",
    "format_evidence",
    "inspect_file",
    "inspect_offline",
]
