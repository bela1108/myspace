"""Redacted, evidence-oriented comparison of OOXML containers.

The report deliberately separates three kinds of evidence:

* public container and encryption-header attributes available without a key;
* plaintext identity, only after credentials and payload integrity checks pass;
* evidence that could not be examined because a credential was unavailable.

No plaintext, password, salt, verifier, encrypted key, or other secret value is
returned.  The report contains only normalized attributes, locations, sizes, and
SHA-256 digests.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import zipfile
from struct import unpack
from xml.etree import ElementTree

import olefile

from msoffcrypto.exceptions import (
    DecryptionError,
    FileFormatError,
    InvalidKeyError,
)
from msoffcrypto.format.ooxml import OOXMLFile, _is_ooxml, _parseinfo_standard

_REPORT_SCHEMA = "msoffcrypto-comparison/v1"

_ALG_ID_NAMES = {
    0x00000000: "RC4",
    0x00006801: "RC4",
    0x0000660E: "AES-128",
    0x0000660F: "AES-192",
    0x00006610: "AES-256",
}

_HASH_ID_NAMES = {
    0x00000000: "SHA1",
    0x00008004: "SHA1",
    0x0000800C: "SHA256",
    0x0000800D: "SHA384",
    0x0000800E: "SHA512",
}

_ENC_NS = "http://schemas.microsoft.com/office/2006/encryption"
_PASSWORD_NS = "http://schemas.microsoft.com/office/2006/keyEncryptor/password"


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _canonical_digest(value):
    encoded = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return _digest(encoded)


def _read_source(source):
    """Return source bytes without closing a caller-owned file handle."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)

    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as stream:
            return stream.read()

    if not hasattr(source, "read"):
        raise TypeError("source must be a path, bytes, or a binary file handle")

    position = None
    try:
        position = source.tell()
        source.seek(0)
    except (AttributeError, OSError):
        pass

    try:
        data = source.read()
    finally:
        if position is not None:
            try:
                source.seek(position)
            except (AttributeError, OSError):
                pass

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("source file handle must be opened in binary mode")
    return bytes(data)


def _ole_streams(data):
    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        paths = sorted(
            ole.listdir(streams=True, storages=False),
            key=lambda path: "/".join(path),
        )
        streams = []
        for path in paths:
            name = "/".join(path)
            content = ole.openstream(path).read()
            streams.append(
                {
                    "trace": {"container": "ole", "stream": name},
                    "size": len(content),
                    "sha256": _digest(content),
                }
            )
        return streams
    finally:
        ole.close()


def _int_attr(node, name):
    value = node.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _decoded_attr_digest(node, name):
    value = node.get(name)
    if value is None:
        return None
    try:
        return _digest(base64.b64decode(value, validate=True))
    except (ValueError, TypeError):
        return None


def _agile_header_attributes(raw):
    descriptor = raw[8:]
    root = ElementTree.fromstring(descriptor)

    key_data = root.find("{%s}keyData" % _ENC_NS)
    if key_data is None:
        raise FileFormatError("Agile EncryptionInfo has no keyData")

    integrity = root.find("{%s}dataIntegrity" % _ENC_NS)
    password = root.find(
        ".//{%s}encryptedKey" % _PASSWORD_NS
    )

    key_encryptors = []
    for node in root.findall(".//{%s}keyEncryptor" % _ENC_NS):
        key_encryptors.append(node.get("uri"))

    attributes = {
        "key_data": {
            "cipher_algorithm": key_data.get("cipherAlgorithm"),
            "cipher_chaining": key_data.get("cipherChaining"),
            "hash_algorithm": key_data.get("hashAlgorithm"),
            "salt_size": _int_attr(key_data, "saltSize"),
            "block_size": _int_attr(key_data, "blockSize"),
            "key_bits": _int_attr(key_data, "keyBits"),
            "hash_size": _int_attr(key_data, "hashSize"),
        },
        "data_integrity": {
            "present": integrity is not None,
            "encrypted_hmac_key_size": (
                len(base64.b64decode(integrity.get("encryptedHmacKey", "")))
                if integrity is not None
                else None
            ),
            "encrypted_hmac_value_size": (
                len(base64.b64decode(integrity.get("encryptedHmacValue", "")))
                if integrity is not None
                else None
            ),
        },
        "key_encryptor_uris": key_encryptors,
        "password_encryptor_present": password is not None,
    }

    digests = {
        "key_data_salt_sha256": _decoded_attr_digest(key_data, "saltValue"),
        "encrypted_hmac_key_sha256": (
            _decoded_attr_digest(integrity, "encryptedHmacKey")
            if integrity is not None
            else None
        ),
        "encrypted_hmac_value_sha256": (
            _decoded_attr_digest(integrity, "encryptedHmacValue")
            if integrity is not None
            else None
        ),
    }

    if password is not None:
        attributes["password_key"] = {
            "spin_count": _int_attr(password, "spinCount"),
            "cipher_algorithm": password.get("cipherAlgorithm"),
            "cipher_chaining": password.get("cipherChaining"),
            "hash_algorithm": password.get("hashAlgorithm"),
            "salt_size": _int_attr(password, "saltSize"),
            "block_size": _int_attr(password, "blockSize"),
            "key_bits": _int_attr(password, "keyBits"),
            "hash_size": _int_attr(password, "hashSize"),
        }
        digests.update(
            {
                "password_salt_sha256": _decoded_attr_digest(
                    password, "saltValue"
                ),
                "encrypted_verifier_hash_input_sha256": _decoded_attr_digest(
                    password, "encryptedVerifierHashInput"
                ),
                "encrypted_verifier_hash_value_sha256": _decoded_attr_digest(
                    password, "encryptedVerifierHashValue"
                ),
                "encrypted_key_value_sha256": _decoded_attr_digest(
                    password, "encryptedKeyValue"
                ),
            }
        )

    return {"attributes": attributes, "digests": digests}


def _standard_header_attributes(raw):
    info = _parseinfo_standard(io.BytesIO(raw[4:]))
    header = info["header"]
    verifier = info["verifier"]
    alg_id = header["algId"]
    hash_id = header["algIdHash"]

    attributes = {
        "flags": header["flags"],
        "size_extra": header["sizeExtra"],
        "alg_id": alg_id,
        "alg_id_name": _ALG_ID_NAMES.get(alg_id),
        "alg_id_hash": hash_id,
        "alg_id_hash_name": _HASH_ID_NAMES.get(hash_id),
        "key_size": header["keySize"],
        "provider_type": header["providerType"],
        "csp_name": header["cspName"],
        "verifier": {
            "salt_size": verifier["saltSize"],
            "hash_size": verifier["verifierHashSize"],
        },
    }
    digests = {
        "verifier_salt_sha256": _digest(verifier["salt"]),
        "encrypted_verifier_sha256": _digest(verifier["encryptedVerifier"]),
        "encrypted_verifier_hash_sha256": _digest(
            verifier["encryptedVerifierHash"]
        ),
    }
    return {"attributes": attributes, "digests": digests}


def _plain_header(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            content_types = package.read("[Content_Types].xml")
    except (KeyError, zipfile.BadZipFile):
        return None

    return {
        "trace": {
            "container": "ooxml-zip",
            "part": "[Content_Types].xml",
        },
        "size": len(content_types),
        "sha256": _digest(content_types),
        "attributes": {"kind": "ooxml_content_types"},
    }


def _public_profile(data):
    binary = io.BytesIO(data)
    container = {
        "size": len(data),
        "sha256": _digest(data),
    }

    if olefile.isOleFile(io.BytesIO(data)):
        container["kind"] = "ole"
        ole = olefile.OleFileIO(io.BytesIO(data))
        try:
            if not ole.exists("EncryptionInfo"):
                raise FileFormatError("OLE container has no EncryptionInfo stream")
            with ole.openstream("EncryptionInfo") as stream:
                raw = stream.read()
            with ole.openstream("EncryptedPackage") as stream:
                encrypted_package = stream.read()
        finally:
            ole.close()

        if len(raw) < 8:
            raise FileFormatError("EncryptionInfo stream is truncated")

        version_major, version_minor = unpack("<HH", raw[:4])
        if (version_major, version_minor) == (4, 4):
            scheme = "agile"
            parsed = _agile_header_attributes(raw)
        elif version_major in (2, 3, 4) and version_minor == 2:
            scheme = "standard"
            parsed = _standard_header_attributes(raw)
        else:
            scheme = "unsupported"
            parsed = {"attributes": {}, "digests": {}}

        header = {
            "trace": {"container": "ole", "stream": "EncryptionInfo"},
            "size": len(raw),
            "sha256": _digest(raw),
            "version": {
                "major": version_major,
                "minor": version_minor,
            },
            "scheme": scheme,
            "attributes": parsed["attributes"],
            "digests": parsed["digests"],
        }
        payload = {
            "trace": {"container": "ole", "stream": "EncryptedPackage"},
            "size": len(encrypted_package),
            "sha256": _digest(encrypted_package),
        }
        return {
            "container": container,
            "encrypted": True,
            "scheme": scheme,
            "header": header,
            "payload": payload,
            "container_parts": _ole_streams(data),
        }

    if _is_ooxml(binary):
        header = _plain_header(data)
        return {
            "container": dict(container, kind="zip"),
            "encrypted": False,
            "scheme": "plain",
            "header": header,
            "payload": None,
            "container_parts": (
                [
                    {
                        "trace": header["trace"],
                        "size": header["size"],
                        "sha256": header["sha256"],
                    }
                ]
                if header is not None
                else []
            ),
        }

    raise FileFormatError("Unsupported file format")


def _part_key(name, occurrence):
    return name, occurrence


def _part_location(name, occurrence):
    if occurrence == 1:
        return "zip:" + name
    return "zip:{}#{}".format(name, occurrence)


def _plaintext_parts(plaintext):
    if not zipfile.is_zipfile(io.BytesIO(plaintext)):
        raise FileFormatError("Plaintext is not an OOXML ZIP package")

    parts = []
    with zipfile.ZipFile(io.BytesIO(plaintext)) as package:
        occurrences = {}
        for info in package.infolist():
            if info.is_dir():
                continue
            occurrence = occurrences.get(info.filename, 0) + 1
            occurrences[info.filename] = occurrence
            content = package.read(info)
            parts.append(
                {
                    "name": info.filename,
                    "occurrence": occurrence,
                    "location": _part_location(info.filename, occurrence),
                    "size": len(content),
                    "sha256": _digest(content),
                }
            )

    parts.sort(key=lambda part: _part_key(part["name"], part["occurrence"]))
    manifest = [
        [part["name"], part["occurrence"], part["size"], part["sha256"]]
        for part in parts
    ]
    return parts, _canonical_digest(manifest)


def _unavailable_identity(
    reason,
    credential_required,
    credential_supplied,
    verification=None,
    integrity_status="not_checked",
):
    return {
        "available": False,
        "reason": reason,
        "verification": list(verification or []),
        "credential_required": credential_required,
        "credential_supplied": credential_supplied,
        "integrity_status": integrity_status,
        "package": None,
        "parts": None,
        "part_manifest_sha256": None,
    }


def _plaintext_identity(
    data,
    public_profile,
    password,
    credential_required,
):
    if not credential_required:
        plaintext = data
        verification = ["ooxml_zip", "part_crc"]
        integrity_status = "plain_input"
        package_container = "ooxml-zip"
    else:
        if password is None:
            return _unavailable_identity(
                "password_not_supplied",
                credential_required=True,
                credential_supplied=False,
            )

        try:
            office_file = OOXMLFile(io.BytesIO(data))
            office_file.load_key(password=password, verify_password=True)
        except InvalidKeyError:
            return _unavailable_identity(
                "credential_rejected",
                credential_required=True,
                credential_supplied=True,
            )
        except (FileFormatError, OSError, ValueError, zipfile.BadZipFile):
            return _unavailable_identity(
                "plaintext_unavailable",
                credential_required=True,
                credential_supplied=True,
            )

        decrypted = io.BytesIO()
        verify_integrity = office_file.type == "agile"
        try:
            office_file.decrypt(decrypted, verify_integrity=verify_integrity)
            plaintext = decrypted.getvalue()
        except InvalidKeyError:
            return _unavailable_identity(
                "payload_verification_failed",
                credential_required=True,
                credential_supplied=True,
                verification=["password_verifier"],
            )
        except DecryptionError:
            return _unavailable_identity(
                "decryption_failed",
                credential_required=True,
                credential_supplied=True,
                verification=["password_verifier"],
            )
        except (FileFormatError, OSError, ValueError, zipfile.BadZipFile):
            return _unavailable_identity(
                "plaintext_unavailable",
                credential_required=True,
                credential_supplied=True,
                verification=["password_verifier"],
            )

        verification = ["password_verifier", "ooxml_zip", "part_crc"]
        if public_profile["scheme"] == "agile":
            verification.insert(1, "agile_hmac")
            integrity_status = "hmac_verified"
        else:
            integrity_status = "password_verified_only"
        package_container = "decrypted-ooxml"

    try:
        parts, manifest_sha256 = _plaintext_parts(plaintext)
    except (FileFormatError, OSError, ValueError, zipfile.BadZipFile):
        return _unavailable_identity(
            "plaintext_invalid",
            credential_required=credential_required,
            credential_supplied=not credential_required or password is not None,
            verification=verification[:-1],
            integrity_status=integrity_status,
        )

    return {
        "available": True,
        "reason": None,
        "verification": verification,
        "credential_required": credential_required,
        "credential_supplied": not credential_required or password is not None,
        "integrity_status": integrity_status,
        "package": {
            "trace": {"container": package_container, "part": "/"},
            "size": len(plaintext),
            "sha256": _digest(plaintext),
        },
        "parts": parts,
        "part_manifest_sha256": manifest_sha256,
    }


def _flatten_changes(left, right, prefix):
    if not isinstance(left, dict) or not isinstance(right, dict):
        return [] if left == right else [prefix]

    changes = []
    for key in sorted(set(left) | set(right)):
        path = "{}.{}".format(prefix, key)
        left_value = left.get(key)
        right_value = right.get(key)
        if isinstance(left_value, dict) and isinstance(right_value, dict):
            changes.extend(_flatten_changes(left_value, right_value, path))
        elif left_value != right_value:
            changes.append(path)
    return changes


def _trace_location(trace):
    name = trace.get("stream") or trace.get("part") or trace.get("path") or "/"
    return "{}:{}".format(trace["container"], name)


def _container_part_comparison(left, right):
    left_map = {
        _trace_location(part["trace"]): part
        for part in left["container_parts"]
    }
    right_map = {
        _trace_location(part["trace"]): part
        for part in right["container_parts"]
    }

    changed = []
    for location in sorted(set(left_map) | set(right_map)):
        left_part = left_map.get(location)
        right_part = right_map.get(location)
        if left_part is None:
            status = "only_in_right"
        elif right_part is None:
            status = "only_in_left"
        elif left_part["sha256"] == right_part["sha256"]:
            status = "same"
        else:
            status = "changed"

        if status != "same":
            changed.append(
                {
                    "location": location,
                    "status": status,
                    "left": (
                        {
                            "size": left_part["size"],
                            "sha256": left_part["sha256"],
                        }
                        if left_part is not None
                        else None
                    ),
                    "right": (
                        {
                            "size": right_part["size"],
                            "sha256": right_part["sha256"],
                        }
                        if right_part is not None
                        else None
                    ),
                }
            )

    return {
        "parts_identical": not changed,
        "changed_parts": changed,
    }


def _public_header_comparison(left, right):
    left_header = left.get("header")
    right_header = right.get("header")
    left_attributes = {
        "attributes": (
            left_header.get("attributes", {}) if left_header is not None else {}
        ),
        "digests": (
            left_header.get("digests", {}) if left_header is not None else {}
        ),
    }
    right_attributes = {
        "attributes": (
            right_header.get("attributes", {}) if right_header is not None else {}
        ),
        "digests": (
            right_header.get("digests", {}) if right_header is not None else {}
        ),
    }
    attribute_changes = _flatten_changes(
        left_attributes, right_attributes, "header"
    )

    left_header_sha = (
        left_header.get("sha256") if left_header is not None else None
    )
    right_header_sha = (
        right_header.get("sha256") if right_header is not None else None
    )
    left_payload = left.get("payload")
    right_payload = right.get("payload")
    left_payload_sha = (
        left_payload.get("sha256") if left_payload is not None else None
    )
    right_payload_sha = (
        right_payload.get("sha256") if right_payload is not None else None
    )

    public_only_same = (
        left_header_sha == right_header_sha
        and left_payload_sha == right_payload_sha
        and left["container"]["sha256"] == right["container"]["sha256"]
    )

    return {
        "same_file_sha256": left["container"]["sha256"]
        == right["container"]["sha256"],
        "changed": not public_only_same,
        "same_container_part_set": {
            _trace_location(part["trace"])
            for part in left["container_parts"]
        }
        == {
            _trace_location(part["trace"])
            for part in right["container_parts"]
        },
        "same_encryption_scheme": left["scheme"] == right["scheme"],
        "same_header_sha256": left_header_sha == right_header_sha,
        "same_encryption_attributes": left_attributes == right_attributes,
        "same_encrypted_payload_sha256": left_payload_sha == right_payload_sha,
        "changed_attribute_paths": attribute_changes,
        "container_parts": _container_part_comparison(left, right),
    }


def _plaintext_comparison(left, right):
    if not left["available"] or not right["available"]:
        return None

    left_parts = {
        _part_key(part["name"], part["occurrence"]): part
        for part in left["parts"]
    }
    right_parts = {
        _part_key(part["name"], part["occurrence"]): part
        for part in right["parts"]
    }

    same_parts = []
    changed_parts = []
    only_in_left = []
    only_in_right = []

    for key in sorted(set(left_parts) | set(right_parts)):
        left_part = left_parts.get(key)
        right_part = right_parts.get(key)
        if right_part is None:
            only_in_left.append(
                {
                    "location": left_part["location"],
                    "size": left_part["size"],
                    "sha256": left_part["sha256"],
                }
            )
        elif left_part is None:
            only_in_right.append(
                {
                    "location": right_part["location"],
                    "size": right_part["size"],
                    "sha256": right_part["sha256"],
                }
            )
        elif left_part["sha256"] == right_part["sha256"]:
            same_parts.append(left_part["location"])
        else:
            changed_parts.append(
                {
                    "location": left_part["location"],
                    "left": {
                        "size": left_part["size"],
                        "sha256": left_part["sha256"],
                    },
                    "right": {
                        "size": right_part["size"],
                        "sha256": right_part["sha256"],
                    },
                }
            )

    parts_identical = not (changed_parts or only_in_left or only_in_right)
    package_sha256_identical = (
        left["package"]["sha256"] == right["package"]["sha256"]
    )
    return {
        "parts_identical": parts_identical,
        "package_sha256_identical": package_sha256_identical,
        "same_part_count": len(same_parts),
        "same_parts": same_parts,
        "changed_parts": changed_parts,
        "only_in_left": only_in_left,
        "only_in_right": only_in_right,
    }


def _credential_status(identity, profile):
    if identity["available"]:
        return {
            "available": True,
            "reason": None,
            "credential_required": identity["credential_required"],
            "credential_supplied": identity["credential_supplied"],
            "blocked_evidence": [],
        }

    trace = (
        profile["payload"]["trace"]
        if profile.get("payload") is not None
        else profile["header"]["trace"]
    )
    blocked = [
        {
            "evidence": "verified_plaintext_identity",
            "trace": trace,
        }
    ]
    return {
        "available": False,
        "reason": identity["reason"],
        "credential_required": identity["credential_required"],
        "credential_supplied": identity["credential_supplied"],
        "blocked_evidence": blocked,
    }


def _conclusion(public_comparison, plaintext_comparison, left_identity, right_identity):
    left_available = left_identity["available"]
    right_available = right_identity["available"]

    if not (left_available and right_available):
        code = "plaintext_unverified"
    elif plaintext_comparison["parts_identical"]:
        if (
            public_comparison["same_file_sha256"]
            and public_comparison["same_header_sha256"]
            and public_comparison["same_encrypted_payload_sha256"]
        ):
            code = "same_plaintext_same_encryption"
        else:
            code = "same_plaintext_encryption_changed"
    else:
        code = "different_plaintext"

    evidence = {
        "left_plaintext_verified": left_available,
        "right_plaintext_verified": right_available,
        "plaintext_parts_identical": (
            plaintext_comparison["parts_identical"]
            if plaintext_comparison is not None
            else None
        ),
        "plaintext_package_sha256_identical": (
            plaintext_comparison["package_sha256_identical"]
            if plaintext_comparison is not None
            else None
        ),
        "file_sha256_identical": public_comparison["same_file_sha256"],
        "header_sha256_identical": public_comparison["same_header_sha256"],
        "encryption_attributes_identical": public_comparison[
            "same_encryption_attributes"
        ],
        "encrypted_payload_sha256_identical": public_comparison[
            "same_encrypted_payload_sha256"
        ],
    }

    plaintext_relation = {
        "plaintext_unverified": "unverified",
        "different_plaintext": "different",
    }.get(code, "identical")

    return {
        "code": code,
        "plaintext_relation": plaintext_relation,
        "evidence": evidence,
        "trace": [
            "public_header.comparison",
            "verified_plaintext_identity.comparison",
            "credential_unavailable",
        ],
    }


def compare_office_files(
    left,
    right,
    password=None,
    *,
    left_password=None,
    right_password=None,
):
    """Compare two OOXML files and return a redacted evidence report.

    Args:
        left: Left path, bytes, or binary file handle.
        right: Right path, bytes, or binary file handle.
        password: Password shared by both files.
        left_password: Left-side password override.
        right_password: Right-side password override.

    Returns:
        A JSON-serializable dictionary with three separate evidence sections:
        ``public_header``, ``verified_plaintext_identity``, and
        ``credential_unavailable``.  The ``conclusion.code`` value is one of
        ``same_plaintext_encryption_changed``, ``different_plaintext``,
        ``plaintext_unverified``, or ``same_plaintext_same_encryption``.

    Plaintext is never included in the report.  Header attributes are
    normalized; salt, verifier, HMAC, and encrypted-key values are represented
    by SHA-256 digests only.
    """
    left_data = _read_source(left)
    right_data = _read_source(right)

    if left_password is None:
        left_password = password
    if right_password is None:
        right_password = password

    left_profile = _public_profile(left_data)
    right_profile = _public_profile(right_data)
    left_identity = _plaintext_identity(
        left_data,
        left_profile,
        left_password,
        credential_required=left_profile["encrypted"],
    )
    right_identity = _plaintext_identity(
        right_data,
        right_profile,
        right_password,
        credential_required=right_profile["encrypted"],
    )

    public_comparison = _public_header_comparison(
        left_profile, right_profile
    )
    plaintext_comparison = _plaintext_comparison(
        left_identity, right_identity
    )

    return {
        "schema": _REPORT_SCHEMA,
        "public_header": {
            "left": left_profile,
            "right": right_profile,
            "comparison": public_comparison,
        },
        "verified_plaintext_identity": {
            "left": left_identity,
            "right": right_identity,
            "comparison": plaintext_comparison,
        },
        "credential_unavailable": {
            "any": not (
                left_identity["available"]
                and right_identity["available"]
            ),
            "left": _credential_status(left_identity, left_profile),
            "right": _credential_status(right_identity, right_profile),
        },
        "conclusion": _conclusion(
            public_comparison,
            plaintext_comparison,
            left_identity,
            right_identity,
        ),
    }


comparison_report = compare_office_files
