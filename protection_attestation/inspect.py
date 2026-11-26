"""Read Office protection metadata without deriving keys or touching plaintext."""

from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from xml.dom.minidom import parseString

import olefile

from msoffcrypto import OfficeFile


def tool_version() -> str:
    try:
        return version("msoffcrypto-tool")
    except PackageNotFoundError:
        return "source-checkout"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _attribute(node: Any, name: str) -> Any:
    if not node.hasAttribute(name):
        return None
    value = node.getAttribute(name)
    if name in {"keyBits", "spinCount", "saltSize", "blockSize", "hashSize"}:
        return int(value)
    return value


def _read_agile_xml(path: Path) -> dict[str, Any]:
    with olefile.OleFileIO(path) as ole:
        raw = ole.openstream("EncryptionInfo").read()
    # The first eight bytes are EncryptionInfo version/reserved fields.
    document = parseString(raw[8:])
    key_data = document.getElementsByTagName("keyData")[0]
    encrypted_key = document.getElementsByTagNameNS(
        "http://schemas.microsoft.com/office/2006/keyEncryptor/password",
        "encryptedKey",
    )[0]

    fields = (
        "saltSize",
        "blockSize",
        "keyBits",
        "hashSize",
        "cipherAlgorithm",
        "cipherChaining",
        "hashAlgorithm",
    )
    key_data_attrs = {name: _attribute(key_data, name) for name in fields}
    password_attrs = {name: _attribute(encrypted_key, name) for name in (*fields, "spinCount")}
    return {"keyData": key_data_attrs, "passwordKey": password_attrs}


def inspect_package(path: str | Path) -> dict[str, Any]:
    """Return non-secret protection parameters for an encrypted Office package.

    This function intentionally never calls load_key or decrypt. It only lets
    msoffcrypto parse EncryptionInfo and then reads non-secret XML attributes.
    """
    path = Path(path)
    file_sha256 = sha256_file(path)

    with path.open("rb") as handle:
        office = OfficeFile(handle)
        protection_format = getattr(office, "type", None)
        msoffcrypto_format = getattr(office, "format", None)

        if protection_format == "agile":
            xml_attrs = _read_agile_xml(path)
            password = xml_attrs["passwordKey"]
            key_data = xml_attrs["keyData"]
            bits = int(password["keyBits"])
            chaining = str(password["cipherChaining"]).removeprefix("ChainingMode").upper()
            parameters = {
                "protection_kind": "agile",
                "encryption_suite": {
                    "cipher_algorithm": password["cipherAlgorithm"],
                    "key_length_bits": bits,
                    "cipher_chaining": password["cipherChaining"],
                },
                "cipher_algorithm": password["cipherAlgorithm"],
                "cipher_chaining": password["cipherChaining"],
                "key_length_bits": bits,
                "hash_algorithm": password["hashAlgorithm"],
                "spin_count": password["spinCount"],
                "salt_length_bytes": password["saltSize"],
                "block_size_bytes": password.get("blockSize") or key_data["blockSize"],
                "hash_size_bytes": password.get("hashSize") or key_data["hashSize"],
            }
            source_locator = "EncryptionInfo XML: p:encryptedKey and keyData attributes"
        elif protection_format == "standard":
            info = office.info
            header = info["header"]
            alg_id_to_bits = {0x0000660E: 128, 0x0000660F: 192, 0x00006610: 256}
            bits = int(header["keySize"]) or alg_id_to_bits.get(header["algId"], 0)
            parameters = {
                "protection_kind": "standard",
                "encryption_suite": f"AES-{bits}-ECB" if bits else "RC4",
                "cipher_algorithm": "AES" if header["algId"] & 0xFF00 == 0x6600 else "RC4",
                "key_length_bits": bits,
                "salt_length_bytes": info["verifier"]["saltSize"],
            }
            source_locator = "EncryptionInfo standard header and verifier"
        else:
            parameters = {"protection_kind": protection_format or msoffcrypto_format or "unknown"}
            source_locator = "msoffcrypto.OfficeFile format detection"

        ole = getattr(office, "file", None)
        if ole is not None and hasattr(ole, "close"):
            try:
                ole.close()
            except Exception:
                pass

    return {
        "path": str(path),
        "sha256": file_sha256,
        "msoffcrypto_format": msoffcrypto_format,
        "protection_format": protection_format,
        "tool": "msoffcrypto-tool",
        "tool_version": tool_version(),
        "source_locator": source_locator,
        "parameters": parameters,
        "plaintext_accessed": False,
    }
