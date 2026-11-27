"""Offline protection inspection and comparable reports.

The inspection in this module is deliberately non-decrypting. It records what
the container itself declares, which supporting materials are present, and the
smallest conclusion that evidence supports. It never claims that a password is
valid or that encrypted content can be recovered.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from struct import unpack, unpack_from
from types import SimpleNamespace
from typing import Any, Iterable, Mapping
from xml.dom.minidom import parseString

import olefile

from msoffcrypto.format.doc97 import _parseFibBase
from msoffcrypto.format.ppt97 import (
    _parseCryptSession10Container,
    _parseCurrentUser,
    _parseUserEditAtom,
    construct_persistobjectdirectory,
)
from msoffcrypto.format.xls97 import recordNameNum

REPORT_SCHEMA = "msoffcrypto.protection-report"
REPORT_VERSION = 1

__all__ = [
    "REPORT_SCHEMA",
    "REPORT_VERSION",
    "inspect_file",
    "protection_report",
    "render_comparison",
    "render_json",
    "render_markdown",
    "render_report",
    "render_text",
]

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_OOXML_CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"

_KNOWN_REPORT_KEYS = {
    "schema",
    "version",
    "file",
    "container_type",
    "format",
    "protection",
    "materials",
    "conclusion",
    "notes",
}

_NO_DECRYPTION_LIMIT = "No password was supplied; no decryption or password verification was attempted."
_PERMISSIONS_LIMIT = "This checks protection markers only; it does not assess editing permissions or content sensitivity."


def _read_source(source: Any, filename: str | None) -> tuple[bytes, str | None]:
    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        with open(path, "rb") as stream:
            data = stream.read()
        return data, filename or os.path.basename(path)

    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source), filename

    if not hasattr(source, "read"):
        raise TypeError("source must be a path, bytes, or a binary file-like object")

    position = None
    if hasattr(source, "tell") and hasattr(source, "seek"):
        try:
            position = source.tell()
            source.seek(0)
        except (OSError, io.UnsupportedOperation):
            position = None

    try:
        data = source.read()
    finally:
        if position is not None:
            source.seek(position)

    if isinstance(data, str):
        raise TypeError("source must be opened in binary mode")

    name = filename or getattr(source, "name", None)
    if isinstance(name, os.PathLike):
        name = os.fspath(name)
    if isinstance(name, str):
        name = os.path.basename(name)
    return bytes(data), name


def _empty_report(name: str | None, data: bytes, container_type: str) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "version": REPORT_VERSION,
        "file": {
            "name": name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "container_type": container_type,
        "format": "unknown",
        "protection": {
            "declared": False,
            "indicated": False,
            "method": None,
            "source": None,
            "sources": [],
        },
        "materials": {
            "status": "unknown",
            "required": [],
            "present": [],
            "missing": [],
        },
        "conclusion": {
            "code": "unknown",
            "statement": "The container or protection markers are not recognized; no protection conclusion is possible.",
            "limits": [_NO_DECRYPTION_LIMIT, _PERMISSIONS_LIMIT],
        },
        "notes": [],
    }


def _source(
    kind: str,
    name: str,
    field: str | None = None,
    value: Any = None,
    proves: str | None = None,
) -> dict[str, Any]:
    evidence = {"kind": kind, "name": name}
    if field is not None:
        evidence["field"] = field
    if value is not None:
        evidence["value"] = value
    if proves is not None:
        evidence["proves"] = proves
    return evidence


def _source_id(evidence: Mapping[str, Any]) -> str:
    text = "{}:{}".format(evidence.get("kind", "unknown"), evidence.get("name", "unknown"))
    if evidence.get("field"):
        text += "#{}".format(evidence["field"])
    return text


def _add_source(report: dict[str, Any], evidence: dict[str, Any], declared: bool = True) -> None:
    report["protection"]["sources"].append(evidence)
    report["protection"]["indicated"] = True
    if declared:
        report["protection"]["declared"] = True
    if report["protection"]["source"] is None:
        report["protection"]["source"] = _source_id(evidence)


def _set_materials(report: dict[str, Any], required: list[str], present: list[str]) -> None:
    missing = [name for name in required if name not in present]
    if not required:
        status = "not_required"
    elif not missing:
        status = "complete"
    elif present:
        status = "partial"
    else:
        status = "absent"
    report["materials"] = {
        "status": status,
        "required": required,
        "present": present,
        "missing": missing,
    }


def _ole_names(ole: olefile.OleFileIO) -> dict[str, str]:
    names = {}
    for entry in ole.listdir():
        if len(entry) == 1:
            names[entry[0].lower()] = entry[0]
    return names


def _read_ole_prefix(ole: olefile.OleFileIO, name: str, length: int) -> bytes:
    with ole.openstream(name) as stream:
        return stream.read(length)


def _ooxml_method_from_prefix(prefix: bytes) -> tuple[str, str | None]:
    if len(prefix) < 4:
        return "unknown", "EncryptionInfo is too short to contain a version"

    major, minor = unpack("<HH", prefix[:4])
    version = "{}:{}".format(major, minor)
    if (major, minor) == (4, 4):
        return "agile", None
    if major in (2, 3, 4) and minor == 2:
        return "standard", None
    if major in (3, 4) and minor == 3:
        return "extensible", None
    return "unknown", "Unrecognized EncryptionInfo version {}".format(version)


def _legacy_method_from_prefix(prefix: bytes) -> tuple[str, str | None]:
    if len(prefix) < 4:
        return "unknown", "Encryption header is too short to contain a version"

    major, minor = unpack("<HH", prefix[:4])
    if (major, minor) == (1, 1):
        return "rc4", None
    if major in (2, 3, 4) and minor == 2:
        return "rc4_cryptoapi", None
    return "unknown", "Unrecognized encryption header version {}:{}".format(major, minor)


def _inspect_doc97(ole: olefile.OleFileIO, names: Mapping[str, str]) -> dict[str, Any]:
    report = _empty_report(None, b"", "ole")
    report["format"] = "doc97"
    word_stream = names.get("worddocument")
    present = [word_stream] if word_stream else []

    if word_stream is None:
        report["notes"].append("wordDocument stream is missing")
        _set_materials(report, ["wordDocument"], [])
        return report

    try:
        with ole.openstream(word_stream) as stream:
            fib = _parseFibBase(stream)
    except Exception as exc:
        report["notes"].append("Unable to parse the DOC FIB: {}".format(exc))
        _set_materials(report, ["wordDocument"], present)
        return report

    if fib.fEncrypted != 1:
        _set_materials(report, [], present)
        return report

    _add_source(
        report,
        _source(
            "ole-stream",
            word_stream,
            "FibBase.fEncrypted",
            fib.fEncrypted,
            "The DOC encryption flag is set.",
        ),
    )

    table_name = "1Table" if fib.fWhichTblStm == 1 else "0Table"
    if fib.fObfuscation == 1:
        report["protection"]["method"] = "xor"
        _add_source(
            report,
            _source(
                "ole-stream",
                word_stream,
                "FibBase.fObfuscation",
                fib.fObfuscation,
                "XOR obfuscation is declared.",
            ),
            declared=False,
        )
        _set_materials(report, [word_stream], present)
        return report

    required = [word_stream, table_name]
    table_stream = names.get(table_name.lower())
    if table_stream is not None:
        present.append(table_stream)
    _set_materials(report, required, present)

    if table_stream is None:
        report["protection"]["method"] = "unknown"
        return report

    try:
        with ole.openstream(table_stream) as stream:
            prefix = stream.read(4)
        method, note = _legacy_method_from_prefix(prefix)
        report["protection"]["method"] = method
        if note:
            report["notes"].append(note.replace("Encryption header", "{} encryption header".format(table_name)))
    except Exception as exc:
        report["protection"]["method"] = "unknown"
        report["notes"].append("Unable to parse the DOC encryption table: {}".format(exc))

    return report


def _find_biff_record(data: bytes, target: int) -> tuple[bytes | None, str | None]:
    offset = 0
    while offset + 4 <= len(data):
        number, size = unpack_from("<HH", data, offset)
        payload_start = offset + 4
        payload_end = payload_start + size
        if payload_end > len(data):
            return None, "Incomplete BIFF record payload at offset {}".format(offset)
        if number == target:
            return data[payload_start:payload_end], None
        if number == recordNameNum["EOF"]:
            return None, None
        offset = payload_end

    if offset != len(data):
        return None, "Incomplete BIFF record header at offset {}".format(offset)
    return None, None


def _inspect_xls97(ole: olefile.OleFileIO, names: Mapping[str, str]) -> dict[str, Any]:
    report = _empty_report(None, b"", "ole")
    report["format"] = "xls97"
    workbook_name = names.get("workbook")
    if workbook_name is None:
        report["notes"].append("Workbook stream is missing")
        _set_materials(report, ["Workbook"], [])
        return report

    try:
        with ole.openstream(workbook_name) as stream:
            workbook = stream.read()
    except Exception as exc:
        report["notes"].append("Unable to read the Workbook stream: {}".format(exc))
        _set_materials(report, ["Workbook"], [])
        return report

    filepass, parse_error = _find_biff_record(workbook, recordNameNum["FilePass"])
    if parse_error:
        report["notes"].append(parse_error)
        _set_materials(report, ["Workbook"], [workbook_name])
        return report

    if filepass is None:
        _set_materials(report, [], [workbook_name])
        return report

    _add_source(
        report,
        _source(
            "ole-stream",
            workbook_name,
            "FilePass",
            "present",
            "A Workbook FilePass record is present.",
        ),
    )
    required = [workbook_name, "FilePass payload"]
    present = [workbook_name]
    if len(filepass) >= 2:
        present.append("FilePass payload")
    _set_materials(report, required, present)

    if len(filepass) < 2:
        report["protection"]["method"] = "unknown"
        report["notes"].append("FilePass payload is too short to contain an encryption type")
        return report

    encryption_type = unpack("<H", filepass[:2])[0]
    if encryption_type == 0:
        report["protection"]["method"] = "xor"
    elif encryption_type == 1:
        if len(filepass) < 6:
            report["protection"]["method"] = "unknown"
            report["notes"].append("RC4 FilePass payload is too short to contain a version")
        else:
            method, note = _legacy_method_from_prefix(filepass[2:6])
            report["protection"]["method"] = method
            if note:
                report["notes"].append(note.replace("header", "FilePass"))
    else:
        report["protection"]["method"] = "unknown"
        report["notes"].append("Unrecognized FilePass encryption type {}".format(encryption_type))

    return report


def _inspect_ppt97(ole: olefile.OleFileIO, names: Mapping[str, str]) -> dict[str, Any]:
    report = _empty_report(None, b"", "ole")
    report["format"] = "ppt97"
    current_name = names.get("current user")
    document_name = names.get("powerpoint document")
    present = [name for name in (current_name, document_name) if name]

    if current_name is None or document_name is None:
        report["notes"].append("Current User or PowerPoint Document stream is missing")
        _set_materials(report, ["Current User", "PowerPoint Document"], present)
        return report

    try:
        with ole.openstream(current_name) as current_stream:
            current_bytes = current_stream.read()
            currentuser = _parseCurrentUser(io.BytesIO(current_bytes)).currentuseratom
        with ole.openstream(document_name) as document_stream:
            document_stream.seek(currentuser.offsetToCurrentEdit)
            usereditatom = _parseUserEditAtom(document_stream)
            audit = SimpleNamespace(
                currentuser=io.BytesIO(current_bytes),
                powerpointdocument=document_stream,
            )
            directory = construct_persistobjectdirectory(audit)
    except Exception as exc:
        report["notes"].append("Unable to parse the PPT user edit data: {}".format(exc))
        _set_materials(report, ["Current User", "PowerPoint Document"], present)
        return report

    reference = usereditatom.encryptSessionPersistIdRef
    declared = usereditatom.rh.recLen == 0x20 or reference not in (None, 0)
    if not declared:
        _set_materials(report, [], present)
        return report

    _add_source(
        report,
        _source(
            "ole-stream",
            document_name,
            "UserEditAtom.encryptSessionPersistIdRef",
            reference,
            "The PPT UserEditAtom declares an encryption session.",
        ),
    )

    required = [current_name, document_name, "CryptSession10Container"]
    if reference not in directory:
        _set_materials(report, required, present)
        report["protection"]["method"] = "unknown"
        report["notes"].append("The PPT persist directory has no CryptSession10Container for the declared reference")
        return report

    present.append("CryptSession10Container")
    _set_materials(report, required, present)
    try:
        with ole.openstream(document_name) as document_stream:
            document_stream.seek(directory[reference])
            container = _parseCryptSession10Container(document_stream)
            prefix = container.data[:4]
        method, note = _legacy_method_from_prefix(prefix)
        report["protection"]["method"] = method
        if note:
            report["notes"].append(note.replace("Encryption header", "CryptSession10Container encryption header"))
    except Exception as exc:
        report["protection"]["method"] = "unknown"
        report["notes"].append("Unable to parse the PPT CryptSession10Container: {}".format(exc))

    return report


def _inspect_ooxml_entries(entries: Mapping[str, Any], container_type: str) -> dict[str, Any]:
    report = _empty_report(None, b"", container_type)
    report["format"] = "ooxml"

    info_name = next((name for name in entries if name.lower() == "encryptioninfo"), None)
    package_name = next((name for name in entries if name.lower() == "encryptedpackage"), None)

    if info_name is None and package_name is None:
        _set_materials(report, [], [])
        return report

    info_ok = False
    if info_name is not None:
        source_kind = "ole-stream" if container_type == "ole" else "zip-entry"
        _add_source(
            report,
            _source(
                source_kind,
                info_name,
                "version",
                "present",
                "An EncryptionInfo entry is present.",
            ),
        )
        try:
            prefix = entries[info_name](4)
            info_ok = len(prefix) >= 4
            method, note = _ooxml_method_from_prefix(prefix)
        except Exception as exc:
            method = "unknown"
            note = "Unable to read EncryptionInfo: {}".format(exc)
        report["protection"]["method"] = method
        if note:
            report["notes"].append(note)
    else:
        report["protection"]["indicated"] = True
        report["protection"]["method"] = "unknown"
        report["notes"].append("EncryptedPackage is present without EncryptionInfo")

    package_ok = False
    if package_name is not None:
        try:
            package_ok = len(entries[package_name](1)) == 1
        except Exception as exc:
            report["notes"].append("Unable to read EncryptedPackage: {}".format(exc))

    required = ["EncryptionInfo", "EncryptedPackage"]
    canonical_present = []
    if info_ok:
        canonical_present.append("EncryptionInfo")
    if package_ok:
        canonical_present.append("EncryptedPackage")
    if info_name is not None and not info_ok:
        report["notes"].append("EncryptionInfo is empty or truncated")
    _set_materials(report, required, canonical_present)
    return report


def _inspect_ole(data: bytes) -> dict[str, Any]:
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:
        report = _empty_report(None, data, "ole")
        report["notes"].append("Unable to read the OLE container: {}".format(exc))
        return report

    try:
        names = _ole_names(ole)

        def reader(name: str):
            return lambda length: _read_ole_prefix(ole, name, length)

        if "encryptioninfo" in names:
            entries = {names["encryptioninfo"]: reader(names["encryptioninfo"])}
            if "encryptedpackage" in names:
                entries[names["encryptedpackage"]] = reader(names["encryptedpackage"])
            report = _inspect_ooxml_entries(entries, "ole")
        elif "encryptedpackage" in names:
            report = _inspect_ooxml_entries(
                {names["encryptedpackage"]: reader(names["encryptedpackage"])},
                "ole",
            )
        elif "worddocument" in names:
            report = _inspect_doc97(ole, names)
        elif "workbook" in names:
            report = _inspect_xls97(ole, names)
        elif "powerpoint document" in names:
            report = _inspect_ppt97(ole, names)
        else:
            report = _empty_report(None, data, "ole")
            report["notes"].append("No recognized Office stream was found in the OLE container")
            _set_materials(report, [], [])
        return report
    finally:
        ole.close()


def _zip_is_ooxml(archive: zipfile.ZipFile) -> bool:
    try:
        xml = parseString(archive.read("[Content_Types].xml"))
        return xml.documentElement.tagName == "Types" and xml.documentElement.namespaceURI == _OOXML_CONTENT_TYPES_NS
    except Exception:
        return False


def _inspect_zip(data: bytes) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        report = _empty_report(None, data, "zip")
        report["notes"].append("Unable to read the ZIP container: {}".format(exc))
        return report

    with archive:
        if not _zip_is_ooxml(archive):
            report = _empty_report(None, data, "zip")
            report["notes"].append("The ZIP container is not an OOXML package")
            _set_materials(report, [], [])
            return report

        def reader(name: str):
            def read_prefix(length: int) -> bytes:
                with archive.open(name) as stream:
                    return stream.read(length)

            return read_prefix

        root_entries = {name for name in archive.namelist() if "/" not in name}
        protection_entries = {name: reader(name) for name in root_entries if name.lower() in ("encryptioninfo", "encryptedpackage")}
        return _inspect_ooxml_entries(protection_entries, "zip")


def _finalize(report: dict[str, Any]) -> dict[str, Any]:
    protection = report["protection"]
    materials = report["materials"]
    declared = protection["declared"]
    indicated = protection["indicated"]
    material_status = materials["status"]

    if declared and material_status in ("partial", "absent"):
        code = "protection_incomplete"
        statement = "Protection is declared, but required material is missing: {}.".format(", ".join(materials["missing"]))
    elif declared:
        code = "protection_declared"
        statement = "Protection is declared by the recorded source; no decryption was attempted."
    elif indicated and material_status in ("partial", "absent", "unknown"):
        code = "protection_incomplete"
        statement = "Protection material is present, but the evidence is incomplete or inconsistent."
    elif report["format"] != "unknown" and material_status in (
        "not_required",
        "complete",
    ):
        code = "not_protected"
        statement = "No protection declaration was found in the recognized Office container."
    else:
        code = "unknown"
        statement = "The container or protection markers are not recognized; no protection conclusion is possible."

    report["conclusion"] = {
        "code": code,
        "statement": statement,
        "limits": [_NO_DECRYPTION_LIMIT, _PERMISSIONS_LIMIT],
    }
    return report


def inspect_file(source: Any, *, filename: str | None = None) -> dict[str, Any]:
    """Inspect Office protection markers without decrypting the input.

    Args:
        source: A path, bytes, or binary file-like object.
        filename: Optional display name for bytes or unnamed file handles.

    Returns:
        A JSON-compatible report. The original container type is recorded in
        container_type; format is the logical Office format.
    """
    data, name = _read_source(source, filename)
    if data.startswith(_OLE_MAGIC):
        report = _inspect_ole(data)
    elif data.startswith(_ZIP_MAGICS):
        report = _inspect_zip(data)
    else:
        report = _empty_report(None, data, "unknown")
        report["notes"].append("The input does not have a recognized OLE or ZIP signature")
        _set_materials(report, [], [])

    report["file"] = {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    return _finalize(report)


def render_json(report: Mapping[str, Any], *, indent: int = 2) -> str:
    """Render a report as deterministic JSON."""
    return json.dumps(report, indent=indent, ensure_ascii=False, default=str)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _join(value: Any) -> str:
    if not value:
        return "none"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)
    return str(value)


def render_text(report: Mapping[str, Any]) -> str:
    """Render a report as compact plain text, tolerating unknown fields."""
    file_info = _mapping(report.get("file"))
    protection = _mapping(report.get("protection"))
    materials = _mapping(report.get("materials"))
    conclusion = _mapping(report.get("conclusion"))
    sources = protection.get("sources")
    if not isinstance(sources, list):
        sources = []

    lines = [
        "File: {}".format(file_info.get("name") or "<unnamed>"),
        "Container: {} / {}".format(report.get("container_type", "unknown"), report.get("format", "unknown")),
        "Protection: {} (method: {})".format(
            "declared" if protection.get("declared") else "not declared",
            protection.get("method") or "unknown",
        ),
    ]
    if sources:
        for evidence in sources:
            if isinstance(evidence, Mapping):
                lines.append("Source: {}".format(_source_id(evidence)))
            else:
                lines.append("Source: {}".format(evidence))
    else:
        lines.append("Source: none observed")

    missing = materials.get("missing") or []
    lines.append("Materials: {}".format(materials.get("status", "unknown")))
    if missing:
        lines.append("Missing: {}".format(_join(missing)))
    lines.append("Conclusion: {}".format(conclusion.get("code", "unknown")))
    if conclusion.get("statement"):
        lines.append("Basis: {}".format(conclusion["statement"]))

    extras = sorted(key for key in report if key not in _KNOWN_REPORT_KEYS)
    if extras:
        lines.append("Unknown fields: {}".format(", ".join(extras)))
        for key in extras:
            lines.append("  {}: {}".format(key, json.dumps(report[key], ensure_ascii=False, default=str)))
    if report.get("notes"):
        lines.append("Notes: {}".format("; ".join(str(note) for note in report["notes"])))
    return "\n".join(lines)


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render a report as Markdown, preserving unknown fields verbatim."""
    file_info = _mapping(report.get("file"))
    protection = _mapping(report.get("protection"))
    materials = _mapping(report.get("materials"))
    conclusion = _mapping(report.get("conclusion"))
    sources = protection.get("sources")
    if not isinstance(sources, list):
        sources = []

    lines = [
        "# Protection report: {}".format(file_info.get("name") or "<unnamed>"),
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Container | {} |".format(report.get("container_type", "unknown")),
        "| Format | {} |".format(report.get("format", "unknown")),
        "| Protection declared | {} |".format(bool(protection.get("declared"))),
        "| Method | {} |".format(protection.get("method") or "unknown"),
        "| Materials | {} |".format(materials.get("status", "unknown")),
        "| Conclusion | {} |".format(conclusion.get("code", "unknown")),
        "",
        "## Protection sources",
        "",
    ]
    if sources:
        for evidence in sources:
            if isinstance(evidence, Mapping):
                lines.append("- {}: {}".format(_source_id(evidence), evidence.get("proves", "")))
            else:
                lines.append("- {}".format(evidence))
    else:
        lines.append("None observed.")

    lines.extend(["", "## Materials", ""])
    lines.append("- Present: {}".format(_join(materials.get("present"))))
    lines.append("- Missing: {}".format(_join(materials.get("missing"))))
    lines.extend(
        [
            "",
            "## Minimal conclusion",
            "",
            str(conclusion.get("statement", "Unknown.")),
        ]
    )
    limits = conclusion.get("limits") or []
    if isinstance(limits, list) and limits:
        lines.append("")
        for limit in limits:
            lines.append("- {}".format(limit))

    extras = sorted(key for key in report if key not in _KNOWN_REPORT_KEYS)
    if extras:
        lines.extend(["", "## Unknown fields", ""])
        for key in extras:
            lines.append("- {}: {}".format(key, json.dumps(report[key], ensure_ascii=False, default=str)))
    if report.get("notes"):
        lines.extend(["", "## Notes", ""])
        for note in report["notes"]:
            lines.append("- {}".format(note))
    return "\n".join(lines)


def render_report(report: Mapping[str, Any], *, format: str = "text") -> str:
    """Render a report in text, markdown, or json form."""
    if format == "json":
        return render_json(report)
    if format == "markdown":
        return render_markdown(report)
    if format == "text":
        return render_text(report)
    raise ValueError("Unsupported report format: {}".format(format))


def render_comparison(reports: Iterable[Mapping[str, Any]]) -> str:
    """Render several reports as a stable Markdown comparison table."""
    lines = [
        "| File | Container | Format | Declared | Method | Materials | Conclusion |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for report in reports:
        file_info = _mapping(report.get("file"))
        protection = _mapping(report.get("protection"))
        materials = _mapping(report.get("materials"))
        conclusion = _mapping(report.get("conclusion"))
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                file_info.get("name") or "<unnamed>",
                report.get("container_type", "unknown"),
                report.get("format", "unknown"),
                bool(protection.get("declared")),
                protection.get("method") or "unknown",
                materials.get("status", "unknown"),
                conclusion.get("code", "unknown"),
            )
        )
    return "\n".join(lines)


protection_report = inspect_file
