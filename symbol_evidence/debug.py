"""Read-only extraction of CodeView identities from a PE image."""

import hashlib
import os
import uuid

import pefile

from .model import DebugIdentity, parse_identity_value

DEBUG_TYPE_CODEVIEW = 2


class PEImage:
    """The PE evidence side of a report."""

    def __init__(self, path, pe, sha256, size, identities, warnings=None):
        self.path = path
        self.pe = pe
        self.sha256 = sha256
        self.size = size
        self.identities = list(identities)
        self.warnings = list(warnings or [])

    def to_dict(self):
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "debug_record_count": len(self.identities),
            "debug_records": [identity.to_dict() for identity in self.identities],
            "warnings": self.warnings,
        }


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).replace("\x00", "").strip()


def _rsds_guid(entry):
    fields = []
    for name in (
        "Signature_Data1",
        "Signature_Data2",
        "Signature_Data3",
        "Signature_Data4",
        "Signature_Data5",
        "Signature_Data6_value",
    ):
        value = getattr(entry, name, None)
        if value is None:
            fields = []
            break
        fields.append(value)
    if len(fields) == 6:
        try:
            return uuid.UUID(fields=tuple(fields)).hex
        except (ValueError, TypeError):
            pass
    signature_string = _entry_text(getattr(entry, "Signature_String", None))
    _kind, guid, _age = parse_identity_value(signature_string)
    return guid


def _identity_from_debug_entry(dbg, index):
    if getattr(dbg, "struct", None) is None:
        return None
    if getattr(dbg.struct, "Type", None) != DEBUG_TYPE_CODEVIEW:
        return None
    entry = getattr(dbg, "entry", None)
    if entry is None:
        return None

    pdb_path = _entry_text(getattr(entry, "PdbFileName", None))
    cv_signature = getattr(entry, "CvSignature", None)
    cv_header = getattr(entry, "CvHeaderSignature", None)
    if cv_signature == b"RSDS" or cv_header == 0x53445352:
        kind = "rsds"
        guid = _rsds_guid(entry)
        age = getattr(entry, "Age", None)
        signature = None
    elif cv_header == 0x3031424E or cv_signature == b"NB10":
        kind = "nb10"
        guid = None
        age = getattr(entry, "Age", None)
        raw_signature = getattr(entry, "Signature", None)
        signature = "%08X" % raw_signature if isinstance(raw_signature, int) else None
    else:
        return None

    raw = {
        "Type": getattr(dbg.struct, "Type", None),
        "SizeOfData": getattr(dbg.struct, "SizeOfData", None),
        "PointerToRawData": getattr(dbg.struct, "PointerToRawData", None),
        "PdbFileName": pdb_path or None,
        "Age": age,
        "Signature_String": _entry_text(getattr(entry, "Signature_String", None))
        or None,
    }
    return DebugIdentity(
        kind=kind,
        pdb_path=pdb_path,
        guid=guid,
        age=age,
        signature=signature,
        signature_string=getattr(entry, "Signature_String", None),
        debug_index=index,
        raw=raw,
    )


def extract_debug_identities(pe):
    """Return CodeView identities from ``pe.DIRECTORY_ENTRY_DEBUG``.

    This never writes to the PE and never follows the PDB path.  Multiple
    CodeView records are returned as a list rather than silently choosing the
    first one.
    """

    identities = []
    entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", None) or []
    for index, dbg in enumerate(entries):
        identity = _identity_from_debug_entry(dbg, index)
        if identity is not None:
            identities.append(identity)
    return identities


def extract_debug_identity(pe):
    """Return the first CodeView identity, or ``None`` when there is none."""

    identities = extract_debug_identities(pe)
    return identities[0] if identities else None


def _pe_warnings(pe):
    warnings = []
    getter = getattr(pe, "get_warnings", None)
    if callable(getter):
        try:
            warnings = list(getter())
        except (TypeError, ValueError):
            warnings = []
    return warnings


def load_pe_image(path=None, pe=None, data=None, sha256=None):
    """Load a PE once and return path, SHA-256, size, identities, warnings."""

    if isinstance(pe, PEImage):
        return pe
    if pe is None:
        if data is not None:
            pe = pefile.PE(data=data)
        elif path is not None:
            pe = pefile.PE(path, fast_load=False)
        else:
            raise ValueError("load_pe_image requires path, pe, or data")

    if path is not None and os.path.exists(path):
        sha256 = file_sha256(path)
        size = os.path.getsize(path)
    elif data is not None:
        sha256 = hashlib.sha256(data).hexdigest()
        size = len(data)
    else:
        size = None

    identities = extract_debug_identities(pe)
    warnings = _pe_warnings(pe)
    if not identities:
        warnings.append("PE 未包含可读取的 CodeView(RSDS/NB10) 调试记录")
    if len(identities) > 1:
        warnings.append("PE 包含多条 CodeView 调试记录，需按记录逐条比对")
    return PEImage(path, pe, sha256, size, identities, warnings)


read_pe_identity = load_pe_image
