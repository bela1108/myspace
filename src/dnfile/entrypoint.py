# -*- coding: utf-8 -*-
"""
CLI entry-point resolution.

The CLI header stores one 32-bit value, ``EntryPointTokenOrRva``.  The value
is not self-describing: ``COMIMAGE_FLAGS_NATIVE_ENTRYPOINT`` decides whether
it is a native RVA or a metadata token.  This module keeps that distinction
explicit and cross-checks the selected target against the PE section map.

The resolver is deliberately tolerant of damaged metadata.  The raw CLI
header declaration is always returned, even when the metadata tables needed
to expand a token cannot be read.
"""
import dataclasses
import enum
from typing import Any, Dict, List, Optional, Tuple


# IMAGE_COR20_HEADER flags (CorHdr.h).
COMIMAGE_FLAGS_ILONLY = 0x00000001
COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004
COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010

# Metadata table numbers that are legal in an EntryPointToken.
TABLE_METHODDEF = 0x06
TABLE_FILE = 0x26

IMAGE_SCN_MEM_EXECUTE = 0x20000000

_TOKEN_TABLE_NAMES = {
    0x00: "Module",
    0x01: "TypeRef",
    0x02: "TypeDef",
    0x03: "FieldPtr",
    0x04: "Field",
    0x05: "MethodPtr",
    0x06: "MethodDef",
    0x07: "ParamPtr",
    0x08: "Param",
    0x09: "InterfaceImpl",
    0x0A: "MemberRef",
    0x0B: "Constant",
    0x0C: "CustomAttribute",
    0x0D: "FieldMarshal",
    0x0E: "DeclSecurity",
    0x0F: "ClassLayout",
    0x10: "FieldLayout",
    0x11: "StandAloneSig",
    0x12: "EventMap",
    0x13: "EventPtr",
    0x14: "Event",
    0x15: "PropertyMap",
    0x16: "PropertyPtr",
    0x17: "Property",
    0x18: "MethodSemantics",
    0x19: "MethodImpl",
    0x1A: "ModuleRef",
    0x1B: "TypeSpec",
    0x1C: "ImplMap",
    0x1D: "FieldRva",
    0x1E: "EncLog",
    0x1F: "EncMap",
    0x20: "Assembly",
    0x21: "AssemblyProcessor",
    0x22: "AssemblyOS",
    0x23: "AssemblyRef",
    0x24: "AssemblyRefProcessor",
    0x25: "AssemblyRefOS",
    0x26: "File",
    0x27: "ExportedType",
    0x28: "ManifestResource",
    0x29: "NestedClass",
    0x2A: "GenericParam",
    0x2B: "MethodSpec",
    0x2C: "GenericParamConstraint",
}


class EntryPointKind(str, enum.Enum):
    """The target category declared by the CLI header."""

    NONE = "none"
    METHOD = "method"
    FILE = "file"
    NATIVE = "native"
    INVALID = "invalid"

    def __str__(self) -> str:
        return self.value


class EntryPointStatus(str, enum.Enum):
    """How well the declared target could be verified."""

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    CONTRADICTORY = "contradictory"

    def __str__(self) -> str:
        return self.value


@dataclasses.dataclass(frozen=True)
class PeAddress:
    """A PE RVA and the section/file mapping that applies to it."""

    rva: int
    mapped: bool
    in_section: bool
    section: Optional[str]
    section_index: Optional[int]
    file_offset: Optional[int]
    raw_available: bool
    executable: Optional[bool]
    size_of_image: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class EntryPoint:
    """The entry-point declaration and everything that could be verified.

    ``raw_value`` and ``raw_flags`` are always the values read from the CLI
    header.  They do not depend on metadata being parseable.
    """

    kind: EntryPointKind
    status: EntryPointStatus
    raw_value: int
    raw_flags: int
    declared_slot: str
    native_entrypoint_flag: bool
    ilonly: bool
    il_library: bool
    token: Optional[int]
    token_table: Optional[int]
    token_table_name: Optional[str]
    rid: Optional[int]
    method: Optional[Any]
    file: Optional[Any]
    native_address: Optional[PeAddress]
    method_address: Optional[PeAddress]
    reasons: Tuple[str, ...]
    reason_codes: Tuple[str, ...]
    conflicts: Tuple[str, ...]
    conflict_codes: Tuple[str, ...]
    metadata_available: bool

    @property
    def reason(self) -> str:
        """A single human-readable reason string."""

        return " ".join(self.reasons)

    @property
    def mapped(self) -> bool:
        address = self.native_address or self.method_address
        return bool(address and address.mapped)

    @property
    def rva(self) -> Optional[int]:
        if self.native_address is not None:
            return self.native_address.rva
        if self.method_address is not None:
            return self.method_address.rva
        return None

    @property
    def file_offset(self) -> Optional[int]:
        address = self.native_address or self.method_address
        return address.file_offset if address else None

    @property
    def valid(self) -> bool:
        return self.status is not EntryPointStatus.CONTRADICTORY

    @property
    def is_native(self) -> bool:
        return self.native_entrypoint_flag

    @property
    def entry_point_token(self) -> Optional[int]:
        return None if self.native_entrypoint_flag else self.raw_value

    @property
    def entry_point_rva(self) -> Optional[int]:
        return self.raw_value if self.native_entrypoint_flag else None

    @property
    def raw_entry_point_token_or_rva(self) -> int:
        """The exact CLI header field, without interpretation."""

        return self.raw_value

    @property
    def target(self) -> Any:
        if self.native_address is not None:
            return self.native_address
        if self.method is not None:
            return self.method
        if self.file is not None:
            return self.file
        return None

    @property
    def method_body_kind(self) -> Optional[str]:
        """Body kind for a MethodDef entry, independent of the slot encoding."""

        if self.method is None:
            return None
        impl_names = _method_impl_names(self.method)
        if "miNative" in impl_names or "miUnmanaged" in impl_names:
            return "native"
        if "miIL" in impl_names:
            return "il"
        if "miOPTIL" in impl_names:
            return "optil"
        if "miRuntime" in impl_names:
            return "runtime"
        return "unknown"

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation.

        Metadata row objects are intentionally represented by their token
        metadata, not by their full object graph.
        """

        method = None
        if self.method is not None:
            method = {
                "name": _text_or_none(getattr(self.method, "Name", None)),
                "rva": getattr(self.method, "Rva", None),
                "body_kind": self.method_body_kind,
                "impl_flags": _method_impl_names(self.method),
            }

        external_file = None
        if self.file is not None:
            external_file = {
                "name": _text_or_none(getattr(self.file, "Name", None)),
            }

        return {
            "kind": self.kind.value,
            "status": self.status.value,
            "valid": self.valid,
            "raw_value": self.raw_value,
            "raw_flags": self.raw_flags,
            "entry_point_token": self.entry_point_token,
            "entry_point_rva": self.entry_point_rva,
            "declared_slot": self.declared_slot,
            "native_entrypoint_flag": self.native_entrypoint_flag,
            "ilonly": self.ilonly,
            "il_library": self.il_library,
            "token": self.token,
            "token_table": self.token_table,
            "token_table_name": self.token_table_name,
            "rid": self.rid,
            "method": method,
            "file": external_file,
            "native_address": self.native_address.to_dict() if self.native_address else None,
            "method_address": self.method_address.to_dict() if self.method_address else None,
            "reasons": list(self.reasons),
            "reason_codes": list(self.reason_codes),
            "conflicts": list(self.conflicts),
            "conflict_codes": list(self.conflict_codes),
            "metadata_available": self.metadata_available,
        }


def _coerce_pe(value: Any) -> Any:
    """Accept either a dnPE or one of its ClrData objects."""

    if hasattr(value, "net"):
        return value
    parent = getattr(value, "_pe", None)
    if parent is not None:
        return parent
    return value


def _read_pe_header(pe: Any) -> Tuple[Optional[Any], Optional[int], Optional[int]]:
    net = getattr(pe, "net", None)
    if net is None:
        return None, None, None

    struct_ = getattr(net, "struct", None)
    if struct_ is None:
        return net, None, None

    return net, getattr(struct_, "Flags", None), getattr(struct_, "EntryPointTokenOrRva", None)


def _metadata_tables(pe: Any) -> Optional[Any]:
    net = getattr(pe, "net", None)
    if net is None:
        return None

    try:
        return getattr(net, "mdtables", None)
    except Exception:
        # A lazy table may fail while being expanded.  The raw CLI header is
        # still usable, so callers should receive the degraded result.
        return None


def _table_rows(pe: Any, table_name: str) -> Tuple[Optional[Any], Optional[str]]:
    mdtables = _metadata_tables(pe)
    if mdtables is None:
        return None, "metadata tables are unavailable"

    try:
        table = getattr(mdtables, table_name, None)
    except Exception as error:
        return None, "metadata table {0} could not be read: {1}".format(table_name, error)

    if table is None:
        return None, "metadata table {0} is not present".format(table_name)

    return table, None


def _get_row(table: Any, rid: int) -> Tuple[Optional[Any], Optional[str], bool]:
    """Fetch a 1-based row.

    The third result is true when the row is inside the declared range but
    its bytes were not loaded, which means the metadata is incomplete rather
    than semantically contradictory.
    """

    try:
        num_rows = int(getattr(table, "num_rows", 0))
    except Exception:
        num_rows = 0

    if rid < 1 or rid > num_rows:
        return None, "row {0} is outside the declared range 1..{1}".format(rid, num_rows), False

    try:
        row = table.get_with_row_index(rid)
    except Exception as error:
        return None, "row {0} could not be read: {1}".format(rid, error), True

    if row is None:
        return None, "row {0} has not been loaded".format(rid), True

    return row, None, False


def _section_name(section: Any) -> Optional[str]:
    name = getattr(section, "Name", None)
    if isinstance(name, bytes):
        try:
            return name.rstrip(b"\x00").decode("utf-8", "replace")
        except Exception:
            return repr(name)
    if isinstance(name, str):
        return name.rstrip("\x00")
    return None


def _text_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _is_raw_available(pe: Any, address: PeAddress) -> bool:
    if address.file_offset is None:
        return False
    try:
        return len(pe.get_data(address.rva, 1)) == 1
    except Exception:
        return False


def _map_rva(pe: Any, rva: int) -> PeAddress:
    """Map an RVA using the PE headers without assuming it is valid."""

    optional_header = getattr(pe, "OPTIONAL_HEADER", None)
    size_of_image = getattr(optional_header, "SizeOfImage", None)
    size_of_headers = getattr(optional_header, "SizeOfHeaders", None)
    address = PeAddress(
        rva=rva,
        mapped=False,
        in_section=False,
        section=None,
        section_index=None,
        file_offset=None,
        raw_available=False,
        executable=None,
        size_of_image=size_of_image,
    )

    try:
        sections = list(getattr(pe, "sections", []) or [])
    except Exception:
        sections = []

    for index, section in enumerate(sections):
        virtual_address = int(getattr(section, "VirtualAddress", 0))
        virtual_size = int(getattr(section, "Misc_VirtualSize", 0) or 0)
        raw_size = int(getattr(section, "SizeOfRawData", 0) or 0)
        raw_pointer = int(getattr(section, "PointerToRawData", 0) or 0)
        extent = max(virtual_size, raw_size)
        if extent <= 0:
            continue
        if not (virtual_address <= rva < virtual_address + extent):
            continue

        delta = rva - virtual_address
        file_offset = None
        if delta < raw_size and raw_pointer:
            file_offset = raw_pointer + delta

        characteristics = int(getattr(section, "Characteristics", 0) or 0)
        address = dataclasses.replace(
            address,
            mapped=True,
            in_section=True,
            section=_section_name(section),
            section_index=index,
            file_offset=file_offset,
            executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
        )
        address = dataclasses.replace(
            address,
            raw_available=_is_raw_available(pe, address),
        )
        return address

    # RVAs below SizeOfHeaders are valid image addresses but do not belong to
    # a section.  They are still useful to report when a broken header points
    # the entry slot into the PE headers.
    if size_of_headers is not None and 0 <= rva < size_of_headers:
        address = dataclasses.replace(
            address,
            mapped=True,
            file_offset=rva,
            executable=False,
        )
        address = dataclasses.replace(
            address,
            raw_available=_is_raw_available(pe, address),
        )
        return address

    if size_of_image is not None and 0 <= rva < size_of_image:
        return dataclasses.replace(address, mapped=True, executable=False)

    return address


def _token_parts(value: int) -> Tuple[int, int, str]:
    table = (value >> 24) & 0xFF
    rid = value & 0x00FFFFFF
    return table, rid, _TOKEN_TABLE_NAMES.get(table, "table 0x{0:02x}".format(table))


def _in_clr_metadata(pe: Any, rva: int) -> bool:
    net = getattr(pe, "net", None)
    struct_ = getattr(net, "struct", None)
    if struct_ is None:
        return False
    start = getattr(struct_, "MetaDataRva", 0) or 0
    size = getattr(struct_, "MetaDataSize", 0) or 0
    return bool(start and size and start <= rva < start + size)


def _method_impl_names(method: Any) -> List[str]:
    impl = getattr(method, "ImplFlags", None)
    if impl is None:
        return []
    return [
        name
        for name in (
            "miIL",
            "miNative",
            "miOPTIL",
            "miRuntime",
            "miManaged",
            "miUnmanaged",
        )
        if getattr(impl, name, False)
    ]


def _resolve_method(pe: Any, token: int, rid: int, reasons: List[str], reason_codes: List[str],
                    conflicts: List[str], conflict_codes: List[str]) -> Tuple[EntryPointKind, EntryPointStatus,
                                                                                Optional[Any], Optional[PeAddress],
                                                                                bool]:
    metadata_available = _metadata_tables(pe) is not None
    reasons.append("Entry slot 0x{0:08x} is a MethodDef token (table 0x06, RID {1}).".format(token, rid))
    reason_codes.append("slot.method_token")

    table, error = _table_rows(pe, "MethodDef")
    if table is None:
        reasons.append(
            "The MethodDef token is recorded verbatim, but it cannot be expanded: {0}.".format(error)
        )
        if metadata_available:
            message = "MethodDef token 0x{0:08x} does not resolve because the MethodDef table is missing.".format(token)
            reasons.append(message)
            conflicts.append(message)
            reason_codes.append("token.unresolved_table")
            conflict_codes.append("conflict.method_table_missing")
            return EntryPointKind.METHOD, EntryPointStatus.CONTRADICTORY, None, None, metadata_available
        reason_codes.append("token.unresolved_metadata")
        return EntryPointKind.METHOD, EntryPointStatus.UNVERIFIED, None, None, metadata_available

    method, error, incomplete = _get_row(table, rid)
    if method is None:
        message = "MethodDef token 0x{0:08x} does not resolve: {1}.".format(token, error)
        reasons.append(message)
        if incomplete:
            reason_codes.append("token.unresolved_incomplete")
            return EntryPointKind.METHOD, EntryPointStatus.UNVERIFIED, None, None, metadata_available
        conflicts.append(message)
        reason_codes.append("token.unresolved_row")
        conflict_codes.append("conflict.method_row_missing")
        return EntryPointKind.METHOD, EntryPointStatus.CONTRADICTORY, None, None, metadata_available

    struct_ = getattr(method, "struct", None)
    if struct_ is not None and not hasattr(struct_, "Rva"):
        message = "MethodDef row {0} is present but its bytes are incomplete.".format(rid)
        reasons.append(message)
        reason_codes.append("token.unresolved_incomplete")
        return EntryPointKind.METHOD, EntryPointStatus.UNVERIFIED, None, None, metadata_available

    name = _text_or_none(getattr(method, "Name", None))
    if not name:
        name = "<unreadable>"
    reasons.append(
        "MethodDef row {0} is {1!r}; the entry declaration is a managed method token, not a native RVA.".format(
            rid, name
        )
    )
    reason_codes.append("method.resolved")

    impl_names = _method_impl_names(method)
    if impl_names:
        reasons.append("MethodDef ImplFlags: {0}.".format(", ".join(impl_names)))
        reason_codes.append("method.impl_flags")
        if "miNative" in impl_names or "miUnmanaged" in impl_names:
            reasons.append(
                "The method body is native, but the entry slot remains the MethodDef token; "
                "it is not reinterpreted as a native RVA."
            )
            reason_codes.append("method.native_body")

    method_rva = getattr(method, "Rva", None)
    if method_rva is None:
        try:
            method_rva = getattr(getattr(method, "struct", None), "Rva", None)
        except Exception:
            method_rva = None

    if not method_rva:
        message = "MethodDef row {0} has RVA 0, so it has no body to use as an entry target.".format(rid)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("method.rva_zero")
        conflict_codes.append("conflict.method_rva_missing")
        return EntryPointKind.METHOD, EntryPointStatus.CONTRADICTORY, method, None, metadata_available

    address = _map_rva(pe, int(method_rva))
    if not address.mapped:
        message = "MethodDef RVA 0x{0:x} is not mapped by the PE image.".format(method_rva)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("pe.unmapped")
        conflict_codes.append("conflict.method_rva_unmapped")
        return EntryPointKind.METHOD, EntryPointStatus.CONTRADICTORY, method, address, metadata_available

    if _in_clr_metadata(pe, int(method_rva)):
        message = "MethodDef entry RVA 0x{0:x} points inside the CLR metadata stream.".format(method_rva)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("method.rva_in_clr_metadata")
        conflict_codes.append("conflict.method_rva_in_metadata")

    reasons.append(
        "Managed method RVA 0x{0:x} maps to {1}{2}; raw data is {3}.".format(
            method_rva,
            address.section or "the PE headers",
            "" if address.file_offset is None else " at file offset 0x{0:x}".format(address.file_offset),
            "available" if address.raw_available else "not available",
        )
    )
    reason_codes.append("pe.mapped")

    flags = getattr(method, "Flags", None)
    if flags is not None and not getattr(flags, "mdStatic", True):
        message = "MethodDef row {0} is not static; an entry point must be a static method.".format(rid)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("method.not_static")
        conflict_codes.append("conflict.method_not_static")

    if flags is not None and getattr(flags, "mdAbstract", False):
        message = "MethodDef row {0} is abstract and has no implementation to enter.".format(rid)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("method.abstract")
        conflict_codes.append("conflict.method_abstract")

    if flags is not None and getattr(flags, "mdPinvokeImpl", False):
        message = "MethodDef row {0} is a P/Invoke stub, not an entry-point implementation.".format(rid)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("method.pinvoke")
        conflict_codes.append("conflict.method_pinvoke")

    if not address.executable:
        message = "MethodDef RVA 0x{0:x} maps to a non-executable section.".format(method_rva)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("pe.nonexecutable")
        conflict_codes.append("conflict.method_rva_nonexecutable")

    status = EntryPointStatus.CONTRADICTORY if conflicts else EntryPointStatus.VERIFIED
    return EntryPointKind.METHOD, status, method, address, metadata_available


def _resolve_file(pe: Any, token: int, rid: int, reasons: List[str], reason_codes: List[str],
                  conflicts: List[str], conflict_codes: List[str]) -> Tuple[EntryPointKind, EntryPointStatus,
                                                                              Optional[Any], bool]:
    metadata_available = _metadata_tables(pe) is not None
    reasons.append("Entry slot 0x{0:08x} is a File token (table 0x26, RID {1}).".format(token, rid))
    reason_codes.append("slot.file_token")

    table, error = _table_rows(pe, "File")
    if table is None:
        reasons.append(
            "The File token is recorded verbatim, but it cannot be expanded: {0}.".format(error)
        )
        if metadata_available:
            message = "File token 0x{0:08x} does not resolve because the File table is missing.".format(token)
            reasons.append(message)
            conflicts.append(message)
            reason_codes.append("token.unresolved_table")
            conflict_codes.append("conflict.file_table_missing")
            return EntryPointKind.FILE, EntryPointStatus.CONTRADICTORY, None, metadata_available
        reason_codes.append("token.unresolved_metadata")
        return EntryPointKind.FILE, EntryPointStatus.UNVERIFIED, None, metadata_available

    file_row, error, incomplete = _get_row(table, rid)
    if file_row is None:
        message = "File token 0x{0:08x} does not resolve: {1}.".format(token, error)
        reasons.append(message)
        if incomplete:
            reason_codes.append("token.unresolved_incomplete")
            return EntryPointKind.FILE, EntryPointStatus.UNVERIFIED, None, metadata_available
        conflicts.append(message)
        reason_codes.append("token.unresolved_row")
        conflict_codes.append("conflict.file_row_missing")
        return EntryPointKind.FILE, EntryPointStatus.CONTRADICTORY, None, metadata_available

    struct_ = getattr(file_row, "struct", None)
    if struct_ is not None and not hasattr(struct_, "Name_StringIndex"):
        message = "File row {0} is present but its bytes are incomplete.".format(rid)
        reasons.append(message)
        reason_codes.append("token.unresolved_incomplete")
        return EntryPointKind.FILE, EntryPointStatus.UNVERIFIED, None, metadata_available

    name = _text_or_none(getattr(file_row, "Name", None))
    if not name:
        name = "<unreadable>"
    reasons.append(
        "File row {0} names {1!r}; this module delegates its entry point to an external file.".format(rid, name)
    )
    reason_codes.append("file.resolved")

    flags = getattr(file_row, "Flags", None)
    if flags is not None and getattr(flags, "ffContainsNoMetaData", False):
        message = "File row {0} names a resource/non-metadata file, so it cannot supply a CLI entry point.".format(rid)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("file.not_metadata")
        conflict_codes.append("conflict.file_not_metadata")

    reasons.append("External files are not mapped through this module's PE section table.")
    reason_codes.append("file.external")
    status = EntryPointStatus.CONTRADICTORY if conflicts else EntryPointStatus.VERIFIED
    return EntryPointKind.FILE, status, file_row, metadata_available


def _resolve_native(pe: Any, raw_value: int, reasons: List[str], reason_codes: List[str],
                    conflicts: List[str], conflict_codes: List[str]) -> Tuple[EntryPointKind, EntryPointStatus,
                                                                               Optional[PeAddress]]:
    reasons.append(
        "CLR_NATIVE_ENTRYPOINT (0x{0:08x}) is set, so the entry slot is a native RVA, not a metadata token.".format(
            COMIMAGE_FLAGS_NATIVE_ENTRYPOINT
        )
    )
    reason_codes.append("slot.native_rva")

    table = (raw_value >> 24) & 0xFF
    if table in (TABLE_METHODDEF, TABLE_FILE):
        reasons.append(
            "The value 0x{0:08x} resembles a {1} token, but the native flag takes precedence; "
            "it is interpreted only as an RVA.".format(raw_value, _TOKEN_TABLE_NAMES[table])
        )
        reason_codes.append("slot.native_overrides_token_shape")

    address = _map_rva(pe, raw_value)
    if not address.mapped:
        message = "Native entry RVA 0x{0:x} is not mapped by any PE section or image range.".format(raw_value)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("pe.unmapped")
        conflict_codes.append("conflict.native_rva_unmapped")
        return EntryPointKind.NATIVE, EntryPointStatus.CONTRADICTORY, address

    reasons.append(
        "Native RVA 0x{0:x} maps to {1}{2}; the section is {3} and raw data is {4}.".format(
            raw_value,
            address.section or "the PE headers",
            "" if address.file_offset is None else " at file offset 0x{0:x}".format(address.file_offset),
            "executable" if address.executable else "not executable",
            "available" if address.raw_available else "not available",
        )
    )
    reason_codes.append("pe.mapped")

    if _in_clr_metadata(pe, raw_value):
        message = "Native entry RVA 0x{0:x} points inside the CLR metadata stream.".format(raw_value)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("pe.in_clr_metadata")
        conflict_codes.append("conflict.native_rva_in_metadata")

    if not address.executable:
        message = "Native entry RVA 0x{0:x} maps to a non-executable region.".format(raw_value)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("pe.nonexecutable")
        conflict_codes.append("conflict.native_rva_nonexecutable")

    status = EntryPointStatus.CONTRADICTORY if conflicts else EntryPointStatus.VERIFIED
    return EntryPointKind.NATIVE, status, address


def resolve_entry_point(pe: Any) -> EntryPoint:
    """Resolve the CLI entry-point declaration of a ``dnPE``.

    The function never raises because metadata is damaged.  If the CLI header
    itself is absent, a ``NONE`` result is returned.
    """

    pe = _coerce_pe(pe)
    reasons: List[str] = []
    reason_codes: List[str] = []
    conflicts: List[str] = []
    conflict_codes: List[str] = []

    net, raw_flags, raw_value = _read_pe_header(pe)
    if net is None or raw_flags is None or raw_value is None:
        reasons.append("The file has no readable CLR header, so it declares no CLI entry point.")
        reason_codes.append("entrypoint.no_clr_header")
        return EntryPoint(
            kind=EntryPointKind.NONE,
            status=EntryPointStatus.VERIFIED,
            raw_value=0,
            raw_flags=0,
            declared_slot="none",
            native_entrypoint_flag=False,
            ilonly=False,
            il_library=False,
            token=None,
            token_table=None,
            token_table_name=None,
            rid=None,
            method=None,
            file=None,
            native_address=None,
            method_address=None,
            reasons=tuple(reasons),
            reason_codes=tuple(reason_codes),
            conflicts=tuple(conflicts),
            conflict_codes=tuple(conflict_codes),
            metadata_available=False,
        )

    raw_flags = int(raw_flags)
    raw_value = int(raw_value)
    native_flag = bool(raw_flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)
    ilonly = bool(raw_flags & COMIMAGE_FLAGS_ILONLY)
    il_library = bool(raw_flags & COMIMAGE_FLAGS_IL_LIBRARY)
    metadata_available = _metadata_tables(pe) is not None

    reasons.append(
        "CLI header flags 0x{0:08x}: ILONLY={1}, IL_LIBRARY={2}, NATIVE_ENTRYPOINT={3}.".format(
            raw_flags, int(ilonly), int(il_library), int(native_flag)
        )
    )
    reason_codes.append("header.flags")

    if native_flag and ilonly:
        message = "Contradictory headers: CLR_ILONLY and CLR_NATIVE_ENTRYPOINT are both set."
        reasons.append(message)
        conflicts.append(message)
        conflict_codes.append("conflict.native_flag_with_ilonly")

    if raw_value == 0:
        reasons.append("EntryPointTokenOrRva is zero, which ECMA-335 defines as no entry point.")
        reason_codes.append("entrypoint.none")
        if il_library:
            reasons.append("CLR_IL_LIBRARY is set, consistent with a library that has no entry point.")
            reason_codes.append("header.il_library")
        if native_flag:
            message = "CLR_NATIVE_ENTRYPOINT is set but the entry slot is zero; zero still means no entry."
            reasons.append(message)
            conflicts.append(message)
            conflict_codes.append("conflict.native_flag_without_entry")
        status = EntryPointStatus.CONTRADICTORY if conflicts else EntryPointStatus.VERIFIED
        return EntryPoint(
            kind=EntryPointKind.NONE,
            status=status,
            raw_value=raw_value,
            raw_flags=raw_flags,
            declared_slot="none",
            native_entrypoint_flag=native_flag,
            ilonly=ilonly,
            il_library=il_library,
            token=None,
            token_table=None,
            token_table_name=None,
            rid=None,
            method=None,
            file=None,
            native_address=None,
            method_address=None,
            reasons=tuple(reasons),
            reason_codes=tuple(reason_codes),
            conflicts=tuple(conflicts),
            conflict_codes=tuple(conflict_codes),
            metadata_available=metadata_available,
        )

    if il_library:
        message = "Contradictory headers: CLR_IL_LIBRARY is set but EntryPointTokenOrRva is nonzero."
        reasons.append(message)
        conflicts.append(message)
        conflict_codes.append("conflict.il_library_with_entry")

    if native_flag:
        kind, status, native_address = _resolve_native(
            pe, raw_value, reasons, reason_codes, conflicts, conflict_codes
        )
        return EntryPoint(
            kind=kind,
            status=status,
            raw_value=raw_value,
            raw_flags=raw_flags,
            declared_slot="native-rva",
            native_entrypoint_flag=native_flag,
            ilonly=ilonly,
            il_library=il_library,
            token=None,
            token_table=None,
            token_table_name=None,
            rid=None,
            method=None,
            file=None,
            native_address=native_address,
            method_address=None,
            reasons=tuple(reasons),
            reason_codes=tuple(reason_codes),
            conflicts=tuple(conflicts),
            conflict_codes=tuple(conflict_codes),
            metadata_available=metadata_available,
        )

    table, rid, table_name = _token_parts(raw_value)
    reasons.append(
        "CLR_NATIVE_ENTRYPOINT is clear, so entry slot 0x{0:08x} is a metadata token "
        "(table 0x{1:02x} {2}, RID {3}).".format(raw_value, table, table_name, rid)
    )
    reason_codes.append("slot.metadata_token")

    token_fields = dict(
        token=raw_value,
        token_table=table,
        token_table_name=table_name,
        rid=rid,
    )

    if table == TABLE_METHODDEF:
        kind, status, method, method_address, metadata_available = _resolve_method(
            pe, raw_value, rid, reasons, reason_codes, conflicts, conflict_codes
        )
        native_address = None
        file_row = None
    elif table == TABLE_FILE:
        kind, status, file_row, metadata_available = _resolve_file(
            pe, raw_value, rid, reasons, reason_codes, conflicts, conflict_codes
        )
        method = None
        method_address = None
        native_address = None
    else:
        if table in _TOKEN_TABLE_NAMES:
            message = (
                "Contradictory headers: token 0x{0:08x} names table 0x{1:02x} ({2}), "
                "but an entry-point token may be only MethodDef (0x06) or File (0x26)."
            ).format(raw_value, table, table_name)
        else:
            message = (
                "Contradictory headers: token 0x{0:08x} names unknown metadata table 0x{1:02x}."
            ).format(raw_value, table)
        reasons.append(message)
        conflicts.append(message)
        reason_codes.append("token.not_entry_table")
        conflict_codes.append("conflict.token_table_not_allowed")
        kind = EntryPointKind.INVALID
        status = EntryPointStatus.CONTRADICTORY
        method = None
        file_row = None
        native_address = None
        method_address = None

    if kind is EntryPointKind.METHOD and method is not None:
        if ilonly and "miNative" in _method_impl_names(method):
            message = "Contradictory headers: CLR_ILONLY is set but the entry MethodDef is native."
            reasons.append(message)
            conflicts.append(message)
            conflict_codes.append("conflict.ilonly_with_native_method")
            status = EntryPointStatus.CONTRADICTORY

    if conflicts and status is EntryPointStatus.VERIFIED:
        status = EntryPointStatus.CONTRADICTORY

    return EntryPoint(
        kind=kind,
        status=status,
        raw_value=raw_value,
        raw_flags=raw_flags,
        declared_slot="metadata-token",
        native_entrypoint_flag=native_flag,
        ilonly=ilonly,
        il_library=il_library,
        method=method,
        file=file_row,
        native_address=native_address,
        method_address=method_address,
        reasons=tuple(reasons),
        reason_codes=tuple(reason_codes),
        conflicts=tuple(conflicts),
        conflict_codes=tuple(conflict_codes),
        metadata_available=metadata_available,
        **token_fields,
    )


def describe_entry_point(pe: Any) -> str:
    """Return a compact, multi-line report suitable for a CLI backend."""

    result = resolve_entry_point(pe)
    lines = [
        "kind: {0}".format(result.kind.value),
        "status: {0}".format(result.status.value),
        "raw_value: 0x{0:08x}".format(result.raw_value),
        "raw_flags: 0x{0:08x}".format(result.raw_flags),
        "declared_slot: {0}".format(result.declared_slot),
    ]
    if result.token is not None:
        lines.append("token: 0x{0:08x}".format(result.token))
        lines.append("token_table: 0x{0:02x} ({1})".format(result.token_table, result.token_table_name))
        lines.append("rid: {0}".format(result.rid))
    if result.rva is not None:
        lines.append("rva: 0x{0:x}".format(result.rva))
    if result.file_offset is not None:
        lines.append("file_offset: 0x{0:x}".format(result.file_offset))
    lines.append("reasons:")
    lines.extend("  - {0}".format(reason) for reason in result.reasons)
    if result.conflicts:
        lines.append("conflicts:")
        lines.extend("  - {0}".format(conflict) for conflict in result.conflicts)
    return "\n".join(lines)


# Short aliases for callers that treat the resolver as a backend service.
get_entry_point = resolve_entry_point
resolve = resolve_entry_point


class EntryPointResolver(object):
    """Small stateful wrapper around :func:`resolve_entry_point`."""

    def __init__(self, pe: Any):
        self.pe = pe

    def resolve(self) -> EntryPoint:
        return resolve_entry_point(self.pe)
