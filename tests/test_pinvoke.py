import struct
from types import SimpleNamespace

import dnfile
from dnfile.pinvoke import (
    PInvokeInventory,
    build_pinvoke_inventory,
    collect_pinvoke_entries,
)


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def _build_metadata():
    strings = bytearray(b"\x00")
    blobs = bytearray(b"\x00")

    def string_index(value):
        index = len(strings)
        strings.extend(value.encode("utf-8") + b"\x00")
        return index

    def blob_index(value):
        index = len(blobs)
        blobs.append(len(value))
        blobs.extend(value)
        return index

    module_name = string_index("pinvoke-fixture.exe")
    type_namespace = string_index("Demo")
    type_name = string_index("NativeCalls")
    method_names = [
        string_index("MessageBoxA_StdCall"),
        string_index("MessageBoxA_CDecl"),
        string_index("MessageBoxA_ThisCall"),
    ]
    method_signature = blob_index(b"\x00\x00\x01")
    import_name = string_index("MessageBoxA")
    module_ref_name = string_index("user32.dll")

    module_rows = struct.pack("<HHHHH", 0, module_name, 0, 0, 0)
    type_rows = struct.pack("<IHHHHH", 0, type_name, type_namespace, 0, 0, 1)
    method_rows = b"".join(
        struct.pack("<IHHHHH", 0, 0x0080, 0x2006, name, method_signature, 0)
        for name in method_names
    )
    module_ref_rows = struct.pack("<H", module_ref_name)

    impl_map = [
        (0x0302, (1 << 1) | 1, 1),
        (0x0206, (2 << 1) | 1, 1),
        (0x0404, (3 << 1) | 1, 1),
        (0x0302, (1 << 1) | 1, 1),
        (0x0300, (99 << 1) | 1, 1),
        (0x0200, (2 << 1) | 1, 99),
    ]
    impl_map_rows = b"".join(
        struct.pack("<HHHH", flags, member, import_name, scope)
        for flags, member, scope in impl_map
    )

    valid = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 26) | (1 << 28)
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
    tables += struct.pack("<IIIII", 1, 1, 3, 1, len(impl_map))
    tables += module_rows + type_rows + method_rows + module_ref_rows + impl_map_rows

    version = b"v4.0.30319\x00\x00"
    stream_specs = [(b"#~", tables), (b"#Strings", bytes(strings)), (b"#Blob", bytes(blobs))]
    header_size = 16 + len(version) + 4
    header_size += sum(8 + _align(len(name) + 1, 4) for name, _ in stream_specs)

    offset = header_size
    headers = bytearray()
    payload = bytearray()
    for name, data in stream_specs:
        headers.extend(struct.pack("<II", offset, len(data)))
        headers.extend(name + b"\x00")
        headers.extend(b"\x00" * (_align(len(name) + 1, 4) - len(name) - 1))
        payload.extend(data)
        offset += len(data)
        padding = _align(len(payload), 4) - len(payload)
        payload.extend(b"\x00" * padding)
        offset += padding

    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
    root += version + struct.pack("<HH", 0, len(stream_specs))
    return root + bytes(headers) + bytes(payload)


def _build_pe():
    metadata = _build_metadata()
    section_rva = 0x2000
    metadata_rva = section_rva + 0x50

    clr = bytearray(72)
    struct.pack_into("<I", clr, 0, 72)
    struct.pack_into("<H", clr, 4, 2)
    struct.pack_into("<H", clr, 6, 5)
    struct.pack_into("<I", clr, 8, metadata_rva)
    struct.pack_into("<I", clr, 12, len(metadata))
    struct.pack_into("<I", clr, 16, 0x00000001)

    section = bytearray(0x800)
    section[:len(clr)] = clr
    section[0x50:0x50 + len(metadata)] = metadata

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x2102)
    optional_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        8,
        0,
        0x800,
        0x800,
        0,
        0,
        section_rva,
        0,
        0x400000,
        0x1000,
        0x200,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        0x3000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional_header += b"\x00" * (16 * 8)
    optional_header = bytearray(optional_header)
    struct.pack_into("<II", optional_header, 96 + 14 * 8, section_rva, 72)

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(section),
        section_rva,
        len(section),
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional_header) + section_header
    headers += b"\x00" * (0x200 - len(headers))
    return headers + bytes(section)


def test_pinvoke_inventory_keeps_same_name_different_conventions():
    pe = dnfile.dnPE(data=_build_pe())

    entries = pe.pinvoke_entries
    assert len(entries) == 6
    assert [entry.calling_convention for entry in entries[:4]] == [
        "stdcall",
        "cdecl",
        "thiscall",
        "stdcall",
    ]
    assert all(entry.module_name == "user32.dll" for entry in entries[:5])
    assert all(entry.import_name == "MessageBoxA" for entry in entries)
    assert [entry.impl_map_row_number for entry in entries] == [1, 2, 3, 4, 5, 6]

    inventory = build_pinvoke_inventory(pe)
    assert isinstance(inventory, PInvokeInventory)
    assert len(inventory.by_import_name("messageboxa")) == 6
    assert len(inventory.by_calling_convention("stdcall")) == 3
    assert len(inventory.duplicates()[("user32.dll", "MessageBoxA")]) == 5


def test_pinvoke_entry_recovers_member_names_and_original_locations():
    pe = dnfile.dnPE(data=_build_pe())

    entries = collect_pinvoke_entries(pe)
    first = entries[0]
    assert first.managed_name == "MessageBoxA_StdCall"
    assert first.declaring_type == "Demo.NativeCalls"
    assert first.managed_member == "Demo.NativeCalls::MessageBoxA_StdCall"
    assert first.target_table == "MethodDef"
    assert first.target_row_number == 1
    assert first.target_token == (6 << 24) | 1
    assert first.impl_map_token == (28 << 24) | 1
    assert first.impl_map_rva == 0x2110
    assert first.impl_map_file_offset == 0x310
    assert first.target_rva == 0x20E4
    assert first.target_file_offset == 0x2E4
    assert first.module_ref_rva == 0x210E
    assert first.module_ref_file_offset == 0x30E
    assert first.resolved is True
    assert first.declared_pinvoke is True
    assert first.parameter_count == 0
    assert first.return_type == "void"


def test_pinvoke_inventory_works_with_lazy_loading():
    pe = dnfile.dnPE(data=_build_pe(), clr_lazy_load=True)

    entries = pe.net.mdtables.pinvoke_entries()

    assert len(entries) == 6
    assert entries[0].managed_member == "Demo.NativeCalls::MessageBoxA_StdCall"
    assert entries[0].calling_convention == "stdcall"
    assert entries[0].impl_map_file_offset == 0x310


def test_pinvoke_entry_records_missing_target_and_module():
    pe = dnfile.dnPE(data=_build_pe())

    entries = pe.pinvoke_entries
    missing_target = entries[4]
    assert missing_target.impl_map_row_number == 5
    assert missing_target.target_row_number == 99
    assert missing_target.missing_target is True
    assert missing_target.resolved is False
    assert missing_target.raw_member_forwarded == ((99 << 1) | 1)
    assert missing_target.managed_name is None

    missing_module = entries[5]
    assert missing_module.module_ref_row_number == 99
    assert missing_module.missing_module is True
    assert missing_module.module_name is None
    assert missing_module.managed_name == "MessageBoxA_CDecl"

    assert all(entry.module_name != "does-not-exist.dll" for entry in entries)


class _FakeTable:
    def __init__(self, name, rows, row_size=4, rva=0x2000, file_offset=0x100):
        self.name = name
        self.rows = list(rows)
        self.num_rows = len(self.rows)
        self.row_size = row_size
        self.rva = rva
        self.file_offset = file_offset

    def __getitem__(self, index):
        return self.rows[index]


def test_pinvoke_field_target_is_preserved():
    module_ref = _FakeTable(
        "ModuleRef",
        [SimpleNamespace(Name="native.dll", struct=SimpleNamespace())],
        row_size=2,
    )
    field = _FakeTable(
        "Field",
        [
            SimpleNamespace(
                Name="NativeValue",
                Signature=b"\x06\x08",
                Flags=SimpleNamespace(fdPinvokeImpl=True),
                struct=SimpleNamespace(get_file_offset=lambda: 0x444),
            )
        ],
    )
    type_def = _FakeTable(
        "TypeDef",
        [
            SimpleNamespace(
                TypeName="Natives",
                TypeNamespace="Demo",
                FieldList=[SimpleNamespace(row_index=1)],
                MethodList=[],
                struct=SimpleNamespace(),
            )
        ],
        row_size=14,
    )
    impl_map = _FakeTable(
        "ImplMap",
        [
            SimpleNamespace(
                ImportName="NativeValue",
                ImportScope=SimpleNamespace(table=module_ref, row_index=1),
                MemberForwarded=SimpleNamespace(table=field, row_index=1),
                struct=SimpleNamespace(
                    MappingFlags=0x0100,
                    MemberForwarded_CodedIndex=(1 << 1) | 0,
                    ImportScope_Index=1,
                    get_file_offset=lambda: 0x500,
                ),
            )
        ],
        row_size=8,
    )
    mdtables = SimpleNamespace(
        tables_list=[type_def, field, module_ref, impl_map],
        TypeDef=type_def,
        Field=field,
        ModuleRef=module_ref,
        ImplMap=impl_map,
    )

    entries = collect_pinvoke_entries(mdtables)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.target_table == "Field"
    assert entry.target_kind == "Field"
    assert entry.target_token == (4 << 24) | 1
    assert entry.managed_name == "NativeValue"
    assert entry.declaring_type == "Demo.Natives"
    assert entry.declared_pinvoke is True
    assert entry.calling_convention == "winapi"
    assert entry.signature_calling_convention == "field"
