import os

import dnfile
import entrypoint_fixtures as fixtures


def _load(tmp_path, **kwargs):
    path = fixtures.write_fixture(tmp_path, "fixture.exe", **kwargs)
    return dnfile.dnPE(path)


def _load_named(tmp_path, name, **kwargs):
    path = fixtures.write_fixture(tmp_path, name, **kwargs)
    return dnfile.dnPE(path)


def test_managed_method_entry(tmp_path):
    dn = _load_named(
        tmp_path,
        "managed.exe",
        entry_value=fixtures.METHOD_ENTRY,
        flags=fixtures.CLR_ILONLY,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.METHOD
    assert result.status == dnfile.EntryPointStatus.VERIFIED
    assert result.raw_value == fixtures.METHOD_ENTRY
    assert result.declared_slot == "metadata-token"
    assert result.token == fixtures.METHOD_ENTRY
    assert result.token_table == 0x06
    assert result.rid == 1
    assert str(result.method.Name) == "Main"
    assert result.native_address is None
    assert result.method_address is not None
    assert result.method_address.section == ".text"
    assert result.method_address.executable is True
    assert result.method_address.file_offset == 0x400
    assert "managed method token" in result.reason
    assert "method.resolved" in result.reason_codes
    assert dn.net.entry_point.kind == dnfile.EntryPointKind.METHOD


def test_external_file_entry(tmp_path):
    dn = _load_named(
        tmp_path,
        "external.exe",
        entry_value=fixtures.FILE_ENTRY,
    )

    result = dn.entry_point

    assert result.kind == dnfile.EntryPointKind.FILE
    assert result.status == dnfile.EntryPointStatus.VERIFIED
    assert result.token_table == 0x26
    assert str(result.file.Name) == "other.dll"
    assert result.method is None
    assert result.native_address is None
    assert result.rva is None
    assert "external file" in result.reason
    assert "file.external" in result.reason_codes


def test_native_rva_entry(tmp_path):
    dn = _load_named(
        tmp_path,
        "native.exe",
        entry_value=fixtures.NATIVE_ENTRY,
        flags=fixtures.CLR_NATIVE_ENTRYPOINT,
    )

    result = dn.entrypoint

    assert result.kind == dnfile.EntryPointKind.NATIVE
    assert result.status == dnfile.EntryPointStatus.VERIFIED
    assert result.raw_value == fixtures.NATIVE_ENTRY
    assert result.declared_slot == "native-rva"
    assert result.token is None
    assert result.native_address is not None
    assert result.native_address.rva == fixtures.NATIVE_ENTRY
    assert result.native_address.section == ".text"
    assert result.native_address.executable is True
    assert result.native_address.file_offset == 0x400
    assert result.native_address.raw_available is True
    assert "native RVA, not a metadata token" in result.reason
    assert "slot.native_rva" in result.reason_codes


def test_no_entry(tmp_path):
    dn = _load_named(
        tmp_path,
        "library.dll",
        entry_value=0,
        flags=fixtures.CLR_IL_LIBRARY,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.NONE
    assert result.status == dnfile.EntryPointStatus.VERIFIED
    assert result.raw_value == 0
    assert result.declared_slot == "none"
    assert result.rva is None
    assert "zero" in result.reason
    assert "entrypoint.none" in result.reason_codes


def test_contradictory_flags_keep_native_mapping(tmp_path):
    dn = _load_named(
        tmp_path,
        "contradictory.exe",
        entry_value=fixtures.NATIVE_ENTRY,
        flags=fixtures.CLR_ILONLY | fixtures.CLR_NATIVE_ENTRYPOINT,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.NATIVE
    assert result.status == dnfile.EntryPointStatus.CONTRADICTORY
    assert result.valid is False
    assert result.rva == fixtures.NATIVE_ENTRY
    assert "conflict.native_flag_with_ilonly" in result.conflict_codes
    assert any("CLR_ILONLY" in reason for reason in result.reasons)


def test_token_shaped_value_is_still_native_when_flag_is_set(tmp_path):
    dn = _load_named(
        tmp_path,
        "token-shaped-native.exe",
        entry_value=fixtures.METHOD_ENTRY,
        flags=fixtures.CLR_NATIVE_ENTRYPOINT,
        virtual_size=0x06000000,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.NATIVE
    assert result.status == dnfile.EntryPointStatus.VERIFIED
    assert result.token is None
    assert result.method is None
    assert result.rva == fixtures.METHOD_ENTRY
    assert result.native_address.section == ".text"
    assert "slot.native_overrides_token_shape" in result.reason_codes


def test_same_value_is_not_the_same_target_without_native_flag(tmp_path):
    native = _load_named(
        tmp_path,
        "same-native.exe",
        entry_value=fixtures.NATIVE_ENTRY,
        flags=fixtures.CLR_NATIVE_ENTRYPOINT,
    )
    token = _load_named(
        tmp_path,
        "same-token.exe",
        entry_value=fixtures.NATIVE_ENTRY,
        flags=0,
    )

    native_result = native.get_entry_point()
    token_result = token.get_entry_point()

    assert native_result.raw_value == token_result.raw_value
    assert native_result.kind == dnfile.EntryPointKind.NATIVE
    assert native_result.rva == fixtures.NATIVE_ENTRY
    assert native_result.native_address.section == ".text"
    assert token_result.kind == dnfile.EntryPointKind.INVALID
    assert token_result.native_address is None
    assert token_result.rva is None
    assert token_result.token_table == 0
    assert "conflict.token_table_not_allowed" in token_result.conflict_codes


def test_same_methoddef_bits_are_not_a_native_target(tmp_path):
    method = _load_named(
        tmp_path,
        "same-method.exe",
        entry_value=fixtures.METHOD_ENTRY,
        flags=fixtures.CLR_ILONLY,
    )
    native = _load_named(
        tmp_path,
        "same-token-native.exe",
        entry_value=fixtures.METHOD_ENTRY,
        flags=fixtures.CLR_NATIVE_ENTRYPOINT,
        virtual_size=0x06000000,
    )

    method_result = method.get_entry_point()
    native_result = native.get_entry_point()

    assert method_result.raw_value == native_result.raw_value
    assert method_result.kind == dnfile.EntryPointKind.METHOD
    assert native_result.kind == dnfile.EntryPointKind.NATIVE
    assert method_result.rva == fixtures.METHOD_BODY_RVA
    assert native_result.rva == fixtures.METHOD_ENTRY
    assert method_result.rva != native_result.rva
    assert method_result.method is not None
    assert native_result.method is None


def test_non_entry_token_table_is_contradictory(tmp_path):
    dn = _load_named(
        tmp_path,
        "assembly-ref-token.exe",
        entry_value=fixtures.ASSEMBLYREF_ENTRY,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.INVALID
    assert result.status == dnfile.EntryPointStatus.CONTRADICTORY
    assert result.token_table == 0x23
    assert result.token_table_name == "AssemblyRef"
    assert "conflict.token_table_not_allowed" in result.conflict_codes


def test_unmapped_native_rva_is_contradictory(tmp_path):
    dn = _load_named(
        tmp_path,
        "unmapped.exe",
        entry_value=0x90000000,
        flags=fixtures.CLR_NATIVE_ENTRYPOINT,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.NATIVE
    assert result.status == dnfile.EntryPointStatus.CONTRADICTORY
    assert result.native_address.mapped is False
    assert "conflict.native_rva_unmapped" in result.conflict_codes


def test_native_flag_with_zero_slot_is_no_entry_but_conflicting(tmp_path):
    dn = _load_named(
        tmp_path,
        "native-zero.exe",
        entry_value=0,
        flags=fixtures.CLR_NATIVE_ENTRYPOINT,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.NONE
    assert result.status == dnfile.EntryPointStatus.CONTRADICTORY
    assert "conflict.native_flag_without_entry" in result.conflict_codes


def test_corrupt_metadata_still_reports_raw_declaration(tmp_path):
    dn = _load_named(
        tmp_path,
        "corrupt-metadata.exe",
        entry_value=fixtures.METHOD_ENTRY,
        flags=fixtures.CLR_ILONLY,
        corrupt_metadata=True,
    )

    result = dn.get_entry_point()

    assert dn.net is not None
    assert dn.net.metadata is None
    assert result.kind == dnfile.EntryPointKind.METHOD
    assert result.status == dnfile.EntryPointStatus.UNVERIFIED
    assert result.raw_value == fixtures.METHOD_ENTRY
    assert result.raw_flags == fixtures.CLR_ILONLY
    assert result.declared_slot == "metadata-token"
    assert result.token == fixtures.METHOD_ENTRY
    assert result.token_table == 0x06
    assert result.rid == 1
    assert result.method is None
    assert "recorded verbatim" in result.reason
    assert "token.unresolved_metadata" in result.reason_codes


def test_metadata_unavailable_still_reports_raw_file_declaration(tmp_path):
    dn = _load_named(
        tmp_path,
        "corrupt-file.exe",
        entry_value=fixtures.FILE_ENTRY,
        corrupt_metadata=True,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.FILE
    assert result.status == dnfile.EntryPointStatus.UNVERIFIED
    assert result.token == fixtures.FILE_ENTRY
    assert result.token_table == 0x26
    assert result.file is None
    assert result.to_dict()["raw_value"] == fixtures.FILE_ENTRY


def test_partial_method_table_still_reports_raw_declaration(tmp_path):
    path = fixtures.write_fixture(
        tmp_path,
        "partial-metadata.exe",
        entry_value=fixtures.METHOD_ENTRY,
        flags=fixtures.CLR_ILONLY,
    )
    baseline = dnfile.dnPE(path)
    method_offset = baseline.net.mdtables.MethodDef.file_offset
    baseline.close()

    # Keep only three bytes of the 14-byte MethodDef row.
    os.truncate(path, method_offset + 3)

    result = dnfile.dnPE(path).get_entry_point()

    assert result.kind == dnfile.EntryPointKind.METHOD
    assert result.status == dnfile.EntryPointStatus.UNVERIFIED
    assert result.raw_value == fixtures.METHOD_ENTRY
    assert result.token == fixtures.METHOD_ENTRY
    assert result.method is None
    assert "token.unresolved_incomplete" in result.reason_codes


def test_methoddef_native_body_keeps_method_token_interpretation(tmp_path):
    dn = _load_named(
        tmp_path,
        "mixed-mode-method.exe",
        entry_value=fixtures.METHOD_ENTRY,
        flags=0,
        method_impl_flags=0x0005,
    )

    result = dn.get_entry_point()

    assert result.kind == dnfile.EntryPointKind.METHOD
    assert result.status == dnfile.EntryPointStatus.VERIFIED
    assert result.token == fixtures.METHOD_ENTRY
    assert result.method_body_kind == "native"
    assert "method.native_body" in result.reason_codes
    assert "not reinterpreted as a native RVA" in result.reason


def test_non_clr_file_has_no_entry(tmp_path):
    path = fixtures.write_fixture(
        tmp_path,
        "plain.bin",
        entry_value=0,
        clr_directory=False,
    )

    result = dnfile.resolve_entry_point(dnfile.dnPE(path))

    assert result.kind == dnfile.EntryPointKind.NONE
    assert "entrypoint.no_clr_header" in result.reason_codes
