import struct
import unittest

import ordlookup
import pefile


IMAGE_BASE = 0x400000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
SECTION_RVA = 0x1000
SECTION_RAW_OFFSET = 0x200


def build_small_pe(direct_imports, delay_imports):
    """Build a minimal PE32 with name and ordinal based import tables."""

    blob = bytearray(0x600)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)

    blob[0x80:0x84] = b"PE\0\0"
    coff_offset = 0x84
    struct.pack_into(
        "<HHIIIHH",
        blob,
        coff_offset,
        0x14C,  # IMAGE_FILE_MACHINE_I386
        1,
        0,
        0,
        0,
        0xE0,
        0x0102,
    )

    optional_offset = coff_offset + 20
    struct.pack_into("<H", blob, optional_offset, pefile.OPTIONAL_HEADER_MAGIC_PE)
    blob[optional_offset + 2] = 1
    struct.pack_into("<I", blob, optional_offset + 4, 0x200)
    struct.pack_into("<I", blob, optional_offset + 16, SECTION_RVA)
    struct.pack_into("<I", blob, optional_offset + 20, SECTION_RVA)
    struct.pack_into("<I", blob, optional_offset + 24, 0x2000)
    struct.pack_into("<I", blob, optional_offset + 28, IMAGE_BASE)
    struct.pack_into("<I", blob, optional_offset + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", blob, optional_offset + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", blob, optional_offset + 40, 4)
    struct.pack_into("<H", blob, optional_offset + 46, 4)
    struct.pack_into("<H", blob, optional_offset + 48, 4)
    struct.pack_into("<I", blob, optional_offset + 56, 0x3000)
    struct.pack_into("<I", blob, optional_offset + 60, FILE_ALIGNMENT)
    struct.pack_into("<H", blob, optional_offset + 68, 3)
    struct.pack_into("<I", blob, optional_offset + 72, 0x100000)
    struct.pack_into("<I", blob, optional_offset + 76, 0x1000)
    struct.pack_into("<I", blob, optional_offset + 80, 0x100000)
    struct.pack_into("<I", blob, optional_offset + 84, 0x1000)
    struct.pack_into("<I", blob, optional_offset + 92, 16)

    data_directory_offset = optional_offset + 96
    cursor = SECTION_RVA

    def reserve(size):
        nonlocal cursor
        rva = cursor
        cursor += size
        return rva

    def file_offset(rva):
        return SECTION_RAW_OFFSET + (rva - SECTION_RVA)

    def place_string(text):
        rva = reserve(len(text) + 1)
        offset = file_offset(rva)
        blob[offset : offset + len(text)] = text
        blob[offset + len(text)] = 0
        return rva

    def place_dwords(values):
        rva = reserve(4 * len(values))
        offset = file_offset(rva)
        for index, value in enumerate(values):
            struct.pack_into("<I", blob, offset + 4 * index, value)
        return rva

    def build_descriptors(imports):
        descriptors = []
        for dll_name, symbols in imports:
            dll_rva = place_string(dll_name)
            thunk_values = []
            for kind, value in symbols:
                if kind == "name":
                    hint_rva = reserve(2 + len(value) + 1)
                    hint_offset = file_offset(hint_rva)
                    struct.pack_into("<H", blob, hint_offset, 0)
                    blob[hint_offset + 2 : hint_offset + 2 + len(value)] = value
                    blob[hint_offset + 2 + len(value)] = 0
                    thunk_values.append(hint_rva)
                else:
                    thunk_values.append(0x80000000 | value)
            thunk_values.append(0)
            lookup_rva = place_dwords(thunk_values)
            address_rva = place_dwords(thunk_values)
            descriptors.append((dll_rva, lookup_rva, address_rva))
        return descriptors

    direct_descriptors = build_descriptors(direct_imports)
    direct_directory_rva = reserve(20 * (len(direct_descriptors) + 1))
    delay_descriptors = build_descriptors(delay_imports)
    delay_directory_rva = reserve(32 * (len(delay_descriptors) + 1))

    for index, (name_rva, lookup_rva, address_rva) in enumerate(direct_descriptors):
        struct.pack_into(
            "<IIIII",
            blob,
            file_offset(direct_directory_rva) + index * 20,
            lookup_rva,
            0,
            0,
            name_rva,
            address_rva,
        )

    for index, (name_rva, lookup_rva, address_rva) in enumerate(delay_descriptors):
        struct.pack_into(
            "<IIIIIIII",
            blob,
            file_offset(delay_directory_rva) + index * 32,
            1,
            name_rva,
            0,
            address_rva,
            lookup_rva,
            0,
            0,
            0,
        )

    struct.pack_into(
        "<II",
        blob,
        data_directory_offset + 8,
        direct_directory_rva,
        20 * len(direct_descriptors),
    )
    struct.pack_into(
        "<II",
        blob,
        data_directory_offset + 13 * 8,
        delay_directory_rva,
        32 * len(delay_descriptors),
    )

    section_offset = optional_offset + 0xE0
    blob[section_offset : section_offset + 8] = b".rdata\0\0"
    struct.pack_into("<I", blob, section_offset + 8, 0x1000)
    struct.pack_into("<I", blob, section_offset + 12, SECTION_RVA)
    struct.pack_into("<I", blob, section_offset + 16, 0x400)
    struct.pack_into("<I", blob, section_offset + 20, SECTION_RAW_OFFSET)
    struct.pack_into("<I", blob, section_offset + 36, 0x40000040)

    return bytes(blob)


DIRECT_IMPORTS = [
    (b"kernel32.dll", [("name", b"CreateFileW"), ("name", b"CloseHandle")]),
    (b"ws2_32.dll", [("ordinal", 24)]),
]

PE_MANIFEST_A = build_small_pe(
    DIRECT_IMPORTS,
    [(b"user32.dll", [("name", b"MessageBoxW")])],
)
PE_MANIFEST_B = build_small_pe(
    DIRECT_IMPORTS,
    [(b"oleaut32.dll", [("name", b"SysAllocString")])],
)


def status_by_name(matches):
    return {
        match.dependency.dll.lower() + b"." + match.dependency.symbol.lower():
        match.status
        for match in matches
    }


class TestDependencyEvidence(unittest.TestCase):
    def test_manifests_share_direct_evidence_but_differ_on_delay(self):
        all_evidence = []
        for data in (PE_MANIFEST_A, PE_MANIFEST_B):
            with pefile.PE(data=data) as pe:
                all_evidence.append(pe.get_dependency_evidence())

        direct_evidence = tuple(
            tuple(
                record
                for record in evidence
                if record.table == pefile.PE.IMPORT_TABLE_DIRECT
            )
            for evidence in all_evidence
        )
        delay_dlls = tuple(
            tuple(
                record.dll
                for record in evidence
                if record.table == pefile.PE.IMPORT_TABLE_DELAY
            )
            for evidence in all_evidence
        )

        self.assertEqual(direct_evidence[0], direct_evidence[1])
        self.assertEqual(delay_dlls[0], (b"user32.dll",))
        self.assertEqual(delay_dlls[1], (b"oleaut32.dll",))

    def test_direct_dependencies_match_across_manifests(self):
        manifest = [
            b"kernel32.dll.CreateFileW",
            b"kernel32.dll.CloseHandle",
            b"ws2_32.dll.WSApSetPostRoutine",
            b"ws2_32.dll.GetAddrInfoW",
        ]
        results = []
        for data in (PE_MANIFEST_A, PE_MANIFEST_B):
            with pefile.PE(data=data) as pe:
                matches = pe.cross_reference_dependencies(manifest)
                results.append(status_by_name(matches))

        self.assertEqual(results[0], results[1])
        for name in (
            b"kernel32.dll.createfilew",
            b"kernel32.dll.closehandle",
        ):
            self.assertEqual(results[0][name], pefile.PE.DEPENDENCY_MATCH_CONFIRMED)

        # The same ordinal has two in-range interpretations, so neither name is
        # allowed to silently take precedence over the other.
        ordinal_statuses = {
            name: results[0][name]
            for name in results[0]
            if name.startswith(b"ws2_32.dll.")
        }
        self.assertTrue(
            all(
                status == pefile.PE.DEPENDENCY_MATCH_AMBIGUOUS
                for status in ordinal_statuses.values()
            )
        )

    def test_delay_only_dependencies_remain_pending(self):
        manifest = [b"user32.dll.MessageBoxW", b"oleaut32.dll.SysAllocString"]
        expected = (
            (PE_MANIFEST_A, pefile.PE.DEPENDENCY_MATCH_PENDING,
             pefile.PE.DEPENDENCY_MATCH_UNRESOLVED),
            (PE_MANIFEST_B, pefile.PE.DEPENDENCY_MATCH_UNRESOLVED,
             pefile.PE.DEPENDENCY_MATCH_PENDING),
        )
        for data, user32_status, oleaut32_status in expected:
            with pefile.PE(data=data) as pe:
                statuses = status_by_name(pe.cross_reference_dependencies(manifest))
            self.assertEqual(
                statuses[b"user32.dll.messageboxw"], user32_status
            )
            self.assertEqual(
                statuses[b"oleaut32.dll.sysallocstring"], oleaut32_status
            )

    def test_same_name_from_different_tables_does_not_mask_evidence(self):
        data = build_small_pe(
            [(b"kernel32.dll", [("name", b"LoadLibraryW")])],
            [(b"kernel32.dll", [("name", b"LoadLibraryW")])],
        )
        with pefile.PE(data=data) as pe:
            matches = pe.cross_reference_dependencies(
                [b"kernel32.dll.LoadLibraryW"]
            )

        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertEqual(match.status, pefile.PE.DEPENDENCY_MATCH_AMBIGUOUS)
        self.assertEqual(
            {candidate.table for candidate in match.candidates},
            {pefile.PE.IMPORT_TABLE_DIRECT, pefile.PE.IMPORT_TABLE_DELAY},
        )
        self.assertEqual(len(match.candidates), 2)

    def test_library_version_scopes_ordinal_candidates(self):
        data = build_small_pe(
            [(b"ws2_32.dll", [("ordinal", 24)])],
            [],
        )
        with pefile.PE(data=data) as pe:
            modern = pe.get_dependency_evidence(
                library_versions={b"ws2_32.dll": "10.0.22621"}
            )
            legacy = pe.get_dependency_evidence(
                library_versions={b"ws2_32.dll": (5, 1, 2600)}
            )

        self.assertEqual(len(modern), 1)
        self.assertEqual(modern[0].symbol, None)
        self.assertEqual(modern[0].ordinal, 24)
        self.assertEqual(
            modern[0].candidates, (b"WSApSetPostRoutine",)
        )
        self.assertEqual(
            legacy[0].candidates,
            (b"WSApSetPostRoutine", b"GetAddrInfoW"),
        )

    def test_evidence_is_read_only_and_does_not_mutate_the_image(self):
        original = bytearray(PE_MANIFEST_A)
        with pefile.PE(data=bytes(original)) as pe:
            evidence = pe.get_dependency_evidence()
            matches = pe.cross_reference_dependencies(
                [
                    (b"kernel32.dll", b"CreateFileW"),
                    ("user32.dll", "MessageBoxW"),
                ]
            )
            self.assertEqual(bytes(original), pe.__data__)

        self.assertIsInstance(evidence, tuple)
        record = evidence[0]
        self.assertIsInstance(record, pefile.DependencyEvidence)
        with self.assertRaises(AttributeError):
            record.table = pefile.PE.IMPORT_TABLE_DELAY
        self.assertEqual(
            [match.status for match in matches],
            [
                pefile.PE.DEPENDENCY_MATCH_CONFIRMED,
                pefile.PE.DEPENDENCY_MATCH_PENDING,
            ],
        )


class TestOrdinalLookupRanges(unittest.TestCase):
    def test_version_range_filters_ordinal_tables(self):
        preferred, candidates = ordlookup.ordinal_lookup_candidates(
            b"ws2_32.dll", 24, "10.0.22621"
        )
        self.assertEqual(preferred, b"WSApSetPostRoutine")
        self.assertEqual(candidates, (b"WSApSetPostRoutine",))

        _preferred, legacy_candidates = ordlookup.ordinal_lookup_candidates(
            b"ws2_32.dll", 24, (5, 1, 2600)
        )
        self.assertEqual(
            legacy_candidates, (b"WSApSetPostRoutine", b"GetAddrInfoW")
        )

    def test_existing_lookup_remains_unchanged(self):
        self.assertEqual(
            ordlookup.ordinal_lookup(b"ws2_32.dll", 24),
            b"WSApSetPostRoutine",
        )
        self.assertEqual(
            ordlookup.imphash_ordinal_lookup(b"ws2_32.dll", 24),
            b"GetAddrInfoW",
        )

    def test_custom_table_uses_its_own_version_range(self):
        table = ordlookup.OrdinalTable(
            "released-build",
            {b"custom.dll": {7: b"VersionedSymbol"}},
            min_version=(10, 0),
            max_version=(10, 0, 22621),
        )
        in_range = ordlookup.ordinal_lookup_candidates(
            b"custom.dll", 7, "10.0.19045", (table,)
        )
        out_of_range = ordlookup.ordinal_lookup_candidates(
            b"custom.dll", 7, "11.0.22621", (table,)
        )

        self.assertEqual(in_range, (b"VersionedSymbol", (b"VersionedSymbol",)))
        self.assertEqual(out_of_range, (None, ()))


if __name__ == "__main__":
    unittest.main()
