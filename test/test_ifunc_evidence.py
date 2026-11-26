import hashlib
import struct
import unittest

import ifunc_evidence as ie


TEXT_VA = 0x180
TEXT_OFF = 0x180
TEXT_SIZE = 0x100
DYNSTR = 0x300
DYNSYM = 0x380
HASH = 0x480
RELA = 0x500
GOT = 0x600
DYNAMIC = 0x680
DECOY = 0x780
SHSTRTAB = 0x800
SHDR = 0x900
FILE_SIZE = 0xC00


def lea_rax_ret(target_va: int, instruction_va: int) -> bytes:
    displacement = target_va - (instruction_va + 7)
    return b"\x48\x8d\x05" + struct.pack("<i", displacement) + b"\xc3"


class TinyElfBuilder:
    def __init__(
        self,
        section_headers: bool = True,
        conflict_text_mapping: bool = False,
        overlap_load_mapping: bool = False,
        bss_size: int = 0,
    ):
        self.section_headers = section_headers
        self.conflict_text_mapping = conflict_text_mapping
        self.overlap_load_mapping = overlap_load_mapping
        self.bss_size = bss_size
        self.buf = bytearray(FILE_SIZE)
        self.dynstr = bytearray(b"\x00")
        self.symbols: list[tuple[int, int, int, int, int, int]] = []
        self.relocations: list[tuple[int, int, int]] = []

    def add_string(self, value: str) -> int:
        offset = len(self.dynstr)
        self.dynstr.extend(value.encode("ascii") + b"\x00")
        return offset

    def add_symbol(
        self,
        name: str,
        symbol_type: int,
        value: int,
        size: int = 0,
        *,
        bind: int = 1,
        shndx: int = 1,
    ) -> int:
        name_offset = self.add_string(name) if name else 0
        info = (bind << 4) | (symbol_type & 0x0F)
        index = len(self.symbols) + 1
        self.symbols.append((name_offset, info, 0, shndx, value, size))
        return index

    def add_irelative(self, offset_va: int, addend: int, symbol_index: int = 0) -> None:
        info = (symbol_index << 32) | 37
        self.relocations.append((offset_va, info, addend))

    def place(self, va: int, data: bytes) -> None:
        self.buf[va : va + len(data)] = data

    def write_u64(self, va: int, value: int) -> None:
        struct.pack_into("<Q", self.buf, va, value)

    def _section_name_blob(self) -> tuple[bytes, dict[str, int]]:
        table = bytearray(b"\x00")
        offsets: dict[str, int] = {}

        def add(name: str) -> int:
            offset = len(table)
            offsets[name] = offset
            table.extend(name.encode("ascii") + b"\x00")
            return offset

        for name in (
            ".text",
            ".dynstr",
            ".dynsym",
            ".hash",
            ".rela.dyn",
            ".got",
            ".dynamic",
            ".shstrtab",
        ):
            add(name)
        return bytes(table), offsets

    def build(self, machine: int = 62) -> bytes:
        self.buf[DYNSTR : DYNSTR + len(self.dynstr)] = self.dynstr

        all_symbols = [(0, 0, 0, 0, 0, 0), *self.symbols]
        symbol_blob = b"".join(
            struct.pack("<IBBHQQ", *symbol) for symbol in all_symbols
        )
        self.buf[DYNSYM : DYNSYM + len(symbol_blob)] = symbol_blob

        symbol_count = len(all_symbols)
        hash_blob = (
            struct.pack("<II", 1, symbol_count)
            + struct.pack("<I", 0)
            + bytes(4 * symbol_count)
        )
        self.buf[HASH : HASH + len(hash_blob)] = hash_blob

        rela_blob = b"".join(
            struct.pack("<QQq", offset, info, addend)
            for offset, info, addend in self.relocations
        )
        self.buf[RELA : RELA + len(rela_blob)] = rela_blob

        tags = [
            (4, HASH),
            (5, DYNSTR),
            (6, DYNSYM),
            (10, len(self.dynstr)),
            (11, 24),
            (7, RELA),
            (8, len(rela_blob)),
            (9, 24),
            (0, 0),
        ]
        dynamic_blob = b"".join(struct.pack("<qQ", *tag) for tag in tags)
        self.buf[DYNAMIC : DYNAMIC + len(dynamic_blob)] = dynamic_blob

        decoy = b"\x0f\x0b" + b"DECOY-MAPPING-BYTES-0123456789"
        self.buf[DECOY : DECOY + len(decoy)] = decoy[:32]

        shstr_blob, names = self._section_name_blob()
        self.buf[SHSTRTAB : SHSTRTAB + len(shstr_blob)] = shstr_blob

        if self.section_headers:
            text_offset = DECOY if self.conflict_text_mapping else TEXT_OFF
            sections = [
                (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (
                    names[".text"],
                    1,
                    0x6,
                    TEXT_VA,
                    text_offset,
                    TEXT_SIZE,
                    0,
                    0,
                    16,
                    0,
                ),
                (
                    names[".dynstr"],
                    3,
                    0x2,
                    DYNSTR,
                    DYNSTR,
                    len(self.dynstr),
                    0,
                    0,
                    1,
                    0,
                ),
                (
                    names[".dynsym"],
                    11,
                    0x2,
                    DYNSYM,
                    DYNSYM,
                    len(symbol_blob),
                    2,
                    1,
                    8,
                    24,
                ),
                (
                    names[".hash"],
                    5,
                    0x2,
                    HASH,
                    HASH,
                    len(hash_blob),
                    3,
                    0,
                    4,
                    4,
                ),
                (
                    names[".rela.dyn"],
                    4,
                    0x2,
                    RELA,
                    RELA,
                    len(rela_blob),
                    3,
                    0,
                    8,
                    24,
                ),
                (names[".got"], 1, 0x3, GOT, GOT, 0x80, 0, 0, 8, 8),
                (
                    names[".dynamic"],
                    6,
                    0x3,
                    DYNAMIC,
                    DYNAMIC,
                    len(dynamic_blob),
                    2,
                    0,
                    8,
                    16,
                ),
                (
                    names[".shstrtab"],
                    3,
                    0,
                    0,
                    SHSTRTAB,
                    len(shstr_blob),
                    0,
                    0,
                    1,
                    0,
                ),
            ]
            for index, header in enumerate(sections):
                struct.pack_into("<IIQQQQIIQQ", self.buf, SHDR + index * 64, *header)
            shoff = SHDR
            shnum = len(sections)
            shstrndx = 8
        else:
            shoff = 0
            shnum = 0
            shstrndx = 0

        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
        phnum = 3 if self.overlap_load_mapping else 2
        struct.pack_into(
            "<16sHHIQQQIHHHHHH",
            self.buf,
            0,
            ident,
            3,
            machine,
            1,
            0,
            64,
            shoff,
            0,
            64,
            56,
            phnum,
            64,
            shnum,
            shstrndx,
        )
        struct.pack_into(
            "<IIQQQQQQ",
            self.buf,
            64,
            1,
            7,
            0,
            0,
            0,
            FILE_SIZE,
            FILE_SIZE + self.bss_size,
            0x1000,
        )
        struct.pack_into(
            "<IIQQQQQQ",
            self.buf,
            64 + 56,
            2,
            6,
            DYNAMIC,
            DYNAMIC,
            DYNAMIC,
            len(dynamic_blob),
            len(dynamic_blob),
            8,
        )
        if self.overlap_load_mapping:
            struct.pack_into(
                "<IIQQQQQQ",
                self.buf,
                64 + 2 * 56,
                1,
                5,
                DECOY,
                0x200,
                0x200,
                32,
                32,
                0,
            )
        return bytes(self.buf[:FILE_SIZE])


def basic_elf(
    section_headers: bool = True,
    conflict: bool = False,
    overlap_load: bool = False,
) -> bytes:
    builder = TinyElfBuilder(
        section_headers=section_headers,
        conflict_text_mapping=conflict,
        overlap_load_mapping=overlap_load,
    )
    selector_va = 0x200
    implementation_va = 0x220
    got_va = GOT + 0x10
    builder.place(selector_va, lea_rax_ret(implementation_va, selector_va))
    builder.place(implementation_va, b"\x31\xc0\xc3" + b"\x90" * 13)
    builder.add_symbol("dispatch_version", 10, selector_va, 8)
    builder.add_symbol("dispatch_version_alias", 10, selector_va, 8)
    builder.add_symbol("patched_implementation", 2, implementation_va, 16)
    builder.add_irelative(got_va, selector_va, symbol_index=0)
    return builder.build()


class IfuncEvidenceTests(unittest.TestCase):
    def test_merges_dynamic_and_section_rela_and_confirms_direct_target(self):
        inventory = ie.analyze_bytes(basic_elf(True))
        self.assertEqual(inventory.machine, "EM_X86_64")
        self.assertTrue(inventory.has_section_headers)
        self.assertEqual(len(inventory.records), 1)

        record = inventory.records[0]
        self.assertEqual(record.selector_va, 0x200)
        self.assertTrue(record.selector_located)
        self.assertTrue(record.selector_mapping_verified)
        self.assertTrue(record.implementation_confirmed)
        self.assertEqual(record.implementation_va, 0x220)
        self.assertEqual(len(record.relocations), 1)

        reloc = record.relocations[0]
        self.assertEqual(reloc.r_type, 37)
        self.assertEqual(reloc.r_addend, 0x200)
        self.assertEqual(len(reloc.dynamic_occurrences()), 1)
        self.assertEqual(len(reloc.section_occurrences()), 1)
        self.assertEqual(reloc.dynamic_occurrences()[0].locator, "DT_RELA[0]")
        self.assertEqual(reloc.section_occurrences()[0].locator, ".rela.dyn[0]")
        self.assertEqual(reloc.dynamic_occurrences()[0].entry_file_offset, RELA)
        self.assertEqual(reloc.section_occurrences()[0].entry_file_offset, RELA)

        codes = {item.code for item in record.reservations}
        self.assertIn("symbol_aliases", codes)
        self.assertIn("zero_filled_address", codes)  # pre-relocation GOT slot
        self.assertEqual(len(record.aliases), 1)

        markdown = ie.render_markdown(inventory)
        self.assertIn("定位到选择器", markdown)
        self.assertIn("有证据确认实际实现", markdown)
        self.assertIn("是：选择器 VA 0x200", markdown)
        self.assertIn("confirmed_direct_return", ie.render_json(inventory))

    def test_program_headers_only_delivery(self):
        inventory = ie.analyze_bytes(basic_elf(False))
        self.assertFalse(inventory.has_section_headers)
        self.assertTrue(inventory.has_program_headers)
        record = inventory.records[0]
        self.assertTrue(record.selector_located)
        self.assertTrue(record.implementation_confirmed)
        self.assertEqual(len(record.relocations[0].dynamic_occurrences()), 1)
        self.assertEqual(record.relocations[0].section_occurrences(), [])
        self.assertIn("动态线索 1 条/节头线索 0 条", record.selector_column())

    def test_selector_located_does_not_confirm_zero_implementation(self):
        builder = TinyElfBuilder()
        selector_va = 0x240
        got_va = GOT + 0x20
        builder.add_symbol("zero_dispatch", 10, selector_va, 8)
        builder.add_irelative(got_va, selector_va)
        data = builder.build()

        inventory = ie.analyze_bytes(data)
        record = inventory.records[0]
        self.assertTrue(record.selector_located)
        self.assertEqual(record.selector_va, selector_va)
        self.assertFalse(record.implementation_confirmed)
        self.assertNotEqual(record.implementation_status, "confirmed_direct_return")
        codes = {item.code for item in record.reservations}
        self.assertIn("zero_filled_address", codes)
        self.assertTrue(
            any("未确认" in row.implementation_column() for row in inventory.records)
        )

        markdown = ie.render_markdown(inventory)
        self.assertIn("是：选择器 VA 0x240", markdown)
        self.assertIn("未确认：", markdown)

    def test_true_segment_zero_fill_is_locatable(self):
        bss_va = FILE_SIZE + 0x10
        builder = TinyElfBuilder(bss_size=0x40)
        builder.add_symbol("bss_dispatch", 10, bss_va, 16)
        builder.add_irelative(GOT + 0x40, bss_va)

        record = ie.analyze_bytes(builder.build()).records[0]
        self.assertTrue(record.selector_located)
        self.assertFalse(record.implementation_confirmed)
        mapping = record.selector_resolution.primary
        self.assertIsNotNone(mapping)
        self.assertTrue(mapping.zero_fill)
        self.assertIsNone(mapping.file_offset)
        self.assertIn(
            "zero_filled_address",
            {item.code for item in record.reservations},
        )

    def test_conflicting_section_mapping_is_locatable(self):
        inventory = ie.analyze_bytes(basic_elf(True, conflict=True))
        record = inventory.records[0]
        self.assertTrue(record.selector_located)
        self.assertFalse(record.implementation_confirmed)
        self.assertEqual(record.implementation_status, "contradictory_mapping")
        conflict_reservations = [
            item for item in record.reservations if item.code == "mapping_contradiction"
        ]
        self.assertTrue(conflict_reservations)
        where = conflict_reservations[0].where
        self.assertEqual(where["vaddr"], 0x200)
        self.assertIn("left", where)
        self.assertIn("right", where)
        self.assertTrue(where["bytes_differ"])

    def test_conflicting_overlapping_pt_load_mappings_are_locatable(self):
        inventory = ie.analyze_bytes(basic_elf(True, overlap_load=True))
        record = inventory.records[0]
        self.assertTrue(record.selector_located)
        self.assertFalse(record.implementation_confirmed)
        conflicts = [
            item
            for item in record.reservations
            if item.code == "mapping_contradiction" and item.severity == "error"
        ]
        self.assertTrue(conflicts)
        sources = {
            mapping["source"]
            for item in conflicts
            for mapping in (item.where["left"], item.where["right"])
        }
        self.assertIn("program_header", sources)

    def test_multiple_direct_targets_remain_unresolved(self):
        builder = TinyElfBuilder()
        selector_va = 0x200
        target_one = 0x220
        target_two = 0x250
        got_va = GOT + 0x30
        selector_code = lea_rax_ret(target_one, selector_va) + lea_rax_ret(
            target_two, selector_va + 8
        )
        builder.place(selector_va, selector_code)
        builder.place(target_one, b"\x31\xc0\xc3" + b"\x90" * 13)
        builder.place(target_two, b"\x31\xff\xc3" + b"\x90" * 13)
        builder.add_symbol("branching_dispatch", 10, selector_va, len(selector_code))
        builder.add_irelative(got_va, selector_va)

        record = ie.analyze_bytes(builder.build()).records[0]
        self.assertTrue(record.selector_located)
        self.assertFalse(record.implementation_confirmed)
        self.assertEqual(record.implementation_status, "multiple_dispatch_targets")
        strong = [
            candidate for candidate in record.candidates if candidate.direct_return
        ]
        self.assertEqual(
            {candidate.target_va for candidate in strong},
            {target_one, target_two},
        )

    def test_rejects_non_x86_64(self):
        data = bytearray(basic_elf(True))
        struct.pack_into("<H", data, 18, 183)  # EM_AARCH64
        with self.assertRaises(ie.UnsupportedArchitectureError):
            ie.analyze_bytes(bytes(data))

    def test_manifest_selector_match_is_not_implementation_evidence(self):
        implementation_bytes = b"\x31\xc0\xc3" + b"\x90" * 13
        manifest = {
            "selector_addresses": [
                {"address": "0x200", "version": "listed-selector-build"}
            ],
            "implementations": [
                {
                    "implementation_va": "0x220",
                    "size": len(implementation_bytes),
                    "sha256": hashlib.sha256(implementation_bytes).hexdigest(),
                    "version": "patched-fixture",
                    "status": "patched",
                }
            ],
        }
        inventory = ie.analyze_bytes(basic_elf(True), manifest=manifest)
        record = inventory.records[0]
        self.assertTrue(record.implementation_confirmed)
        self.assertTrue(record.manifest_selector_matches)
        self.assertTrue(record.manifest_matches[0]["hash_match"])
        self.assertEqual(record.manifest_matches[0]["hash_size"], 16)
        self.assertIn(
            "manifest_selector_only",
            {item.code for item in record.reservations},
        )


if __name__ == "__main__":
    unittest.main()
