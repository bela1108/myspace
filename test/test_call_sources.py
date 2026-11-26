import io
import struct
import unittest
from dataclasses import dataclass
from pathlib import Path

from elftools.dwarf.call_sources import (
    CallSourceAnalyzer,
    analyze_elf_streams,
    render_text,
)
from elftools.elf.elffile import ELFFile


TAG_COMPILE_UNIT = 0x11
TAG_SUBPROGRAM = 0x2E
TAG_INLINED_SUBROUTINE = 0x1D
TAG_CALL_SITE = 0x48

DW_FORM_ADDR = 0x01
DW_FORM_DATA4 = 0x06
DW_FORM_DATA8 = 0x07
DW_FORM_STRING = 0x08
DW_FORM_DATA1 = 0x0B
DW_FORM_FLAG = 0x0C
DW_FORM_UDATA = 0x0F
DW_FORM_REF_ADDR = 0x10

DW_AT_NAME = 0x03
DW_AT_STMT_LIST = 0x10
DW_AT_LOW_PC = 0x11
DW_AT_HIGH_PC = 0x12
DW_AT_COMP_DIR = 0x1B
DW_AT_ABSTRACT_ORIGIN = 0x31
DW_AT_DECLARATION = 0x3C
DW_AT_CALL_COLUMN = 0x57
DW_AT_CALL_FILE = 0x58
DW_AT_CALL_LINE = 0x59
DW_AT_CALL_RETURN_PC = 0x7D
DW_AT_CALL_ORIGIN = 0x7F
DW_AT_CALL_PC = 0x81
DW_AT_CALL_TAIL_CALL = 0x82


def u8(value):
    return struct.pack("<B", value)


def u16(value):
    return struct.pack("<H", value)


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def uleb(value):
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            return bytes(result)


def sleb(value):
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        sign_bit = byte & 0x40
        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            result.append(byte)
            return bytes(result)
        result.append(byte | 0x80)


def cstring(value):
    return value.encode("utf-8") + b"\0"


@dataclass(frozen=True)
class Ref:
    label: str


@dataclass(frozen=True)
class Abbrev:
    code: int
    tag: int
    children: bool
    attributes: tuple[tuple[int, int], ...]


ABBREV_CU = Abbrev(1, TAG_COMPILE_UNIT, True, (
    (DW_AT_NAME, DW_FORM_STRING),
    (DW_AT_COMP_DIR, DW_FORM_STRING),
    (DW_AT_STMT_LIST, DW_FORM_DATA4),
))
ABBREV_SUBPROGRAM = Abbrev(2, TAG_SUBPROGRAM, True, (
    (DW_AT_NAME, DW_FORM_STRING),
    (DW_AT_LOW_PC, DW_FORM_ADDR),
    (DW_AT_HIGH_PC, DW_FORM_UDATA),
))
ABBREV_DECLARATION = Abbrev(3, TAG_SUBPROGRAM, False, (
    (DW_AT_NAME, DW_FORM_STRING),
    (DW_AT_DECLARATION, DW_FORM_FLAG),
))
ABBREV_INLINE = Abbrev(4, TAG_INLINED_SUBROUTINE, True, (
    (DW_AT_ABSTRACT_ORIGIN, DW_FORM_REF_ADDR),
    (DW_AT_LOW_PC, DW_FORM_ADDR),
    (DW_AT_HIGH_PC, DW_FORM_UDATA),
    (DW_AT_CALL_FILE, DW_FORM_UDATA),
    (DW_AT_CALL_LINE, DW_FORM_UDATA),
    (DW_AT_CALL_COLUMN, DW_FORM_UDATA),
))
ABBREV_ORDINARY_CALL = Abbrev(5, TAG_CALL_SITE, False, (
    (DW_AT_CALL_ORIGIN, DW_FORM_REF_ADDR),
    (DW_AT_CALL_RETURN_PC, DW_FORM_ADDR),
    (DW_AT_CALL_PC, DW_FORM_ADDR),
))
ABBREV_TAIL_CALL = Abbrev(6, TAG_CALL_SITE, False, (
    (DW_AT_CALL_ORIGIN, DW_FORM_REF_ADDR),
    (DW_AT_CALL_PC, DW_FORM_ADDR),
    (DW_AT_CALL_TAIL_CALL, DW_FORM_FLAG),
))

ABBREVIATIONS = (
    ABBREV_CU,
    ABBREV_SUBPROGRAM,
    ABBREV_DECLARATION,
    ABBREV_INLINE,
    ABBREV_ORDINARY_CALL,
    ABBREV_TAIL_CALL,
)


def encode_abbreviations(abbrevs=ABBREVIATIONS):
    output = bytearray()
    for abbrev in abbrevs:
        output += uleb(abbrev.code)
        output += uleb(abbrev.tag)
        output += u8(1 if abbrev.children else 0)
        for name, form in abbrev.attributes:
            output += uleb(name)
            output += uleb(form)
        output += b"\0\0"
    output += b"\0"
    return bytes(output)


class InfoBuilder:
    def __init__(self):
        self.buffer = bytearray()
        self.labels = {}
        self.patches = []
        self.unit_starts = []

    def begin_unit(self):
        start = len(self.buffer)
        self.unit_starts.append(start)
        self.buffer += u32(0) + u16(4) + u32(0) + u8(8)

    def end_unit(self):
        start = self.unit_starts[-1]
        struct.pack_into("<I", self.buffer, start, len(self.buffer) - start - 4)

    def die(self, abbrev, values, label=None):
        if label is not None:
            self.labels[label] = len(self.buffer)
        self.buffer += uleb(abbrev.code)
        for attribute, form in abbrev.attributes:
            self._emit_form(form, values[attribute])

    def end_children(self):
        self.buffer += b"\0"

    def _emit_form(self, form, value):
        if isinstance(value, Ref):
            position = len(self.buffer)
            self.patches.append((position, value.label))
            self.buffer += u32(0)
        elif form == DW_FORM_STRING:
            self.buffer += cstring(value)
        elif form == DW_FORM_ADDR:
            self.buffer += u64(value)
        elif form == DW_FORM_DATA1:
            self.buffer += u8(value)
        elif form == DW_FORM_DATA4:
            self.buffer += u32(value)
        elif form == DW_FORM_DATA8:
            self.buffer += u64(value)
        elif form == DW_FORM_UDATA:
            self.buffer += uleb(value)
        elif form == DW_FORM_FLAG:
            self.buffer += u8(1 if value else 0)
        else:
            raise AssertionError(f"unhandled DWARF form {form:#x}")

    def build(self):
        info = bytearray(self.buffer)
        for position, label in self.patches:
            struct.pack_into("<I", info, position, self.labels[label])
        return bytes(info)


def build_line_program():
    standard_lengths = bytes((0, 1, 1, 1, 1))
    header_tail = (
        struct.pack("<BBbBB", 1, 1, -5, 14, 6)
        + standard_lengths
        + cstring("work")
        + b"\0"
        + cstring("forensic_sample.c")
        + uleb(1)
        + uleb(0)
        + uleb(0)
        + b"\0"
    )
    program = bytearray()
    program += b"\0" + uleb(9) + b"\x02" + u64(0x1013)
    program += b"\x03" + sleb(41)
    program += b"\x05" + uleb(13)
    program += b"\x01"
    program += b"\0" + uleb(9) + b"\x02" + u64(0x1018)
    program += b"\x03" + sleb(1)
    program += b"\x05" + uleb(1)
    program += b"\x01"
    program += b"\x02\x01"
    program += b"\0\x01\x01"
    unit = u16(3) + u32(len(header_tail)) + header_tail + bytes(program)
    return u32(len(unit)) + unit


def build_elf(debug_info, debug_abbrev, debug_line=b""):
    section_names = (".shstrtab", ".debug_info", ".debug_abbrev", ".debug_line")
    shstrtab = bytearray(b"\0")
    name_offsets = {}
    for name in section_names:
        name_offsets[name] = len(shstrtab)
        shstrtab += cstring(name)

    section_data = {
        ".shstrtab": bytes(shstrtab),
        ".debug_info": debug_info,
        ".debug_abbrev": debug_abbrev,
        ".debug_line": debug_line,
    }
    offset = 64
    packed_sections = []
    for name in section_names:
        data = section_data[name]
        packed_sections.append((name_offsets[name], 3 if name == ".shstrtab" else 1,
                                offset, data))
        offset += len(data)

    shoff = (offset + 7) & ~7
    header = bytearray()
    header += b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    header += struct.pack(
        "<HHIQQQIHHHHHH",
        1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64,
        len(section_names) + 1, 1,
    )
    blob = bytearray(header)
    if len(blob) < shoff:
        blob += b"\0" * (shoff - len(blob))
    blob += b"\0" * 64
    for name_offset, section_type, section_offset, data in packed_sections:
        blob += struct.pack(
            "<IIQQQQIIQQ",
            name_offset, section_type, 0, 0, section_offset, len(data),
            0, 0, 1, 0,
        )
    for _, _, section_offset, data in packed_sections:
        if len(blob) < section_offset:
            blob += b"\0" * (section_offset - len(blob))
        blob[section_offset:section_offset + len(data)] = data
    return bytes(blob)


def build_release_elf():
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    return ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 62, 1, 0x401000, 0, 0, 0, 64, 0, 0, 0, 0, 0,
    )


def inline_return_sample():
    builder = InfoBuilder()
    builder.begin_unit()
    builder.die(ABBREV_CU, {
        DW_AT_NAME: "inline_return.c",
        DW_AT_COMP_DIR: "/forensic",
        DW_AT_STMT_LIST: 0,
    }, "cu")
    builder.die(ABBREV_SUBPROGRAM, {
        DW_AT_NAME: "dispatch", DW_AT_LOW_PC: 0x1000, DW_AT_HIGH_PC: 0x40,
    }, "dispatch")
    builder.die(ABBREV_INLINE, {
        DW_AT_ABSTRACT_ORIGIN: Ref("alpha_decl"),
        DW_AT_LOW_PC: 0x1008, DW_AT_HIGH_PC: 0x20,
        DW_AT_CALL_FILE: 1, DW_AT_CALL_LINE: 20, DW_AT_CALL_COLUMN: 5,
    }, "alpha")
    builder.die(ABBREV_INLINE, {
        DW_AT_ABSTRACT_ORIGIN: Ref("beta_decl"),
        DW_AT_LOW_PC: 0x1010, DW_AT_HIGH_PC: 0x10,
        DW_AT_CALL_FILE: 1, DW_AT_CALL_LINE: 30, DW_AT_CALL_COLUMN: 9,
    }, "beta")
    builder.die(ABBREV_ORDINARY_CALL, {
        DW_AT_CALL_ORIGIN: Ref("sensor_decl"),
        DW_AT_CALL_RETURN_PC: 0x1018,
        DW_AT_CALL_PC: 0x1013,
    }, "ordinary_call")
    builder.end_children()
    builder.end_children()
    builder.end_children()
    builder.die(ABBREV_DECLARATION, {DW_AT_NAME: "alpha", DW_AT_DECLARATION: 1}, "alpha_decl")
    builder.die(ABBREV_DECLARATION, {DW_AT_NAME: "beta", DW_AT_DECLARATION: 1}, "beta_decl")
    builder.die(ABBREV_DECLARATION, {DW_AT_NAME: "sensor_read", DW_AT_DECLARATION: 1}, "sensor_decl")
    builder.end_children()
    builder.end_unit()
    return build_elf(builder.build(), encode_abbreviations(), build_line_program())


def _tail_cu(builder, unit_name, base, tail):
    builder.begin_unit()
    builder.die(ABBREV_CU, {
        DW_AT_NAME: unit_name,
        DW_AT_COMP_DIR: "/" + unit_name,
        DW_AT_STMT_LIST: 0,
    })
    builder.die(ABBREV_SUBPROGRAM, {
        DW_AT_NAME: "outer", DW_AT_LOW_PC: base, DW_AT_HIGH_PC: 0x40,
    })
    builder.die(ABBREV_INLINE, {
        DW_AT_ABSTRACT_ORIGIN: Ref(unit_name + ".alpha"),
        DW_AT_LOW_PC: base + 0x08, DW_AT_HIGH_PC: 0x20,
        DW_AT_CALL_FILE: 1, DW_AT_CALL_LINE: 10, DW_AT_CALL_COLUMN: 2,
    })
    builder.die(ABBREV_INLINE, {
        DW_AT_ABSTRACT_ORIGIN: Ref(unit_name + ".beta"),
        DW_AT_LOW_PC: base + 0x10, DW_AT_HIGH_PC: 0x10,
        DW_AT_CALL_FILE: 1, DW_AT_CALL_LINE: 11, DW_AT_CALL_COLUMN: 4,
    })
    if tail:
        builder.die(ABBREV_TAIL_CALL, {
            DW_AT_CALL_ORIGIN: Ref(unit_name + ".work"),
            DW_AT_CALL_PC: base + 0x12,
            DW_AT_CALL_TAIL_CALL: 1,
        })
    else:
        builder.die(ABBREV_ORDINARY_CALL, {
            DW_AT_CALL_ORIGIN: Ref(unit_name + ".work"),
            DW_AT_CALL_RETURN_PC: base + 0x18,
            DW_AT_CALL_PC: base + 0x13,
        })
    builder.end_children()
    builder.end_children()
    builder.end_children()
    builder.die(ABBREV_DECLARATION, {DW_AT_NAME: "alpha", DW_AT_DECLARATION: 1},
                unit_name + ".alpha")
    builder.die(ABBREV_DECLARATION, {DW_AT_NAME: "beta", DW_AT_DECLARATION: 1},
                unit_name + ".beta")
    builder.die(ABBREV_DECLARATION, {DW_AT_NAME: "work", DW_AT_DECLARATION: 1},
                unit_name + ".work")
    builder.end_children()
    builder.end_unit()


def tail_and_multicu_sample():
    builder = InfoBuilder()
    _tail_cu(builder, "cu_zero.c", 0x2000, True)
    second_cu_offset = len(builder.buffer)
    _tail_cu(builder, "cu_one.c", 0x3000, False)
    elf = build_elf(builder.build(), encode_abbreviations())
    return elf, 0, second_cu_offset


class CallSourceMemorySamplesTest(unittest.TestCase):
    def test_inline_stack_and_ordinary_return(self):
        debug_bytes = inline_return_sample()
        report = analyze_elf_streams(
            [0x1018],
            release_stream=io.BytesIO(build_release_elf()),
            debug_stream=io.BytesIO(debug_bytes),
            release_name="memory-release.elf",
            debug_name="memory-debug.elf",
        )

        self.assertFalse(report.release.has_dwarf_info)
        self.assertEqual(report.release.reason.code, "release_without_debug_records")
        self.assertTrue(report.debug.has_dwarf_info)

        address_report = report.addresses[0]
        self.assertEqual(address_report.status, "explained")
        self.assertEqual(len(address_report.ordinary_calls), 1)
        self.assertEqual(address_report.tail_calls, [])

        call = address_report.ordinary_calls[0]
        self.assertEqual(call.matched_by, "DW_AT_call_return_pc")
        self.assertEqual(call.target.name, "sensor_read")
        self.assertEqual(call.caller.name, "dispatch")
        self.assertEqual([frame.symbol.name for frame in call.inline_stack],
                         ["alpha", "beta"])
        self.assertEqual(
            [(frame.call_location.line, frame.call_location.column)
             for frame in call.inline_stack],
            [(20, 5), (30, 9)],
        )
        beta_location = call.inline_stack[1].call_location
        self.assertEqual(beta_location.file, "forensic_sample.c")
        self.assertTrue(beta_location.resolved)
        self.assertEqual(call.source_location.line, 42)
        self.assertEqual(call.source_location.column, 13)
        self.assertIn("DW_AT_call_return_pc", report.to_json())
        self.assertIn("ordinary call", render_text(report))

    def test_tail_candidate_is_separate_and_cu_scoped(self):
        debug_bytes, cu_zero, cu_one = tail_and_multicu_sample()
        report = analyze_elf_streams(
            [0x2012, 0x3018, 0x9999],
            release_stream=io.BytesIO(build_release_elf()),
            debug_stream=io.BytesIO(debug_bytes),
        )

        tail_report, ordinary_report, unknown_report = report.addresses
        self.assertEqual(len(tail_report.tail_calls), 1)
        self.assertEqual(tail_report.ordinary_calls, [])
        tail = tail_report.tail_calls[0]
        self.assertEqual(tail.matched_by, "DW_AT_call_pc")
        self.assertIsNone(tail.return_pc)
        self.assertTrue(tail.is_tail)
        self.assertEqual(tail.target.name, "work")
        self.assertEqual(tail.caller.name, "outer")
        self.assertEqual([frame.symbol.name for frame in tail.inline_stack],
                         ["alpha", "beta"])
        self.assertEqual(tail.call_site.cu_offset, cu_zero)
        self.assertEqual(tail.caller.cu_offset, cu_zero)
        self.assertEqual(tail.target.cu_offset, cu_zero)
        self.assertTrue(all(frame.ref.cu_offset == cu_zero
                            for frame in tail.inline_stack))

        self.assertEqual(len(ordinary_report.ordinary_calls), 1)
        ordinary = ordinary_report.ordinary_calls[0]
        self.assertEqual(ordinary.matched_by, "DW_AT_call_return_pc")
        self.assertEqual(ordinary.return_pc, 0x3018)
        self.assertEqual(ordinary.call_site.cu_offset, cu_one)
        self.assertTrue(all(frame.ref.cu_offset == cu_one
                            for frame in ordinary.inline_stack))

        self.assertEqual(unknown_report.status, "unknown")
        codes = {reason.code for reason in unknown_report.reasons}
        self.assertIn("unattributed_address", codes)
        self.assertIn("no_tail_call_match", codes)

    def test_release_only_gives_reviewable_unknown(self):
        report = analyze_elf_streams(
            [0x1018],
            release_stream=io.BytesIO(build_release_elf()),
        )
        self.assertFalse(report.release.has_dwarf_info)
        self.assertEqual(report.addresses[0].status, "unknown")
        self.assertEqual(report.addresses[0].reasons[0].code,
                         "debug_source_unavailable")
        self.assertEqual(report.release.reason.code,
                         "release_without_debug_records")

    def test_existing_gnu_tailcall_binary(self):
        binary = Path(__file__).resolve().parents[1] / "test/testfiles_for_readelf/gcc_tailcall.o.elf"
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            analyzer = CallSourceAnalyzer(elf.get_dwarf_info(), str(binary))
            [report] = analyzer.analyze_addresses([0x11])
        self.assertEqual(len(report.tail_calls), 1)
        tail = report.tail_calls[0]
        self.assertEqual(tail.target.name, "f2")
        self.assertEqual(tail.caller.name, "f1")
        self.assertEqual(tail.matched_by, "DW_AT_low_pc+DW_AT_GNU_tail_call")


if __name__ == "__main__":
    unittest.main()
