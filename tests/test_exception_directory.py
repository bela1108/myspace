import struct
import unittest

import pefile


MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3


def runtime_function(begin, end, unwind):
    return struct.pack("<III", begin, end, unwind)


def unwind_info(count=0, flags=0, codes=b"", handler=None):
    # Fixed header is 4 bytes: Version|Flags, SizeOfProlog, CountOfCodes,
    # FrameRegister (low nibble) | FrameOffset (high nibble).
    header = struct.pack("<BBBB", (1 & 0x7) | ((flags & 0x1F) << 3), 0, count, 0)
    data = header + codes
    padded = (count + 1) & ~1
    data += b"\x00" * (padded * 2 - len(codes))
    if flags != 0 and handler is not None:
        data += struct.pack("<I", handler)
    return data


class SyntheticPE:
    """Builds a minimal, in-memory PE with a code and a data section."""

    def __init__(self, machine=MACHINE_AMD64):
        self.machine = machine
        self.file_alignment = 0x200
        self.section_alignment = 0x1000
        self.headers_size = 0x400
        self.code_rva = 0x1000
        self.data_rva = 0x2000
        self.code = bytearray(b"\xC3" * 0x200)
        self.data = bytearray(0x400)
        self.exception_rva = None
        self.exception_size = 0

    def put_data(self, rva, blob):
        offset = rva - self.data_rva
        self.data[offset : offset + len(blob)] = blob

    def set_exception_directory(self, rva, size):
        self.exception_rva = rva
        self.exception_size = size

    def build(self):
        size_of_headers = self.headers_size
        size_of_image = self.data_rva + self.section_alignment
        code_raw_size = len(self.code)
        data_raw_size = len(self.data)

        dos_header = bytearray(0x40)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 0x40)

        data_directories = [0] * 32
        if self.exception_rva is not None:
            data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION * 2] = self.exception_rva
            data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION * 2 + 1] = self.exception_size

        optional = bytearray(0xF0)
        struct.pack_into("<HBBIII", optional, 0, 0x20B, 1, 0, code_raw_size, 0, 0)
        struct.pack_into("<III", optional, 16, 0x1000, 0x1000, 0x10000)
        struct.pack_into("<II", optional, 32, self.section_alignment, self.file_alignment)
        struct.pack_into("<HH", optional, 40, 0, 0)
        struct.pack_into("<I", optional, 44, 0)
        struct.pack_into("<IIIII", optional, 48, 0, 0, 0, 0, 0)
        struct.pack_into("<III", optional, 68, 0x100000, 0x1000, 0x10)
        struct.pack_into("<IIIIII", optional, 80, 0, 0, 0, 0, 0, 0)
        struct.pack_into("<I", optional, 104, size_of_headers)
        struct.pack_into("<I", optional, 108, 16)
        struct.pack_into("<I", optional, 120, size_of_image)
        struct.pack_into("<II", optional, 124, self.file_alignment, 0)
        struct.pack_into("<IHH", optional, 132, 0, 3, 0)
        struct.pack_into("<" + "I" * 32, optional, 112, *data_directories)

        section_table = bytearray()
        section_table += self._section_header(
            b".text\x00\x00\x00", len(self.code), self.code_rva,
            code_raw_size, size_of_headers,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        )
        section_table += self._section_header(
            b".rdata\x00\x00", len(self.data), self.data_rva,
            data_raw_size, size_of_headers + code_raw_size,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )

        file_header = struct.pack("<HHIIIHH", self.machine, 2, 0, 0, 0, 0xF0, 0x0022)
        headers = dos_header + b"PE\x00\x00" + file_header + bytes(optional) + section_table
        headers = headers[:size_of_headers].ljust(size_of_headers, b"\x00")

        raw = bytearray(headers)
        raw += bytes(self.code).ljust(code_raw_size, b"\x00")
        raw += bytes(self.data).ljust(data_raw_size, b"\x00")
        return bytes(raw)

    @staticmethod
    def _section_header(name, virtual_size, virtual_address, raw_size, raw_ptr, characteristics):
        return struct.pack(
            "<8sIIIIIIHHI", name, virtual_size, virtual_address, raw_size,
            raw_ptr, 0, 0, 0, 0, characteristics,
        )


def load(builder):
    return pefile.PE(data=builder.build())


class TestExceptionDirectory(unittest.TestCase):
    def _builder_with_two_functions(self):
        builder = SyntheticPE()
        unwind_rva = builder.data_rva
        builder.put_data(unwind_rva, unwind_info())
        entries = runtime_function(builder.code_rva, builder.code_rva + 0x10, unwind_rva)
        entries += runtime_function(builder.code_rva + 0x10, builder.code_rva + 0x20, unwind_rva)
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, entries)
        builder.set_exception_directory(table_rva, len(entries))
        return builder

    def test_valid_entries_are_parsed(self):
        pe = load(self._builder_with_two_functions())
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 2)
        first = pe.DIRECTORY_ENTRY_EXCEPTION[0]
        self.assertEqual(first.struct.BeginAddress, 0x1000)
        self.assertEqual(first.struct.EndAddress, 0x1010)
        self.assertEqual(first.unwindinfo.Version, 1)
        self.assertFalse(
            hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION_ERRORS")
            and pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        )
        pe.close()



    def test_begin_address_outside_section_is_rejected(self):
        builder = SyntheticPE()
        unwind_rva = builder.data_rva
        builder.put_data(unwind_rva, unwind_info())
        bad = runtime_function(0x9000, 0x9010, unwind_rva)
        good = runtime_function(builder.code_rva, builder.code_rva + 0x10, unwind_rva)
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, bad + good)
        builder.set_exception_directory(table_rva, 24)

        pe = load(builder)
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 1)
        kept = pe.DIRECTORY_ENTRY_EXCEPTION[0]
        self.assertEqual(kept.struct.BeginAddress, builder.code_rva)
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].offset, 0)
        self.assertIn("BeginAddress", errors[0].reason)
        pe.close()

    def test_unwind_data_pointing_at_own_runtime_function_is_rejected(self):
        builder = SyntheticPE()
        table_rva = builder.data_rva + 0x40
        good_unwind = builder.data_rva
        builder.put_data(good_unwind, unwind_info())
        # A self-looping UNWIND_INFO: CHAININFO whose FunctionEntry points back
        # to its own RVA, so the unwind walk never terminates.
        loop_unwind = builder.data_rva + 0x10
        builder.put_data(loop_unwind, unwind_info(flags=0x4, handler=loop_unwind))
        bad = runtime_function(builder.code_rva, builder.code_rva + 0x10, loop_unwind)
        good = runtime_function(
            builder.code_rva + 0x10, builder.code_rva + 0x20, good_unwind
        )
        builder.put_data(table_rva, bad + good)
        builder.set_exception_directory(table_rva, 24)

        pe = load(builder)
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 1)
        self.assertEqual(
            pe.DIRECTORY_ENTRY_EXCEPTION[0].struct.BeginAddress,
            builder.code_rva + 0x10,
        )
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertEqual(errors[0].offset, 0)
        self.assertIn("loop", errors[0].reason)
        pe.close()

    def test_directory_size_not_multiple_of_entry_size(self):
        builder = SyntheticPE()
        unwind_rva = builder.data_rva
        builder.put_data(unwind_rva, unwind_info())
        entry = runtime_function(builder.code_rva, builder.code_rva + 0x10, unwind_rva)
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, entry + b"\x01\x02")
        builder.set_exception_directory(table_rva, 14)

        pe = load(builder)
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 1)
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].offset, 12)
        self.assertIn("multiple", errors[0].reason)
        pe.close()


    def test_unknown_unwind_opcode_is_rejected(self):
        builder = SyntheticPE()
        unwind_rva = builder.data_rva
        builder.put_data(unwind_rva, unwind_info(count=1, codes=b"\x05\x07"))
        good_rva = builder.data_rva + 0x10
        builder.put_data(good_rva, unwind_info())
        bad = runtime_function(builder.code_rva, builder.code_rva + 0x10, unwind_rva)
        good = runtime_function(
            builder.code_rva + 0x10, builder.code_rva + 0x20, good_rva
        )
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, bad + good)
        builder.set_exception_directory(table_rva, 24)

        pe = load(builder)
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 1)
        self.assertEqual(
            pe.DIRECTORY_ENTRY_EXCEPTION[0].struct.BeginAddress,
            builder.code_rva + 0x10,
        )
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertEqual(errors[0].offset, 0)
        self.assertIn("UNWIND_CODE", errors[0].reason)
        pe.close()

    def test_chained_unwind_loop_is_rejected(self):
        builder = SyntheticPE()
        table_rva = builder.data_rva + 0x40
        first_rva = builder.data_rva
        second_rva = builder.data_rva + 0x10
        # Each UNWIND_INFO chains to the other one via FunctionEntry (CHAININFO).
        builder.put_data(first_rva, unwind_info(flags=0x4, handler=second_rva))
        builder.put_data(second_rva, unwind_info(flags=0x4, handler=first_rva))
        first = runtime_function(builder.code_rva, builder.code_rva + 0x10, first_rva)
        second = runtime_function(
            builder.code_rva + 0x10, builder.code_rva + 0x20, second_rva
        )
        builder.put_data(table_rva, first + second)
        builder.set_exception_directory(table_rva, 24)

        pe = load(builder)
        self.assertEqual(getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []), [])
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertEqual({error.offset for error in errors}, {0, 12})
        self.assertTrue(
            any("loop" in error.reason for error in errors)
        )
        pe.close()

    def test_unwind_data_rva_outside_sections_is_rejected(self):
        builder = SyntheticPE()
        good_rva = builder.data_rva
        builder.put_data(good_rva, unwind_info())
        bad = runtime_function(builder.code_rva, builder.code_rva + 0x10, 0x7000)
        good = runtime_function(
            builder.code_rva + 0x10, builder.code_rva + 0x20, good_rva
        )
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, bad + good)
        builder.set_exception_directory(table_rva, 24)

        pe = load(builder)
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 1)
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertEqual(errors[0].offset, 0)
        self.assertIn("UnwindData", errors[0].reason)
        pe.close()


    def test_invalid_function_range_is_rejected(self):
        builder = SyntheticPE()
        unwind_rva = builder.data_rva
        builder.put_data(unwind_rva, unwind_info())
        backwards = runtime_function(builder.code_rva + 0x20, builder.code_rva, unwind_rva)
        zero = runtime_function(0, 0, unwind_rva)
        good = runtime_function(builder.code_rva, builder.code_rva + 0x10, unwind_rva)
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, backwards + zero + good)
        builder.set_exception_directory(table_rva, 36)

        pe = load(builder)
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 1)
        offsets = {error.offset for error in pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS}
        self.assertEqual(offsets, {0, 12})
        pe.close()

    def test_entry_count_runaway_is_capped(self):
        builder = SyntheticPE()
        table_rva = builder.data_rva
        limit = pefile.MAX_EXCEPTION_ENTRIES
        declared_size = (limit + 4) * 12
        builder.set_exception_directory(table_rva, declared_size)
        pe = load(builder)
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertTrue(
            any("exceeds the limit" in error.reason for error in errors)
        )
        pe.close()

    def test_bad_entry_does_not_affect_legitimate_entries(self):
        builder = SyntheticPE()
        unwind_rva = builder.data_rva
        builder.put_data(unwind_rva, unwind_info(count=1, codes=b"\x10\x00"))
        good_a = runtime_function(builder.code_rva, builder.code_rva + 0x8, unwind_rva)
        bad = runtime_function(0x9000, 0x9008, unwind_rva)
        good_b = runtime_function(builder.code_rva + 0x8, builder.code_rva + 0x10, unwind_rva)
        table_rva = builder.data_rva + 0x80
        builder.put_data(table_rva, good_a + bad + good_b)
        builder.set_exception_directory(table_rva, 36)

        pe = load(builder)
        entries = pe.DIRECTORY_ENTRY_EXCEPTION
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].struct.BeginAddress, builder.code_rva)
        self.assertEqual(entries[1].struct.BeginAddress, builder.code_rva + 0x8)
        self.assertEqual(len(entries[0].unwindinfo.UnwindCodes), 1)
        self.assertEqual(pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS[0].offset, 12)
        pe.close()

    def test_arm64_keeps_legacy_behavior(self):
        builder = SyntheticPE(machine=MACHINE_ARM64)
        unwind_rva = builder.data_rva
        builder.put_data(unwind_rva, unwind_info())
        entry = runtime_function(builder.code_rva, builder.code_rva + 0x10, unwind_rva)
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, entry)
        builder.set_exception_directory(table_rva, 12)

        pe = load(builder)
        self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"))
        self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION_ERRORS"))
        pe.close()

    def test_legitimate_unwind_opcodes_are_decoded(self):
        builder = SyntheticPE()
        unwind_rva = builder.data_rva
        # UWOP_ALLOC_SMALL (opcode 2) followed by UWOP_PUSH_NONVOL (opcode 0).
        codes = b"\x08\x22" + b"\x10\x00"
        builder.put_data(unwind_rva, unwind_info(count=2, codes=codes))
        entry = runtime_function(builder.code_rva, builder.code_rva + 0x10, unwind_rva)
        table_rva = builder.data_rva + 0x40
        builder.put_data(table_rva, entry)
        builder.set_exception_directory(table_rva, 12)

        pe = load(builder)
        ui = pe.DIRECTORY_ENTRY_EXCEPTION[0].unwindinfo
        self.assertEqual(len(ui.UnwindCodes), 2)
        self.assertEqual(ui.UnwindCodes[0].struct.UnwindOp, 2)
        self.assertEqual(ui.UnwindCodes[1].struct.UnwindOp, 0)
        self.assertFalse(
            hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION_ERRORS")
            and pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        )
        pe.close()


    def test_unwind_data_alias_of_runtime_function_table_entry(self):
        # The malicious case from the report: UnwindData points back at the
        # RUNTIME_FUNCTION table itself, so the decoder would otherwise treat
        # table bytes as an UNWIND_INFO and invent function boundaries.
        builder = SyntheticPE()
        table_rva = builder.data_rva + 0x40
        good_unwind = builder.data_rva
        builder.put_data(good_unwind, unwind_info())
        bad = runtime_function(builder.code_rva, builder.code_rva + 0x10, table_rva)
        good = runtime_function(
            builder.code_rva + 0x10, builder.code_rva + 0x20, good_unwind
        )
        builder.put_data(table_rva, bad + good)
        builder.set_exception_directory(table_rva, 24)

        pe = load(builder)
        self.assertEqual(len(pe.DIRECTORY_ENTRY_EXCEPTION), 1)
        self.assertEqual(
            pe.DIRECTORY_ENTRY_EXCEPTION[0].struct.BeginAddress,
            builder.code_rva + 0x10,
        )
        errors = pe.DIRECTORY_ENTRY_EXCEPTION_ERRORS
        self.assertEqual(errors[0].offset, 0)
        pe.close()


if __name__ == "__main__":
    unittest.main()