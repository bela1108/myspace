import struct
import unittest

from export_test import PE_32, PE_64

import pefile


def _pointer_format(is64):
    return "<Q" if is64 else "<I"


def make_tls_pe(
    template,
    callback_rvas,
    *,
    directory_size=None,
    directory_rva=None,
    array_rva=None,
    array_va=None,
    tls_rva=None,
    section_characteristics=None,
):
    """Patch a minimal TLS directory and callback array into a test PE."""

    data = bytearray(template)
    pe = pefile.PE(data=bytes(data), fast_load=True)
    section = pe.sections[0]
    is64 = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
    image_base = pe.OPTIONAL_HEADER.ImageBase
    pointer_size = 8 if is64 else 4
    tls_struct_size = 40 if is64 else 24
    pointer_format = _pointer_format(is64)

    if tls_rva is None:
        tls_rva = section.VirtualAddress + 0x1c0
    if array_rva is None:
        array_rva = section.VirtualAddress + 0x220

    tls_offset = section.get_offset_from_rva(tls_rva)
    array_offset = section.get_offset_from_rva(array_rva)

    clear_end = min(
        len(data),
        array_offset + max(0x80, (len(callback_rvas) + 1) * pointer_size),
    )
    data[array_offset:clear_end] = b"\0" * (clear_end - array_offset)

    for index, callback_rva in enumerate(callback_rvas):
        struct.pack_into(
            pointer_format,
            data,
            array_offset + index * pointer_size,
            image_base + section.VirtualAddress + callback_rva,
        )

    if array_va is None:
        array_va = image_base + array_rva

    if is64:
        struct.pack_into(
            "<QQQQII",
            data,
            tls_offset,
            image_base + tls_rva,
            image_base + tls_rva,
            image_base,
            array_va,
            0,
            0,
        )
    else:
        struct.pack_into(
            "<IIIIII",
            data,
            tls_offset,
            image_base + tls_rva,
            image_base + tls_rva,
            image_base,
            array_va,
            0,
            0,
        )

    tls_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]
    ]
    if directory_size is None:
        directory_size = tls_struct_size
    if directory_rva is None:
        directory_rva = tls_rva
    struct.pack_into(
        "<II",
        data,
        tls_directory.get_file_offset(),
        directory_rva,
        directory_size,
    )

    if section_characteristics is not None:
        struct.pack_into(
            "<I",
            data,
            section.get_file_offset() + 36,
            section_characteristics,
        )

    return data


class TestTlsCallbacks(unittest.TestCase):
    def test_callbacks_32_and_64(self):
        for template, is64 in ((PE_32, False), (PE_64, True)):
            with self.subTest(bits=64 if is64 else 32):
                data = make_tls_pe(template, [0, 0x10])
                with pefile.PE(data=bytes(data)) as pe:
                    tls = pe.DIRECTORY_ENTRY_TLS
                    section_rva = pe.sections[0].VirtualAddress
                    self.assertEqual(
                        [section_rva, section_rva + 0x10],
                        [callback.rva for callback in tls.callbacks],
                    )
                    self.assertEqual(
                        [b".rdata", b".rdata"],
                        [callback.section_name for callback in tls.callbacks],
                    )
                    self.assertTrue(all(callback.readable for callback in tls.callbacks))
                    self.assertFalse(
                        any(callback.executable for callback in tls.callbacks)
                    )
                    self.assertTrue(tls.callbacks_terminated)

    def test_raw_callback_array_is_preserved(self):
        for template, is64 in ((PE_32, False), (PE_64, True)):
            with self.subTest(bits=64 if is64 else 32):
                callback_rvas = [0, 0x10]
                data = make_tls_pe(template, callback_rvas)
                with pefile.PE(data=bytes(data)) as pe:
                    tls = pe.DIRECTORY_ENTRY_TLS
                    image_base = pe.OPTIONAL_HEADER.ImageBase
                    section_rva = pe.sections[0].VirtualAddress
                    pointer_format = _pointer_format(is64)
                    expected = b"".join(
                        struct.pack(pointer_format, image_base + section_rva + rva)
                        for rva in callback_rvas
                    ) + bytes(8 if is64 else 4)
                    self.assertEqual(expected, tls.raw_callbacks)
                    self.assertEqual(expected, tls.callback_array)

    def test_non_executable_callback_section_is_reported(self):
        data = make_tls_pe(PE_32, [0], section_characteristics=0x40000040)
        with pefile.PE(data=bytes(data)) as pe:
            callback = pe.DIRECTORY_ENTRY_TLS.callbacks[0]
            self.assertTrue(callback.readable)
            self.assertFalse(callback.executable)

    def test_executable_callback_section_is_reported(self):
        data = make_tls_pe(PE_32, [0], section_characteristics=0x60000040)
        with pefile.PE(data=bytes(data)) as pe:
            callback = pe.DIRECTORY_ENTRY_TLS.callbacks[0]
            self.assertTrue(callback.readable)
            self.assertTrue(callback.executable)

    def test_wild_pointer_is_not_a_callback(self):
        data = make_tls_pe(PE_32, [0, 0x10000000])
        with pefile.PE(data=bytes(data)) as pe:
            tls = pe.DIRECTORY_ENTRY_TLS
            self.assertEqual([pe.sections[0].VirtualAddress], [c.rva for c in tls.callbacks])
            self.assertEqual(3 * 4, len(tls.raw_callbacks))
            self.assertTrue(tls.callbacks_terminated)

    def test_duplicate_addresses_are_not_listed_twice(self):
        data = make_tls_pe(PE_32, [0, 0, 0x10])
        with pefile.PE(data=bytes(data)) as pe:
            callbacks = pe.DIRECTORY_ENTRY_TLS.callbacks
            section_rva = pe.sections[0].VirtualAddress
            self.assertEqual([section_rva, section_rva + 0x10], [c.rva for c in callbacks])

    def test_callback_limit(self):
        data = make_tls_pe(PE_32, [0, 0x10, 0x20])
        with pefile.PE(data=bytes(data), max_tls_callbacks=2) as pe:
            tls = pe.DIRECTORY_ENTRY_TLS
            self.assertEqual(2, len(tls.callbacks))
            self.assertTrue(tls.callbacks_limit_reached)
            self.assertEqual(8, len(tls.raw_callbacks))

    def test_callback_limit_can_be_requested_lazily(self):
        data = make_tls_pe(PE_64, [0, 0x10, 0x20])
        with pefile.PE(data=bytes(data), fast_load=True) as pe:
            callbacks = pe.get_tls_callbacks(max_callbacks=1)
            self.assertEqual(1, len(callbacks))
            self.assertTrue(pe.DIRECTORY_ENTRY_TLS.callbacks_limit_reached)

    def test_array_does_not_cross_section_tail(self):
        template_pe = pefile.PE(data=bytes(PE_32), fast_load=True)
        section = template_pe.sections[0]
        pointer_size = 4
        array_rva = (
            section.VirtualAddress + section.Misc_VirtualSize - pointer_size
        )
        data = make_tls_pe(PE_32, [0], array_rva=array_rva)
        with pefile.PE(data=bytes(data)) as pe:
            tls = pe.DIRECTORY_ENTRY_TLS
            self.assertEqual(1, len(tls.callbacks))
            self.assertTrue(tls.callbacks_truncated)
            self.assertFalse(tls.callbacks_terminated)
            self.assertEqual(pointer_size, len(tls.raw_callbacks))

    def test_invalid_directory_size_does_not_break_open(self):
        data = make_tls_pe(PE_32, [0], directory_size=8)
        with pefile.PE(data=bytes(data)) as pe:
            self.assertTrue(hasattr(pe, "DIRECTORY_ENTRY_TLS"))
            self.assertFalse(pe.DIRECTORY_ENTRY_TLS.tls_directory_size_valid)
            self.assertEqual([], pe.DIRECTORY_ENTRY_TLS.callbacks)
            self.assertEqual([], pe.get_tls_callbacks())
            self.assertIn("Invalid TLS directory size", "\n".join(pe.get_warnings()))

    def test_corrupt_tls_directory_rva_does_not_break_open(self):
        data = make_tls_pe(PE_32, [0], directory_rva=0x7fffffff)
        with pefile.PE(data=bytes(data)) as pe:
            self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_TLS"))
            self.assertEqual([], pe.get_tls_callbacks())

    def test_unmapped_callback_array_is_ignored(self):
        data = make_tls_pe(
            PE_32,
            [0],
            array_va=0x10000000,
        )
        with pefile.PE(data=bytes(data)) as pe:
            tls = pe.DIRECTORY_ENTRY_TLS
            self.assertEqual([], tls.callbacks)
            self.assertEqual(b"", tls.raw_callbacks)

    def test_callback_array_va_below_image_base_is_ignored(self):
        data = make_tls_pe(PE_32, [0], array_va=0x1000)
        with pefile.PE(data=bytes(data)) as pe:
            tls = pe.DIRECTORY_ENTRY_TLS
            self.assertEqual([], tls.callbacks)
            self.assertEqual(b"", tls.raw_callbacks)

    def test_callbacks_can_be_disabled(self):
        data = make_tls_pe(PE_32, [0])
        with pefile.PE(data=bytes(data), parse_tls_callbacks=False) as pe:
            tls = pe.DIRECTORY_ENTRY_TLS
            self.assertFalse(tls.callbacks_parsed)
            self.assertEqual([], tls.callbacks)
            self.assertEqual(1, len(pe.get_tls_callbacks()))
            self.assertTrue(tls.callbacks_parsed)


if __name__ == "__main__":
    unittest.main()
