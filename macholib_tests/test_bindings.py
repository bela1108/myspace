import contextlib
import os
import struct
import sys
import tempfile

from macholib import MachO, SymbolTable
from macholib.bindings import (
    STATUS_BOUND,
    STATUS_SPECIAL,
    STATUS_UNRESOLVED,
    STATUS_UNVERIFIED,
    STATUS_WEAK,
    analyze_bindings,
)
from macholib.mach_o import (
    FAT_MAGIC,
    LC_DYSYMTAB,
    LC_LOAD_DYLIB,
    LC_SYMTAB,
    MH_MAGIC_64,
    MH_TWOLEVEL,
    N_EXT,
    N_UNDF,
    N_WEAK_REF,
)

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest


CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_X86_64_ALL = 3
CPU_SUBTYPE_ARM64_ALL = 0


def _align(value, alignment=8):
    return (value + alignment - 1) // alignment * alignment


def _dylib_command(path, command=LC_LOAD_DYLIB):
    raw = path.encode("utf-8") + b"\x00"
    size = _align(24 + len(raw))
    data = struct.pack("<IIIIII", command, size, 24, 0, 0x10000, 0x10000)
    return data + raw + (b"\x00" * (size - 24 - len(raw)))


def _symtab_command(symoff, nsyms, stroff, strsize):
    return struct.pack(
        "<IIIIII", LC_SYMTAB, 24, symoff, nsyms, stroff, strsize
    )


def _dysymtab_command(iundefsym, nundefsym):
    fields = [
        0,
        0,
        0,
        0,
        iundefsym,
        nundefsym,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    return struct.pack("<II" + ("I" * 18), LC_DYSYMTAB, 80, *fields)


def _nlist64(strx, n_type, n_sect, n_desc, n_value=0):
    return struct.pack("<IBBHq", strx, n_type, n_sect, n_desc, n_value)


def _build_slice(
    cputype,
    dylibs,
    symbols,
    flags=MH_TWOLEVEL,
    include_dysymtab=True,
    undefined_count=None,
):
    """Build a minimal 64-bit little-endian Mach-O slice.

    ``symbols`` is a sequence of ``(name, ordinal, weak)`` tuples.  All
    symbols are external undefined symbols in the LC_DYSYMTAB range.
    """
    strtab = bytearray(b"\x00")
    nlists = []
    for name, ordinal, weak in symbols:
        strx = len(strtab)
        strtab.extend(name.encode("utf-8"))
        strtab.append(0)
        n_desc = (ordinal & 0xFF) << 8
        if weak:
            n_desc |= N_WEAK_REF
        nlists.append(_nlist64(strx, N_UNDF | N_EXT, 0, n_desc))

    symbol_bytes = b"".join(nlists)
    commands = [_dylib_command(path) for path in dylibs]
    ncmds = len(commands) + 1 + (1 if include_dysymtab else 0)
    commands_size = sum(len(item) for item in commands) + 24
    if include_dysymtab:
        commands_size += 80
    symoff = 32 + commands_size
    stroff = symoff + len(symbol_bytes)
    commands.append(
        _symtab_command(symoff, len(nlists), stroff, len(strtab))
    )
    if include_dysymtab:
        if undefined_count is None:
            undefined_count = len(nlists)
        commands.append(_dysymtab_command(0, undefined_count))

    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        cputype,
        0,
        2,
        ncmds,
        commands_size,
        flags,
        0,
    )
    return header + b"".join(commands) + symbol_bytes + bytes(strtab)


def _build_fat(slices):
    """Build a fat Mach-O file from ``(cputype, cpusubtype, slice_bytes)``."""
    header_size = 8 + (20 * len(slices))
    offset = _align(header_size, 4096)
    archs = []
    payload = []
    for cputype, cpusubtype, data in slices:
        archs.append(
            struct.pack(
                ">IIIII", cputype, cpusubtype, offset, len(data), 12
            )
        )
        payload.append((offset, data))
        offset = _align(offset + len(data), 4096)

    result = bytearray(struct.pack(">II", FAT_MAGIC, len(slices)))
    result.extend(b"".join(archs))
    for payload_offset, data in payload:
        result.extend(b"\x00" * (payload_offset - len(result)))
        result.extend(data)
    return bytes(result)


@contextlib.contextmanager
def temporary_macho(data):
    handle, path = tempfile.mkstemp(prefix="macholib-bindings-")
    try:
        with os.fdopen(handle, "wb") as fp:
            fp.write(data)
        yield path
    finally:
        os.unlink(path)


class TestBindings(unittest.TestCase):
    def test_same_symbol_in_two_slices_keeps_distinct_attribution(self):
        first = _build_slice(
            CPU_TYPE_X86_64,
            ["/usr/lib/libA.dylib", "/usr/lib/libB.dylib"],
            [("_shared", 1, False)],
        )
        second = _build_slice(
            CPU_TYPE_ARM64,
            ["/usr/lib/libA.dylib", "/usr/lib/libB.dylib"],
            [("_shared", 2, False)],
        )
        data = _build_fat(
            [
                (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, first),
                (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, second),
            ]
        )

        with temporary_macho(data) as path:
            report = analyze_bindings(path)

        self.assertEqual(len(report.slices), 2)
        self.assertEqual(len(report.bindings), 2)
        self.assertEqual(report.bindings[0].name, "_shared")
        self.assertEqual(report.bindings[1].name, "_shared")
        self.assertEqual(report.bindings[0].module, "/usr/lib/libA.dylib")
        self.assertEqual(report.bindings[1].module, "/usr/lib/libB.dylib")
        self.assertEqual(report.bindings[0].ordinal, 1)
        self.assertEqual(report.bindings[1].ordinal, 2)
        self.assertEqual(
            [item.arch for item in report.bindings], ["x86_64", "ARM64"]
        )
        self.assertEqual(len(report.by_symbol("_shared")), 2)
        self.assertEqual(
            len(report.by_symbol(b"_shared")),
            2,
        )
        self.assertEqual(len(report.grouped_by_symbol()["_shared"]), 2)
        self.assertEqual(
            set(item.module for item in report["_shared"]),
            {"/usr/lib/libA.dylib", "/usr/lib/libB.dylib"},
        )

    def test_same_name_with_different_ordinals_in_one_slice_is_not_collapsed(self):
        data = _build_slice(
            CPU_TYPE_ARM64,
            ["/usr/lib/libA.dylib", "/usr/lib/libB.dylib"],
            [("_dup", 1, False), ("_dup", 2, False)],
        )

        with temporary_macho(data) as path:
            report = analyze_bindings(path)

        self.assertEqual(len(report.bindings), 2)
        self.assertEqual(
            [item.module for item in report.bindings],
            ["/usr/lib/libA.dylib", "/usr/lib/libB.dylib"],
        )
        self.assertNotEqual(report.bindings[0].key, report.bindings[1].key)

    def test_weak_special_and_missing_evidence_keep_status(self):
        data = _build_slice(
            CPU_TYPE_ARM64,
            ["/usr/lib/libA.dylib", "/usr/lib/libB.dylib"],
            [
                ("_normal", 1, False),
                ("_weak", 2, True),
                ("_self", 0, False),
                ("_lookup", 0xFE, False),
                ("_main", 0xFF, False),
                ("_missing", 3, False),
            ],
        )

        with temporary_macho(data) as path:
            report = analyze_bindings(path)

        rows = {item.name: item for item in report.bindings}
        self.assertEqual(rows["_normal"].status, STATUS_BOUND)
        self.assertEqual(rows["_normal"].module, "/usr/lib/libA.dylib")

        self.assertEqual(rows["_weak"].status, STATUS_WEAK)
        self.assertTrue(rows["_weak"].weak)
        self.assertEqual(rows["_weak"].module, "/usr/lib/libB.dylib")

        self.assertEqual(rows["_self"].status, STATUS_SPECIAL)
        self.assertEqual(rows["_self"].special, "self")
        self.assertIsNone(rows["_self"].module)

        self.assertEqual(rows["_lookup"].status, STATUS_SPECIAL)
        self.assertEqual(rows["_lookup"].special, "dynamic_lookup")
        self.assertIsNone(rows["_lookup"].module)

        self.assertEqual(rows["_main"].status, STATUS_SPECIAL)
        self.assertEqual(rows["_main"].special, "executable")
        self.assertIsNone(rows["_main"].module)

        self.assertEqual(rows["_missing"].status, STATUS_UNRESOLVED)
        self.assertIsNone(rows["_missing"].module)
        self.assertIn("no matching load command", rows["_missing"].reason)

    def test_missing_dysymtab_preserves_unverified_symbols(self):
        data = _build_slice(
            CPU_TYPE_ARM64,
            ["/usr/lib/libA.dylib"],
            [("_normal", 1, False)],
            include_dysymtab=False,
        )

        with temporary_macho(data) as path:
            report = analyze_bindings(path)

        self.assertEqual(len(report.bindings), 1)
        item = report.bindings[0]
        self.assertEqual(item.status, STATUS_UNVERIFIED)
        self.assertFalse(item.in_dynamic_range)
        self.assertIn("missing LC_DYSYMTAB", report.slices[0].problems)

    def test_only_dynamic_undefined_range_is_an_import(self):
        data = _build_slice(
            CPU_TYPE_ARM64,
            ["/usr/lib/libA.dylib", "/usr/lib/libB.dylib"],
            [("_inside", 1, False), ("_outside", 2, False)],
            undefined_count=1,
        )

        with temporary_macho(data) as path:
            report = analyze_bindings(path)
            extended = analyze_bindings(path, include_outside_range=True)

        self.assertEqual([item.name for item in report.bindings], ["_inside"])
        self.assertEqual(
            [item.name for item in extended.bindings],
            ["_inside", "_outside"],
        )
        self.assertEqual(extended.bindings[1].status, STATUS_UNVERIFIED)
        self.assertFalse(extended.bindings[1].in_dynamic_range)

    def test_macho_and_symbol_table_entry_points(self):
        data = _build_slice(
            CPU_TYPE_ARM64,
            ["/usr/lib/libA.dylib"],
            [("_normal", 1, False)],
        )

        with temporary_macho(data) as path:
            macho = MachO.MachO(path)
            report = macho.bindings()
            symbol_table = SymbolTable.SymbolTable(macho)
            slice_report = symbol_table.bindings()
            header_report = macho.headers[0].bindings()

        self.assertEqual(report.bindings[0].module, "/usr/lib/libA.dylib")
        self.assertEqual(slice_report.bindings[0].module, "/usr/lib/libA.dylib")
        self.assertEqual(header_report.bindings[0].module, "/usr/lib/libA.dylib")


if __name__ == "__main__":
    unittest.main()
