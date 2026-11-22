"""
Tests for macholib.build_provenance using synthetic Mach-O headers
spanning several toolchain eras:

* 32-bit little-endian i386 with LC_VERSION_MIN_MACOSX (pre-build-version)
* big-endian PowerPC with LC_VERSION_MIN_MACOSX (even older era)
* 64-bit arm64 with LC_BUILD_VERSION carrying tool versions
* a fat binary where only one slice carries tool versions
* a fat binary whose slices declare contradicting tool versions
"""

import contextlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile

from macholib import mach_o
from macholib.build_provenance import extract_build_evidence, main

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest

MH_FILETYPE_EXECUTE = 0x2
CPU_TYPE_I386 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_POWERPC = 18


def pack_version(major, minor, patch):
    return (major << 16) | (minor << 8) | patch


def lc_version_min_macosx(minos, sdk, endian="<"):
    return struct.pack(
        endian + "IIII",
        mach_o.LC_VERSION_MIN_MACOSX,
        16,
        pack_version(*minos),
        pack_version(*sdk),
    )


def lc_build_version(platform, minos, sdk, tools, endian="<"):
    cmdsize = 24 + 8 * len(tools)
    result = struct.pack(
        endian + "IIIIII",
        mach_o.LC_BUILD_VERSION,
        cmdsize,
        platform,
        pack_version(*minos),
        pack_version(*sdk),
        len(tools),
    )
    for tool, version in tools:
        result += struct.pack(endian + "II", tool, pack_version(*version))
    return result


def lc_uuid():
    return struct.pack("<II", mach_o.LC_UUID, 24) + b"\x00" * 16


def thin_macho(cputype, load_commands, is_64=True, endian="<"):
    if is_64:
        header = struct.pack(
            endian + "IIIIIIII",
            mach_o.MH_MAGIC_64,
            cputype,
            0,
            MH_FILETYPE_EXECUTE,
            len(load_commands),
            sum(len(lc) for lc in load_commands),
            0,
            0,
        )
    else:
        header = struct.pack(
            endian + "IIIIIII",
            mach_o.MH_MAGIC,
            cputype,
            0,
            MH_FILETYPE_EXECUTE,
            len(load_commands),
            sum(len(lc) for lc in load_commands),
            0,
        )
    return header + b"".join(load_commands)


def fat_macho(slices):
    """Build a fat binary from (cputype, slice_bytes) pairs."""
    arch_size = 20
    offset = 8 + arch_size * len(slices)
    archs = b""
    body = b""
    for cputype, data in slices:
        archs += struct.pack(">IIIII", cputype, 0, offset, len(data), 0)
        body += data
        offset += len(data)
    return struct.pack(">II", mach_o.FAT_MAGIC, len(slices)) + archs + body


class BuildProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, True)

    def write_sample(self, name, data):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as fp:
            fp.write(data)
        return path

    def test_thin_version_min_is_platform_only(self):
        path = self.write_sample(
            "legacy-i386",
            thin_macho(
                CPU_TYPE_I386,
                [lc_version_min_macosx((10, 6, 0), (10, 8, 0))],
                is_64=False,
            ),
        )
        report = extract_build_evidence(path)
        self.assertEqual(report["format"], "thin")
        self.assertEqual(report["summary"], "platform-only")
        self.assertEqual(report["conflicts"], [])

        (slice_info,) = report["slices"]
        self.assertEqual(slice_info["arch"], "i386")
        self.assertEqual(slice_info["slice_offset"], 0)
        self.assertEqual(slice_info["status"], "platform-only")

        (evidence,) = slice_info["evidence"]
        self.assertEqual(evidence["command"], "LC_VERSION_MIN_MACOSX")
        self.assertEqual(evidence["offset"], 28)
        self.assertEqual(evidence["platform"], "macOS")
        self.assertEqual(evidence["minos"], "10.6.0")
        self.assertEqual(evidence["sdk"], "10.8.0")
        self.assertEqual(evidence["tools"], [])

    def test_big_endian_version_min(self):
        path = self.write_sample(
            "legacy-ppc",
            thin_macho(
                CPU_TYPE_POWERPC,
                [lc_version_min_macosx((10, 4, 0), (10, 4, 0), endian=">")],
                is_64=False,
                endian=">",
            ),
        )
        report = extract_build_evidence(path)
        self.assertEqual(report["summary"], "platform-only")
        (evidence,) = report["slices"][0]["evidence"]
        self.assertEqual(evidence["minos"], "10.4.0")
        self.assertEqual(report["slices"][0]["arch"], "PowerPC")

    def test_thin_build_version_is_known_tool(self):
        path = self.write_sample(
            "modern-arm64",
            thin_macho(
                CPU_TYPE_ARM64,
                [
                    lc_build_version(
                        mach_o.PLATFORM_MACOS,
                        (13, 0, 0),
                        (13, 1, 0),
                        [
                            (mach_o.TOOL_CLANG, (14, 0, 0)),
                            (mach_o.TOOL_LD, (16, 2, 0)),
                        ],
                    )
                ],
            ),
        )
        report = extract_build_evidence(path)
        self.assertEqual(report["summary"], "known-tool")
        self.assertEqual(report["conflicts"], [])

        (slice_info,) = report["slices"]
        self.assertEqual(slice_info["status"], "known-tool")
        (evidence,) = slice_info["evidence"]
        self.assertEqual(evidence["command"], "LC_BUILD_VERSION")
        self.assertEqual(evidence["offset"], 32)
        self.assertEqual(evidence["platform"], "macOS")
        self.assertEqual(evidence["minos"], "13.0.0")
        self.assertEqual(
            [(t["tool"], t["version"]) for t in evidence["tools"]],
            [("clang", "14.0.0"), ("ld", "16.2.0")],
        )
        # Tool entries live right after the 24-byte build_version_command.
        self.assertEqual(evidence["tools"][0]["offset"], 32 + 24)
        self.assertEqual(evidence["tools"][1]["offset"], 32 + 24 + 8)

    def test_fat_does_not_propagate_tool_versions(self):
        x86_slice = thin_macho(
            CPU_TYPE_X86_64,
            [
                lc_build_version(
                    mach_o.PLATFORM_MACOS,
                    (12, 0, 0),
                    (12, 3, 0),
                    [(mach_o.TOOL_CLANG, (13, 1, 6))],
                )
            ],
        )
        arm_slice = thin_macho(
            CPU_TYPE_ARM64, [lc_version_min_macosx((11, 0, 0), (12, 1, 0))]
        )
        path = self.write_sample(
            "fat-mixed",
            fat_macho([(CPU_TYPE_X86_64, x86_slice), (CPU_TYPE_ARM64, arm_slice)]),
        )
        report = extract_build_evidence(path)
        self.assertEqual(report["format"], "fat")
        self.assertEqual(report["summary"], "mixed")
        self.assertEqual(report["conflicts"], [])

        first, second = report["slices"]
        self.assertEqual(first["status"], "known-tool")
        self.assertEqual(second["status"], "platform-only")
        # The tool version of slice 0 must not leak into slice 1.
        self.assertEqual(second["evidence"][0]["tools"], [])
        self.assertEqual(first["evidence"][0]["tools"][0]["version"], "13.1.6")
        # Offsets are absolute file offsets, not slice-relative.
        self.assertEqual(first["evidence"][0]["offset"], first["slice_offset"] + 32)
        self.assertEqual(second["evidence"][0]["offset"], second["slice_offset"] + 32)

    def test_fat_conflicting_tool_versions(self):
        x86_slice = thin_macho(
            CPU_TYPE_X86_64,
            [
                lc_build_version(
                    mach_o.PLATFORM_MACOS,
                    (12, 0, 0),
                    (12, 3, 0),
                    [(mach_o.TOOL_CLANG, (13, 1, 6))],
                )
            ],
        )
        arm_slice = thin_macho(
            CPU_TYPE_ARM64,
            [
                lc_build_version(
                    mach_o.PLATFORM_MACOS,
                    (12, 0, 0),
                    (12, 3, 0),
                    [(mach_o.TOOL_CLANG, (14, 0, 3))],
                )
            ],
        )
        path = self.write_sample(
            "fat-conflict",
            fat_macho([(CPU_TYPE_X86_64, x86_slice), (CPU_TYPE_ARM64, arm_slice)]),
        )
        report = extract_build_evidence(path)
        self.assertEqual(report["summary"], "conflicting")

        (conflict,) = report["conflicts"]
        self.assertEqual(conflict["kind"], "tool-version-mismatch")
        self.assertEqual(conflict["tool"], "clang")
        versions = {d["version"] for d in conflict["declarations"]}
        self.assertEqual(versions, {"13.1.6", "14.0.3"})
        # Every declaration points at its on-disk location for review.
        for declaration in conflict["declarations"]:
            (location,) = declaration["locations"]
            self.assertIn("slice", location)
            self.assertGreater(location["offset"], 0)

    def test_platform_mismatch_conflict(self):
        x86_slice = thin_macho(
            CPU_TYPE_X86_64,
            [
                lc_build_version(
                    mach_o.PLATFORM_MACOS,
                    (12, 0, 0),
                    (12, 3, 0),
                    [(mach_o.TOOL_CLANG, (13, 1, 6))],
                )
            ],
        )
        arm_slice = thin_macho(
            CPU_TYPE_ARM64,
            [
                lc_build_version(
                    mach_o.PLATFORM_IOSSIMULATOR,
                    (16, 0, 0),
                    (16, 2, 0),
                    [(mach_o.TOOL_CLANG, (13, 1, 6))],
                )
            ],
        )
        path = self.write_sample(
            "fat-platform-conflict",
            fat_macho([(CPU_TYPE_X86_64, x86_slice), (CPU_TYPE_ARM64, arm_slice)]),
        )
        report = extract_build_evidence(path)
        self.assertEqual(report["summary"], "conflicting")
        kinds = {c["kind"] for c in report["conflicts"]}
        self.assertEqual(kinds, {"platform-mismatch"})

    def test_no_build_info(self):
        path = self.write_sample("bare", thin_macho(CPU_TYPE_X86_64, [lc_uuid()]))
        report = extract_build_evidence(path)
        self.assertEqual(report["summary"], "no-build-info")
        self.assertEqual(report["slices"][0]["evidence"], [])

    def test_extraction_is_read_only(self):
        data = thin_macho(
            CPU_TYPE_ARM64,
            [
                lc_build_version(
                    mach_o.PLATFORM_MACOS,
                    (13, 0, 0),
                    (13, 1, 0),
                    [(mach_o.TOOL_CLANG, (14, 0, 0))],
                )
            ],
        )
        path = self.write_sample("readonly", data)
        extract_build_evidence(path)
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), data)

    def test_main_emits_json(self):
        path = self.write_sample("cli", thin_macho(CPU_TYPE_X86_64, [lc_uuid()]))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = main([path])
        self.assertEqual(result, 0)
        (report,) = json.loads(stdout.getvalue())
        self.assertEqual(report["summary"], "no-build-info")


if __name__ == "__main__":
    unittest.main()
