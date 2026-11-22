"""
Read-only extraction of build-provenance evidence from Mach-O headers.

Modern Mach-O binaries record how they were built in one of two ways:

* ``LC_VERSION_MIN_*`` load commands (older SDKs) only declare the target
  platform and minimum OS/SDK versions.
* ``LC_BUILD_VERSION`` load commands additionally carry a list of build
  tools (clang, swift, ld, ...) with their exact versions.

This module normalizes both formats into a single per-slice evidence
report that a backend can consume uniformly.  Every observation keeps the
absolute file offset of the load command it was read from, so consumers
can always trace a value back to its on-disk location.

Two rules are enforced by the report structure:

* Evidence is never propagated between slices of a fat binary: if only
  one slice carries tool versions, the other slices are reported as
  ``platform-only`` (or ``no-build-info``), not as built by that tool.
* Contradicting declarations (e.g. two slices built with different
  versions of the same tool, or disagreeing platform declarations) are
  surfaced as ``conflicts`` with the offsets of every declaration, so a
  reviewer has a basis for judging which one to trust.

The module is strictly read-only: files are only ever opened in binary
read mode.

The report can be emitted as JSON from the command line::

    python -m macholib.build_provenance file1 [file2 ...]
"""

from __future__ import print_function

import json
import struct
import sys

from macholib.MachO import MachO
from macholib.mach_o import (
    CPU_TYPE_NAMES,
    LC_BUILD_VERSION,
    LC_VERSION_MIN_IPHONEOS,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    PLATFORM_NAMES,
    TOOL_NAMES,
)
from macholib.ptypes import sizeof

__all__ = ["extract_build_evidence", "summarize_evidence", "main"]

_STATUS_TOOL_KNOWN = "known-tool"
_STATUS_PLATFORM_ONLY = "platform-only"
_STATUS_NO_INFO = "no-build-info"
_STATUS_CONFLICTING = "conflicting"
_STATUS_MIXED = "mixed"

_VERSION_MIN_COMMANDS = {
    LC_VERSION_MIN_MACOSX: ("LC_VERSION_MIN_MACOSX", PLATFORM_NAMES[1]),
    LC_VERSION_MIN_IPHONEOS: ("LC_VERSION_MIN_IPHONEOS", PLATFORM_NAMES[2]),
    LC_VERSION_MIN_TVOS: ("LC_VERSION_MIN_TVOS", PLATFORM_NAMES[3]),
    LC_VERSION_MIN_WATCHOS: ("LC_VERSION_MIN_WATCHOS", PLATFORM_NAMES[4]),
}


def _decode_version(value):
    """Decode a packed xxxx.yy.zz version word into a dotted string."""
    return "%d.%d.%d" % ((value >> 16) & 0xFFFF, (value >> 8) & 0xFF, value & 0xFF)


def _tool_name(tool):
    return TOOL_NAMES.get(tool, "tool_%d" % (tool,))


def _platform_name(platform):
    return PLATFORM_NAMES.get(platform, "platform_%d" % (platform,))


def _parse_version_min(command_name, platform, offset, payload, endian):
    version, sdk = struct.unpack(endian + "II", payload)
    return {
        "command": command_name,
        "offset": offset,
        "platform": platform,
        "minos": _decode_version(version),
        "sdk": _decode_version(sdk),
        "tools": [],
    }


def _parse_build_version(offset, payload, endian):
    platform, minos, sdk, ntools = struct.unpack(endian + "IIII", payload[:16])
    tools = []
    tool_offset = offset + 8 + 16
    for index in range(ntools):
        tool, version = struct.unpack(
            endian + "II", payload[16 + index * 8 : 16 + (index + 1) * 8]
        )
        tools.append(
            {
                "tool": _tool_name(tool),
                "version": _decode_version(version),
                "offset": tool_offset + index * 8,
            }
        )
    return {
        "command": "LC_BUILD_VERSION",
        "offset": offset,
        "platform": _platform_name(platform),
        "minos": _decode_version(minos),
        "sdk": _decode_version(sdk),
        "tools": tools,
    }


def _slice_evidence(fp, header):
    """Yield normalized evidence records for a single Mach-O header."""
    evidence = []
    endian = header.endian
    cursor = header.offset + sizeof(header.mach_header)
    for _index in range(header.header.ncmds):
        fp.seek(cursor)
        raw = fp.read(8)
        if len(raw) < 8:
            break
        cmd, cmdsize = struct.unpack(endian + "II", raw)
        fp.seek(cursor)
        payload = fp.read(cmdsize)[8:]
        if cmd in _VERSION_MIN_COMMANDS:
            command_name, platform = _VERSION_MIN_COMMANDS[cmd]
            evidence.append(
                _parse_version_min(command_name, platform, cursor, payload, endian)
            )
        elif cmd == LC_BUILD_VERSION:
            evidence.append(_parse_build_version(cursor, payload, endian))
        cursor += cmdsize
    return evidence


def _slice_status(evidence):
    has_tools = any(record["tools"] for record in evidence)
    has_platform = any(record["platform"] for record in evidence)
    if has_tools:
        return _STATUS_TOOL_KNOWN
    if has_platform:
        return _STATUS_PLATFORM_ONLY
    return _STATUS_NO_INFO


def _find_conflicts(slices):
    """Collect contradicting declarations, each with its file offsets."""
    conflicts = []

    tool_declarations = {}
    platform_declarations = {}
    for slice_info in slices:
        for record in slice_info["evidence"]:
            platform_declarations.setdefault(record["platform"], []).append(
                {"slice": slice_info["slice"], "offset": record["offset"]}
            )
            for tool in record["tools"]:
                tool_declarations.setdefault(tool["tool"], {}).setdefault(
                    tool["version"], []
                ).append({"slice": slice_info["slice"], "offset": tool["offset"]})

    for tool, versions in sorted(tool_declarations.items()):
        if len(versions) > 1:
            conflicts.append(
                {
                    "kind": "tool-version-mismatch",
                    "tool": tool,
                    "declarations": [
                        {"version": version, "locations": locations}
                        for version, locations in sorted(versions.items())
                    ],
                }
            )

    if len(platform_declarations) > 1:
        conflicts.append(
            {
                "kind": "platform-mismatch",
                "declarations": [
                    {"platform": platform, "locations": locations}
                    for platform, locations in sorted(platform_declarations.items())
                ],
            }
        )

    return conflicts


def extract_build_evidence(filename):
    """
    Read *filename* and return a normalized build-provenance report.

    The file is opened read-only and is never modified.
    """
    macho = MachO(filename)
    slices = []
    with open(filename, "rb") as fp:
        for index, header in enumerate(macho.headers):
            evidence = _slice_evidence(fp, header)
            slices.append(
                {
                    "slice": index,
                    "arch": CPU_TYPE_NAMES.get(
                        header.header.cputype,
                        "cputype_%d" % (header.header.cputype,),
                    ),
                    "slice_offset": header.offset,
                    "status": _slice_status(evidence),
                    "evidence": evidence,
                }
            )

    conflicts = _find_conflicts(slices)
    report = {
        "file": filename,
        "format": "fat" if macho.fat is not None else "thin",
        "slices": slices,
        "conflicts": conflicts,
    }
    report["summary"] = summarize_evidence(report)
    return report


def summarize_evidence(report):
    """
    Reduce a report to one of: ``known-tool``, ``platform-only``,
    ``conflicting``, ``mixed`` or ``no-build-info``.

    ``mixed`` means at least one slice carries tool versions while at
    least one other slice does not; the tool information must not be
    assumed to apply to those other slices.
    """
    if report["conflicts"]:
        return _STATUS_CONFLICTING
    statuses = {slice_info["status"] for slice_info in report["slices"]}
    if statuses == {_STATUS_TOOL_KNOWN}:
        return _STATUS_TOOL_KNOWN
    if _STATUS_TOOL_KNOWN in statuses:
        return _STATUS_MIXED
    if _STATUS_PLATFORM_ONLY in statuses:
        return _STATUS_PLATFORM_ONLY
    return _STATUS_NO_INFO


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("usage: python -m macholib.build_provenance file...", file=sys.stderr)
        return 2
    reports = [extract_build_evidence(filename) for filename in argv]
    json.dump(reports, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
