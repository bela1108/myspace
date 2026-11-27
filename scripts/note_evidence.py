#!/usr/bin/env python
# -------------------------------------------------------------------------------
# scripts/note_evidence.py
#
# Offline, provenance-preserving ELF note evidence report.
#
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import json
import sys

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, ".")

from elftools.elf.note_evidence import collect_note_evidence
from elftools.elf.note_types import NOTE_TYPE_REGISTRIES


def _render_observation(observation) -> str:
    data = observation.as_dict()
    views = ", ".join(f"{view.kind}:{view.name}" for view in observation.views)
    name = data["n_type_name"] or "unresolved"
    return (
        f"  {views} offset=0x{observation.offset:08x} size={observation.size}\n"
        f"    owner={observation.owner!r} raw={data['n_type_raw_hex']} "
        f"legacy={data['n_type']!r} name={name}\n"
        f"    source={data['n_type_source']!r} "
        f"vocabulary={data['n_type_vocabulary_version']!r}"
    )


def _render_report(report) -> str:
    lines = [
        f"Artifact: {report.artifact or '<open ELFFile>'}",
        f"Note type registry: {report.vocabulary.version}",
        f"Observations: {len(report.observations)}",
    ]
    lines.extend(_render_observation(obs) for obs in report.observations)

    if report.unresolved:
        lines.append("\nUnresolved observations:")
        lines.extend(_render_observation(obs) for obs in report.unresolved)

    if report.disputed:
        lines.append("\nDisputed observations (same owner and code):")
        lines.extend(_render_observation(obs) for obs in report.disputed)

    if report.conflicts:
        lines.append("\nConflicts (one owner, one code, multiple explanations):")
        for conflict in report.conflicts:
            names = ", ".join(entry.name for entry in conflict.entries)
            lines.append(
                f"  owner={conflict.owner!r} code=0x{conflict.value:08x}: {names}"
            )

    if report.shared_symbols:
        lines.append("\nShared abbreviations (legitimate because owners differ):")
        for group in report.shared_symbols:
            lines.append(f"  {group.name}: " + ", ".join(group.owners))

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Report ELF notes with raw observations, owner-scoped "
            "interpretations, sources and vocabulary versions."
        )
    )
    parser.add_argument("files", nargs="+", help="ELF files to inspect")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON",
    )
    parser.add_argument(
        "--vocabulary",
        choices=sorted(NOTE_TYPE_REGISTRIES),
        default=None,
        help="note type vocabulary version to use",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reports = [
        collect_note_evidence(path, vocabulary=args.vocabulary) for path in args.files
    ]
    if args.json:
        print(json.dumps([report.as_dict() for report in reports], indent=2))
    else:
        print("\n\n".join(_render_report(report) for report in reports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
