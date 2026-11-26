#!/usr/bin/env python3
"""Compare TypeDef row positions between two managed assembly builds."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import dnfile
from dnfile.compare import TypeIndex


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a parent- and module-qualified TypeDef cross-reference."
    )
    parser.add_argument("old_assembly")
    parser.add_argument("new_assembly")
    parser.add_argument("--json", action="store_true", help="emit the checklist as JSON")
    args = parser.parse_args()

    old_pe = dnfile.dnPE(args.old_assembly)
    new_pe = dnfile.dnPE(args.new_assembly)
    try:
        report = TypeIndex.build(old_pe).compare(TypeIndex.build(new_pe))
        if args.json:
            print(json.dumps(report.to_dicts(), ensure_ascii=False, indent=2))
        else:
            print(report.render_text())
    finally:
        old_pe.close()
        new_pe.close()


if __name__ == "__main__":
    main()
