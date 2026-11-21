#!/usr/bin/env python
# -------------------------------------------------------------------------------
# scripts/gnu_property_inventory.py
#
# Report architecture feature coverage across an explicit deployment file list.
# -------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, ".")

from elftools.common.exceptions import ELFError
from elftools.elf.gnu_properties import (
    build_property_inventory,
    render_json,
    render_text,
)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a cross-artifact GNU property inventory. Pass only the "
            "ELF files included in this deployment."
        ),
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="ELF",
        help="ELF file included in the deployment",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the complete inventory as JSON",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        inventory = build_property_inventory(Path(path) for path in args.files)
    except (OSError, ELFError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(render_json(inventory))
    else:
        print(render_text(inventory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
