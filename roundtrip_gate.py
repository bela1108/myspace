#!/usr/bin/env python3
"""Repository-local entry point for the Plyara round-trip quality gate."""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from plyara.roundtrip_gate import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
