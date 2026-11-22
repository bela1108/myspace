"""
Public API for building disclosure-safe dependency remediation handovers.

The implementation lives in :mod:`pip_audit._handover`; this module re-exports
the supported interface and makes the command available via
``python -m pip_audit.handover``.
"""

from __future__ import annotations

from pip_audit._handover import (
    SCHEMA_VERSION,
    HandoverError,
    build_handover,
    build_handover_package,
    main,
    reconcile_handover,
    render_markdown,
    verify_handover,
)

__all__ = [
    "SCHEMA_VERSION",
    "HandoverError",
    "build_handover",
    "build_handover_package",
    "main",
    "reconcile_handover",
    "render_markdown",
    "verify_handover",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
