"""
Public API for disclosure-safe `pip-audit` handover packages.
"""

from pip_audit._handover import (
    DEFAULT_EVIDENCE,
    PACKAGE_KIND,
    RECEIPT_KIND,
    SCHEMA_VERSION,
    STATE_KIND,
    HandoverError,
    HandoverIntegrityError,
    HandoverReceiptError,
    PlanItem,
    apply_receipt,
    build_handover,
    dumps,
    load_file,
    new_state,
    reconcile,
    verify_handover,
)

__all__ = [
    "DEFAULT_EVIDENCE",
    "HandoverError",
    "HandoverIntegrityError",
    "HandoverReceiptError",
    "PACKAGE_KIND",
    "PlanItem",
    "RECEIPT_KIND",
    "SCHEMA_VERSION",
    "STATE_KIND",
    "apply_receipt",
    "build_handover",
    "dumps",
    "load_file",
    "new_state",
    "reconcile",
    "verify_handover",
]

if __name__ == "__main__":  # pragma: no cover
    from pip_audit._handover_cli import main

    raise SystemExit(main())
