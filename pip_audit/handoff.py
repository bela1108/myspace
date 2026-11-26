"""Public compatibility wrapper for the offline handoff reconciler."""

from __future__ import annotations

from pip_audit._handoff import *  # noqa: F403
from pip_audit._handoff import (
    HandoffLedger,
    HandoffReconciler,
    HandoffReport,
    build_reopen_list,
    load_handoff_batch,
    main,
    reconcile_handoffs,
    save_handoff,
)

__all__ = [  # noqa: F405
    "HandoffLedger",
    "HandoffReconciler",
    "HandoffReport",
    "build_reopen_list",
    "load_handoff_batch",
    "main",
    "reconcile_handoffs",
    "save_handoff",
]


if __name__ == "__main__":
    raise SystemExit(main())
