"""Compatibility alias for :mod:`offline_export_plan`.

Lets callers use either ``import offline_export`` or
``import offline_export_plan`` against the same implementation.
"""

from __future__ import annotations

from offline_export_plan import *  # noqa: F401,F403
from offline_export_plan import (  # noqa: F401
    ExportPlan,
    OfflineExportPlanner,
    TransferManifest,
    build_export_plan,
    main,
    plan_export,
    plan_export_dict,
)

plan = plan_export


if __name__ == "__main__":
    raise SystemExit(main())
