"""Compatibility alias for :mod:`offline_export_plan`.

The task asks for an "offline export plan"; this short module lets callers
``import export_plan`` while keeping one implementation.
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
)

plan = plan_export
create_plan = plan_export
minimal_roles_export = plan_export


if __name__ == "__main__":
    raise SystemExit(main())
