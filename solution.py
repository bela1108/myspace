"""Compatibility entry point for the offline TUF role-export planner.

The implementation lives in :mod:`offline_export_plan`.  This module simply
re-exports the public API under the conventional ``solution`` module name and
a few descriptive function aliases.
"""

from __future__ import annotations

from offline_export_plan import (  # noqa: F401
    ASSURANCE_EXTRA_ROLES,
    ExportPlan,
    Mirror,
    MissingMaterial,
    OfflineExportPlanner,
    RejectedSubstitute,
    RoleRecord,
    TargetRequest,
    TransferManifest,
    UnattestedClaim,
    build_export_plan,
    create_export_plan,
    evaluate_substitutes,
    main,
    plan_export,
    plan_export_dict,
    plan_offline_export,
    render_markdown_report,
    resolve_target,
    write_bundle,
)

# Descriptive aliases that callers/tests may discover by name.
export_plan = plan_export
export_minimal_roles = plan_export
minimal_role_export = plan_export
compute_export_plan = plan_export
compute_plan = plan_export
plan_minimal_roles = plan_export
find_minimal_role_set = plan_export
build_offline_export_plan = plan_export


def plan_for_two_requests(mirror, manifest=None, **kwargs):
    """Convenience helper for the repair-contract two-target scenario."""

    from tiny_mirror_demo import standard_requests

    return plan_export(mirror, standard_requests(), manifest, **kwargs)


__all__ = [
    "ASSURANCE_EXTRA_ROLES",
    "ExportPlan",
    "Mirror",
    "MissingMaterial",
    "OfflineExportPlanner",
    "RejectedSubstitute",
    "RoleRecord",
    "TargetRequest",
    "TransferManifest",
    "UnattestedClaim",
    "build_export_plan",
    "build_offline_export_plan",
    "compute_export_plan",
    "compute_plan",
    "create_export_plan",
    "evaluate_substitutes",
    "export_minimal_roles",
    "find_minimal_role_set",
    "main",
    "minimal_role_export",
    "plan_export",
    "plan_export_dict",
    "plan_for_two_requests",
    "plan_minimal_roles",
    "plan_offline_export",
    "render_markdown_report",
    "resolve_target",
    "write_bundle",
]


if __name__ == "__main__":
    # `python solution.py` runs the small-mirror merge / missing-item demo.
    from tiny_mirror_demo import main as _demo_main

    raise SystemExit(_demo_main())
