"""
Rendering of receipt reconciliation results.

The report layer is separate from the reconciliation engine: the engine
decides what happened (a status plus per-stage evidence and conflicts),
while this module presents the items that still need human review.

Every pending item is keyed by its actual distribution file so that two
different platform-specific artifacts of the same package version always
appear on separate, independently inspectable rows.
"""

from __future__ import annotations

from pip_audit._receipt.model import (
    ReconciliationReport,
    ReconciliationRow,
    ReconciliationStatus,
)


def report_to_dict(report: ReconciliationReport) -> dict[str, object]:
    """Serialize a full report to JSON-compatible data."""

    return {
        "rows": [row.to_dict() for row in report.rows],
        "pending_filenames": [row.filename for row in report.pending_rows],
    }


def _display_filename(row: ReconciliationRow) -> str:
    return row.filename if row.filename is not None else "<no distribution file>"


def _coordinate_label(row: ReconciliationRow) -> str:
    return f"{row.coordinate.name}=={row.coordinate.version}"


def render_pending_report(report: ReconciliationReport) -> str:
    """
    Render the pending (non-matched) items, one distribution file per line.

    Each row is self-contained: it shows the distribution file, its package
    coordinate, status, the provider of every handoff stage, and the materials
    still missing for confirmation. Rows without an artifact identity are
    rendered with a placeholder filename rather than being dropped.
    """

    lines = [
        "Receipt reconciliation: items pending confirmation",
        "=" * 47,
    ]

    pending_rows = list(report.pending_rows)
    if not pending_rows:
        lines.append("No pending items: every distribution file reconciled.")
        return "\n".join(lines)

    for index, row in enumerate(pending_rows, start=1):
        lines.append(
            f"{index}. {_display_filename(row)}  [{_coordinate_label(row)}] "
            f"status={row.status.value}"
        )
        for record in sorted(row.evidence, key=lambda item: item.stage.order):
            digest = record.digest if record.digest is not None else "<no digest>"
            lines.append(
                f"   evidence@{record.stage.value}: provider={record.provided_by} "
                f"document={record.source_document} digest={digest}"
            )
        for conflict in row.conflicts:
            lines.append(
                f"   conflict@{conflict.stage.value}: {conflict.detail}"
            )
            lines.append(
                f"     expected({conflict.expected_source})={conflict.expected_digest} "
                f"vs observed({conflict.observed_source})={conflict.observed_digest}"
            )
        if row.missing_materials:
            for material in row.missing_materials:
                lines.append(
                    f"   missing@{material.stage.value}: {material.material} - {material.detail}"
                )
        else:
            lines.append("   missing materials: none")

    lines.append("")
    lines.append(f"Total pending items: {len(pending_rows)}")
    return "\n".join(lines)


__all__ = [
    "ReconciliationStatus",
    "render_pending_report",
    "report_to_dict",
]
