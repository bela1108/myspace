"""Multi-ABI review orchestration and human-readable rendering."""

from __future__ import annotations

from .audit import AuditConfig, AuditReport, audit_type
from .config import AbiConfig
from .parser import ParsedUnit


def review_abis(unit: ParsedUnit, configs: list[AbiConfig],
                audit_config: AuditConfig) -> list[AuditReport]:
    """Run the same declarations and audit scope under several ABI profiles."""

    return [audit_type(unit, config, audit_config) for config in configs]


def render_text(report: AuditReport) -> str:
    lines = []
    layout = report.layout
    lines.append(
        f"ABI {report.abi_name}: {layout.kind} {report.type_name} "
        f"size={layout.size} alignment={layout.alignment} "
        f"verdict={report.worst_verdict}")
    if layout.has_bitfields:
        lines.append("  - contains bitfields; exact placement is under review")
    for item in report.review_items:
        loc = item["location"]
        lines.append(
            f"  [review:{item["kind"]}] {loc["file"]}:{loc["line"]}: "
            f"{item["message"]}")
    for verdict in report.verdicts:
        lines.append(
            f"  range {verdict.label} bytes {verdict.start}-{verdict.end}: "
            f"{verdict.verdict.upper()}")
        for finding in verdict.findings:
            loc = finding.location
            if loc is not None and loc.line:
                where = f"{loc.file}:{loc.line}"
            elif loc is not None:
                where = loc.file
            else:
                where = "unknown"
            lines.append(
                f"      @{finding.offset}+{finding.size} "
                f"[{finding.classification}] {where} - "
                f"{finding.explanation}")
    return "\n".join(lines)
