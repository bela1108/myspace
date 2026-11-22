"""Rendering of the offline license-conflict audit report.

Two shapes are produced:

- a machine-readable JSON document mirroring AuditReport;
- a human-readable plain-text digest for the acceptance review.

Both shapes retain every provenance pointer so an auditor can jump straight
back to the original rule text, the sample manifest and the authorization
record without re-running the offline review.
"""
from __future__ import annotations

import json

from license_audit.engine import AuditReport


def report_to_dict(report: AuditReport) -> dict:
    """Convert an AuditReport into JSON-serialisable data."""
    return report.as_dict()


def render_json(report: AuditReport, indent: int = 2) -> str:
    """Return the machine-readable JSON representation of the report."""
    return json.dumps(report_to_dict(report), indent=indent, ensure_ascii=False)


def render_text(report: AuditReport) -> str:
    """Return the human-readable plain-text digest of the report."""
    summary = report.summary()
    books_label = ", ".join(report.books)
    foldable = summary["foldable"]
    keep = summary["keep_duplicate"]
    violation = summary["violation"]
    single = summary["single"]
    lines = [
        "License Conflict Review Report",
        "=" * 31,
        f"Frozen rule version : {report.frozen_version}",
        f"Release books       : {books_label}",
        "",
        "Summary",
        "-------",
        f"  foldable dossiers  : {foldable}",
        f"  keep-duplicate     : {keep}",
        f"  violations         : {violation}",
        f"  single receipts    : {single}",
        "",
    ]

    lines.append("Case Dossiers")
    lines.append("-------------")
    for index, dossier in enumerate(report.dossiers, start=1):
        lines.append(f"Case {index}: logic_hash={dossier.logic_hash}")
        lines.append(f"  verdict : {dossier.verdict.upper()}")
        if dossier.verdict == "foldable":
            kept = ", ".join(item.rule_name for item in dossier.keep_receipts)
            folded = ", ".join(item.rule_name for item in dossier.folded_receipts)
            lines.append(f"  fold    : keep [{kept}], collapse [{folded}]")
        else:
            kept = ", ".join(item.rule_name for item in dossier.keep_receipts)
            lines.append(f"  retain  : {kept}")
        for reason in dossier.reasons:
            lines.append(f"  reason  : {reason}")
        lines.append("  receipts:")
        for receipt in dossier.receipts:
            lines.append(
                "    - {rule} [{book}] auth={auth} sample={sample} scope={scope}".format(
                    rule=receipt.rule_name,
                    book=receipt.book,
                    auth=receipt.authorization_id,
                    sample=receipt.sample_id,
                    scope=receipt.scope,
                )
            )
        lines.append("  trace   :")
        for trace in dossier.as_dict()["trace"]:
            lines.append(f"    @ {trace}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_report(report: AuditReport) -> str:
    """Alias kept for callers that prefer the build_ naming."""
    return render_text(report)


def to_json(report: AuditReport) -> str:
    """Alias kept for callers that prefer the to_json naming."""
    return render_json(report)
