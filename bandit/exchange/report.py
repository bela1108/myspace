#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
"""Load Bandit scan reports, including the legacy baseline format.

A modern Bandit JSON report stores findings under ``results`` together with
``metrics``, ``errors`` and a ``generated_at`` timestamp.  Historical
baseline files use exactly the same envelope, while even older snapshots may
omit some optional fields.  The loader is permissive about optional fields
but strict about the top-level envelope so broken reports fail loudly
instead of silently producing empty approvals.
"""
import json

from bandit.exchange.errors import ReportValidationError
from bandit.exchange.model import Finding

#: Schema marker used to distinguish exchange documents from raw reports.
REPORT_ENVELOPE = "bandit-json-report"


def load_report_text(text):
    """Parse a Bandit JSON report from a string."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportValidationError(
            f"Scan report is not valid JSON: {exc.msg}"
        ) from exc
    return load_report(payload)


def load_report(payload):
    """Build :class:`Finding` objects from a parsed JSON report.

    The returned dictionary keeps the report metadata alongside the
    findings, which lets the views reproduce timestamps and errors without
    re-reading the original file.
    """
    if not isinstance(payload, dict):
        raise ReportValidationError(
            "Scan report must be a JSON object with a 'results' list"
        )
    if "results" not in payload or not isinstance(
        payload["results"], list
    ):
        raise ReportValidationError(
            "Scan report is missing the 'results' list"
        )

    findings = []
    for index, raw in enumerate(payload["results"]):
        if not isinstance(raw, dict):
            raise ReportValidationError(
                f"Result entry {index} is not a JSON object"
            )
        findings.append(Finding(raw))

    return {
        "findings": findings,
        "errors": list(payload.get("errors", []) or []),
        "metrics": payload.get("metrics", {}) or {},
        "generated_at": payload.get("generated_at"),
        "legacy": bool(payload.get("legacy", False)),
        "source_envelope": REPORT_ENVELOPE,
    }


def load_legacy_baseline_text(text):
    """Read a pre-exchange baseline file.

    Legacy baselines remain readable: they are treated as ordinary reports.
    When the envelope already carries the historical ``generated_at`` field
    it is preserved verbatim, and a ``legacy`` marker is exposed so callers
    can tell new and old inputs apart without breaking either.
    """
    loaded = load_report_text(text)
    loaded["legacy"] = True
    return loaded
