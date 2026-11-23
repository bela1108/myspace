"""
Formatters for offline lock-plan remediation reports.

The formatters render a `RemediationReport` produced from two already-resolved
lock plans and their precomputed `pip-audit` JSON results. They never trigger
package installation, dependency resolution, or vulnerability-service
traffic: every rendered statement is backed by the inputs the user supplies.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from typing import Any

from pip_audit._remediation.report import (
    GroupReport,
    RemediationFinding,
    RemediationReport,
    RemediationStatus,
)


class RemediationFormatChoice(str, enum.Enum):
    """
    Output formats supported by the remediation check.
    """

    Columns = "columns"
    Json = "json"

    def __str__(self) -> str:
        """
        Return the command-line spelling of this format choice.
        """

        return self.value

    def to_format(self) -> RemediationFormat:
        """
        Build the formatter associated with this choice.
        """

        if self is RemediationFormatChoice.Columns:
            return RemediationColumnsFormat()
        elif self is RemediationFormatChoice.Json:
            return RemediationJsonFormat()
        else:  # pragma: no cover
            raise ValueError(f"unknown format: {self}")


class RemediationFormat:
    """
    Abstract base class for remediation report formatters.
    """

    def format(self, report: RemediationReport) -> str:  # pragma: no cover
        """
        Render `report` as a string.
        """

        raise NotImplementedError


@dataclass(frozen=True)
class RemediationJsonFormat(RemediationFormat):
    """
    Render a `RemediationReport` as a machine-readable JSON document.
    """

    def format(self, report: RemediationReport) -> str:
        """
        Serialize the full report, including per-group findings and evidence.
        """

        payload: dict[str, Any] = {
            "before_lock": report.before_lock,
            "after_lock": report.after_lock,
            "before_audit": report.before_audit,
            "after_audit": report.after_audit,
            "before_environments": list(report.before_environments),
            "after_environments": list(report.after_environments),
            "groups": [self._format_group(group) for group in report.groups],
        }
        return json.dumps(payload, indent=2)

    def _format_group(self, group: GroupReport) -> dict[str, Any]:
        """
        Serialize one group's summary and findings.
        """

        return {
            "group": group.name,
            "summary": {
                "closed": group.closed,
                "moved_chain": group.moved_chain,
                "unresolved": group.unresolved,
                "incomplete_evidence": group.incomplete,
            },
            "findings": [self._format_finding(finding) for finding in group.findings],
        }

    def _format_finding(self, finding: RemediationFinding) -> dict[str, Any]:
        """
        Serialize a single finding and the evidence behind its classification.
        """

        return {
            "package": finding.package,
            "vulnerability": finding.vulnerability_id,
            "status": str(finding.status),
            "before_version": finding.before_version,
            "after_version": finding.after_version,
            "aliases": sorted(finding.aliases),
            "before_chains": [list(chain) for chain in finding.before_chains],
            "after_chains": [list(chain) for chain in finding.after_chains],
            "evidence_notes": list(finding.evidence_notes),
            "detail": finding.detail,
        }


@dataclass(frozen=True)
class RemediationColumnsFormat(RemediationFormat):
    """
    Render a `RemediationReport` as a human-readable, group-by-group table.
    """

    def format(self, report: RemediationReport) -> str:
        """
        Render each group's findings, separating alerts that are closed from
        alerts that merely moved chains or that lack sufficient evidence.
        """

        lines: list[str] = []
        lines.append(f"before lock: {report.before_lock}")
        lines.append(f"after lock:  {report.after_lock}")
        lines.append("")
        for group in report.groups:
            lines.append(f"[{group.name}]")
            if not group.findings:
                lines.append("  no vulnerabilities carried by this group")
                lines.append("")
                continue

            lines.append(
                "  "
                f"closed={group.closed} moved-chain={group.moved_chain} "
                f"unresolved={group.unresolved} incomplete-evidence={group.incomplete}"
            )
            for finding in group.findings:
                lines.append(f"  - {finding.package} {finding.vulnerability_id}: {finding.status}")
                if finding.before_version is not None:
                    lines.append(f"      before version: {finding.before_version}")
                if finding.after_version is not None:
                    lines.append(f"      after version:  {finding.after_version}")
                lines.extend(
                    f"      before chain:   {' -> '.join(chain)}" for chain in finding.before_chains
                )
                lines.extend(
                    f"      after chain:    {' -> '.join(chain)}" for chain in finding.after_chains
                )
                if finding.status is RemediationStatus.IncompleteEvidence:
                    lines.extend(f"      evidence gap:   {note}" for note in finding.evidence_notes)
                lines.append(f"      detail:          {finding.detail}")
            lines.append("")
        return "\n".join(lines).rstrip()
