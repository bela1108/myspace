"""Offline report rendering for a completed credential-event replay.

The report is pure data derived from a finished :class:`ReplayEngine`.  Every
finding occurrence names the ownership record that fixed its responsible team,
and every audit entry names the record (ownership rule or exemption) that the
decision was based on, so past decisions remain traceable.
"""
from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from detect_secrets.incident.enums import ReviewState
from detect_secrets.incident.replay import ReplayEngine


def build_report(
    engine: ReplayEngine,
    *,
    as_of: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a JSON-serializable report for a completed replay."""
    at = as_of or engine.last_event_at or ""

    described: List[Dict[str, Any]] = []
    for finding_id in sorted(engine.occurrences):
        for path in sorted(engine.occurrences[finding_id]):
            described.append(
                _describe_occurrence(
                    engine,
                    engine.occurrences[finding_id][path],
                    at,
                ),
            )

    all_occurrences = [
        occurrence
        for paths in engine.occurrences.values()
        for occurrence in paths.values()
    ]
    summary = {
        "findings_total": len(engine.findings),
        "occurrences_total": len(all_occurrences),
        "open_total": sum(
            1
            for occurrence in all_occurrences
            if occurrence.state != ReviewState.SUPPRESSED
        ),
        "suppressed_total": sum(
            1
            for occurrence in all_occurrences
            if occurrence.state == ReviewState.SUPPRESSED
        ),
        "overdue_total": sum(
            1
            for occurrence in all_occurrences
            if occurrence.state == ReviewState.OVERDUE
        ),
        "exempt_total": sum(
            1
            for occurrence in all_occurrences
            if occurrence.state == ReviewState.EXEMPT
        ),
        "events_replayed": engine.event_count,
    }

    return {
        "generated_at": at,
        "summary": summary,
        "findings": described,
        "audit_trail": engine.audit_log.to_dicts(),
    }


def _describe_occurrence(
    engine: ReplayEngine,
    occurrence: Any,
    at: str,
) -> Dict[str, Any]:
    active_exemption = None
    if occurrence.active_exemption_id is not None:
        record = engine._exemptions.get(  # noqa: SLF001 - intentional read model
            occurrence.active_exemption_id,
        )
        if record.active_at(at):
            active_exemption = {
                "exemption_id": record.exemption_id,
                "expires_at": record.expires_at,
                "granted_at": record.granted_at,
                "justification": record.justification,
            }

    overdue = (
        occurrence.state == ReviewState.OVERDUE
        or (
            occurrence.state != ReviewState.SUPPRESSED
            and occurrence.review_deadline is not None
            and at >= occurrence.review_deadline
        )
    )
    return {
        "finding_id": occurrence.finding_id,
        "path": occurrence.path,
        "state": occurrence.state.value,
        "team": occurrence.team,
        "ownership_record_id": occurrence.ownership_record_id,
        "active_exemption_id": occurrence.active_exemption_id,
        "active_exemption": active_exemption,
        "review_deadline": occurrence.review_deadline,
        "review_overdue": overdue,
        "forked_from": occurrence.forked_from,
        "born_at": occurrence.born_at,
        "last_event_id": occurrence.last_event_id,
    }


def render_text_report(report: Dict[str, Any]) -> str:
    """Compact, human-readable view of :func:`build_report` output."""
    lines = [
        "Credential Event Replay Report",
        "=" * 31,
        f"generated_at: {report['generated_at']}",
        "summary:",
    ]
    for key in sorted(report["summary"]):
        lines.append(f"  {key}: {report['summary'][key]}")

    lines.extend(["", "findings:"])
    for finding in report["findings"]:
        lines.append(
            "  {finding_id} {path} [{state}] team={team} owner_record="
            "{ownership_record_id} due={review_deadline} "
            "exemption={exemption}".format(
                finding_id=finding["finding_id"],
                path=finding["path"],
                state=finding["state"],
                team=finding["team"],
                ownership_record_id=finding["ownership_record_id"],
                review_deadline=finding["review_deadline"],
                exemption=finding["active_exemption_id"] or "-",
            ),
        )

    lines.extend(["", "audit_trail:"])
    for entry in report["audit_trail"]:
        lines.append(
            "  #{sequence} {timestamp} {action} finding={finding_id} "
            "decision={decision} team={team} owner_record={owner} "
            "exemption={exemption}".format(
                sequence=entry["sequence"],
                timestamp=entry["timestamp"],
                action=entry["action"],
                finding_id=entry["finding_id"] or "-",
                decision=entry["decision"],
                team=entry["team"] or "-",
                owner=entry["ownership_record_id"] or "-",
                exemption=entry["exemption_id"] or "-",
            ),
        )
        lines.append(f"      reason: {entry['reason']}")
    return "\n".join(lines)


__all__ = ["build_report", "render_text_report"]
