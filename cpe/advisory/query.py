# -*- coding: utf-8 -*-

"""
Query and report layer for slot-scoped advisory adjudication.

The public entry point is :func:`query_case`.  It accepts an
``AdvisoryCase``, a plain dictionary, a JSON string, or a path to a JSON
file and returns a structured :class:`QueryReport`.  The CLI in
``cpe.advisory.cli`` is a thin wrapper around the same function.
"""

from __future__ import unicode_literals

from dataclasses import dataclass
import json
import os
from typing import Tuple

from .engine import (
    EvidenceTimeline,
    SlotAdjudicator,
    build_host_rollup,
    detect_responsibility_notes,
    policy_notes,
)
from .model import (
    CLOSURE_CLOSED,
    CLOSURE_INDETERMINATE,
    CLOSURE_NOT_REQUIRED,
    CLOSURE_OPEN,
    CLOSURE_PARTIALLY_CLOSED,
    CONDITION_ABSENT,
    CONDITION_MATCHED,
    CONDITION_SHADOWED,
    CONDITION_UNKNOWN,
    HOST_SCOPE,
    SLOT_SCOPE,
    STATUS_APPLICABLE,
    STATUS_INDETERMINATE,
    STATUS_NOT_APPLICABLE,
    Advisory,
    Cabinet,
    ClosureRecord,
    QueryReport,
    ResponsibilityNote,
    SlotSnapshotReport,
    Snapshot,
    SnapshotReport,
)


@dataclass(frozen=True)
class AdvisoryCase:
    """A complete fictional cabinet/advisory/snapshot/closure case."""

    cabinet: Cabinet
    advisory: Advisory
    snapshots: Tuple[Snapshot, ...] = ()
    closures: Tuple[ClosureRecord, ...] = ()
    case_id: str = ""
    description: str = ""

    def __post_init__(self):
        object.__setattr__(self, "snapshots", tuple(self.snapshots))
        object.__setattr__(self, "closures", tuple(self.closures))
        if not self.snapshots:
            raise ValueError("at least one snapshot is required")

    def to_dict(self):
        return {
            "case_id": self.case_id,
            "description": self.description,
            "cabinet": self.cabinet.to_dict(),
            "advisory": self.advisory.to_dict(),
            "snapshots": [item.to_dict() for item in self.snapshots],
            "closures": [item.to_dict() for item in self.closures],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            case_id=data.get("case_id", ""),
            description=data.get("description", ""),
            cabinet=Cabinet.from_dict(data["cabinet"]),
            advisory=Advisory.from_dict(data["advisory"]),
            snapshots=tuple(
                Snapshot.from_dict(item)
                for item in data.get("snapshots", ())),
            closures=tuple(
                ClosureRecord.from_dict(item)
                for item in data.get("closures", ())),
        )


def load_case(source):
    """Load an :class:`AdvisoryCase` from a dict, JSON string, or path."""

    if isinstance(source, AdvisoryCase):
        return source
    if isinstance(source, dict):
        return AdvisoryCase.from_dict(source)
    if isinstance(source, os.PathLike):
        source = os.fspath(source)
    if not isinstance(source, str):
        raise TypeError("case source must be a dict, JSON string, or path")

    stripped = source.strip()
    if os.path.exists(source):
        with open(source, "r", encoding="utf-8") as handle:
            return AdvisoryCase.from_dict(json.load(handle))
    if stripped.startswith("{"):
        return AdvisoryCase.from_dict(json.loads(stripped))
    raise ValueError("case path does not exist: {0}".format(source))


def _validate_case(case):
    cabinet = case.cabinet
    slot_ids = set(cabinet.slot_ids)
    if not slot_ids:
        raise ValueError("cabinet must declare at least one application slot")

    seen_snapshots = set()
    for snapshot in case.snapshots:
        if snapshot.snapshot_id in seen_snapshots:
            raise ValueError(
                "duplicate snapshot_id {0!r}".format(snapshot.snapshot_id))
        seen_snapshots.add(snapshot.snapshot_id)
        if snapshot.cabinet_id != cabinet.cabinet_id:
            raise ValueError(
                "snapshot {0!r} belongs to cabinet {1!r}, not {2!r}".format(
                    snapshot.snapshot_id,
                    snapshot.cabinet_id,
                    cabinet.cabinet_id,
                ))
        if snapshot.evidence_slots is not None:
            unknown = snapshot.evidence_slots - slot_ids
            if unknown:
                raise ValueError(
                    "snapshot {0!r} re-evidences unknown slot(s) {1}".format(
                        snapshot.snapshot_id,
                        ", ".join(sorted(unknown)),
                    ))
        for component in snapshot.components:
            unknown = component.slots - slot_ids
            if unknown:
                raise ValueError(
                    "component {0!r} refers to unknown slot(s) {1}".format(
                        component.component_id,
                        ", ".join(sorted(unknown)),
                    ))

    for condition in case.advisory.conditions:
        if condition.slot_id is not None and condition.slot_id not in slot_ids:
            raise ValueError(
                "condition {0!r} targets unknown slot {1!r}".format(
                    condition.condition_id, condition.slot_id))

    for record in case.closures:
        unknown = record.slot_ids - slot_ids
        if unknown:
            raise ValueError(
                "closure {0!r} names unknown slot(s) {1}".format(
                    record.closure_id,
                    ", ".join(sorted(unknown)),
                ))


def _slot_responsibility_notes(snapshot, slot, evidence, slot_result):
    notes = []

    if evidence.slot_source_snapshot_id != snapshot.snapshot_id:
        notes.append(ResponsibilityNote(
            scenario="single-slot-evidence",
            summary=(
                "slot {0} is using carried-over evidence from snapshot {1}"
                .format(slot.slot_id, evidence.slot_source_snapshot_id or "none")),
            detail=(
                "Snapshot {0} did not re-evidence slot {1}.  The slot keeps "
                "the newest earlier evidence and its previous owner; it is "
                "not updated by another slot's fresh evidence.".format(
                    snapshot.snapshot_id, slot.slot_id)
            ),
            slots=(slot.slot_id,),
        ))

    shared_components = tuple(
        item.component for item in evidence.components
        if item.component.is_shared)
    if shared_components:
        shared = tuple(sorted(
            component.component_id for component in shared_components))
        other_slots = set()
        for component in shared_components:
            other_slots.update(component.slots)
        other_slots.discard(slot.slot_id)
        notes.append(ResponsibilityNote(
            scenario="shared-component",
            summary=(
                "slot {0} shares component(s) {1} with another slot".format(
                    slot.slot_id, ", ".join(shared))),
            detail=(
                "A shared fix can be performed once, but the closure record "
                "must name every affected slot.  A closure that lists only "
                "slot {0} does not discharge the other slot(s) {1}.".format(
                    slot.slot_id,
                    ", ".join(sorted(other_slots)),
                )
            ),
            slots=(slot.slot_id,) + tuple(sorted(other_slots)),
            components=shared,
        ))

    if slot_result.applicable is False and slot_result.conditions:
        notes.append(ResponsibilityNote(
            scenario="slot-remediated",
            summary=(
                "slot {0} is no longer applicable in snapshot {1}".format(
                    slot.slot_id, snapshot.snapshot_id)),
            detail=(
                "The advisory no longer applies to this slot.  That "
                "conclusion is local to slot {0}; it does not close another "
                "slot that still has a matching component version.".format(
                    slot.slot_id)
            ),
            slots=(slot.slot_id,),
        ))

    return tuple(notes)


def query_case(source):
    """
    Adjudicate a case per application slot for every snapshot.

    The report keeps the host identity only for display.  Every applicability
    result, closure result, and substitution check is keyed by slot id.
    """

    case = load_case(source)
    _validate_case(case)
    timeline = EvidenceTimeline(case.cabinet, case.snapshots)
    adjudicator = SlotAdjudicator(case.advisory)

    snapshot_reports = []
    for position, snapshot in enumerate(case.snapshots):
        slot_reports = {}
        for slot in case.cabinet.slots:
            evidence = timeline.resolve(snapshot, slot.slot_id)
            result = adjudicator.evaluate_slot(
                case.cabinet, evidence, slot)
            closure = adjudicator.evaluate_closures(
                case.cabinet,
                evidence,
                result,
                case.closures,
                timeline=timeline,
            )
            substitutions = adjudicator.substitution_checks(
                case.cabinet, evidence, result, case.closures)
            notes = _slot_responsibility_notes(
                snapshot, slot, evidence, result)
            slot_reports[slot.slot_id] = SlotSnapshotReport(
                snapshot_id=snapshot.snapshot_id,
                slot_id=slot.slot_id,
                application=slot.application,
                evidence_sources=evidence.source_map(),
                applicability=result,
                closure=closure,
                substitution_checks=substitutions,
                responsibility_notes=notes,
            )

        snapshot_reports.append(SnapshotReport(
            snapshot_id=snapshot.snapshot_id,
            captured_at=snapshot.captured_at,
            evidence_slots=(
                None if snapshot.evidence_slots is None
                else tuple(sorted(snapshot.evidence_slots))),
            slots=slot_reports,
            responsibility_notes=detect_responsibility_notes(
                case.cabinet, case.snapshots[:position + 1]),
            host_rollup=build_host_rollup(
                case.cabinet,
                slot_reports,
                case.closures,
                advisory_id=case.advisory.advisory_id,
            ),
        ))

    return QueryReport(
        cabinet=case.cabinet,
        advisory=case.advisory,
        snapshots=tuple(snapshot_reports),
        responsibility_notes=detect_responsibility_notes(
            case.cabinet, case.snapshots),
        policy_notes=policy_notes(),
    )


def query(cabinet, snapshots, advisory, closures=()):
    """
    Convenience entry point for a cabinet, advisory, and snapshot list.

    This is the direct form of the local query interface; it is equivalent to
    building an :class:`AdvisoryCase` and calling :func:`query_case`.
    """

    return query_case(AdvisoryCase(
        cabinet=cabinet,
        advisory=advisory,
        snapshots=tuple(snapshots),
        closures=tuple(closures),
    ))


def _condition_match_to_dict(match):
    return {
        "condition_id": match.condition.condition_id,
        "scope": match.condition.scope,
        "target_slot": match.condition.slot_id,
        "cpe": match.condition.cpe,
        "status": match.status,
        "reason_code": match.reason_code,
        "explanation": match.explanation,
        "witness": None if match.witness is None else match.witness.to_dict(),
        "eligible_witnesses": [
            item.to_dict() for item in match.eligible_witnesses],
        "shadow_witnesses": [
            item.to_dict() for item in match.shadow_witnesses],
    }


def _closure_to_dict(closure):
    return {
        "status": closure.status,
        "required_condition_ids": sorted(closure.required_condition_ids),
        "covered_condition_ids": sorted(closure.covered_condition_ids),
        "missing_condition_ids": sorted(closure.missing_condition_ids),
        "accepted": [
            {
                "closure_id": item.record.closure_id,
                "condition_id": item.condition.condition_id,
                "witness": item.witness.to_dict(),
                "reused_from_other_slot": item.reused_from_other_slot,
            }
            for item in closure.accepted
        ],
        "rejected": [
            {
                "closure_id": item.record.closure_id,
                "condition_id": (
                    None if item.condition is None
                    else item.condition.condition_id),
                "witness": (
                    None if item.witness is None
                    else item.witness.to_dict()),
                "reason_code": item.reason_code,
                "explanation": item.explanation,
            }
            for item in closure.rejected
        ],
    }


def _substitution_to_dict(check):
    return {
        "source_closure_id": check.source_closure_id,
        "source_slot_ids": sorted(check.source_slot_ids),
        "target_slot_id": check.target_slot_id,
        "can_substitute": check.can_substitute,
        "reusable_conditions": list(check.reusable_conditions),
        "blocked_conditions": list(check.blocked_conditions),
        "reason_code": check.reason_code,
        "explanation": check.explanation,
    }


def _note_to_dict(note):
    return {
        "scenario": note.scenario,
        "summary": note.summary,
        "detail": note.detail,
        "slots": list(note.slots),
        "components": list(note.components),
    }


def _slot_report_to_dict(report):
    return {
        "slot_id": report.slot_id,
        "application": report.application,
        "evidence_sources": dict(report.evidence_sources),
        "applicability": {
            "status": report.applicability.status,
            "applicable": report.applicability.applicable,
            "reasons": list(report.applicability.reasons),
            "conditions": [
                _condition_match_to_dict(item)
                for item in report.applicability.conditions
            ],
        },
        "closure": _closure_to_dict(report.closure),
        "substitution_checks": [
            _substitution_to_dict(item)
            for item in report.substitution_checks
        ],
        "responsibility_notes": [
            _note_to_dict(item) for item in report.responsibility_notes
        ],
    }


def _snapshot_conclusion(snapshot):
    applicable = []
    not_applicable = []
    indeterminate = []
    closed_slots = []
    open_slots = []
    blocked_substitutions = []

    for slot_id in sorted(snapshot.slots):
        slot = snapshot.slots[slot_id]
        if slot.applicability.applicable is True:
            applicable.append(slot_id)
        elif slot.applicability.applicable is False:
            not_applicable.append(slot_id)
        else:
            indeterminate.append(slot_id)

        if slot.closure.status == CLOSURE_CLOSED:
            closed_slots.append(slot_id)
        elif slot.closure.status in (
                CLOSURE_OPEN, CLOSURE_PARTIALLY_CLOSED):
            open_slots.append(slot_id)

        if (
            slot.applicability.applicable is not True
            and slot.closure.status not in (
                CLOSURE_OPEN, CLOSURE_PARTIALLY_CLOSED)
        ):
            continue

        for check in slot.substitution_checks:
            if check.can_substitute:
                continue
            blocked_substitutions.append({
                "source_closure_id": check.source_closure_id,
                "target_slot_id": check.target_slot_id,
                "reason_code": check.reason_code,
                "blocked_conditions": list(check.blocked_conditions),
            })

    return {
        "applicable_slots": applicable,
        "not_applicable_slots": not_applicable,
        "indeterminate_slots": indeterminate,
        "closed_slots": closed_slots,
        "open_slots": open_slots,
        "blocked_substitutions": blocked_substitutions,
    }


def report_to_dict(report):
    """Return a JSON-serialisable representation of a query report."""

    snapshots = []
    for snapshot in report.snapshots:
        rollup = snapshot.host_rollup
        snapshots.append({
            "snapshot_id": snapshot.snapshot_id,
            "captured_at": snapshot.captured_at,
            "evidence_slots": (
                None if snapshot.evidence_slots is None
                else list(snapshot.evidence_slots)),
            "slots": {
                slot_id: _slot_report_to_dict(slot_report)
                for slot_id, slot_report in snapshot.slots.items()
            },
            "host_rollup": None if rollup is None else {
                "cabinet_id": rollup.cabinet_id,
                "host_id": rollup.host_id,
                "applicable_slots": list(rollup.applicable_slots),
                "closed_slots": list(rollup.closed_slots),
                "host_aggregated_closures": list(
                    rollup.host_aggregated_closures),
                "valid": rollup.valid,
                "warning": rollup.warning,
            },
            "conclusion": _snapshot_conclusion(snapshot),
            "responsibility_notes": [
                _note_to_dict(item)
                for item in snapshot.responsibility_notes
            ],
        })

    return {
        "cabinet": report.cabinet.to_dict(),
        "advisory": report.advisory.to_dict(),
        "snapshots": snapshots,
        "responsibility_notes": [
            _note_to_dict(item) for item in report.responsibility_notes
        ],
        "policy_notes": [
            _note_to_dict(item) for item in report.policy_notes
        ],
    }


def _format_witness(witness):
    if witness is None:
        return "no witness"
    ownership = (
        "host-common" if not witness.component_slots
        else "slot " + ", ".join(sorted(witness.component_slots)))
    return "{0} [{1}; from {2}]".format(
        witness.component_id, ownership, witness.source_snapshot_id)


def format_report(report, include_policy=True, include_details=True):
    """Render a query report as a human-readable multi-line string."""

    cabinet = report.cabinet
    advisory = report.advisory
    lines = []
    lines.append(
        "Cabinet {0} / host {1}{2}".format(
            cabinet.cabinet_id,
            cabinet.host_id,
            " — " + cabinet.name if cabinet.name else "",
        ))
    lines.append(
        "Advisory {0}{1} [{2}]".format(
            advisory.advisory_id,
            " — " + advisory.title if advisory.title else "",
            advisory.operator,
        ))
    lines.append("")

    for snapshot in report.snapshots:
        scope = (
            "full cabinet"
            if snapshot.evidence_slots is None
            else "re-evidenced slots: " + ", ".join(snapshot.evidence_slots)
        )
        lines.append("=" * 78)
        lines.append(
            "Snapshot {0}{1} ({2})".format(
                snapshot.snapshot_id,
                " @ " + snapshot.captured_at if snapshot.captured_at else "",
                scope,
            ))
        lines.append("=" * 78)

        for slot_id in sorted(snapshot.slots):
            slot = snapshot.slots[slot_id]
            applicability = slot.applicability
            lines.append("")
            lines.append(
                "Slot {0} — {1}: {2}".format(
                    slot_id,
                    slot.application or "(unnamed application)",
                    applicability.status.upper(),
                ))

            if include_details:
                for match in applicability.conditions:
                    condition = match.condition
                    target = (
                        "slot " + condition.slot_id
                        if condition.slot_id else
                        "current slot" if condition.scope == SLOT_SCOPE
                        else "host-common")
                    lines.append(
                        "  [{0}: {1}] {2}: {3}".format(
                            condition.scope,
                            target,
                            condition.condition_id,
                            match.status.upper(),
                        ))
                    if match.witness is not None:
                        lines.append(
                            "      witness: " + _format_witness(match.witness))
                    if match.explanation:
                        lines.append("      " + match.explanation)
                    for shadow in match.shadow_witnesses:
                        lines.append(
                            "      shadow: " + _format_witness(shadow))

            closure = slot.closure
            lines.append(
                "  Closure: {0}".format(closure.status.upper()))
            if (
                closure.missing_condition_ids
                and closure.status not in (
                    CLOSURE_NOT_REQUIRED,
                    CLOSURE_INDETERMINATE,
                )
            ):
                lines.append(
                    "    missing conditions: " +
                    ", ".join(sorted(closure.missing_condition_ids)))
            if closure.accepted:
                lines.append(
                    "    accepted witnesses: " + ", ".join(
                        "{0}/{1}".format(
                            item.condition.condition_id,
                            item.witness.component_id,
                        )
                        for item in closure.accepted
                    ))

            if slot.substitution_checks:
                lines.append("  Other-slot closures cannot substitute:")
                for check in slot.substitution_checks:
                    lines.append(
                        "    {0} -> slot {1}: BLOCKED ({2})".format(
                            check.source_closure_id,
                            slot_id,
                            check.reason_code,
                        ))
                    lines.append("      " + check.explanation)

            for note in slot.responsibility_notes:
                if note.scenario == "slot-remediated":
                    continue
                lines.append(
                    "  Responsibility [{0}]: {1}".format(
                        note.scenario, note.summary))

        if snapshot.host_rollup is not None:
            lines.append("")
            lines.append(
                "Host roll-up: {0}".format(
                    "VALID" if snapshot.host_rollup.valid else "INVALID"))
            if snapshot.host_rollup.warning:
                lines.append("  " + snapshot.host_rollup.warning)
            if snapshot.host_rollup.applicable_slots:
                lines.append(
                    "  applicable slots: " +
                    ", ".join(snapshot.host_rollup.applicable_slots))
            if snapshot.host_rollup.host_aggregated_closures:
                lines.append(
                    "  host-aggregated closures: " +
                    ", ".join(snapshot.host_rollup.host_aggregated_closures))

        conclusion = _snapshot_conclusion(snapshot)
        lines.append("")
        lines.append("Conclusion:")
        lines.append(
            "  applicable slots: " +
            (", ".join(conclusion["applicable_slots"]) or "none"))
        lines.append(
            "  not applicable slots: " +
            (", ".join(conclusion["not_applicable_slots"]) or "none"))
        lines.append(
            "  closed slots: " +
            (", ".join(conclusion["closed_slots"]) or "none"))
        lines.append(
            "  still open slots: " +
            (", ".join(conclusion["open_slots"]) or "none"))
        if conclusion["blocked_substitutions"]:
            lines.append("  blocked closure substitutions:")
            for item in conclusion["blocked_substitutions"]:
                lines.append(
                    "    {0} -> slot {1} ({2}; blocked conditions: {3})".format(
                        item["source_closure_id"],
                        item["target_slot_id"],
                        item["reason_code"],
                        ", ".join(item["blocked_conditions"]) or "none",
                    ))
        lines.append("")

    if report.responsibility_notes:
        lines.append("Responsibility changes detected in this case:")
        for note in report.responsibility_notes:
            lines.append(
                "  [{0}] {1}".format(note.scenario, note.summary))
            lines.append("    " + note.detail)
        lines.append("")

    if include_policy and report.policy_notes:
        lines.append("Responsibility policy (applies even when not detected):")
        for note in report.policy_notes:
            lines.append(
                "  [{0}] {1}".format(note.scenario, note.summary))
            lines.append("    " + note.detail)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
