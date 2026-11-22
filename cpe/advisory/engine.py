# -*- coding: utf-8 -*-

"""
Slot-scoped advisory adjudication.

The engine keeps three identities separate:

* the cabinet/host identity (one host number for the whole cabinet),
* the application slot identity, and
* the component witness identity (the exact component and snapshot that
  made a condition true).

Applicability is evaluated per slot.  A host-scoped condition can only be
witnessed by a host-common component; a slot-scoped condition can only be
witnessed by a component that belongs to the slot under evaluation.  Closure
records carry their witnesses, so a closure owned by one slot cannot silently
close another slot.
"""

from __future__ import unicode_literals

from dataclasses import replace

from .matching import canonical, condition_matches
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
    AcceptedClosure,
    ClosureEvaluation,
    ClosureRecord,
    ConditionMatch,
    HostRollup,
    RejectedClosure,
    ResolvedComponent,
    ResolvedEvidence,
    ResponsibilityNote,
    SlotResult,
    SubstitutionCheck,
    Witness,
)


def _sorted_resolved(items):
    return tuple(sorted(
        items,
        key=lambda item: (
            item.component.component_id,
            item.component.cpe,
            item.source_snapshot_id,
        ),
    ))


def _dedupe_resolved(items):
    seen = set()
    result = []
    for item in items:
        key = (item.component.component_id, item.source_snapshot_id)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return tuple(result)


def _join_ids(values):
    values = tuple(sorted(values))
    if not values:
        return "none"
    return ", ".join(values)


class EvidenceTimeline(object):
    """
    Resolve per-slot evidence from an ordered snapshot timeline.

    A snapshot that re-evidences only slot A does not update slot B.  Slot B
    continues to use the newest earlier snapshot that actually contained B
    evidence.  This is the "single-slot supplement" rule: evidence is never
    borrowed from a different slot at the same or a later time.
    """

    def __init__(self, cabinet, snapshots):
        self.cabinet = cabinet
        self.snapshots = tuple(snapshots)
        if not self.snapshots:
            raise ValueError("at least one snapshot is required")

        index = {}
        for position, snapshot in enumerate(self.snapshots):
            if snapshot.cabinet_id != cabinet.cabinet_id:
                raise ValueError(
                    "snapshot {0!r} belongs to cabinet {1!r}, not {2!r}".format(
                        snapshot.snapshot_id,
                        snapshot.cabinet_id,
                        cabinet.cabinet_id,
                    ))
            if snapshot.snapshot_id in index:
                raise ValueError(
                    "duplicate snapshot_id {0!r}".format(
                        snapshot.snapshot_id))
            index[snapshot.snapshot_id] = position
        self._index = index
        self._known_slots = frozenset(cabinet.slot_ids)

        for snapshot in self.snapshots:
            for component in snapshot.components:
                unknown = component.slots - self._known_slots
                if unknown:
                    raise ValueError(
                        "component {0!r} refers to unknown slot(s) {1}".format(
                            component.component_id, _join_ids(unknown)))

    def position(self, snapshot_id):
        try:
            return self._index[snapshot_id]
        except KeyError:
            raise KeyError("unknown snapshot_id {0!r}".format(snapshot_id))

    def _resolve_one(self, as_of, slot_id):
        if slot_id not in self._known_slots:
            raise KeyError("unknown slot_id {0!r}".format(slot_id))

        end = self.position(as_of.snapshot_id) + 1
        window = self.snapshots[:end]

        slot_snapshot = None
        for snapshot in reversed(window):
            if snapshot.has_evidence_for(slot_id):
                slot_snapshot = snapshot
                break

        host_snapshot = None
        for snapshot in reversed(window):
            if snapshot.host_evidence:
                host_snapshot = snapshot
                break

        components = []
        if host_snapshot is not None:
            for component in host_snapshot.components:
                if component.is_host_common:
                    components.append(ResolvedComponent(
                        component=component,
                        source_snapshot_id=host_snapshot.snapshot_id,
                    ))

        if slot_snapshot is not None:
            for component in slot_snapshot.components:
                if component.belongs_to(slot_id):
                    components.append(ResolvedComponent(
                        component=component,
                        source_snapshot_id=slot_snapshot.snapshot_id,
                    ))

        # Slot evidence wins over host evidence for the same id.  In a valid
        # inventory the id cannot be both host-common and slot-bound, but this
        # keeps the resolver deterministic if a malformed snapshot contains
        # both.
        by_id = {}
        for item in components:
            by_id[item.component.component_id] = item

        complete = bool(
            slot_snapshot is not None and slot_snapshot.complete)

        return ResolvedEvidence(
            slot_id=slot_id,
            as_of_snapshot_id=as_of.snapshot_id,
            components=_sorted_resolved(by_id.values()),
            host_source_snapshot_id=(
                None if host_snapshot is None
                else host_snapshot.snapshot_id),
            slot_source_snapshot_id=(
                None if slot_snapshot is None
                else slot_snapshot.snapshot_id),
            complete=complete,
        )

    def resolve(self, as_of, slot_id):
        own = self._resolve_one(as_of, slot_id)
        own_ids = set(
            item.component.component_id for item in own.components)

        context = []
        for other_slot in self.cabinet.slot_ids:
            if other_slot == slot_id:
                continue
            other = self._resolve_one(as_of, other_slot)
            for item in other.components:
                if item.component.component_id in own_ids:
                    continue
                context.append(item)

        return replace(
            own,
            context_components=_sorted_resolved(_dedupe_resolved(context)),
        )

    def resolve_all(self, as_of):
        return {
            slot_id: self.resolve(as_of, slot_id)
            for slot_id in self.cabinet.slot_ids
        }


class SlotAdjudicator(object):
    """Evaluate one advisory against application slots."""

    def __init__(self, advisory):
        self.advisory = advisory

    def required_conditions(self, slot_id):
        return self.advisory.conditions_for_slot(slot_id)

    @staticmethod
    def _eligible(condition, slot_id, component):
        if condition.scope == HOST_SCOPE:
            return component.is_host_common
        if condition.scope == SLOT_SCOPE:
            return component.belongs_to(slot_id)
        return False

    @staticmethod
    def _witness(condition, resolved_component):
        component = resolved_component.component
        return Witness(
            component_id=component.component_id,
            cpe=component.cpe,
            source_snapshot_id=resolved_component.source_snapshot_id,
            condition_id=condition.condition_id,
            condition_scope=condition.scope,
            component_slots=component.slots,
            label=component.label,
        )

    @staticmethod
    def _shadow_reason(condition, slot_id, shadow):
        parts = []
        for item in shadow:
            component = item.component
            if condition.scope == SLOT_SCOPE:
                if component.is_host_common:
                    parts.append(
                        "{0} is host-common and cannot witness a "
                        "slot-scoped condition".format(component.component_id))
                else:
                    parts.append(
                        "{0} belongs to slot(s) {1}, not slot {2}".format(
                            component.component_id,
                            _join_ids(component.slots),
                            slot_id,
                        ))
            else:
                parts.append(
                    "{0} is bound to slot(s) {1} and cannot witness a "
                    "host-common condition".format(
                        component.component_id,
                        _join_ids(component.slots),
                    ))
        return "; ".join(parts)

    def _evaluate_condition(self, condition, slot_id, evidence):
        if condition.scope == HOST_SCOPE:
            source_missing = evidence.host_source_snapshot_id is None
        else:
            source_missing = evidence.slot_source_snapshot_id is None

        if source_missing:
            return ConditionMatch(
                condition=condition,
                status=CONDITION_UNKNOWN,
                reason_code="missing_evidence_source",
                explanation=(
                    "no {0} evidence is available for slot {1} at snapshot "
                    "{2}".format(
                        "host" if condition.scope == HOST_SCOPE else "slot",
                        slot_id,
                        evidence.as_of_snapshot_id,
                    )
                ),
            )

        matches = []
        for item in evidence.all_components:
            if condition_matches(condition.cpe, item.component.cpe):
                matches.append(item)

        eligible = [
            item for item in matches
            if self._eligible(condition, slot_id, item.component)
        ]
        shadow = [
            item for item in matches
            if not self._eligible(condition, slot_id, item.component)
        ]

        eligible = _sorted_resolved(_dedupe_resolved(eligible))
        shadow = _sorted_resolved(_dedupe_resolved(shadow))

        if eligible:
            witnesses = tuple(
                self._witness(condition, item) for item in eligible)
            return ConditionMatch(
                condition=condition,
                status=CONDITION_MATCHED,
                witness=witnesses[0],
                eligible_witnesses=witnesses,
                shadow_witnesses=tuple(
                    self._witness(condition, item) for item in shadow),
                explanation=(
                    "matched {0} in slot {1}".format(
                        witnesses[0].component_id, slot_id)),
            )

        if shadow:
            return ConditionMatch(
                condition=condition,
                status=CONDITION_SHADOWED,
                shadow_witnesses=tuple(
                    self._witness(condition, item) for item in shadow),
                reason_code="matched_outside_scope",
                explanation=(
                    "the CPE matches {0}, but no eligible component can "
                    "witness the condition for slot {1}: {2}".format(
                        _join_ids(
                            item.component.component_id for item in shadow),
                        slot_id,
                        self._shadow_reason(condition, slot_id, shadow),
                    )
                ),
            )

        if not evidence.complete:
            return ConditionMatch(
                condition=condition,
                status=CONDITION_UNKNOWN,
                reason_code="incomplete_evidence",
                explanation=(
                    "snapshot {0} does not provide complete evidence for "
                    "slot {1}".format(
                        evidence.slot_source_snapshot_id or
                        evidence.as_of_snapshot_id,
                        slot_id,
                    )
                ),
            )

        return ConditionMatch(
            condition=condition,
            status=CONDITION_ABSENT,
            reason_code="no_matching_component",
            explanation=(
                "no component in the resolved evidence for slot {0} matches "
                "{1}".format(slot_id, condition.cpe)),
        )

    def evaluate_slot(self, cabinet, evidence, slot):
        conditions = self.required_conditions(slot.slot_id)
        results = tuple(
            self._evaluate_condition(condition, slot.slot_id, evidence)
            for condition in conditions
        )

        if not results:
            return SlotResult(
                cabinet_id=cabinet.cabinet_id,
                advisory_id=self.advisory.advisory_id,
                slot_id=slot.slot_id,
                application=slot.application,
                status=STATUS_NOT_APPLICABLE,
                applicable=False,
                conditions=results,
                evidence=evidence,
                reasons=(
                    "the advisory has no conditions for this slot",
                ),
            )

        statuses = [item.status for item in results]

        if self.advisory.operator == "AND":
            if all(status == CONDITION_MATCHED for status in statuses):
                status = STATUS_APPLICABLE
                applicable = True
            elif any(
                    status in (CONDITION_ABSENT, CONDITION_SHADOWED)
                    for status in statuses):
                status = STATUS_NOT_APPLICABLE
                applicable = False
            else:
                status = STATUS_INDETERMINATE
                applicable = None
        else:  # OR
            if any(status == CONDITION_MATCHED for status in statuses):
                status = STATUS_APPLICABLE
                applicable = True
            elif any(status == CONDITION_UNKNOWN for status in statuses):
                status = STATUS_INDETERMINATE
                applicable = None
            else:
                status = STATUS_NOT_APPLICABLE
                applicable = False

        reasons = tuple(
            item.explanation for item in results
            if item.status != CONDITION_MATCHED
        )

        return SlotResult(
            cabinet_id=cabinet.cabinet_id,
            advisory_id=self.advisory.advisory_id,
            slot_id=slot.slot_id,
            application=slot.application,
            status=status,
            applicable=applicable,
            conditions=results,
            evidence=evidence,
            reasons=reasons,
        )

    def _witness_validation(
            self, record, condition, witness, slot_id, evidence, timeline):
        if witness.source_snapshot_id and timeline is not None:
            try:
                witness_position = timeline.position(
                    witness.source_snapshot_id)
            except KeyError:
                return "witness_unknown_snapshot", (
                    "witness {0} cites unknown snapshot {1}".format(
                        witness.component_id, witness.source_snapshot_id))
            if witness_position > timeline.position(evidence.as_of_snapshot_id):
                return "witness_from_future", (
                    "witness {0} comes from snapshot {1}, which is later "
                    "than adjudication snapshot {2}".format(
                        witness.component_id,
                        witness.source_snapshot_id,
                        evidence.as_of_snapshot_id,
                    ))

        resolved = evidence.find_any(witness.component_id)
        if resolved is None:
            return "witness_missing", (
                "witness component {0} is not present in the resolved "
                "evidence for slot {1}".format(
                    witness.component_id, slot_id))

        component = resolved.component
        try:
            witness_cpe = canonical(witness.cpe)
            component_cpe = canonical(component.cpe)
        except Exception as exc:
            return "witness_cpe_unparseable", (
                "witness {0} or component {1} has an unparseable CPE: "
                "{2}".format(witness.component_id, component.component_id, exc))
        if witness_cpe != component_cpe:
            return "witness_cpe_changed", (
                "witness {0} records {1}, but the current component is {2}".format(
                    witness.component_id, witness.cpe, component.cpe))

        if condition.scope == HOST_SCOPE:
            if not component.is_host_common:
                return "witness_not_host_common", (
                    "witness {0} is bound to slot(s) {1}, so it cannot "
                    "witness host-common condition {2}".format(
                        witness.component_id,
                        _join_ids(component.slots),
                        condition.condition_id,
                    ))
            return None, ""

        if condition.scope == SLOT_SCOPE:
            if record.is_host_aggregated:
                return "host_aggregated_closure", (
                    "closure {0} is aggregated only by host {1}; it carries "
                    "no slot identity and cannot close slot-scoped condition "
                    "{2} for slot {3}".format(
                        record.closure_id,
                        record.cabinet_id,
                        condition.condition_id,
                        slot_id,
                    ))
            if not record.covers_slot(slot_id):
                return "other_slot_closure", (
                    "closure {0} is scoped to slot(s) {1}, not slot {2}; its "
                    "witness {3} cannot close slot-scoped condition {4}".format(
                        record.closure_id,
                        _join_ids(record.slot_ids),
                        slot_id,
                        witness.component_id,
                        condition.condition_id,
                    ))
            if not component.belongs_to(slot_id):
                if component.is_host_common:
                    return "witness_not_in_slot", (
                        "witness {0} is host-common and cannot witness "
                        "slot-scoped condition {1} for slot {2}".format(
                            witness.component_id,
                            condition.condition_id,
                            slot_id,
                        ))
                return "witness_in_other_slot", (
                    "witness {0} belongs to slot(s) {1}, not slot {2}".format(
                        witness.component_id,
                        _join_ids(component.slots),
                        slot_id,
                    ))
            return None, ""

        return "unknown_scope", (
            "condition {0} has unknown scope {1}".format(
                condition.condition_id, condition.scope))

    def evaluate_closures(
            self, cabinet, evidence, slot_result, records, timeline=None):
        required = slot_result.required_condition_ids
        accepted = []
        rejected = []
        covered = set()

        for record in records:
            if record.cabinet_id != cabinet.cabinet_id:
                continue
            if record.advisory_id != self.advisory.advisory_id:
                continue
            for witness in record.witnesses:
                condition = self.advisory.get_condition(witness.condition_id)
                if condition is None:
                    rejected.append(RejectedClosure(
                        record=record,
                        condition=None,
                        witness=witness,
                        reason_code="unknown_condition",
                        explanation=(
                            "closure {0} cites condition {1}, which is not "
                            "part of advisory {2}".format(
                                record.closure_id,
                                witness.condition_id,
                                self.advisory.advisory_id,
                            )
                        ),
                    ))
                    continue

                if not condition.applies_to_slot(slot_result.slot_id):
                    rejected.append(RejectedClosure(
                        record=record,
                        condition=condition,
                        witness=witness,
                        reason_code="condition_not_for_slot",
                        explanation=(
                            "condition {0} targets slot {1}, not slot {2}".format(
                                condition.condition_id,
                                condition.slot_id,
                                slot_result.slot_id,
                            )
                        ),
                    ))
                    continue

                reason_code, explanation = self._witness_validation(
                    record, condition, witness, slot_result.slot_id,
                    evidence, timeline)
                if reason_code is not None:
                    rejected.append(RejectedClosure(
                        record=record,
                        condition=condition,
                        witness=witness,
                        reason_code=reason_code,
                        explanation=explanation,
                    ))
                    continue

                if condition.condition_id in covered:
                    rejected.append(RejectedClosure(
                        record=record,
                        condition=condition,
                        witness=witness,
                        reason_code="duplicate_condition",
                        explanation=(
                            "condition {0} is already closed for slot {1}".format(
                                condition.condition_id, slot_result.slot_id)),
                    ))
                    continue

                covered.add(condition.condition_id)
                accepted.append(AcceptedClosure(
                    record=record,
                    condition=condition,
                    witness=witness,
                    reused_from_other_slot=bool(
                        record.slot_ids
                        and slot_result.slot_id not in record.slot_ids),
                ))

        covered_required = frozenset(covered & required)
        missing = frozenset(required - covered)

        if slot_result.applicable is False:
            status = CLOSURE_NOT_REQUIRED
        elif slot_result.applicable is None:
            status = CLOSURE_INDETERMINATE
        elif not missing:
            status = CLOSURE_CLOSED
        elif covered_required:
            status = CLOSURE_PARTIALLY_CLOSED
        else:
            status = CLOSURE_OPEN

        return ClosureEvaluation(
            slot_id=slot_result.slot_id,
            status=status,
            required_condition_ids=required,
            covered_condition_ids=covered_required,
            missing_condition_ids=missing,
            accepted=tuple(accepted),
            rejected=tuple(rejected),
        )

    def _valid_host_reuse(self, record, condition, evidence):
        for witness in record.witnesses_for_condition(condition.condition_id):
            resolved = evidence.find_any(witness.component_id)
            if resolved is None:
                continue
            component = resolved.component
            if not component.is_host_common:
                continue
            try:
                if canonical(witness.cpe) != canonical(component.cpe):
                    continue
            except Exception:
                continue
            return witness
        return None

    def substitution_checks(
            self, cabinet, evidence, slot_result, records):
        checks = []
        required = tuple(
            item.condition for item in slot_result.conditions)
        slot_conditions = tuple(
            item for item in required if item.scope == SLOT_SCOPE)
        host_conditions = tuple(
            item for item in required if item.scope == HOST_SCOPE)

        for record in records:
            if record.cabinet_id != cabinet.cabinet_id:
                continue
            if record.advisory_id != self.advisory.advisory_id:
                continue
            if record.covers_slot(slot_result.slot_id):
                continue

            reusable = []
            for condition in host_conditions:
                if self._valid_host_reuse(record, condition, evidence):
                    reusable.append(condition.condition_id)

            blocked = []
            for condition in slot_conditions:
                blocked.append(condition.condition_id)

            if record.is_host_aggregated:
                reason_code = "host_aggregated_closure"
                explanation = (
                    "closure {0} is a host-level disposition for {1}; it has "
                    "no application-slot identity.  It may be reused for "
                    "host-common condition(s) {2}, but it cannot substitute "
                    "for slot {3}: slot-scoped condition(s) {4} still need a "
                    "witness owned by slot {3}.".format(
                        record.closure_id,
                        record.cabinet_id,
                        _join_ids(reusable),
                        slot_result.slot_id,
                        _join_ids(blocked),
                    )
                )
            else:
                reason_code = "cross_slot_closure"
                shared = []
                for condition in slot_conditions:
                    for witness in record.witnesses_for_condition(
                            condition.condition_id):
                        if len(witness.component_slots) > 1:
                            shared.append(witness.component_id)
                shared_text = ""
                if shared:
                    shared_text = (
                        "  Witness component(s) {0} are shared with slot {1}, "
                        "so remediation may be joint, but the closure is "
                        "still scoped to slot(s) {2}; slot {1} needs its own "
                        "witness or an explicit joint closure listing slot "
                        "{1}.".format(
                            _join_ids(shared),
                            slot_result.slot_id,
                            _join_ids(record.slot_ids),
                        )
                    )
                explanation = (
                    "closure {0} belongs to slot(s) {1}, not slot {2}.  It "
                    "may be reused for host-common condition(s) {3}, but it "
                    "cannot substitute for slot {2}: condition(s) {4} are "
                    "bound to the components of slot {2}.{5}".format(
                        record.closure_id,
                        _join_ids(record.slot_ids),
                        slot_result.slot_id,
                        _join_ids(reusable),
                        _join_ids(blocked),
                        shared_text,
                    )
                )

            checks.append(SubstitutionCheck(
                source_closure_id=record.closure_id,
                source_slot_ids=record.slot_ids,
                target_slot_id=slot_result.slot_id,
                can_substitute=False,
                reusable_conditions=tuple(sorted(reusable)),
                blocked_conditions=tuple(sorted(blocked)),
                reason_code=reason_code,
                explanation=explanation,
            ))

        return tuple(checks)

    def build_closure_record(
            self,
            slot_result,
            closure_id,
            condition_ids=None,
            slot_ids=None,
            joint_slot_ids=(),
            recorded_at="",
            note="",
            source="",
    ):
        """
        Create a closure record that carries the exact match witnesses.

        This is the supported way to produce a disclosure record.  It refuses
        to invent a witness: every requested condition must have been matched
        for the slot.
        """

        if condition_ids is None:
            requested = set(slot_result.required_condition_ids)
        else:
            requested = set(condition_ids)

        selected = []
        for match in slot_result.conditions:
            if match.condition.condition_id not in requested:
                continue
            if match.status != CONDITION_MATCHED or match.witness is None:
                raise ValueError(
                    "condition {0!r} is not matched for slot {1!r} and "
                    "cannot be closed".format(
                        match.condition.condition_id, slot_result.slot_id))
            selected.append(match)

        matched_ids = set(item.condition.condition_id for item in selected)
        missing = requested - matched_ids
        if missing:
            raise ValueError(
                "conditions {0} are not part of this slot result".format(
                    _join_ids(missing)))

        if slot_ids is None:
            resolved_slot_ids = frozenset(
                {slot_result.slot_id} | set(joint_slot_ids))
        else:
            resolved_slot_ids = frozenset(slot_ids)

        if not resolved_slot_ids:
            disallowed = [
                item for item in selected
                if item.condition.scope == SLOT_SCOPE
            ]
            if disallowed:
                raise ValueError(
                    "a host-aggregated closure cannot carry slot-scoped "
                    "conditions: {0}".format(
                        _join_ids(
                            item.condition.condition_id
                            for item in disallowed)))
        else:
            disallowed = [
                item for item in selected
                if item.condition.scope == SLOT_SCOPE
                and slot_result.slot_id not in resolved_slot_ids
            ]
            if disallowed:
                raise ValueError(
                    "slot-scoped conditions {0} can only be closed by a "
                    "record that names slot {1}".format(
                        _join_ids(
                            item.condition.condition_id
                            for item in disallowed),
                        slot_result.slot_id))

        witnesses = tuple(item.witness for item in selected)
        return ClosureRecord(
            closure_id=closure_id,
            cabinet_id=slot_result.cabinet_id,
            advisory_id=slot_result.advisory_id,
            slot_ids=resolved_slot_ids,
            witnesses=witnesses,
            recorded_at=recorded_at,
            note=note,
            source=source,
        )


def build_host_rollup(cabinet, slot_reports, records, advisory_id=None):
    """
    Build a deliberately lossy host-level view.

    The result is always marked invalid when the cabinet has more than one
    slot or when host-aggregated closures are present.  It exists so a report
    can show, explicitly, why the host roll-up is not a substitute for the
    per-slot disposition.
    """

    applicable = tuple(sorted(
        slot_id for slot_id, report in slot_reports.items()
        if report.applicability.applicable is True
    ))
    closed = tuple(sorted(
        slot_id for slot_id, report in slot_reports.items()
        if report.closure.status == CLOSURE_CLOSED
    ))
    host_records = tuple(sorted(
        record.closure_id for record in records
        if record.cabinet_id == cabinet.cabinet_id
        and (advisory_id is None or record.advisory_id == advisory_id)
        and record.is_host_aggregated
    ))

    invalid_reasons = []
    if len(cabinet.slots) > 1:
        invalid_reasons.append(
            "the cabinet has {0} application slots sharing host {1}".format(
                len(cabinet.slots), cabinet.host_id))
    if host_records:
        invalid_reasons.append(
            "host-aggregated closure(s) {0} carry no slot identity".format(
                _join_ids(host_records)))

    if invalid_reasons:
        warning = (
            "Host roll-up is invalid for disposition: {0}.  Use the per-slot "
            "applicability and closure results instead.".format(
                "; ".join(invalid_reasons))
        )
    else:
        warning = (
            "Host roll-up happens to agree here, but slot identity should "
            "still be retained in the closure record."
        )

    return HostRollup(
        cabinet_id=cabinet.cabinet_id,
        host_id=cabinet.host_id,
        applicable_slots=applicable,
        closed_slots=closed,
        host_aggregated_closures=host_records,
        valid=not invalid_reasons,
        warning=warning,
    )


def detect_responsibility_notes(cabinet, snapshots):
    """
    Explain how responsibility changes for the three required scenarios.

    The notes are derived from the input data, so they appear only when the
    corresponding situation is actually present.
    """

    notes = []
    snapshots = tuple(snapshots)

    # Shared components: one component, several slot owners.
    seen = {}
    for snapshot in snapshots:
        for component in snapshot.components:
            if len(component.slots) > 1:
                seen[component.component_id] = component
    for component_id in sorted(seen):
        component = seen[component_id]
        notes.append(ResponsibilityNote(
            scenario="shared-component",
            summary=(
                "component {0} is shared by slots {1}".format(
                    component_id, _join_ids(component.slots))),
            detail=(
                "The component is one inventory object, but each slot owns "
                "its own closure responsibility.  A single-slot closure that "
                "cites {0} closes only that slot.  To close both slots, use "
                "one explicit joint closure whose slot_ids contain {1}, or "
                "two separate per-slot closures.  A host-level roll-up is "
                "not sufficient because it does not name the joint owners."
                .format(component_id, _join_ids(component.slots))
            ),
            slots=tuple(sorted(component.slots)),
            components=(component_id,),
        ))

    # Migration: the same component identity changes slot ownership between
    # consecutive snapshots.
    for previous, current in zip(snapshots, snapshots[1:]):
        previous_by_id = {
            component.component_id: component
            for component in previous.components
        }
        for component in current.components:
            old = previous_by_id.get(component.component_id)
            if old is None:
                continue
            if old.slots == component.slots:
                continue
            notes.append(ResponsibilityNote(
                scenario="slot-migration",
                summary=(
                    "component {0} moved from slot(s) {1} to slot(s) {2}".format(
                        component.component_id,
                        _join_ids(old.slots),
                        _join_ids(component.slots),
                    )),
                detail=(
                    "The old slot's closure is historical and does not "
                    "transfer to the new slot.  Host-common conditions may "
                    "still be witnessed by the host component, but every "
                    "slot-scoped condition must be re-witnessed by the new "
                    "slot.  Responsibility moves to the new slot owner at "
                    "the migration snapshot ({0} -> {1}).".format(
                        previous.snapshot_id, current.snapshot_id)
                ),
                slots=tuple(sorted(old.slots | component.slots)),
                components=(component.component_id,),
            ))

    # Single-slot supplement: only one slot received new evidence.
    for snapshot in snapshots:
        if snapshot.evidence_slots is None:
            continue
        evidence_slots = tuple(sorted(snapshot.evidence_slots))
        if len(evidence_slots) == 1 and len(cabinet.slots) > 1:
            slot_id = evidence_slots[0]
            others = tuple(
                item.slot_id for item in cabinet.slots
                if item.slot_id != slot_id)
            notes.append(ResponsibilityNote(
                scenario="single-slot-evidence",
                summary=(
                    "snapshot {0} supplements only slot {1}".format(
                        snapshot.snapshot_id, slot_id)),
                detail=(
                    "Only slot {0} is re-evidenced by this snapshot.  Slot(s) "
                    "{1} keep their previous evidence and their previous "
                    "responsible owner.  A closure created for slot {0} "
                    "cannot close slot(s) {1}; and a host-level closure "
                    "cannot stand in for the missing per-slot witnesses."
                    .format(slot_id, _join_ids(others))
                ),
                slots=(slot_id,) + others,
                components=(),
            ))
        elif len(evidence_slots) != len(cabinet.slots):
            notes.append(ResponsibilityNote(
                scenario="partial-evidence",
                summary=(
                    "snapshot {0} re-evidences slots {1}".format(
                        snapshot.snapshot_id, _join_ids(evidence_slots))),
                detail=(
                    "Slots outside this set keep their previous evidence and "
                    "responsibility.  Do not promote a partial snapshot to a "
                    "host-wide disposition."
                ),
                slots=evidence_slots,
                components=(),
            ))

    return tuple(notes)


def policy_notes():
    """Return the baseline responsibility policy for every report."""

    return (
        ResponsibilityNote(
            scenario="shared-component",
            summary="A shared component has joint slot responsibility.",
            detail=(
                "When one component belongs to two slots, a fix may be "
                "physically shared, but the audit closure is not.  Close "
                "each slot explicitly, or create one joint closure whose "
                "slot_ids name every affected slot.  A single-slot closure "
                "does not discharge the other slot's responsibility."
            ),
        ),
        ResponsibilityNote(
            scenario="slot-migration",
            summary="Migration moves slot-scoped responsibility to the new slot.",
            detail=(
                "A closure bound to the old slot is historical evidence "
                "only.  After migration, the new slot must re-witness every "
                "slot-scoped condition.  Host-common evidence can remain "
                "valid if the host component is unchanged."
            ),
        ),
        ResponsibilityNote(
            scenario="single-slot-evidence",
            summary="A single-slot supplement discharges only that slot.",
            detail=(
                "When a snapshot only re-evidences one slot, the other slots "
                "keep their previous evidence and their previous owners.  "
                "The supplement cannot be promoted to a host-level closure."
            ),
        ),
    )
