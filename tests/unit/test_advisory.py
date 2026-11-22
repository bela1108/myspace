from __future__ import unicode_literals

import json

import pytest

from cpe.advisory import (
    Advisory,
    AdvisoryCase,
    Cabinet,
    ClosureRecord,
    Component,
    Condition,
    Slot,
    Snapshot,
    Witness,
    query,
)
from cpe.advisory.cli import DEMO_PATH, MIGRATION_PATH, main
from cpe.advisory.engine import EvidenceTimeline, SlotAdjudicator
from cpe.advisory.matching import condition_matches
from cpe.advisory.query import (
    format_report,
    load_case,
    query_case,
    report_to_dict,
)


RT = "cpe:2.3:a:acme:plc_runtime:4.2.1:*:*:*:*:*:*:*"
HMI_A = "cpe:2.3:a:acme:hmi:2.1:*:*:*:*:*:*:*"
HMI_A_PATCHED = "cpe:2.3:a:acme:hmi:2.2:*:*:*:*:*:*:*"
HMI_B = "cpe:2.3:a:acme:hmi:3.0:*:*:*:*:*:*:*"
VALVE = "cpe:2.3:a:acme:valve_driver:5.0:*:*:*:*:*:*:*"


def make_cabinet(slot_ids=("A", "B")):
    return Cabinet(
        cabinet_id="CAB-T",
        host_id="HOST-T",
        name="Test cabinet",
        slots=tuple(
            Slot(slot_id, "Application " + slot_id)
            for slot_id in slot_ids),
    )


def make_advisory(conditions=None, operator="AND"):
    if conditions is None:
        conditions = (
            Condition("host-runtime", RT, "host"),
            Condition("slot-a-hmi", HMI_A, "slot", "A"),
            Condition("slot-b-hmi", HMI_B, "slot", "B"),
        )
    return Advisory(
        advisory_id="ADV-T",
        title="Test advisory",
        operator=operator,
        conditions=conditions,
    )


def make_components(
        version_a=HMI_A,
        version_b=HMI_B,
        include_b=True,
        valve=VALVE,
):
    components = [
        Component("rt-01", RT, frozenset(), "runtime"),
        Component("hmi-a-01", version_a, frozenset({"A"}), "hmi A"),
    ]
    if include_b:
        components.append(
            Component("hmi-b-01", version_b, frozenset({"B"}), "hmi B"))
    if valve is not None:
        components.append(
            Component("valve-drv-01", valve, frozenset({"A", "B"}), "valve"))
    return tuple(components)


def make_case(closures=(), second_slots=("A",)):
    return AdvisoryCase(
        cabinet=make_cabinet(),
        advisory=make_advisory(),
        snapshots=(
            Snapshot(
                snapshot_id="snap-1",
                cabinet_id="CAB-T",
                captured_at="2026-11-18T02:00:00+08:00",
                components=make_components(),
                evidence_slots=frozenset({"A", "B"}),
            ),
            Snapshot(
                snapshot_id="snap-2",
                cabinet_id="CAB-T",
                captured_at="2026-11-22T09:30:00+08:00",
                components=(
                    Component("rt-01", RT, frozenset(), "runtime"),
                    Component(
                        "hmi-a-01",
                        HMI_A_PATCHED,
                        frozenset({"A"}),
                        "hmi A patched"),
                    Component(
                        "valve-drv-01",
                        "cpe:2.3:a:acme:valve_driver:5.1:*:*:*:*:*:*:*",
                        frozenset({"A", "B"}),
                        "valve updated"),
                ),
                evidence_slots=frozenset(second_slots),
            ),
        ),
        closures=tuple(closures),
    )


def test_condition_matching_uses_cpe_23_superset():
    assert condition_matches(HMI_A, HMI_A)
    assert not condition_matches(HMI_A, HMI_B)
    assert condition_matches(
        "cpe:2.3:a:acme:hmi:2.*:*:*:*:*:*:*:*", HMI_A)


def test_slot_condition_does_not_match_other_slot_component():
    cabinet = make_cabinet()
    advisory = make_advisory(conditions=(
        Condition("slot-a-hmi", HMI_A, "slot"),
    ))
    snapshot = Snapshot(
        "snap-1", cabinet.cabinet_id, components=make_components())
    timeline = EvidenceTimeline(cabinet, (snapshot,))
    adjudicator = SlotAdjudicator(advisory)

    result_a = adjudicator.evaluate_slot(
        cabinet, timeline.resolve(snapshot, "A"), cabinet.get_slot("A"))
    result_b = adjudicator.evaluate_slot(
        cabinet, timeline.resolve(snapshot, "B"), cabinet.get_slot("B"))

    assert result_a.applicable is True
    assert result_b.applicable is False
    match_b = result_b.conditions[0]
    assert match_b.status == "shadowed"
    assert "belongs to slot" in match_b.explanation
    assert match_b.witness is None


def test_host_condition_requires_host_common_component():
    cabinet = make_cabinet()
    advisory = make_advisory(conditions=(
        Condition("host-hmi", HMI_A, "host"),
    ))
    snapshot = Snapshot(
        "snap-1", cabinet.cabinet_id, components=make_components())
    timeline = EvidenceTimeline(cabinet, (snapshot,))
    result = SlotAdjudicator(advisory).evaluate_slot(
        cabinet, timeline.resolve(snapshot, "A"), cabinet.get_slot("A"))

    assert result.applicable is False
    assert result.conditions[0].status == "shadowed"
    assert result.conditions[0].shadow_witnesses[0].component_id == "hmi-a-01"


def test_closure_record_carries_witness_identity():
    cabinet = make_cabinet()
    advisory = make_advisory()
    snapshot = Snapshot(
        "snap-1", cabinet.cabinet_id, components=make_components())
    timeline = EvidenceTimeline(cabinet, (snapshot,))
    adjudicator = SlotAdjudicator(advisory)
    result = adjudicator.evaluate_slot(
        cabinet, timeline.resolve(snapshot, "A"), cabinet.get_slot("A"))

    record = adjudicator.build_closure_record(
        result, "CL-A", recorded_at="2026-11-20T00:00:00+08:00")

    assert record.slot_ids == frozenset({"A"})
    assert record.condition_ids == frozenset({"host-runtime", "slot-a-hmi"})
    by_condition = {
        witness.condition_id: witness for witness in record.witnesses
    }
    assert by_condition["slot-a-hmi"].component_id == "hmi-a-01"
    assert by_condition["slot-a-hmi"].component_slots == frozenset({"A"})
    assert by_condition["host-runtime"].component_id == "rt-01"
    assert by_condition["host-runtime"].component_slots == frozenset()
    assert by_condition["slot-a-hmi"].source_snapshot_id == "snap-1"


def test_host_level_closure_cannot_close_slot_condition():
    host_level = ClosureRecord(
        closure_id="CL-HOST",
        cabinet_id="CAB-T",
        advisory_id="ADV-T",
        slot_ids=frozenset(),
        witnesses=(
            Witness(
                "rt-01", RT, "snap-1", "host-runtime", "host", frozenset()),
            Witness(
                "rt-01", RT, "snap-1", "slot-b-hmi", "slot", frozenset()),
        ),
    )
    report = query_case(make_case(closures=(host_level,)))
    slot_b = report.snapshots[0].slots["B"]

    assert slot_b.closure.status == "partially_closed"
    assert slot_b.closure.covered_condition_ids == frozenset({"host-runtime"})
    assert slot_b.closure.missing_condition_ids == frozenset({"slot-b-hmi"})
    reasons = [item.reason_code for item in slot_b.closure.rejected]
    assert "host_aggregated_closure" in reasons


def test_cross_slot_closure_is_not_a_substitute():
    slot_a_record = ClosureRecord(
        closure_id="CL-A",
        cabinet_id="CAB-T",
        advisory_id="ADV-T",
        slot_ids=frozenset({"A"}),
        witnesses=(
            Witness(
                "hmi-a-01", HMI_A, "snap-1", "slot-a-hmi", "slot",
                frozenset({"A"})),
        ),
    )
    report = query_case(make_case(closures=(slot_a_record,)))
    slot_b = report.snapshots[0].slots["B"]
    checks = {item.source_closure_id: item for item in slot_b.substitution_checks}

    assert "CL-A" in checks
    assert checks["CL-A"].can_substitute is False
    assert "slot-b-hmi" in checks["CL-A"].blocked_conditions
    assert checks["CL-A"].reason_code == "cross_slot_closure"
    assert slot_b.closure.status == "open"
    assert "slot-b-hmi" in slot_b.closure.missing_condition_ids
    assert slot_b.closure.closed is False


def test_shared_component_needs_joint_or_per_slot_closure():
    cabinet = make_cabinet()
    advisory = make_advisory(conditions=(
        Condition("shared-driver", VALVE, "slot"),
    ))
    snapshot = Snapshot(
        "snap-1", cabinet.cabinet_id, components=make_components())
    timeline = EvidenceTimeline(cabinet, (snapshot,))
    adjudicator = SlotAdjudicator(advisory)
    result_a = adjudicator.evaluate_slot(
        cabinet, timeline.resolve(snapshot, "A"), cabinet.get_slot("A"))
    result_b = adjudicator.evaluate_slot(
        cabinet, timeline.resolve(snapshot, "B"), cabinet.get_slot("B"))

    single = adjudicator.build_closure_record(result_a, "CL-A")
    assert single.witnesses[0].component_slots == frozenset({"A", "B"})
    closure_b_single = adjudicator.evaluate_closures(
        cabinet, timeline.resolve(snapshot, "B"), result_b,
        (single,), timeline=timeline)
    assert closure_b_single.status == "open"

    joint = adjudicator.build_closure_record(
        result_a, "CL-AB", joint_slot_ids=("B",))
    assert joint.slot_ids == frozenset({"A", "B"})
    closure_b_joint = adjudicator.evaluate_closures(
        cabinet, timeline.resolve(snapshot, "B"), result_b,
        (joint,), timeline=timeline)
    assert closure_b_joint.status == "closed"


def test_single_slot_supplement_keeps_other_slot_evidence():
    report = query_case(make_case())
    snap_2 = report.snapshots[1]
    slot_a = snap_2.slots["A"]
    slot_b = snap_2.slots["B"]

    assert slot_a.applicability.applicable is False
    assert slot_b.applicability.applicable is True
    assert slot_a.evidence_sources["hmi-a-01"].startswith("snap-2")
    assert slot_b.evidence_sources["hmi-b-01"] == "snap-1"
    scenarios = [note.scenario for note in slot_b.responsibility_notes]
    assert "single-slot-evidence" in scenarios


def test_migration_moves_slot_scoped_responsibility():
    cabinet = make_cabinet(slot_ids=("A", "B", "C"))
    advisory = make_advisory(conditions=(
        Condition("driver", VALVE, "slot"),
    ))
    snap_1 = Snapshot(
        "snap-1",
        cabinet.cabinet_id,
        components=(Component("drv-01", VALVE, frozenset({"A"})),),
    )
    snap_2 = Snapshot(
        "snap-2",
        cabinet.cabinet_id,
        components=(Component("drv-01", VALVE, frozenset({"C"})),),
    )

    from cpe.advisory.engine import detect_responsibility_notes
    notes = detect_responsibility_notes(cabinet, (snap_1, snap_2))
    migration = [item for item in notes if item.scenario == "slot-migration"]
    assert migration
    assert "old slot" in migration[0].detail


def test_bundled_demo_blocks_cross_slot_and_host_rollup():
    case = load_case(DEMO_PATH)
    report = query_case(case)
    latest = report.snapshots[-1]

    assert latest.slots["A"].applicability.applicable is False
    assert latest.slots["B"].applicability.applicable is True
    assert latest.slots["B"].closure.status == "partially_closed"
    assert "slot-b-hmi" in latest.slots["B"].closure.missing_condition_ids
    assert latest.host_rollup.valid is False

    checks = {
        item.source_closure_id: item
        for item in latest.slots["B"].substitution_checks
    }
    assert checks["CL-A-0002"].can_substitute is False
    assert checks["CL-A-0002"].reason_code == "cross_slot_closure"
    assert "slot-b-hmi" in checks["CL-A-0002"].blocked_conditions
    assert checks["CL-HOST-0001"].reason_code == "host_aggregated_closure"


def test_bundled_migration_demo_moves_responsibility():
    report = query_case(load_case(MIGRATION_PATH))
    latest = report.snapshots[-1]

    assert latest.slots["A"].applicability.applicable is False
    assert latest.slots["C"].applicability.applicable is True
    assert latest.slots["C"].closure.status == "open"
    checks = {
        item.source_closure_id: item
        for item in latest.slots["C"].substitution_checks
    }
    assert checks["CL-A-0001"].reason_code == "cross_slot_closure"
    assert any(
        note.scenario == "slot-migration"
        for note in report.responsibility_notes)


def test_report_is_json_serialisable_and_formats():
    closure = ClosureRecord(
        closure_id="CL-A",
        cabinet_id="CAB-T",
        advisory_id="ADV-T",
        slot_ids=frozenset({"A"}),
        witnesses=(
            Witness(
                "hmi-a-01", HMI_A, "snap-1", "slot-a-hmi", "slot",
                frozenset({"A"})),
        ),
    )
    report = query_case(make_case(closures=(closure,)))
    payload = report_to_dict(report)
    encoded = json.dumps(payload, ensure_ascii=False)
    decoded = json.loads(encoded)

    assert decoded["cabinet"]["host_id"] == "HOST-T"
    assert set(decoded["snapshots"][0]["slots"]) == {"A", "B"}
    text = format_report(report)
    assert "Slot A" in text
    assert "cannot substitute" in text


def test_query_convenience_entry_point():
    cabinet = make_cabinet()
    advisory = make_advisory()
    snapshot = Snapshot(
        "snap-1", cabinet.cabinet_id, components=make_components())
    report = query(cabinet, (snapshot,), advisory)

    assert report.cabinet.cabinet_id == "CAB-T"
    assert report.snapshots[0].slots["A"].applicability.applicable is True


def test_build_closure_refuses_unmatched_or_slotless_slot_condition():
    cabinet = make_cabinet()
    advisory = make_advisory()
    snapshot = Snapshot(
        "snap-1", cabinet.cabinet_id, components=make_components())
    timeline = EvidenceTimeline(cabinet, (snapshot,))
    adjudicator = SlotAdjudicator(advisory)
    result = adjudicator.evaluate_slot(
        cabinet, timeline.resolve(snapshot, "A"), cabinet.get_slot("A"))

    with pytest.raises(ValueError):
        adjudicator.build_closure_record(
            result, "CL-BAD", condition_ids={"does-not-exist"})
    with pytest.raises(ValueError):
        adjudicator.build_closure_record(
            result, "CL-BAD", slot_ids=frozenset())


def test_cli_demo_json(capsys):
    exit_code = main(["--demo", "--json", "--compact"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["cabinet"]["cabinet_id"] == "CAB-07"
    assert len(payload["snapshots"]) == 2
