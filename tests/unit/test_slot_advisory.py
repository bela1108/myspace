from cpe.slot_advisory.demo import demo_payload
from cpe.slot_advisory.query import run_query


def _slot(report, slot_id):
    return next(item for item in report["slots"] if item["slot_id"] == slot_id)


def _decision(slot_report, advisory_id):
    return next(
        item for item in slot_report["applicability"]
        if item["advisory_id"] == advisory_id
    )


def test_each_slot_has_independent_verdict_and_bound_witness():
    report = run_query(demo_payload())
    plc = _slot(report, "plc-control")
    hmi = _slot(report, "hmi-control")

    assert _decision(plc, "ADV-CTRL-047")["verdict"] == "not_applicable"
    assert _decision(hmi, "ADV-CTRL-047")["verdict"] == "applicable"

    closure = report["created_closures"][0]
    assert closure["closure_scope"] == "slot"
    assert closure["slot_id"] == "plc-control"
    assert closure["record_hash"]
    component_ids = {item["component_id"] for item in closure["witnesses"]}
    assert "inst-host-edge-bus" in component_ids
    assert "inst-plc-runtime" in component_ids
    assert all(item["identity_fingerprint"] for item in closure["witnesses"])


def test_cross_slot_closure_is_rejected():
    report = run_query(demo_payload())
    hmi = _slot(report, "hmi-control")
    substitution = hmi["other_slot_closure_substitutions"][0]
    assert substitution["accepted"] is False
    assert substitution["source_slot_id"] == "plc-control"
    assert substitution["target_slot_id"] == "hmi-control"
    for code in ("SLOT_MISMATCH", "STRICT_WITNESS_NOT_IN_SLOT", "TARGET_STILL_APPLICABLE"):
        assert code in substitution["reason_codes"]
