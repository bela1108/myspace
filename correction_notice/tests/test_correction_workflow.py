"""Tests for the partial-signature correction-notice workflow."""

import json

import pytest

from correction_notice.cli import main as cli_main
from correction_notice.fixtures import (
    CHANGED_SECTION,
    NO_SECTION_SIGNED,
    RECIPIENT_A_ID,
    RECIPIENT_B_ID,
    RECIPIENT_C_ID,
    T_CORRECTION,
    T_EXPLANATION_EXPIRY,
    build_history_bundle,
)
from correction_notice.processor import (
    REASON_INCLUDED,
    REASON_MISSING_SECTION,
    REASON_NOT_SIGNED,
    determine_recipient_scope,
    load_history,
    process_correction,
)


@pytest.fixture()
def store():
    history = build_history_bundle()
    return load_history(json.loads(history.serialize()))


def test_history_contains_three_local_receipts(store):
    receipts = [obj for obj in store.query() if obj.type == "x-delivery-receipt"]
    assert len(receipts) == 3
    by_recipient = {obj.x_recipient_ref: obj for obj in receipts}
    assert by_recipient[RECIPIENT_A_ID].x_signed_sections == ["section-a"]
    assert by_recipient[RECIPIENT_B_ID].x_signed_sections == ["section-b"]
    assert by_recipient[RECIPIENT_C_ID].x_signed is False
    assert by_recipient[RECIPIENT_C_ID].x_signed_sections == [NO_SECTION_SIGNED]


def test_only_section_a_signer_is_included(store):
    scope = determine_recipient_scope(store)
    assert scope.included_refs == [RECIPIENT_A_ID]
    assert set(scope.excluded_refs) == {RECIPIENT_B_ID, RECIPIENT_C_ID}


def test_excluded_reasons_come_from_same_receipt_list(store):
    scope = determine_recipient_scope(store)
    reasons = {item["recipient_ref"]: item for item in scope.excluded}

    bravo = reasons[RECIPIENT_B_ID]
    assert bravo["reason"] == REASON_MISSING_SECTION
    assert bravo["signed_sections"] == ["section-b"]
    assert CHANGED_SECTION in bravo["explanation"]

    charlie = reasons[RECIPIENT_C_ID]
    assert charlie["reason"] == REASON_NOT_SIGNED
    assert charlie["signed_sections"] == [NO_SECTION_SIGNED]

    included = scope.included[0]
    assert included["reason"] == REASON_INCLUDED


def test_correction_notice_targets_only_included_recipients(store):
    result = process_correction(store)
    notice = result.correction_notice
    assert notice.x_corrects_section == CHANGED_SECTION
    assert notice.x_target_recipient_refs == [RECIPIENT_A_ID]
    assert RECIPIENT_B_ID not in notice.x_target_recipient_refs
    assert RECIPIENT_C_ID not in notice.x_target_recipient_refs
    # The corrected object is a new version of the same id, not a new object.
    assert result.corrected_indicator.id == store.get(
        "indicator--01234567-0000-4000-8000-000000000020",
    ).id
    assert result.corrected_indicator.modified > store.get(
        "indicator--01234567-0000-4000-8000-000000000020",
    ).modified


def test_section_b_restriction_is_retained(store):
    result = process_correction(store)
    indicator = result.corrected_indicator

    # The restricted content itself is carried over unchanged.
    assert indicator.x_section_b_content == "section-b: restricted handling detail"
    markings = indicator.granular_markings
    assert len(markings) == 1
    assert markings[0].selectors == ["x_section_b_content"]
    marking_id = markings[0].marking_ref

    # The same marking object is retained and referenced by the new notice.
    assert result.restriction_marking.id == marking_id
    assert marking_id in result.correction_notice.x_restricted_section_refs
    assert marking_id in result.extended_explanation.object_marking_refs


def test_explanation_expiry_and_extension_state_are_preserved(store):
    result = process_correction(store)
    note = result.extended_explanation
    # Original deadline is retained for the audit trail.
    assert note.x_valid_until == T_EXPLANATION_EXPIRY
    assert note.x_explanation_state == "extended"
    # x_extended_at is a custom string property holding a STIX timestamp.
    assert note.x_extended_at == T_CORRECTION
    # It is a new version of the original explanation, same id.
    assert note.id == "note--01234567-0000-4000-8000-000000000050"


def test_decision_objects_explain_every_recipient(store):
    result = process_correction(store)
    decisions = result.decisions
    assert len(decisions) == 3
    by_recipient = {obj.x_recipient_ref: obj for obj in decisions}

    assert by_recipient[RECIPIENT_A_ID].x_decision == "included"
    assert by_recipient[RECIPIENT_B_ID].x_decision == "excluded"
    assert by_recipient[RECIPIENT_C_ID].x_decision == "excluded"
    for decision in decisions:
        assert decision.x_explanation
        assert decision.x_reason


def test_output_bundle_round_trips_and_is_deterministic(store, tmp_path):
    result = process_correction(store)
    serialized = result.as_bundle().serialize(pretty=True)
    reparsed = json.loads(serialized)
    types = {obj["type"] for obj in reparsed["objects"]}
    assert {
        "indicator",
        "report",
        "note",
        "marking-definition",
        "x-recipient-decision",
    } <= types

    second = process_correction(load_history(
        json.loads(build_history_bundle().serialize()),
    )).as_bundle().serialize(pretty=True)
    assert second == serialized


def test_cli_writes_history_and_correction_bundles(tmp_path):
    history_path = tmp_path / "history.json"
    out_path = tmp_path / "correction.json"
    exit_code = cli_main([
        "--history-out", str(history_path),
        "--out", str(out_path),
    ])
    assert exit_code == 0

    history = json.loads(history_path.read_text())
    assert any(
        obj["type"] == "x-delivery-receipt"
        for obj in history["objects"]
    )
    correction = json.loads(out_path.read_text())
    notice = next(
        obj for obj in correction["objects"] if obj["type"] == "report"
    )
    assert notice["x_target_recipient_refs"] == [RECIPIENT_A_ID]
