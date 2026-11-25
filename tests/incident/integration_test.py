"""End-to-end replay of the synthetic handoff case on disk."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from detect_secrets.incident.enums import Decision
from detect_secrets.incident.enums import ReviewState
from detect_secrets.incident.report import render_text_report
from detect_secrets.incident.replay import replay_case

CASE_PATH = Path("test_data/incident/handoff_case.json")


@pytest.fixture
def case_data():
    return json.loads(CASE_PATH.read_text())


@pytest.fixture
def report(case_data):
    return replay_case(case_data)


def _audit_for(report, event_id):
    return next(
        entry for entry in report["audit_trail"] if entry["event_id"] == event_id
    )


def test_full_handoff_lifecycle_replays_all_events(report):
    assert report["summary"]["events_replayed"] == 14
    assert report["summary"]["occurrences_total"] == 4
    assert report["summary"]["findings_total"] == 3


def test_every_audit_decision_cites_a_responsibility_or_exemption_record(report):
    for entry in report["audit_trail"]:
        assert entry["decision"]
        assert entry["reason"]
        assert (
            entry["ownership_record_id"] is not None
            or entry["exemption_id"] is not None
        ), entry


def test_code_move_hands_off_to_platform_team_record(report):
    entry = _audit_for(report, "E06")
    assert entry["decision"] == Decision.MOVED.value
    assert entry["team"] == "platform-team"
    assert entry["ownership_record_id"] == "OWN-PLAT-2"
    assert entry["evidence"]["previous_path"] == "src/payments/charges.py"


def test_expired_path_bound_exemption_does_not_close_moved_occurrence(report):
    entry = _audit_for(report, "E14")
    assert entry["decision"] == Decision.SUPPRESSION_REJECTED.value
    assert "src/payments/charges.py" in entry["reason"]
    moved = next(
        item
        for item in report["findings"]
        if item["path"] == "src/platform/billing/charges.py"
    )
    assert moved["state"] != ReviewState.SUPPRESSED.value
    assert moved["ownership_record_id"] == "OWN-PLAT-2"


def test_fork_siblings_cannot_share_one_exemption(report):
    entry = _audit_for(report, "E09")
    assert entry["decision"] == Decision.SUPPRESSION_REJECTED.value
    sibling = next(
        item
        for item in report["findings"]
        if item["path"] == "src/platform/billing/refunds_copy.py"
    )
    original = next(
        item
        for item in report["findings"]
        if item["path"] == "src/payments/refunds.py"
    )
    assert sibling["state"] != ReviewState.SUPPRESSED.value
    assert sibling["forked_from"] == "src/payments/refunds.py"
    assert original["state"] == ReviewState.SUPPRESSED.value


def test_revoked_exemption_cannot_close_legacy_occurrence(report):
    entry = _audit_for(report, "E12")
    assert entry["decision"] == Decision.SUPPRESSION_REJECTED.value
    assert entry["exemption_id"] == "EX-503"
    legacy = next(
        item for item in report["findings"] if item["finding_id"] == "F-1003"
    )
    assert legacy["review_overdue"] is True


def test_re_attribution_picks_up_new_ownership_record(report):
    entry = _audit_for(report, "E11")
    assert entry["decision"] == Decision.OWNER_ASSIGNED.value
    assert entry["team"] == "payments-guild"
    assert entry["ownership_record_id"] == "OWN-PAY-3"


def test_past_decisions_remain_queryable_by_finding(report):
    f1001 = [
        entry
        for entry in report["audit_trail"]
        if entry["finding_id"] == "F-1001"
    ]
    decisions = [entry["decision"] for entry in f1001]
    assert Decision.REGISTERED.value in decisions
    assert Decision.MOVED.value in decisions
    sequences = [entry["sequence"] for entry in report["audit_trail"]]
    assert sequences == sorted(sequences)


def test_text_report_renders_responsibility_records(report):
    text = render_text_report(report)
    assert "owner_record=OWN-PLAT-2" in text
    assert "Credential Event Replay Report" in text


def test_cli_writes_json_report(tmp_path, case_data):
    report_path = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "detect_secrets.incident",
            str(CASE_PATH),
            "--report",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0
    written = json.loads(report_path.read_text())
    assert written["summary"]["events_replayed"] == 14
    assert len(written["audit_trail"]) == 14


def test_replay_is_deterministic(case_data):
    first = replay_case(case_data)
    second = replay_case(case_data)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_as_of_recomputes_review_state_at_a_historical_point(case_data):
    historical = replay_case(case_data, as_of="2026-06-15T00:00:00")
    current = replay_case(case_data)

    def refunds_occurrence(report):
        return next(
            item
            for item in report["findings"]
            if item["path"] == "src/payments/refunds.py"
        )

    assert historical["generated_at"] == "2026-06-15T00:00:00"
    assert refunds_occurrence(historical)["active_exemption_id"] == "EX-502"
    assert refunds_occurrence(current)["state"] == ReviewState.SUPPRESSED.value

    moved_now = next(
        item
        for item in current["findings"]
        if item["path"] == "src/platform/billing/charges.py"
    )
    assert moved_now["state"] == ReviewState.OVERDUE.value
    assert moved_now["active_exemption_id"] is None
