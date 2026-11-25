"""Tests for the deterministic event replay engine."""
import pytest

from detect_secrets.incident.enums import Decision
from detect_secrets.incident.enums import EventType
from detect_secrets.incident.enums import ReviewState
from detect_secrets.incident.exceptions import DuplicateEventError
from detect_secrets.incident.exceptions import EventOrderError
from detect_secrets.incident.exceptions import UnknownFindingError
from detect_secrets.incident.models import Event
from detect_secrets.incident.models import Exemption
from detect_secrets.incident.models import Finding
from detect_secrets.incident.models import OwnershipRule
from detect_secrets.incident.replay import ReplayEngine


def _finding():
    return Finding(
        finding_id="F-1",
        secret_type="AWS Access Key",
        hashed_secret="hash1234",
        initial_path="src/payments/a.py",
        line_number=9,
    )


def _rules():
    return [
        OwnershipRule("OWN-PAY", "src/payments", "payments-team",
                      "2026-01-01T00:00:00", "2026-06-01T00:00:00"),
        OwnershipRule("OWN-PLAT", "src/platform", "platform-team",
                      "2026-01-01T00:00:00"),
        OwnershipRule("OWN-PAY2", "src/payments", "payments-guild",
                      "2026-06-01T00:00:00"),
    ]


def _event(event_id, event_type, timestamp, **kwargs):
    return Event(
        event_id=event_id,
        event_type=EventType(event_type),
        timestamp=timestamp,
        **kwargs,
    )


def _engine(exemptions=None, sla=30):
    return ReplayEngine([_finding()], _rules(), exemptions or [], review_sla_days=sla)


def test_introduction_assigns_owner_and_sla_deadline():
    engine = _engine()
    engine.run(
        [
            _event(
                "E1", "finding_introduced", "2026-02-01T00:00:00",
                finding_id="F-1", to_path="src/payments/a.py",
            ),
        ],
    )
    occurrence = engine.occurrences["F-1"]["src/payments/a.py"]
    assert occurrence.team == "payments-team"
    assert occurrence.ownership_record_id == "OWN-PAY"
    assert occurrence.review_deadline == "2026-03-03T00:00:00"


def test_code_move_hands_off_to_new_owner_and_drops_exemption():
    exemption = Exemption(
        "EX-1", "F-1", "src/payments/a.py",
        "2026-02-02T00:00:00", "2026-12-31T00:00:00",
    )
    engine = _engine([exemption])
    engine.run(
        [
            _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                   finding_id="F-1", to_path="src/payments/a.py"),
            _event("E2", "exemption_granted", "2026-02-02T00:00:00",
                   finding_id="F-1", exemption_id="EX-1"),
            _event("E3", "code_moved", "2026-04-01T00:00:00",
                   finding_id="F-1", from_path="src/payments/a.py",
                   to_path="src/platform/a.py"),
        ],
    )
    assert "src/payments/a.py" not in engine.occurrences["F-1"]
    moved = engine.occurrences["F-1"]["src/platform/a.py"]
    assert moved.team == "platform-team"
    assert moved.ownership_record_id == "OWN-PLAT"
    assert moved.active_exemption_id is None
    move_entry = engine.audit_log.for_finding("F-1")[2]
    assert move_entry.decision == Decision.MOVED.value
    assert move_entry.ownership_record_id == "OWN-PLAT"


def test_stale_path_bound_exemption_cannot_close_moved_occurrence():
    exemption = Exemption(
        "EX-1", "F-1", "src/payments/a.py",
        "2026-02-02T00:00:00", "2026-12-31T00:00:00",
    )
    engine = _engine([exemption])
    engine.run(
        [
            _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                   finding_id="F-1", to_path="src/payments/a.py"),
            _event("E2", "code_moved", "2026-04-01T00:00:00",
                   finding_id="F-1", from_path="src/payments/a.py",
                   to_path="src/platform/a.py"),
            _event("E3", "suppress", "2026-04-02T00:00:00",
                   finding_id="F-1", from_path="src/platform/a.py",
                   exemption_id="EX-1"),
        ],
    )
    occurrence = engine.occurrences["F-1"]["src/platform/a.py"]
    assert occurrence.state != ReviewState.SUPPRESSED
    last = engine.audit_log.entries()[-1]
    assert last.decision == Decision.SUPPRESSION_REJECTED.value
    assert "bound to src/payments/a.py" in last.reason


def test_fork_creates_independent_occurrences_that_cannot_share_exemption():
    exemption = Exemption(
        "EX-1", "F-1", "src/payments/a.py",
        "2026-02-02T00:00:00", "2026-12-31T00:00:00",
    )
    engine = _engine([exemption])
    engine.run(
        [
            _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                   finding_id="F-1", to_path="src/payments/a.py"),
            _event("E2", "exemption_granted", "2026-02-02T00:00:00",
                   finding_id="F-1", exemption_id="EX-1"),
            _event("E3", "suppress", "2026-02-03T00:00:00",
                   finding_id="F-1", from_path="src/payments/a.py",
                   exemption_id="EX-1"),
            _event("E4", "finding_forked", "2026-05-01T00:00:00",
                   finding_id="F-1", from_path="src/payments/a.py",
                   to_path="src/platform/copy.py"),
            _event("E5", "suppress", "2026-05-02T00:00:00",
                   finding_id="F-1", from_path="src/platform/copy.py",
                   exemption_id="EX-1"),
        ],
    )
    original = engine.occurrences["F-1"]["src/payments/a.py"]
    sibling = engine.occurrences["F-1"]["src/platform/copy.py"]
    assert original.state == ReviewState.SUPPRESSED
    assert sibling.state != ReviewState.SUPPRESSED
    assert sibling.forked_from == "src/payments/a.py"
    assert engine.audit_log.entries()[-1].decision == \
        Decision.SUPPRESSION_REJECTED.value


def test_revoked_exemption_reopens_suppressed_occurrence():
    exemption = Exemption(
        "EX-1", "F-1", "src/payments/a.py",
        "2026-02-02T00:00:00", "2026-12-31T00:00:00",
    )
    engine = _engine([exemption])
    engine.run(
        [
            _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                   finding_id="F-1", to_path="src/payments/a.py"),
            _event("E2", "suppress", "2026-02-03T00:00:00",
                   finding_id="F-1", from_path="src/payments/a.py",
                   exemption_id="EX-1"),
            _event("E3", "exemption_revoked", "2026-03-01T00:00:00",
                   finding_id="F-1", exemption_id="EX-1"),
        ],
    )
    occurrence = engine.occurrences["F-1"]["src/payments/a.py"]
    assert occurrence.state != ReviewState.SUPPRESSED
    assert occurrence.active_exemption_id is None
    assert engine.audit_log.entries()[-1].decision == \
        Decision.EXEMPTION_REVOKED.value


def test_ownership_change_reassigns_team_but_keeps_deadline():
    engine = _engine()
    engine.run(
        [
            _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                   finding_id="F-1", to_path="src/payments/a.py"),
            _event("E2", "ownership_changed", "2026-06-02T00:00:00",
                   finding_id="F-1", from_path="src/payments/a.py"),
        ],
    )
    occurrence = engine.occurrences["F-1"]["src/payments/a.py"]
    assert occurrence.team == "payments-guild"
    assert occurrence.ownership_record_id == "OWN-PAY2"
    assert occurrence.review_deadline == "2026-03-03T00:00:00"


def test_audit_trail_is_queryable_per_finding_and_append_only():
    engine = _engine()
    engine.run(
        [
            _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                   finding_id="F-1", to_path="src/payments/a.py"),
        ],
    )
    entries = engine.audit_log.for_finding("F-1")
    assert len(entries) == 1
    assert entries[0].sequence == 0
    assert entries[0].ownership_record_id == "OWN-PAY"
    snapshot = engine.audit_log.to_dicts()
    engine.run([])
    assert engine.audit_log.to_dicts() == snapshot


def test_duplicate_event_id_rejected():
    engine = _engine()
    with pytest.raises(DuplicateEventError):
        engine.run(
            [
                _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                       finding_id="F-1", to_path="src/payments/a.py"),
                _event("E1", "ownership_changed", "2026-02-02T00:00:00",
                       finding_id="F-1", from_path="src/payments/a.py"),
            ],
        )


def test_out_of_order_timestamps_rejected():
    engine = _engine()
    engine.run(
        [
            _event("E1", "finding_introduced", "2026-03-01T00:00:00",
                   finding_id="F-1", to_path="src/payments/a.py"),
        ],
    )
    # Reusing the engine with an earlier event breaks monotonic time and
    # must be rejected rather than silently rewriting history.
    with pytest.raises(EventOrderError):
        engine.run(
            [
                _event("E2", "ownership_changed", "2026-02-01T00:00:00",
                       finding_id="F-1", from_path="src/payments/a.py"),
            ],
        )


def test_unknown_finding_reference_rejected():
    engine = _engine()
    with pytest.raises(UnknownFindingError):
        engine.run(
            [
                _event("E1", "finding_introduced", "2026-02-01T00:00:00",
                       finding_id="GHOST", to_path="src/payments/a.py"),
            ],
        )
