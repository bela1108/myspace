"""Tests for time-limited exemption coverage rules."""
import pytest

from detect_secrets.incident.enums import ExemptionStatus
from detect_secrets.incident.exceptions import InvalidEventError
from detect_secrets.incident.exemptions import ExemptionRegistry
from detect_secrets.incident.models import Exemption


def _exemption(exemption_id="EX-1", finding_id="F-1", path="src/a.py",
               granted_at="2026-02-01T00:00:00", expires_at="2026-03-01T00:00:00",
               revoked_at=None):
    return Exemption(
        exemption_id=exemption_id,
        finding_id=finding_id,
        path=path,
        granted_at=granted_at,
        expires_at=expires_at,
        revoked_at=revoked_at,
    )


def test_active_exemption_allows_suppression():
    registry = ExemptionRegistry([_exemption()])
    decision = registry.evaluate("F-1", "src/a.py", "2026-02-10T00:00:00", "EX-1")
    assert decision.allowed is True
    assert decision.status == ExemptionStatus.ACTIVE


def test_path_mismatch_is_rejected():
    registry = ExemptionRegistry([_exemption()])
    decision = registry.evaluate("F-1", "src/moved.py", "2026-02-10T00:00:00", "EX-1")
    assert decision.allowed is False
    assert "bound to src/a.py" in decision.reason


def test_expired_exemption_is_rejected():
    registry = ExemptionRegistry([_exemption()])
    decision = registry.evaluate("F-1", "src/a.py", "2026-03-02T00:00:00", "EX-1")
    assert decision.allowed is False
    assert decision.status == ExemptionStatus.EXPIRED


def test_revoked_exemption_is_rejected():
    registry = ExemptionRegistry([_exemption(revoked_at="2026-02-15T00:00:00")])
    decision = registry.evaluate("F-1", "src/a.py", "2026-02-20T00:00:00", "EX-1")
    assert decision.allowed is False
    assert decision.status == ExemptionStatus.REVOKED


def test_exemption_bound_to_other_finding_is_rejected():
    registry = ExemptionRegistry([_exemption(finding_id="F-OTHER")])
    decision = registry.evaluate("F-1", "src/a.py", "2026-02-10T00:00:00", "EX-1")
    assert decision.allowed is False
    assert "another finding" in decision.reason


def test_auto_pick_only_considers_path_bound_exemptions():
    registry = ExemptionRegistry(
        [
            _exemption("EX-1", path="src/a.py", expires_at="2026-03-01T00:00:00"),
            _exemption("EX-2", path="src/b.py", expires_at="2026-12-31T00:00:00"),
        ],
    )
    decision = registry.evaluate("F-1", "src/a.py", "2026-02-10T00:00:00")
    assert decision.allowed is True
    assert decision.exemption_id == "EX-1"


def test_unknown_exemption_id_raises():
    registry = ExemptionRegistry([_exemption()])
    with pytest.raises(InvalidEventError):
        registry.evaluate("F-1", "src/a.py", "2026-02-10T00:00:00", "NOPE")


def test_duplicate_exemption_id_rejected():
    with pytest.raises(InvalidEventError):
        ExemptionRegistry([_exemption("DUP"), _exemption("DUP")])


def test_next_expiry_tracks_live_exemption_only():
    registry = ExemptionRegistry(
        [_exemption("EX-1", expires_at="2026-03-01T00:00:00")],
    )
    assert registry.next_expiry("F-1", "src/a.py", "2026-02-01T00:00:00") == \
        "2026-03-01T00:00:00"
    assert registry.next_expiry("F-1", "src/a.py", "2026-04-01T00:00:00") is None
