"""Tests for offline release-order verification."""

from datetime import datetime, timedelta, timezone

import pytest

from sigma.matching import (
    Event,
    EventLogSource,
    MarkerEvent,
    ReleaseOrder,
    ReleaseOrderVerifier,
    SignalStatus,
    verify_release_order,
)


OLD_RULES = """
title: Old Login
name: login_old
status: test
logsource:
    category: auth
    product: test
detection:
    selection:
        event: login
    condition: selection
---
title: Old Access
name: access_old
status: test
logsource:
    category: auth
    product: test
detection:
    selection:
        event: access
    condition: selection
---
title: Demo Security Signal
name: demo_signal
status: test
correlation:
    type: temporal_ordered
    rules:
        - login_old
        - access_old
    group-by:
        - user
    timespan: 5m
"""

NEW_RULES = """
title: New Login
name: login_new
status: test
logsource:
    category: auth
    product: test
detection:
    selection:
        event: login
    condition: selection
---
title: New Access
name: access_new
status: test
logsource:
    category: auth
    product: test
detection:
    selection:
        event: access
    condition: selection
---
title: Demo Security Signal
name: demo_signal
status: test
correlation:
    type: temporal_ordered
    rules:
        - login_new
        - access_new
    group-by:
        - user
    timespan: 5m
"""

EFFECTIVE_AT = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
LOGSOURCE = EventLogSource(category="auth", product="test")


def marker_events() -> list[MarkerEvent]:
    return [
        MarkerEvent(
            "login_marker",
            Event(
                timestamp=EFFECTIVE_AT + timedelta(minutes=1),
                logsource=LOGSOURCE,
                data={"event": "login", "user": "alice"},
            ),
        ),
        MarkerEvent(
            "access_marker",
            Event(
                timestamp=EFFECTIVE_AT + timedelta(minutes=1, seconds=30),
                logsource=LOGSOURCE,
                data={"event": "access", "user": "alice"},
            ),
        ),
    ]


def verifier(**kwargs) -> ReleaseOrderVerifier:
    return ReleaseOrderVerifier(
        OLD_RULES, NEW_RULES, EFFECTIVE_AT, marker_events(), **kwargs
    )


class TestBaselines:
    def test_both_versions_match_independently(self):
        report = verifier().verify()
        assert report.old_baseline.compiled
        assert report.new_baseline.compiled
        for stage in (report.old_baseline, report.new_baseline):
            signal = stage.signal("demo_signal")
            assert signal.status is SignalStatus.COMPLETE
            assert signal.fired
            assert signal.matched_markers == ("access_marker", "login_marker")


class TestSwitchOrders:
    def test_base_first_has_no_gap(self):
        report = verifier().verify()
        assessment = report.order(ReleaseOrder.BASE_FIRST)
        assert all(
            stage.signal("demo_signal").status is SignalStatus.COMPLETE
            for stage in assessment.stages
        )
        assert assessment.first_loss["demo_signal"] is None

    def test_correlation_first_loses_signal_until_bases_arrive(self):
        report = verifier().verify()
        assessment = report.order(ReleaseOrder.CORRELATION_FIRST)
        first, second, final = assessment.stages

        assert first.start_minute == 0
        assert first.end_minute == 30
        signal = first.signal("demo_signal")
        assert signal.status is SignalStatus.INCOMPLETE
        assert signal.missing_rules == ("access_new", "login_new")
        # Compilation is not the problem: the stage compiles, but the dependency is absent.
        assert first.compiled
        assert signal.compiled

        assert second.signal("demo_signal").status is SignalStatus.COMPLETE
        assert final.signal("demo_signal").status is SignalStatus.COMPLETE
        assert assessment.first_loss["demo_signal"] == 0

    def test_final_rules_are_identical_in_both_orders(self):
        report = verifier().verify()
        assert report.final_rules_identical
        for assessment in report.orders.values():
            assert assessment.final_rules_identical
            final = assessment.stages[-1]
            assert final.start_minute == report.rollout_minutes
            assert final.signal("demo_signal").status is SignalStatus.COMPLETE
            assert "login_old" not in final.rule_names
            assert "access_old" not in final.rule_names

    def test_dependency_check_is_per_stage(self):
        report = verifier().verify()
        first = report.order(ReleaseOrder.CORRELATION_FIRST).stages[0]
        dependency = next(d for d in first.dependencies if d.correlation == "demo_signal")
        assert dependency.required_rules == ("login_new", "access_new")
        assert dependency.missing_rules == ("access_new", "login_new")
        assert not dependency.complete

    def test_custom_phase_boundary(self):
        report = verifier(rollout_minutes=90, phase_minutes=45).verify()
        first = report.order(ReleaseOrder.CORRELATION_FIRST).stages[0]
        assert (first.start_minute, first.end_minute) == (0, 45)
        assert report.order(ReleaseOrder.CORRELATION_FIRST).first_loss["demo_signal"] == 0


class TestRendering:
    def test_table_marks_gap_and_first_loss(self):
        table = verifier().render()
        assert "base_first" in table
        assert "correlation_first" in table
        assert "GAP" in table
        assert "first loss: demo_signal at minute 0" in table
        assert "final rules identical to new collection: yes" in table

    def test_non_compact_table_has_one_row_per_minute(self):
        report = verifier(rollout_minutes=4, phase_minutes=2).verify()
        table = report.to_table(compact=False)
        corr_first = table.split("correlation_first", 1)[1]
        assert "00:00" in corr_first
        assert "00:01" in corr_first
        assert "00:02" in corr_first
        assert "00:03" in corr_first

    def test_minute_rows(self):
        report = verifier(rollout_minutes=4, phase_minutes=2).verify()
        rows = report.minute_rows()
        assert len(rows) == 8
        first = next(
            row
            for row in rows
            if row["order"] is ReleaseOrder.CORRELATION_FIRST and row["minute"] == 0
        )
        assert first["demo_signal"] is SignalStatus.INCOMPLETE


class TestInputs:
    def test_plain_events_get_generated_names(self):
        events = [marker.event for marker in marker_events()]
        report = ReleaseOrderVerifier(OLD_RULES, NEW_RULES, EFFECTIVE_AT, events).verify()
        assert report.order(ReleaseOrder.BASE_FIRST).first_loss["demo_signal"] is None

    def test_signal_filter(self):
        report = verifier(signal_names=["demo_signal"]).verify()
        assert report.signals == ("demo_signal",)

    def test_convenience_function(self):
        report = verify_release_order(
            OLD_RULES, NEW_RULES, EFFECTIVE_AT, marker_events()
        )
        assert report.order(ReleaseOrder.BASE_FIRST).first_loss["demo_signal"] is None

    def test_invalid_phase(self):
        with pytest.raises(ValueError):
            verifier(rollout_minutes=10, phase_minutes=10)

    def test_no_markers_rejected(self):
        with pytest.raises(ValueError):
            ReleaseOrderVerifier(OLD_RULES, NEW_RULES, EFFECTIVE_AT, [])
