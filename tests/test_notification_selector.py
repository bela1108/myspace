"""Tests for post-match notification compression and accountability decisions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.matching import (
    Event,
    EventLogSource,
    NotificationSelector,
    SigmaMatcher,
    SigmaMatch,
    compare_selections,
    event_fingerprint,
)
from sigma.rule.rule import SigmaRule

EVENT_TIME = datetime(2026, 11, 27, 2, 0, tzinfo=timezone.utc)


def make_event(*, marker: str = "shared") -> Event:
    return Event(
        timestamp=EVENT_TIME,
        logsource=EventLogSource(category="notification_test", product="fake"),
        data={"marker": marker, "command": "original-secret-dump"},
        raw="original raw evidence",
    )


def yaml_list(values: tuple[str, ...] | list[str] | None) -> str:
    if not values:
        return " []"
    return "\n" + "\n".join(f"    - {value}" for value in values)


def make_match(
    name: str,
    *,
    level: str = "high",
    group: str | None = "identity-team",
    item: str | None = "ACCT-1",
    supersedes: tuple[str, ...] | list[str] | None = None,
    superseded_by: tuple[str, ...] | list[str] | None = None,
    covers: tuple[str, ...] | list[str] | None = None,
    event: Event | None = None,
) -> SigmaMatch:
    event = event or make_event()
    group_yaml = f"responsible_group: {group}" if group else ""
    item_yaml = (
        f"""responsibility:
    item: {item}"""
        if item
        else ""
    )
    yaml_text = f"""
title: {name.replace("_", " ").title()}
name: {name}
status: test
level: {level}
{group_yaml}
{item_yaml}
supersedes:{yaml_list(supersedes)}
superseded_by:{yaml_list(superseded_by)}
covers:{yaml_list(covers)}
logsource:
  category: notification_test
  product: fake
detection:
  selection:
    marker: shared
  condition: selection
"""
    rule = SigmaRule.from_yaml(yaml_text)
    return SigmaMatch(rule=rule, events=[event], timestamp=event.timestamp)


class TestNotificationSelector:
    def test_active_successor_compresses_group_and_keeps_accountability(self) -> None:
        event = make_event()
        matches = [
            make_match("old_high", level="high", event=event, superseded_by=["current_cover"]),
            make_match("old_medium", level="medium", event=event, superseded_by=["current_cover"]),
            make_match(
                "current_cover",
                level="critical",
                event=event,
                supersedes=["old_high", "old_medium"],
                covers=["old_high", "old_medium"],
            ),
        ]

        result = NotificationSelector().select(matches)

        assert len(result.notifications) == 1
        notification = result.notifications[0]
        assert notification.rule_name == "current_cover"
        assert notification.severity == "critical"
        assert notification.responsibility.group == "identity-team"
        assert notification.responsibility.item == "ACCT-1"
        assert set(notification.compressed_refs) == {"old_high", "old_medium"}
        assert any(reason.startswith("severity_order:") for reason in notification.reasons)
        assert any("accountability_basis" in reason for reason in notification.reasons)

    def test_offline_successor_revives_old_alert_with_accountability_reason(self) -> None:
        event = make_event()
        matches = [
            make_match(
                "old_high",
                level="high",
                event=event,
                superseded_by=["current_cover"],
            ),
            make_match("other_rule", level="medium", event=event),
        ]

        result = NotificationSelector(
            offline_rules=["current_cover"],
        ).select(matches)

        old_notification = next(
            item for item in result.notifications if item.rule_name == "old_high"
        )
        decision = next(item for item in result.decisions if item.rule_ref == "old_high")
        assert old_notification.responsibility.group == "identity-team"
        assert old_notification.responsibility.item == "ACCT-1"
        assert "责任组 identity-team" in old_notification.explain()
        assert "ACCT-1" in old_notification.explain()
        assert "declared_successor_offline:current_cover" in decision.blockers
        assert all(item.disposition == "notify" for item in result.decisions)

    def test_transition_reports_revived_alert(self) -> None:
        event = make_event()
        old = make_match("old_rule", event=event, superseded_by=["cover_rule"])
        cover = make_match(
            "cover_rule",
            level="critical",
            event=event,
            supersedes=["old_rule"],
            covers=["old_rule"],
        )
        before = NotificationSelector().select([old, cover])
        after = NotificationSelector(offline_rules=["cover_rule"]).select([old])

        transition = compare_selections(before, after)

        assert transition.revived_refs == ["old_rule"]
        assert "old_rule" in transition.explain()

    def test_stale_match_from_just_disabled_successor_cannot_compress(self) -> None:
        event = make_event()
        cover = make_match(
            "current_cover",
            level="critical",
            event=event,
            supersedes=["old_high"],
            covers=["old_high"],
        )
        old = make_match("old_high", level="high", event=event, superseded_by=["current_cover"])

        result = NotificationSelector(offline_rules=["current_cover"]).select([cover, old])

        refs = {item.rule_ref for item in result.notifications}
        assert refs == {"current_cover", "old_high"}
        stale_cover = next(
            item for item in result.notifications if item.rule_name == "current_cover"
        )
        assert stale_cover.active is False
        assert any(
            check.winner_ref == "current_cover"
            and "winner_rule_offline_or_disabled" in check.blockers
            for check in result.checks
        )

    def test_equal_severity_mutual_claims_are_retained(self) -> None:
        event = make_event()
        matches = [
            make_match("mutual_a", level="high", event=event, supersedes=["mutual_b"]),
            make_match("mutual_b", level="high", event=event, supersedes=["mutual_a"]),
        ]

        result = NotificationSelector().select(matches)

        assert len(result.notifications) == 2
        assert len(result.conflicts) == 1
        assert result.conflicts[0].kind == "mutual_suppression_claim"
        assert result.conflicts[0].resolution == "equal_severity_retained"
        assert result.compressed == []

    def test_higher_severity_resolves_mutual_claim_when_configured(self) -> None:
        event = make_event()
        matches = [
            make_match(
                "mutual_critical", level="critical", event=event, supersedes=["mutual_high"]
            ),
            make_match("mutual_high", level="high", event=event, supersedes=["mutual_critical"]),
        ]

        result = NotificationSelector().select(matches)

        assert [item.rule_name for item in result.notifications] == ["mutual_critical"]
        assert [item.rule_ref for item in result.compressed] == ["mutual_high"]
        conflict = result.conflicts[0]
        assert conflict.resolution == "higher_severity_selected"

    def test_responsibility_group_mismatch_blocks_compression(self) -> None:
        event = make_event()
        matches = [
            make_match(
                "winner_team_a",
                group="team-a",
                level="critical",
                event=event,
                supersedes=["loser_team_b"],
                covers=["loser_team_b"],
            ),
            make_match("loser_team_b", group="team-b", level="high", event=event),
        ]

        result = NotificationSelector().select(matches)

        assert len(result.notifications) == 2
        check = result.checks[0]
        assert check.allowed is False
        assert any("responsibility_group_mismatch:team-a!=team-b" in b for b in check.blockers)

    def test_severity_downgrade_blocks_compression(self) -> None:
        event = make_event()
        matches = [
            make_match(
                "lower_winner",
                level="medium",
                event=event,
                supersedes=["higher_loser"],
                covers=["higher_loser"],
            ),
            make_match("higher_loser", level="critical", event=event),
        ]

        result = NotificationSelector().select(matches)

        assert len(result.notifications) == 2
        assert any(
            "severity_downgrade_blocked" in blocker for blocker in result.decisions[0].blockers
        )

    def test_original_event_evidence_is_deep_copied(self) -> None:
        event = make_event()
        matches = [
            make_match("cover", level="critical", event=event, supersedes=["old"]),
            make_match("old", level="high", event=event, superseded_by=["cover"]),
        ]
        result = NotificationSelector().select(matches)
        notification = result.notifications[0]
        event.data["command"] = "mutated"

        assert len(notification.evidence) == 1
        assert notification.evidence[0].data["command"] == "original-secret-dump"
        assert notification.evidence[0].raw == "original raw evidence"
        assert notification.evidence[0].fingerprint == event_fingerprint(
            Event(
                timestamp=EVENT_TIME,
                logsource=EventLogSource(category="notification_test", product="fake"),
                data={"marker": "shared", "command": "original-secret-dump"},
                raw="original raw evidence",
            )
        )

    def test_different_events_are_grouped_separately(self) -> None:
        event_one = make_event(marker="one")
        event_two = make_event(marker="two")
        matches = [
            make_match("cover_one", event=event_one, supersedes=["old_one"]),
            make_match("old_one", event=event_one, superseded_by=["cover_one"]),
            make_match("cover_two", event=event_two, supersedes=["old_two"]),
            make_match("old_two", event=event_two, superseded_by=["cover_two"]),
        ]

        result = NotificationSelector(require_severity=False).select(matches)

        assert len(result.groups) == 2
        assert len(result.notifications) == 2
        assert {item.rule_name for item in result.notifications} == {
            "cover_one",
            "cover_two",
        }

    def test_result_is_json_serializable(self) -> None:
        event = make_event()
        matches = [
            make_match("cover", event=event, supersedes=["old"], covers=["old"]),
            make_match("old", event=event),
        ]

        payload = NotificationSelector().select(matches).to_dict()

        encoded = json.dumps(payload, ensure_ascii=False)
        assert "ACCT-1" in encoded
        assert payload["notification_count"] == 1


def test_actual_sigma_matcher_output_feeds_selector() -> None:
    rules = """
title: Integration Old
name: integration_old
status: test
level: high
responsible_group: integration-team
superseded_by: integration_cover
logsource:
  category: integration_notification
  product: fake
detection:
  selection:
    marker: integration
  condition: selection
---
title: Integration Cover
name: integration_cover
status: test
level: critical
responsible_group: integration-team
supersedes:
  - integration_old
covers:
  - integration_old
logsource:
  category: integration_notification
  product: fake
detection:
  selection:
    marker: integration
  condition: selection
"""
    event = Event(
        timestamp=EVENT_TIME,
        logsource=EventLogSource(category="integration_notification", product="fake"),
        data={"marker": "integration"},
    )
    collection = SigmaCollection.from_yaml(rules)
    with SigmaMatcher(collection) as matcher:
        matches = matcher.match(event)

    assert len(matches) == 2
    result = NotificationSelector().select(matches)
    assert [item.rule_name for item in result.notifications] == ["integration_cover"]


def test_demo_script_scenario_assertions_pass() -> None:
    demo_path = Path(__file__).resolve().parents[1] / "examples" / "notification_selector_demo.py"
    namespace: dict[str, object] = {
        "__name__": "notification_demo_test",
        "__file__": str(demo_path),
    }
    exec(compile(demo_path.read_text(encoding="utf-8"), str(demo_path), "exec"), namespace)
    assert callable(namespace["main"])
    assert namespace["main"]() == 0
