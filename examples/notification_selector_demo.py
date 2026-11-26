#!/usr/bin/env python3
"""Finite fake-event demo for the post-match notification selector.

Run from the repository root with the project environment::

    python examples/notification_selector_demo.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sigma.collection import SigmaCollection  # noqa: E402
from sigma.matching import (  # noqa: E402
    Event,
    EventLogSource,
    NotificationSelector,
    SigmaMatcher,
    compare_selections,
)

RULE_DOCS = [
    """
title: LSASS Sensitive Handle
name: lsass_sensitive_access
status: test
level: high
responsible_group: identity-defense
responsibility:
  item: ACCT-CRED-001
  owner: identity-oncall
superseded_by:
  - credential_access_cover
basis:
  - lsass_handle
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|contains: lsass.exe
    GrantedAccess: "0x1FFFFF"
  condition: selection
""",
    """
title: ProcDump Credential Dump
name: procdump_credential_dump
status: test
level: critical
responsible_group: identity-defense
responsibility:
  item: ACCT-CRED-001
  owner: identity-oncall
superseded_by:
  - credential_access_cover
basis:
  - command_line
logsource:
  category: process_access
  product: windows
detection:
  procdump:
    CommandLine|contains: procdump
  lsass_cli:
    CommandLine|contains: lsass
  condition: procdump and lsass_cli
""",
    """
title: DbgCore Call Trace Dump
name: dbgcore_call_trace_dump
status: test
level: high
responsible_group: identity-defense
responsibility:
  item: ACCT-CRED-001
  owner: identity-oncall
superseded_by:
  - credential_access_cover
basis:
  - call_trace
logsource:
  category: process_access
  product: windows
detection:
  dbgcore:
    CallTrace|contains: dbgcore
  rundll:
    SourceImage|contains: rundll32
  condition: dbgcore and rundll
""",
    """
title: Credential Access Coverage
name: credential_access_cover
status: test
level: critical
responsibility:
  item: ACCT-CRED-001
  group: identity-defense
  owner: identity-oncall
supersedes:
  - lsass_sensitive_access
  - procdump_credential_dump
  - dbgcore_call_trace_dump
covers:
  - lsass_sensitive_access
  - procdump_credential_dump
  - dbgcore_call_trace_dump
covers_basis:
  - lsass_handle
  - command_line
  - call_trace
logsource:
  category: process_access
  product: windows
detection:
  lsass:
    TargetImage|contains: lsass
  procdump:
    CommandLine|contains: procdump
  dbg:
    CallTrace|contains: dbgcore
  condition: lsass or procdump or dbg
""",
]

ALL_RULES_YAML = "\n---\n".join(RULE_DOCS)
LEGACY_RULES_YAML = "\n---\n".join(RULE_DOCS[:3])

MUTUAL_RULES_YAML = """
title: Mutual Alpha
name: mutual_alpha
status: test
level: high
responsible_group: mutual-demo-team
supersedes:
  - mutual_beta
logsource:
  category: notification_demo
  product: fake
detection:
  selection:
    Scenario: mutual_claim_demo
  condition: selection
---
title: Mutual Beta
name: mutual_beta
status: test
level: high
responsible_group: mutual-demo-team
supersedes:
  - mutual_alpha
logsource:
  category: notification_demo
  product: fake
detection:
  selection:
    Scenario: mutual_claim_demo
  condition: selection
"""


def fake_lsass_event() -> Event:
    return Event(
        timestamp=datetime(2026, 11, 27, 2, 0, tzinfo=timezone.utc),
        logsource=EventLogSource(category="process_access", product="windows"),
        data={
            "EventID": 10,
            "SourceImage": r"C:\Windows\System32\rundll32.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1FFFFF",
            "CallTrace": r"C:\Windows\System32\dbgcore.dll!MiniDumpWriteDump",
            "CommandLine": (
                r"procdump.exe -accepteula -ma lsass.exe " r"C:\Windows\Temp\lsass.dmp"
            ),
        },
        raw="fake sysmon event: procdump wrote a full lsass dump",
    )


def fake_mutual_event() -> Event:
    return Event(
        timestamp=datetime(2026, 11, 27, 2, 5, tzinfo=timezone.utc),
        logsource=EventLogSource(category="notification_demo", product="fake"),
        data={"Scenario": "mutual_claim_demo", "EventID": "fake-2"},
        raw="fake mutual suppression event",
    )


def match_yaml(yaml_text: str, event: Event):
    collection = SigmaCollection.from_yaml(yaml_text)
    with SigmaMatcher(collection) as matcher:
        return matcher.match(event)


def main() -> int:
    event = fake_lsass_event()
    all_matches = match_yaml(ALL_RULES_YAML, event)
    print(f"[1] 同一假事件命中 {len(all_matches)} 条 Sigma 规则：")
    for match in all_matches:
        print(f"    - {match.rule.name} ({match.rule.level})")

    past = NotificationSelector().select(all_matches)
    past_notification = past.notifications[0]
    print("\n[2] 接替规则在线时，过去的排重通知：")
    print(past_notification.explain())
    assert len(all_matches) == 4
    assert len(past.notifications) == 1
    assert past_notification.rule_name == "credential_access_cover"
    assert set(past_notification.compressed_refs) == {
        "lsass_sensitive_access",
        "procdump_credential_dump",
        "dbgcore_call_trace_dump",
    }

    original_command_line = event.data["CommandLine"]
    event.data["CommandLine"] = "tampered after selection"
    preserved = [
        evidence
        for notification in past.notifications
        for evidence in notification.evidence
        if original_command_line in str(evidence.data.get("CommandLine", ""))
    ]
    assert preserved, "original event evidence was not preserved"
    event.data["CommandLine"] = original_command_line
    print("\n[3] 选择后篡改 Event.data，快照中的原始 CommandLine 仍保留。")

    legacy_matches = match_yaml(LEGACY_RULES_YAML, event)
    revived = NotificationSelector(
        offline_rules=["credential_access_cover"],
    ).select(legacy_matches)
    transition = compare_selections(past, revived)
    old_alert = next(
        item for item in revived.notifications if item.rule_name == "lsass_sensitive_access"
    )
    old_decision = next(
        item for item in revived.decisions if item.rule_ref == "lsass_sensitive_access"
    )
    print("\n[4] 接替规则 credential_access_cover 下线后，旧告警被保留：")
    print(transition.explain())
    print(old_alert.explain())
    print("    决策阻断项：" + "; ".join(old_decision.blockers))
    assert old_alert.responsibility.group == "identity-defense"
    assert old_alert.responsibility.item == "ACCT-CRED-001"
    assert any(
        blocker == "declared_successor_offline:credential_access_cover"
        for blocker in old_decision.blockers
    )
    assert "lsass_sensitive_access" in transition.revived_refs

    mutual_matches = match_yaml(MUTUAL_RULES_YAML, fake_mutual_event())
    mutual_result = NotificationSelector().select(mutual_matches)
    print("\n[5] 同等级规则互相声称压制对方时，安全保留两条通知：")
    print(mutual_result.explain())
    assert len(mutual_result.notifications) == 2
    assert mutual_result.conflicts[0].kind == "mutual_suppression_claim"

    print("\nDemo assertions passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
