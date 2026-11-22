from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigma.audit.handover import (
    BranchState,
    HandoverConfig,
    HandoverState,
    ProcessingBranch,
    RuleSelector,
    Shift,
    audit_from_config,
    audit_handover,
    rule_identity,
)
from sigma.collection import SigmaCollection
from sigma.exceptions import (
    SigmaHandoverConfigurationError,
    SigmaHandoverIdentityError,
    SigmaRuleLocation,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

TZ = timezone(timedelta(hours=8))
SHIFT_START = datetime(2026, 11, 23, 0, 0, tzinfo=TZ)
SHIFT_END = datetime(2026, 11, 23, 8, 0, tzinfo=TZ)


def make_rule(
    rule_id: str | None,
    event_id: int,
    name: str = "shared-name",
    title: str = "Shared Title",
    field: str = "EventID",
    category: str | None = None,
) -> SigmaRule:
    logsource = {"product": "windows"}
    if category is not None:
        logsource["category"] = category
    data = {
        "title": title,
        "name": name,
        "logsource": logsource,
        "detection": {
            "selection": {field: event_id},
            "condition": "selection",
        },
    }
    if rule_id is not None:
        data["id"] = rule_id
    return SigmaRule.from_dict(data)


def make_shift(
    on_duty: tuple[str, ...],
    duties: tuple[dict, ...],
    substitutes: tuple[dict, ...] = (),
) -> Shift:
    return Shift.from_dict(
        {
            "shift_id": "shift-1",
            "starts_at": SHIFT_START.isoformat(),
            "ends_at": SHIFT_END.isoformat(),
            "on_duty": list(on_duty),
            "duties": list(duties),
            "substitutes": list(substitutes),
        }
    )


def duty(
    duty_id: str,
    role: str,
    rule_ids: tuple[str, ...],
    notify: bool = True,
    handle: bool = True,
    release_basis: bool = True,
) -> dict:
    return {
        "id": duty_id,
        "role": role,
        "selector": {"rule_ids": list(rule_ids)},
        "notify": notify,
        "handle": handle,
        "release_basis": release_basis,
    }


def substitute(
    approval_id: str,
    for_role: str,
    substitute_role: str,
    rule_ids: tuple[str, ...],
    valid_from: datetime,
    valid_until: datetime,
    notify: bool = True,
    handle: bool = True,
    approved_by: str = "soc-lead",
) -> dict:
    return {
        "id": approval_id,
        "for_role": for_role,
        "substitute": substitute_role,
        "selector": {"rule_ids": list(rule_ids)},
        "approved_by": approved_by,
        "valid_from": valid_from.isoformat(),
        "valid_until": valid_until.isoformat(),
        "notify": notify,
        "handle": handle,
    }


def test_same_name_rules_do_not_merge_permissions() -> None:
    primary = make_rule("11111111-1111-4111-8111-111111111111", 1)
    shadow = make_rule("22222222-2222-4222-8222-222222222222", 2)
    shift = make_shift(
        ("responder", "observer"),
        (
            duty("primary", "responder", (str(primary.id),)),
            duty("shadow", "observer", (str(shadow.id),)),
        ),
    )
    report = audit_handover([primary, shadow], shift)
    by_id = {audit.identity.rule_id: audit for audit in report.audits}

    assert len(report.audits) == 2
    assert report.duplicate_names == ("shared-name",)
    assert report.duplicate_titles == ("Shared Title",)
    primary_audit = by_id[str(primary.id)]
    shadow_audit = by_id[str(shadow.id)]
    assert primary_audit.identity.key != shadow_audit.identity.key
    assert {handler.role for handler in primary_audit.handlers} == {"responder"}
    assert {handler.role for handler in shadow_audit.handlers} == {"observer"}
    assert all(handler.role != "observer" for handler in primary_audit.handlers)
    assert all(handler.role != "responder" for handler in shadow_audit.handlers)
    assert primary_audit.state is HandoverState.ACTIONABLE
    assert shadow_audit.state is HandoverState.ACTIONABLE


def test_rules_without_ids_and_same_name_have_distinct_identities() -> None:
    first = make_rule(None, 1)
    second = make_rule(None, 2)
    first_identity = rule_identity(first)
    shift = make_shift(
        ("responder",),
        (
            {
                "id": "first",
                "role": "responder",
                "selector": {"rule_keys": [first_identity.key]},
                "handle": True,
            },
        ),
    )
    report = audit_handover([first, second], shift)
    by_key = {audit.identity.key: audit for audit in report.audits}

    assert first_identity.key != rule_identity(second).key
    assert by_key[first_identity.key].state is HandoverState.ACTIONABLE
    second_key = rule_identity(second).key
    assert by_key[second_key].state is HandoverState.NO_SUBSTITUTE
    assert by_key[second_key].can_handle is False


def test_approved_substitute_allows_handling() -> None:
    rule = make_rule("11111111-1111-4111-8111-111111111111", 1)
    shift = make_shift(
        ("observer",),
        (duty("legacy", "legacy-tier2", (str(rule.id),)),),
        (
            substitute(
                "sub-1",
                "legacy-tier2",
                "observer",
                (str(rule.id),),
                SHIFT_START - timedelta(hours=2),
                SHIFT_END + timedelta(hours=2),
            ),
        ),
    )
    report = audit_handover([rule], shift)
    audit = report.audits[0]

    assert audit.state is HandoverState.ACTIONABLE
    assert audit.can_handle is True
    assert audit.no_substitute is False
    assert [recipient.role for recipient in audit.recipients] == ["observer"]
    assert audit.recipients[0].via == ("substitute",)
    assert audit.recipients[0].source_roles == ("legacy-tier2",)
    assert audit.chain.release_basis is True


@pytest.mark.parametrize(
    ("approval_kwargs", "expected_reason"),
    (
        (
            {
                "valid_from": SHIFT_START - timedelta(hours=1),
                "valid_until": SHIFT_START + timedelta(hours=1),
            },
            "approval_does_not_cover_full_shift",
        ),
        (
            {
                "valid_from": SHIFT_START - timedelta(hours=1),
                "valid_until": SHIFT_END + timedelta(hours=1),
                "substitute_role": "off-duty",
            },
            "substitute_not_on_duty",
        ),
        (
            {
                "valid_from": SHIFT_START - timedelta(hours=1),
                "valid_until": SHIFT_END + timedelta(hours=1),
                "handle": False,
            },
            "approved_substitute_lacks_required_authority",
        ),
    ),
)
def test_ineffective_substitute_leaves_handler_gap(
    approval_kwargs: dict, expected_reason: str
) -> None:
    rule = make_rule("11111111-1111-4111-8111-111111111111", 1)
    options = dict(approval_kwargs)
    substitute_role = options.pop("substitute_role", "observer")
    approval = substitute(
        "sub-1",
        "legacy-tier2",
        substitute_role,
        (str(rule.id),),
        options.pop("valid_from"),
        options.pop("valid_until"),
        handle=options.pop("handle", True),
    )
    shift = make_shift(
        ("observer",),
        (duty("legacy", "legacy-tier2", (str(rule.id),)),),
        (approval,),
    )
    report = audit_handover([rule], shift)
    audit = report.audits[0]

    assert audit.state is HandoverState.NO_SUBSTITUTE
    assert audit.no_substitute is True
    assert audit.can_notify is False
    assert expected_reason in audit.uncovered_duties[0].reason


def test_notifiable_state_when_only_notification_is_required() -> None:
    rule = make_rule("11111111-1111-4111-8111-111111111111", 1)
    shift = make_shift(
        ("observer",),
        (duty("observe", "observer", (str(rule.id),), handle=False),),
    )
    report = audit_handover([rule], shift)
    audit = report.audits[0]

    assert audit.state is HandoverState.NOTIFIABLE
    assert audit.can_notify is True
    assert audit.can_handle is False
    assert audit.no_substitute is False
    assert audit.chain.reference_only is True
    assert audit.chain.release_basis is False


def test_no_substitute_state_without_approved_replacement() -> None:
    rule = make_rule("11111111-1111-4111-8111-111111111111", 1)
    shift = make_shift(
        ("responder",),
        (duty("specialist", "weekend-specialist", (str(rule.id),)),),
    )
    report = audit_handover([rule], shift)
    audit = report.audits[0]

    assert audit.state is HandoverState.NO_SUBSTITUTE
    assert audit.can_notify is False
    assert audit.can_handle is False
    assert audit.no_substitute is True
    assert audit.uncovered_duties[0].reason == "role_off_duty_no_approved_substitute"
    assert audit.recipients == ()
    assert audit.chain.reference_only is False


def pipeline() -> ProcessingPipeline:
    yaml_text = "\n".join(
        [
            "name: test-pipeline",
            "transformations:",
            "  - id: legacy-edr-enrich",
            "    type: field_name_mapping",
            "    mapping:",
            "      ParentImage: process.parent.executable",
        ]
    )
    return ProcessingPipeline.from_yaml(yaml_text)


def test_disabled_branch_suspends_handling_and_requires_countersign() -> None:
    rule = make_rule(
        "33333333-3333-4333-8333-333333333333",
        1,
        field="ParentImage",
        category="process_creation",
    )
    shift = make_shift(
        ("responder",),
        (duty("respond", "responder", (str(rule.id),)),),
    )
    branch = ProcessingBranch.from_dict(
        {
            "id": "legacy-edr",
            "processing_items": ["legacy-edr-enrich"],
            "state": "disabled",
            "historical_role": "soc-tier2-legacy",
            "reason": "connector maintenance",
        }
    )
    report = audit_handover([rule], shift, pipeline(), (branch,))
    audit = report.audits[0]

    assert audit.processing.applied_item_ids == ("legacy-edr-enrich",)
    assert audit.processing.applied_branches == ("legacy-edr",)
    assert audit.processing.disabled_branches == ("legacy-edr",)
    assert audit.processing.countersign_roles == ("soc-tier2-legacy",)
    assert audit.processing.field_mappings == {"ParentImage": ("process.parent.executable",)}
    assert audit.state is HandoverState.NOTIFIABLE
    assert audit.can_notify is True
    assert audit.can_handle is False
    assert audit.chain.reference_only is True
    assert audit.chain.release_basis is False
    assert audit.chain.countersign_roles == ("soc-tier2-legacy",)
    assert any(
        "disabled_branch_requires_countersign" in blocker
        for blocker in audit.chain.release_blockers
    )
    assert report.reference_only_chains == (audit.chain,)


def test_branch_only_counts_when_rule_was_really_mapped() -> None:
    mapped = make_rule(
        "33333333-3333-4333-8333-333333333333",
        1,
        field="ParentImage",
        category="process_creation",
    )
    untouched = make_rule(
        "44444444-4444-4444-8444-444444444444",
        2,
        field="CommandLine",
        category="process_creation",
    )
    shift = make_shift(
        ("responder",),
        (
            duty("mapped", "responder", (str(mapped.id),)),
            duty("untouched", "responder", (str(untouched.id),)),
        ),
    )
    branch = ProcessingBranch.from_dict(
        {
            "id": "legacy-edr",
            "processing_items": ["legacy-edr-enrich"],
            "state": "disabled",
            "historical_role": "soc-tier2-legacy",
        }
    )
    report = audit_handover([mapped, untouched], shift, pipeline(), (branch,))
    by_id = {audit.identity.rule_id: audit for audit in report.audits}

    assert by_id[str(mapped.id)].processing.disabled_branches == ("legacy-edr",)
    assert by_id[str(untouched.id)].processing.disabled_branches == ()
    assert by_id[str(mapped.id)].state is HandoverState.NOTIFIABLE
    assert by_id[str(untouched.id)].state is HandoverState.ACTIONABLE


def test_disabled_branch_requires_historical_role() -> None:
    with pytest.raises(SigmaHandoverConfigurationError):
        ProcessingBranch.from_dict(
            {
                "id": "legacy-edr",
                "processing_items": ["legacy-edr-enrich"],
                "state": "disabled",
            }
        )


def test_selector_rejects_name_and_title_permissions() -> None:
    with pytest.raises(SigmaHandoverConfigurationError):
        RuleSelector.from_dict({"name": "shared-name"})
    with pytest.raises(SigmaHandoverConfigurationError):
        RuleSelector.from_dict({"title": "Shared Title"})


def test_ambiguous_uuid_with_different_contents_is_rejected() -> None:
    first = make_rule("11111111-1111-4111-8111-111111111111", 1)
    second = make_rule("11111111-1111-4111-8111-111111111111", 2)
    assert rule_identity(first).key != rule_identity(second).key
    shift = make_shift(
        ("responder",),
        (duty("ambiguous", "responder", (str(first.id),)),),
    )
    with pytest.raises(SigmaHandoverIdentityError):
        audit_handover([first, second], shift)


def test_shift_requires_aware_datetimes_and_valid_window() -> None:
    with pytest.raises(SigmaHandoverConfigurationError):
        Shift.from_dict(
            {
                "shift_id": "naive",
                "starts_at": "2026-11-23T00:00:00",
                "ends_at": "2026-11-23T08:00:00",
                "on_duty": ["responder"],
                "duties": [],
            }
        )
    with pytest.raises(SigmaHandoverConfigurationError):
        Shift.from_dict(
            {
                "shift_id": "backwards",
                "starts_at": SHIFT_END.isoformat(),
                "ends_at": SHIFT_START.isoformat(),
                "on_duty": ["responder"],
                "duties": [],
            }
        )


def test_report_json_and_filters() -> None:
    rule = make_rule(
        "33333333-3333-4333-8333-333333333333",
        1,
        field="ParentImage",
        category="process_creation",
    )
    shift = make_shift(
        ("responder",),
        (duty("respond", "responder", (str(rule.id),)),),
    )
    branch = ProcessingBranch.from_dict(
        {
            "id": "legacy-edr",
            "processing_items": ["legacy-edr-enrich"],
            "state": "disabled",
            "historical_role": "soc-tier2-legacy",
        }
    )
    report = audit_handover([rule], shift, pipeline(), (branch,))
    data = json.loads(report.to_json())

    assert data["summary"]["reference_only_chain_ids"] == [report.audits[0].chain.chain_id]
    assert data["chains"][0]["reference_only"] is True
    assert data["chains"][0]["countersign_roles"] == ["soc-tier2-legacy"]
    assert report.filter_chains(reference_only=True) == (report.audits[0].chain,)
    assert report.filter_chains(reference_only=False) == ()
    assert report.filter_chains(state="notifiable") == (report.audits[0].chain,)
    assert report.filter_chains(role="responder") == (report.audits[0].chain,)
    assert report.filter_chains(role="missing") == ()
    markdown = report.to_markdown(reference_only_only=True)
    assert "MUST NOT be used as a shift release basis" in markdown
    assert "soc-tier2-legacy" in markdown


def test_config_parses_shift_and_branches() -> None:
    config = HandoverConfig.from_dict(
        {
            "shift": {
                "id": "shift-1",
                "starts_at": SHIFT_START.isoformat(),
                "ends_at": SHIFT_END.isoformat(),
                "on_duty": ["responder"],
                "duties": [
                    {
                        "id": "d1",
                        "role": "responder",
                        "selector": {"rule_ids": ["11111111-1111-4111-8111-111111111111"]},
                        "handle": True,
                    }
                ],
            },
            "branches": [
                {
                    "id": "legacy-edr",
                    "processing_items": ["legacy-edr-enrich"],
                    "state": "disabled",
                    "historical_role": "soc-tier2-legacy",
                }
            ],
        }
    )

    assert config.shift.shift_id == "shift-1"
    assert config.branches[0].state is BranchState.DISABLED
    assert config.branches[0].historical_role == "soc-tier2-legacy"


def test_correlation_rule_identity_and_permissions_are_supported() -> None:
    correlation = SigmaCorrelationRule.from_dict(
        {
            "title": "Correlated Logons",
            "name": "shared-name",
            "id": "55555555-5555-4555-8555-555555555555",
            "correlation": {
                "type": "event_count",
                "rules": ["base-rule"],
                "timespan": "5m",
                "condition": {"gte": 2},
            },
        }
    )
    shift = make_shift(
        ("responder",),
        (duty("corr", "responder", (str(correlation.id),)),),
    )
    report = audit_handover([correlation], shift)
    audit = report.audits[0]

    assert audit.identity.rule_id == "55555555-5555-4555-8555-555555555555"
    assert audit.state is HandoverState.ACTIONABLE
    assert audit.can_handle is True


def test_audit_does_not_mutate_caller_rules() -> None:
    rule = make_rule(
        "33333333-3333-4333-8333-333333333333",
        1,
        field="ParentImage",
        category="process_creation",
    )
    shift = make_shift(
        ("responder",),
        (duty("respond", "responder", (str(rule.id),)),),
    )
    audit_handover([rule], shift, pipeline())

    detection = next(iter(rule.detection.detections.values()))
    assert detection.detection_items[0].field == "ParentImage"


def test_notify_only_role_off_duty_without_substitute_is_no_substitute() -> None:
    rule = make_rule("11111111-1111-4111-8111-111111111111", 1)
    shift = make_shift(
        ("responder",),
        (duty("observe", "observer", (str(rule.id),), handle=False),),
    )
    report = audit_handover([rule], shift)
    audit = report.audits[0]

    assert audit.state is HandoverState.NO_SUBSTITUTE
    assert audit.can_notify is False
    assert audit.can_handle is False
    assert audit.no_substitute is True
    assert audit.uncovered_duties[0].handle_required is False


def test_example_demo_has_exactly_one_reference_only_chain() -> None:
    root = Path(__file__).resolve().parents[1]
    base = root / "examples" / "handover_audit"
    config = HandoverConfig.from_yaml((base / "shift.yml").read_text(encoding="utf-8"))
    pipeline = ProcessingPipeline.from_yaml((base / "pipeline.yml").read_text(encoding="utf-8"))
    rules = []
    for path in sorted((base / "rules").glob("*.yml")):
        collection = SigmaCollection.from_yaml(
            path.read_text(encoding="utf-8"),
            source=SigmaRuleLocation(path.relative_to(root)),
        )
        rules.extend(collection.rules)
    report = audit_from_config(rules, config, pipeline, generated_at=config.shift.starts_at)

    assert report.state_counts() == {
        "notifiable": 1,
        "actionable": 2,
        "no_substitute": 1,
    }
    assert len(report.reference_only_chains) == 1
    chain = report.reference_only_chains[0]
    assert chain.identity.name == "legacy-edr-heartbeat"
    assert chain.release_basis is False
    assert chain.countersign_roles == ("soc-tier2-legacy",)
    assert chain.chain_id in report.to_dict()["summary"]["reference_only_chain_ids"]
