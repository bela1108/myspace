"""Tests for the offline handover audit layer."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest

from sigma.audit.handover import (
    ApprovedSubstitution,
    AuditStatus,
    BranchSteward,
    HandoverAuditConfig,
    HandoverAuditor,
    ReleaseBranch,
    Responsibility,
    ShiftDuty,
)
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaAuditError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule


TZ = timezone(timedelta(hours=8))
AT = datetime(2026, 11, 23, 2, 10, tzinfo=TZ)

PRIMARY_ID = UUID("11111111-1111-4111-8111-111111111111")
MIRROR_ID = UUID("22222222-2222-4222-8222-222222222222")
CLOUD_ID = UUID("33333333-3333-4333-8333-333333333333")
IDENTITY_ID = UUID("44444444-4444-4444-8444-444444444444")


def make_rule(rule_id, title, product, category=None, service=None):
    logsource = {"product": product}
    if category is not None:
        logsource["category"] = category
    if service is not None:
        logsource["service"] = service
    return SigmaRule.from_dict(
        {
            "title": title,
            "id": str(rule_id),
            "logsource": logsource,
            "detection": {
                "selection": {"field": "value"},
                "condition": "selection",
            },
            "level": "high",
        }
    )


def make_rules():
    return [
        make_rule(
            PRIMARY_ID,
            "Suspicious PowerShell Encoded Command",
            "windows",
            "process_creation",
        ),
        make_rule(
            MIRROR_ID,
            "Suspicious PowerShell Encoded Command",
            "linux",
            "process_creation",
        ),
        make_rule(CLOUD_ID, "Cloud Administrator Role Granted", "aws", service="cloudtrail"),
        make_rule(IDENTITY_ID, "Impossible Travel Sign-in", "azure", service="signinlogs"),
    ]


def make_pipeline():
    return ProcessingPipeline.from_dict(
        {
            "name": "test-handover-branches",
            "transformations": [
                {
                    "id": "primary-release",
                    "type": "set_custom_attribute",
                    "attribute": "release_branch",
                    "value": "primary",
                    "rule_conditions": [
                        {
                            "type": "logsource",
                            "product": "windows",
                            "category": "process_creation",
                        }
                    ],
                },
                {
                    "id": "mirror-release",
                    "type": "set_custom_attribute",
                    "attribute": "release_branch",
                    "value": "mirror",
                    "rule_conditions": [
                        {
                            "type": "logsource",
                            "product": "linux",
                            "category": "process_creation",
                        }
                    ],
                },
                {
                    "id": "cloud-release",
                    "type": "set_custom_attribute",
                    "attribute": "release_branch",
                    "value": "cloud",
                    "rule_conditions": [
                        {"type": "logsource", "product": "aws", "service": "cloudtrail"}
                    ],
                },
                {
                    "id": "identity-release",
                    "type": "set_custom_attribute",
                    "attribute": "release_branch",
                    "value": "identity",
                    "rule_conditions": [
                        {"type": "logsource", "product": "azure", "service": "signinlogs"}
                    ],
                },
            ],
        }
    )


def make_config(**overrides):
    duties = [
        ShiftDuty(
            role="endpoint-commander",
            responsibility=Responsibility.HANDLE,
            person="alice",
            branch_ids=frozenset({"primary-release", "mirror-release"}),
            valid_from=AT - timedelta(hours=2),
            valid_to=AT + timedelta(hours=6),
        ),
        ShiftDuty(
            role="cloud-commander",
            responsibility=Responsibility.HANDLE,
            person="dave",
            available=False,
            branch_ids=frozenset({"cloud-release"}),
            valid_from=AT - timedelta(hours=2),
            valid_to=AT + timedelta(hours=6),
        ),
        ShiftDuty(
            role="identity-commander",
            responsibility=Responsibility.HANDLE,
            person="erin",
            available=False,
            branch_ids=frozenset({"identity-release"}),
            valid_from=AT - timedelta(hours=2),
            valid_to=AT + timedelta(hours=6),
        ),
        ShiftDuty(
            role="security-analyst",
            responsibility=Responsibility.NOTIFY,
            person="bob",
            valid_from=AT - timedelta(hours=2),
            valid_to=AT + timedelta(hours=6),
        ),
    ]
    substitutions = [
        ApprovedSubstitution(
            role="cloud-commander",
            substitute_person="frank",
            substitute_role="cloud-commander",
            approved_by="soc-manager",
            approval_ref="RFC-2026-1122-01",
            approved_at=AT - timedelta(hours=16),
            valid_from=AT - timedelta(hours=2),
            valid_to=AT + timedelta(hours=6),
            rule_ids=frozenset({CLOUD_ID}),
        ),
        ApprovedSubstitution(
            role="identity-commander",
            substitute_person="grace",
            substitute_role="identity-commander",
            approved_by="soc-manager",
            approval_ref="RFC-2026-1122-09",
            approved_at=AT - timedelta(days=2),
            valid_from=AT - timedelta(days=1),
            valid_to=AT - timedelta(hours=18),
            rule_ids=frozenset({IDENTITY_ID}),
        ),
    ]
    branches = [
        ReleaseBranch(
            branch_id="primary-release",
            processing_item_id="primary-release",
            owner_role="endpoint-commander",
            rule_ids=frozenset({PRIMARY_ID}),
        ),
        ReleaseBranch(
            branch_id="mirror-release",
            processing_item_id="mirror-release",
            owner_role="endpoint-commander",
            enabled=False,
            countersign_role="deputy-endpoint-lead",
            rule_ids=frozenset({MIRROR_ID}),
        ),
        ReleaseBranch(
            branch_id="cloud-release",
            processing_item_id="cloud-release",
            owner_role="cloud-commander",
            rule_ids=frozenset({CLOUD_ID}),
        ),
        ReleaseBranch(
            branch_id="identity-release",
            processing_item_id="identity-release",
            owner_role="identity-commander",
            rule_ids=frozenset({IDENTITY_ID}),
        ),
    ]
    values = {
        "shift_id": "shift-test",
        "audit_time": AT,
        "duties": tuple(duties),
        "substitutions": tuple(substitutions),
        "branches": tuple(branches),
    }
    values.update(overrides)
    return HandoverAuditConfig(**values)


def audit_report():
    return HandoverAuditor(make_config()).audit(make_rules(), make_pipeline())


def chain_by_id(report, rule_id):
    return next(chain for chain in report.chains if chain.rule_id == rule_id)


def test_same_title_rules_keep_separate_permissions():
    report = audit_report()
    primary = chain_by_id(report, PRIMARY_ID)
    mirror = chain_by_id(report, MIRROR_ID)

    assert primary.rule_title == mirror.rule_title
    assert primary.chain_id != mirror.chain_id
    assert primary.status is AuditStatus.ACTIONABLE
    assert primary.release_basis is True
    assert mirror.status is AuditStatus.NOTIFIABLE
    assert mirror.release_basis is False
    assert report.same_title_groups[primary.rule_title] == (PRIMARY_ID, MIRROR_ID)


def test_temporarily_disabled_branch_names_historical_countersigner():
    report = audit_report()
    mirror = chain_by_id(report, MIRROR_ID)

    assert len(mirror.closed_branches) == 1
    closed = mirror.closed_branches[0]
    assert closed.reason == "temporarily_disabled"
    assert closed.required is True
    assert closed.countersign_role == "deputy-endpoint-lead"
    assert mirror.countersign_roles == ("deputy-endpoint-lead",)
    assert "branch_closed" in mirror.reason_codes


def test_branch_history_supplies_countersign_role_when_not_explicit():
    closed_branch = ReleaseBranch(
        branch_id="primary-release",
        processing_item_id="primary-release",
        owner_role="endpoint-commander",
        enabled=False,
        rule_ids=frozenset({PRIMARY_ID}),
        history=(
            BranchSteward(
                role="earlier-lead",
                effective_from=AT - timedelta(days=365),
                effective_to=AT - timedelta(days=180),
            ),
            BranchSteward(
                role="prior-lead",
                effective_from=AT - timedelta(days=180),
                effective_to=AT - timedelta(days=1),
            ),
        ),
    )
    report = HandoverAuditor(make_config(branches=(closed_branch,))).audit(
        [make_rules()[0]], make_pipeline()
    )
    closed = report.chains[0].closed_branches[0]

    assert closed.countersign_role == "prior-lead"
    assert report.chains[0].countersign_roles == ("prior-lead",)


def test_active_approved_substitution_grants_handle_coverage():
    report = audit_report()
    cloud = chain_by_id(report, CLOUD_ID)

    assert cloud.status is AuditStatus.ACTIONABLE
    assert cloud.has_substitute is True
    assert len(cloud.handle_assignments) == 1
    assignment = cloud.handle_assignments[0]
    assert assignment.person == "frank"
    assert assignment.source == "approved_substitute"
    assert assignment.approval_ref == "RFC-2026-1122-01"


def test_expired_substitution_produces_no_substitute_state():
    report = audit_report()
    identity = chain_by_id(report, IDENTITY_ID)

    assert identity.status is AuditStatus.NO_SUBSTITUTE
    assert identity.escalation_required is True
    assert identity.reference_only is False
    assert identity.has_substitute is False
    assert identity.handle_assignments == ()
    assert identity.uncovered_handle_roles == ("identity-commander",)
    assert "no_approved_substitute" in identity.reason_codes


def test_reference_only_filter_returns_exactly_one_chain():
    report = audit_report()
    reference_only = report.reference_only_chains()

    assert len(reference_only) == 1
    assert reference_only[0].rule_id == MIRROR_ID
    assert reference_only[0].reference_only is True
    assert reference_only[0].release_basis is False
    assert report.filter(reference_only=True) == reference_only
    assert report.summary()["reference_only_count"] == 1


def test_status_filter_and_summary():
    report = audit_report()
    primary = chain_by_id(report, PRIMARY_ID)
    mirror = chain_by_id(report, MIRROR_ID)
    identity = chain_by_id(report, IDENTITY_ID)

    assert [chain.rule_id for chain in report.filter(status="no_substitute")] == [IDENTITY_ID]
    assert report.summary()["status_counts"] == {
        "notifiable": 1,
        "actionable": 2,
        "no_substitute": 1,
    }
    assert primary.actionable is True
    assert primary.no_substitute is False
    assert mirror.notifiable is True
    assert identity.no_substitute is True
    for chain in report.chains:
        assert (
            sum((chain.notifiable, chain.actionable, chain.no_substitute)) == 1
        )


def test_release_requires_open_branch_evidence():
    config = HandoverAuditConfig(
        shift_id="shift-test",
        audit_time=AT,
        duties=(
            ShiftDuty(
                role="global-handler",
                responsibility=Responsibility.HANDLE,
                person="alice",
            ),
            ShiftDuty(
                role="analyst",
                responsibility=Responsibility.NOTIFY,
                person="bob",
            ),
        ),
        branches=(),
    )
    report = HandoverAuditor(config).audit([make_rules()[0]], make_pipeline())
    chain = report.chains[0]

    assert chain.status is AuditStatus.NOTIFIABLE
    assert chain.can_handle is False
    assert chain.release_basis is False
    assert "missing_release_branch" in chain.reason_codes


def test_missing_rule_uuid_is_rejected():
    rule = SigmaRule.from_dict(
        {
            "title": "No id",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"selection": {"field": "value"}, "condition": "selection"},
        }
    )
    with pytest.raises(SigmaAuditError, match="no UUID"):
        HandoverAuditor(make_config()).audit([rule], make_pipeline())


def test_substitution_requires_approval_metadata():
    with pytest.raises(SigmaAuditError, match="approval_ref"):
        ApprovedSubstitution(
            role="cloud-commander",
            substitute_person="frank",
            approved_by="soc-manager",
            approval_ref="",
            approved_at=AT,
            valid_from=AT,
        )


def test_unknown_config_keys_are_rejected():
    with pytest.raises(SigmaAuditError, match="Unknown handover audit configuration keys"):
        HandoverAuditConfig.from_dict(
            {
                "shift": {
                    "id": "shift-test",
                    "audit_time": "2026-11-23T02:10:00+08:00",
                },
                "duties": [],
                "duty": [],
            }
        )


def test_demo_scenario_has_one_reference_only_chain():
    demo_dir = Path(__file__).resolve().parent.parent / "examples" / "handover_audit"
    config = HandoverAuditConfig.from_yaml_file(demo_dir / "scenario.yml")
    pipeline = ProcessingPipeline.from_yaml(
        (demo_dir / "pipeline.yml").read_text(encoding="utf-8"),
        source_path=str(demo_dir / "pipeline.yml"),
    )
    collection = SigmaCollection.load_ruleset([demo_dir / "rules"])
    report = HandoverAuditor(config).audit(collection.rules, pipeline)

    assert report.summary()["rule_count"] == 4
    assert report.summary()["status_counts"] == {
        "notifiable": 1,
        "actionable": 2,
        "no_substitute": 1,
    }
    reference_only = report.reference_only_chains()
    assert len(reference_only) == 1
    assert reference_only[0].rule_title == "Suspicious PowerShell Encoded Command"
    assert reference_only[0].closed_branches[0].countersign_role == "deputy-endpoint-lead"

    primary = next(
        chain for chain in report.chains if chain.rule_id == PRIMARY_ID
    )
    assert {assignment.person for assignment in primary.notify_assignments} == {
        "alice",
        "bob",
    }
    assert [assignment.person for assignment in primary.handle_assignments] == ["alice"]
