from __future__ import annotations

import pytest
from packaging.version import Version

from pip_audit._audit import ExemptionAuditor
from pip_audit._exemption import (
    Approval,
    ApprovalRegistry,
    AuditVerdict,
    approvals_from_results,
)
from pip_audit._service import (
    AdvisorySnapshot,
    OfflineSnapshotService,
    ResolvedDependency,
)

SNAPSHOT_V1 = "offline/snapshot-v1.json"
SNAPSHOT_V2 = "offline/snapshot-v2.json"
SNAPSHOT_CONFLICT = "offline/snapshot-conflict.json"


@pytest.fixture
def v1(asset):
    return OfflineSnapshotService(AdvisorySnapshot.from_json(asset(SNAPSHOT_V1)))


@pytest.fixture
def v2(asset):
    return OfflineSnapshotService(AdvisorySnapshot.from_json(asset(SNAPSHOT_V2)))


@pytest.fixture
def conflicting(asset):
    return OfflineSnapshotService(AdvisorySnapshot.from_json(asset(SNAPSHOT_CONFLICT)))


def test_v1_baseline_reports_before_approval(v1):
    auditor = ExemptionAuditor(v1)
    decision = auditor.check(ResolvedDependency("foo", Version("1.0.0")))

    assert decision.verdict is AuditVerdict.REPORT
    assert {result.id for result in decision.results} == {"CVE-2026-0001"}
    assert decision.evidence[0].source_version == "2026-10-01"


def test_approval_granted_against_v1_is_pinned_to_package_and_version(v1):
    dep = ResolvedDependency("foo", Version("1.0.0"))
    _, results = v1.query(dep)
    approvals = approvals_from_results(
        dep, results, source=v1.source, source_version=v1.source_version
    )

    assert len(approvals) == 1
    approval = approvals[0]
    assert approval.primary_id == "CVE-2026-0001"
    assert approval.source_version == "2026-10-01"
    assert approval.alias_evidence == frozenset({"GHSA-aaaa-1111-bbbb"})

    # The same advisory on a different package is not covered.
    other = ResolvedDependency("bar", Version("1.0.0"))
    registry = ApprovalRegistry(approvals)
    assert registry.for_dependency(other) == []

    # A different version of the same package is not covered either.
    other_version = ResolvedDependency("foo", Version("2.0.0"))
    assert registry.for_dependency(other_version) == []


def test_alternating_snapshots_split_only_exempts_evidence_linked_branch(v1, v2):
    # First run: the reviewer approves the merged CVE/GHSA advisory on v1.
    dep = ResolvedDependency("foo", Version("1.0.0"))
    _, v1_results = v1.query(dep)
    registry = ApprovalRegistry(
        approvals_from_results(dep, v1_results, source=v1.source, source_version=v1.source_version)
    )

    # Second run against the revised v2 snapshot with the same approvals.
    auditor = ExemptionAuditor(v2, registry=registry)
    decision = auditor.check(dep)

    # The split introduced a new, uncovered branch, so the overall verdict is REPORT.
    assert decision.verdict is AuditVerdict.REPORT
    reported_ids = {result.id for result in decision.results}
    assert reported_ids == {"GHSA-aaaa-1111-bbbb"}

    # The original CVE branch stays exempt because it still carries the approved id.
    exempt_decisions = [result for result in decision.evidence if result.result is not None]
    cve_result = next(item.result for item in exempt_decisions if item.result.id == "CVE-2026-0001")
    assert registry.covering(cve_result, dep) != []

    ghsa_result = next(
        item.result for item in exempt_decisions if item.result.id == "GHSA-aaaa-1111-bbbb"
    )
    assert registry.covering(ghsa_result, dep) == []


def test_exempt_verdict_when_all_results_remain_linked(v1, v2):
    # On "bar" the advisory is unchanged between snapshots.
    dep = ResolvedDependency("bar", Version("1.0.0"))
    _, v1_results = v1.query(dep)
    registry = ApprovalRegistry(
        approvals_from_results(dep, v1_results, source=v1.source, source_version=v1.source_version)
    )

    decision = ExemptionAuditor(v2, registry=registry).check(dep)
    assert decision.verdict is AuditVerdict.EXEMPT
    assert {result.id for result in decision.results} == {"CVE-2026-0004"}
    assert {approval.source_version for approval in decision.approvals} == {"2026-10-01"}
    assert decision.evidence[0].source_version == "2026-11-01"


def test_historical_alias_alone_does_not_cover_split_branch():
    approval = Approval(
        package="foo",
        version=Version("1.0.0"),
        primary_id="CVE-2026-0001",
        source="osv-offline",
        source_version="2026-10-01",
        alias_evidence=frozenset({"GHSA-aaaa-1111-bbbb"}),
    )

    # After the split the GHSA record no longer carries the approved CVE id.
    from pip_audit._service.interface import VulnerabilityResult

    split_ghsa = VulnerabilityResult(
        id="GHSA-aaaa-1111-bbbb",
        description="split branch",
        fix_versions=[Version("1.1.0")],
        aliases=set(),
    )
    split_cve = VulnerabilityResult(
        id="CVE-2026-0001",
        description="retained branch",
        fix_versions=[Version("1.1.0")],
        aliases=set(),
    )

    assert approval.covers(split_cve) is True
    assert approval.covers(split_ghsa) is False


def test_withdrawn_advisory_gets_distinct_verdict(v2):
    auditor = ExemptionAuditor(v2)
    decision = auditor.check(ResolvedDependency("foo", Version("1.0.1")))

    assert decision.verdict is AuditVerdict.WITHDRAWN
    assert {result.id for result in decision.results} == {"CVE-2026-0002"}
    assert all(evidence.withdrawn for evidence in decision.evidence)
    assert decision.evidence[0].source_version == "2026-11-01"


def test_unavailable_feed_gets_distinct_verdict(v2):
    auditor = ExemptionAuditor(v2)
    decision = auditor.check(ResolvedDependency("foo", Version("2.0.0")))

    assert decision.verdict is AuditVerdict.UNAVAILABLE
    assert decision.results == ()
    assert "unavailable" in decision.reason


def test_other_feed_recovers_when_one_feed_is_unavailable(v1, v2):
    dep = ResolvedDependency("foo", Version("2.0.0"))
    auditor = ExemptionAuditor([v1, v2])
    decision = auditor.check(dep)

    # v1 answers while v2 is unreachable; the available feed still decides.
    assert decision.verdict is AuditVerdict.REPORT
    assert {result.id for result in decision.results} == {"CVE-2026-0003"}


def test_conflicting_feeds_retain_both_sides_as_evidence(v2, conflicting):
    dep = ResolvedDependency("foo", Version("1.0.1"))
    auditor = ExemptionAuditor([v2, conflicting])
    decision = auditor.check(dep)

    assert decision.verdict is AuditVerdict.CONFLICT
    sources = {evidence.source for evidence in decision.evidence}
    assert sources == {"osv-offline", "pypi-offline"}

    withdrawn = next(evidence for evidence in decision.evidence if evidence.withdrawn)
    live = next(evidence for evidence in decision.evidence if not evidence.withdrawn)
    assert withdrawn.result.id == "CVE-2026-0002"
    assert live.result.id == "CVE-2026-0002"
    assert withdrawn.source_version == live.source_version == "2026-11-01"
    # Both data-source versions are referenced in the retained reason.
    assert "2026-11-01" in decision.reason


def test_non_conflicting_feeds_merge_active_results(v1, v2):
    dep = ResolvedDependency("bar", Version("1.0.0"))
    decision = ExemptionAuditor([v1, v2]).check(dep)

    assert decision.verdict is AuditVerdict.REPORT
    assert {result.id for result in decision.results} == {"CVE-2026-0004"}


def test_audit_iterates_dependency_source(v1, dep_source):
    auditor = ExemptionAuditor(v1)
    decisions = list(auditor.audit(dep_source()))

    assert len(decisions) == 1
    dep, decision = decisions[0]
    assert dep.name == "foo"
    assert decision.verdict is AuditVerdict.REPORT


def test_empty_service_list_is_rejected():
    with pytest.raises(ValueError):
        ExemptionAuditor([])


def test_skipped_dependency_is_unavailable(v1):
    from pip_audit._service import SkippedDependency

    skipped = SkippedDependency(name="foo", skip_reason="no matching distribution")
    decision = ExemptionAuditor(v1).check(skipped)

    assert decision.verdict is AuditVerdict.UNAVAILABLE
    assert "no matching distribution" in decision.reason
