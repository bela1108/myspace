from __future__ import annotations

from packaging.version import Version

from pip_audit._fix import ResolvedFixVersion
from pip_audit._fix_review import (
    PlannedFix,
    RemediationReview,
    RemediationStatus,
    review_remediation,
)
from pip_audit._service import Dependency, ResolvedDependency, SkippedDependency


def _dep(name: str, version: str) -> ResolvedDependency:
    return ResolvedDependency(name=name, version=Version(version))


def _finding(review: RemediationReview, status: RemediationStatus, canonical_name: str):
    matches = [
        finding
        for finding in review.findings
        if finding.status is status and finding.canonical_name == canonical_name
    ]
    assert len(matches) == 1
    return matches[0]


def test_review_catches_stale_indirect_dependency():
    # The plan claims the vulnerable root package and its indirect dependency.
    plan = [
        PlannedFix(name="root-pkg", fixed_version=Version("2.0.0")),
        PlannedFix(name="transitive-lib", fixed_version=Version("1.5.0")),
    ]
    baseline = [
        _dep("root-pkg", "1.0.0"),
        _dep("transitive-lib", "1.2.0"),
    ]
    # The root was upgraded, but the scan of the target environment still
    # resolves the indirect dependency at its old version.
    target = [
        _dep("root-pkg", "2.0.0"),
        _dep("transitive-lib", "1.2.0"),
    ]

    review = review_remediation(plan, baseline, target)

    assert _finding(review, RemediationStatus.Fixed, "root-pkg").target == _dep("root-pkg", "2.0.0")
    stale = _finding(review, RemediationStatus.StillVulnerable, "transitive-lib")
    assert stale.planned_fix is not None
    assert stale.planned_fix.fixed_version == Version("1.5.0")
    assert stale.target == _dep("transitive-lib", "1.2.0")
    assert review.still_vulnerable == (stale,)
    assert not review.downgraded and not review.removed and not review.under_covered


def test_review_matches_plan_aliases_via_canonical_identity():
    # The plan uses punctuation/underscore aliases that are not valid
    # identities as written; canonicalization must still resolve them.
    plan = [
        PlannedFix(name="Foo_Bar", fixed_version=Version("3.0.0")),
        PlannedFix(name="baz.qux", fixed_version=Version("2.0.0")),
    ]
    baseline = [_dep("foo-bar", "2.4.0"), _dep("baz-qux", "1.0.0")]
    target = [_dep("Foo.Bar", "3.1.0"), _dep("Baz-Qux", "2.0.0")]

    review = review_remediation(plan, baseline, target)

    assert [finding.canonical_name for finding in review.findings] == [
        "foo-bar",
        "baz-qux",
    ]
    assert _finding(review, RemediationStatus.Fixed, "foo-bar")
    assert _finding(review, RemediationStatus.Fixed, "baz-qux")
    assert not review.under_covered


def test_review_alias_without_matching_distribution_is_unverified():
    plan = [PlannedFix(name="ghost-package", fixed_version=Version("1.0.0"))]
    baseline = [_dep("some-pkg", "0.1.0")]
    target = [_dep("some-pkg", "0.1.0")]

    review = review_remediation(plan, baseline, target)

    unverified = _finding(review, RemediationStatus.Unverified, "ghost-package")
    assert unverified.planned_fix is not None
    assert unverified.baseline is None and unverified.target is None
    under_covered = _finding(review, RemediationStatus.UnderCovered, "some-pkg")
    assert under_covered.planned_fix is None


def test_review_reports_removed_distribution():
    plan = [PlannedFix(name="dropped-pkg", fixed_version=Version("2.0.0"))]
    baseline = [_dep("dropped-pkg", "1.0.0")]
    target: list[Dependency] = []

    review = review_remediation(plan, baseline, target)

    removed = _finding(review, RemediationStatus.Removed, "dropped-pkg")
    assert removed.baseline == _dep("dropped-pkg", "1.0.0")
    assert removed.target is None
    assert review.removed == (removed,)


def test_review_reports_downgrade_before_still_vulnerable():
    plan = [PlannedFix(name="rolled-back", fixed_version=Version("3.0.0"))]
    baseline = [_dep("rolled-back", "2.0.0")]
    # Older than both the fixed version and the baseline resolution.
    target = [_dep("rolled-back", "1.0.0")]

    review = review_remediation(plan, baseline, target)

    downgraded = _finding(review, RemediationStatus.Downgraded, "rolled-back")
    assert downgraded.target == _dep("rolled-back", "1.0.0")
    assert not review.still_vulnerable


def test_review_reports_under_covered_distributions():
    plan = [PlannedFix(name="planned-pkg", fixed_version=Version("2.0.0"))]
    baseline = [
        _dep("planned-pkg", "1.0.0"),
        _dep("unplanned-pkg", "1.0.0"),
    ]
    target = [
        _dep("planned-pkg", "2.0.0"),
        _dep("unplanned-pkg", "1.0.0"),
        # A newly introduced transitive dependency is uncovered as well.
        _dep("new-transitive", "0.9.0"),
    ]

    review = review_remediation(plan, baseline, target)

    under_covered = {finding.canonical_name for finding in review.under_covered}
    assert under_covered == {"unplanned-pkg", "new-transitive"}
    assert _finding(review, RemediationStatus.Fixed, "planned-pkg")


def test_review_newer_than_fixed_version_is_fixed():
    plan = [PlannedFix(name="ahead-pkg", fixed_version=Version("1.5.0"))]
    baseline = [_dep("ahead-pkg", "1.0.0")]
    target = [_dep("ahead-pkg", "2.0.0")]

    review = review_remediation(plan, baseline, target)

    assert _finding(review, RemediationStatus.Fixed, "ahead-pkg")
    assert not review.still_vulnerable


def test_review_ignores_skipped_dependencies():
    plan = [PlannedFix(name="resolved-pkg", fixed_version=Version("2.0.0"))]
    baseline: list[Dependency] = [
        _dep("resolved-pkg", "1.0.0"),
        SkippedDependency(name="unresolved-pkg", skip_reason="no version"),
    ]
    target: list[Dependency] = [
        _dep("resolved-pkg", "2.0.0"),
        SkippedDependency(name="unresolved-pkg", skip_reason="no version"),
    ]

    review = review_remediation(plan, baseline, target)

    assert [finding.canonical_name for finding in review.findings] == ["resolved-pkg"]
    assert _finding(review, RemediationStatus.Fixed, "resolved-pkg")


def test_review_is_read_only_and_pure():
    plan = [PlannedFix(name="root-pkg", fixed_version=Version("2.0.0"))]
    baseline = [_dep("root-pkg", "1.0.0"), _dep("transitive-lib", "1.0.0")]
    target = [_dep("root-pkg", "2.0.0"), _dep("transitive-lib", "1.0.0")]

    review_first = review_remediation(plan, baseline, target)
    review_second = review_remediation(plan, baseline, target)

    assert review_first == review_second
    assert baseline == [_dep("root-pkg", "1.0.0"), _dep("transitive-lib", "1.0.0")]
    assert target == [_dep("root-pkg", "2.0.0"), _dep("transitive-lib", "1.0.0")]
    assert plan == [PlannedFix(name="root-pkg", fixed_version=Version("2.0.0"))]


def test_planned_fix_from_resolved_fix_version():
    dep = _dep("fix-me", "1.0.0")
    resolved_fix = ResolvedFixVersion(dep=dep, version=Version("1.5.0"))

    planned = PlannedFix.from_resolved_fix_version(resolved_fix)

    assert planned.name == "fix-me"
    assert planned.fixed_version == Version("1.5.0")
