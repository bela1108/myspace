# -*- coding: utf-8 -*-

"""Tests for retraction-aware CPE impact assessment."""

from __future__ import absolute_import, unicode_literals


from cpe.impact import (
    Advisory,
    Asset,
    AssessmentStatus,
    ComponentObservation,
    FamilyCoverage,
    InventoryScope,
    ReplacementEvidence,
    assess_retraction,
)


AFFECTED = "cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*"
PATCHED = "cpe:2.3:a:oracle:weblogic_server:12.2.1.4:*:*:*:*:*:*:*"
LINUX = "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*"


def advisory():
    return Advisory.from_cpe_names(
        "CVE-2026-0001",
        [AFFECTED],
        applies_from="2026-09-01T00:00:00Z",
        applies_until="2026-10-01T00:00:00Z",
        retracted_at="2026-10-03T00:00:00Z",
    )


def scope(with_log4j=True):
    return InventoryScope(
        approved_families=("oracle_weblogic", "apache_log4j"),
        coverage={
            "oracle_weblogic": FamilyCoverage(
                "oracle_weblogic", True, "complete CMDB export"),
            "apache_log4j": FamilyCoverage(
                "apache_log4j", with_log4j, "inventory export"),
        },
        requested_exclusions=("apache_log4j",),
    )


def three_assets():
    return (
        Asset(
            "wls-01", "oracle_weblogic",
            observations=(
                ComponentObservation(AFFECTED, "2026-09-15T00:00:00Z"),
                ComponentObservation(PATCHED, "2026-10-20T00:00:00Z"),
            ),
            manifest_complete=True,
            manifest_evidence="full manifest",
        ),
        Asset(
            "wls-02", "oracle_weblogic",
            observations=(
                ComponentObservation(AFFECTED, "2026-09-15T00:00:00Z"),
                ComponentObservation(AFFECTED, "2026-10-20T00:00:00Z"),
            ),
            manifest_complete=True,
            manifest_evidence="full manifest",
        ),
        Asset(
            "wls-03", "oracle_weblogic",
            observations=(
                ComponentObservation(LINUX, "2026-10-20T00:00:00Z"),
            ),
            manifest_complete=False,
            manifest_evidence="1 of 3 package sources",
        ),
    )


def test_before_after_inventory_has_three_distinct_outcomes():
    replacements = (
        ReplacementEvidence(
            asset_id="wls-01",
            removed_cpe=AFFECTED,
            installed_cpe=PATCHED,
            replaced_at="2026-10-18T00:00:00Z",
            evidence_ref="CHG-4711",
            verified=True,
        ),
    )

    report = assess_retraction(
        three_assets(), advisory(), scope(),
        replacement_evidence=replacements,
        as_of="2026-11-01T00:00:00Z",
    )

    by_id = {item.asset_id: item for item in report.assessments}
    assert by_id["wls-01"].status is AssessmentStatus.CLOSED
    assert "verified_replacement" in by_id["wls-01"].basis
    assert by_id["wls-02"].status is AssessmentStatus.AFFECTED
    assert "cpe_match" in by_id["wls-02"].basis
    assert by_id["wls-03"].status is AssessmentStatus.INSUFFICIENT_EVIDENCE
    assert "incomplete_manifest" in by_id["wls-03"].basis

    assert report.summary == {
        "closed": 1,
        "affected": 1,
        "insufficient_evidence": 1,
    }
    assert report.provable_scope["confirmed_closed"] == ["wls-01"]
    assert report.provable_scope["still_affected"] == ["wls-02"]
    assert report.provable_scope["missing_evidence"] == ["wls-03"]


def test_non_match_with_incomplete_manifest_is_not_closed():
    asset = Asset(
        "wls-03", "oracle_weblogic",
        observations=(ComponentObservation(LINUX, "2026-10-20T00:00:00Z"),),
        manifest_complete=False,
        manifest_evidence="1 of 3 package sources",
    )

    report = assess_retraction(
        [asset], advisory(), scope(), as_of="2026-11-01T00:00:00Z")

    result = report.assessments[0]
    assert result.status is AssessmentStatus.INSUFFICIENT_EVIDENCE
    assert "incomplete_manifest" in result.basis


def test_family_exclusion_requires_complete_family_coverage():
    incomplete = InventoryScope(
        approved_families=("apache_log4j",),
        coverage={
            "apache_log4j": FamilyCoverage(
                "apache_log4j", False, "2 of 3 collectors"),
        },
        requested_exclusions=("apache_log4j",),
    )
    complete = InventoryScope(
        approved_families=("apache_log4j",),
        coverage={
            "apache_log4j": FamilyCoverage(
                "apache_log4j", True, "signed full export"),
        },
        requested_exclusions=("apache_log4j",),
    )

    denied = incomplete.exclusion_decision("apache_log4j")
    allowed = complete.exclusion_decision("apache_log4j")

    assert denied.excluded is False
    assert denied.basis.code.value == "family_exclusion_unproven"
    assert "non-match cannot exclude" in denied.basis.message
    assert allowed.excluded is True
    assert allowed.basis.code.value == "family_excluded_with_proof"


def test_unverified_replacement_does_not_close_an_affected_asset():
    asset = Asset(
        "wls-02", "oracle_weblogic",
        observations=(ComponentObservation(AFFECTED, "2026-10-20T00:00:00Z"),),
        manifest_complete=True,
    )
    replacement = ReplacementEvidence(
        asset_id="wls-02",
        removed_cpe=AFFECTED,
        installed_cpe=PATCHED,
        replaced_at="2026-10-18T00:00:00Z",
        evidence_ref="unverified ticket",
        verified=False,
    )

    report = assess_retraction(
        [asset], advisory(), scope(),
        replacement_evidence=[replacement],
        as_of="2026-11-01T00:00:00Z",
    )

    result = report.assessments[0]
    assert result.status is AssessmentStatus.AFFECTED
    assert "unverified_replacement" in result.basis


def test_verified_replacement_cpe_is_sufficient_without_a_prior_match():
    asset = Asset(
        "wls-04", "oracle_weblogic",
        observations=(ComponentObservation(LINUX, "2026-10-20T00:00:00Z"),),
        manifest_complete=False,
        manifest_evidence="partial manifest",
    )
    replacement = ReplacementEvidence(
        asset_id="wls-04",
        removed_cpe=AFFECTED,
        installed_cpe=PATCHED,
        replaced_at="2026-10-18T00:00:00Z",
        evidence_ref="CHG-9001 / install receipt",
        verified=True,
    )

    report = assess_retraction(
        [asset], advisory(), scope(),
        replacement_evidence=[replacement],
        as_of="2026-11-01T00:00:00Z",
    )

    assert report.assessments[0].status is AssessmentStatus.CLOSED
    assert "verified_replacement" in report.assessments[0].basis


def test_nvd_json_version_interval_is_applied():
    expression = [{
        "operator": "OR",
        "children": [],
        "cpe_match": [{
            "vulnerable": True,
            "cpe23Uri": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.0",
            "versionEndExcluding": "2.15.0",
        }],
    }]

    condition = Advisory("CVE-2026-0002", expression)
    old = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    new = "cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*"

    assert condition.evaluate([old]).value is True
    assert condition.evaluate([new]).value is False


def test_observation_outside_advisory_interval_is_marked_but_still_evidence():
    asset = Asset(
        "wls-05", "oracle_weblogic",
        observations=(ComponentObservation(AFFECTED, "2026-10-20T00:00:00Z"),),
        manifest_complete=True,
    )

    report = assess_retraction(
        [asset], advisory(), scope(), as_of="2026-11-01T00:00:00Z")

    result = report.assessments[0]
    assert result.status is AssessmentStatus.AFFECTED
    assert result.matches[0].within_applicability_window is False


def test_conditional_and_expression_uses_the_whole_inventory_snapshot():
    operating_system = "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*"
    condition = Advisory.from_cpe_names(
        "CVE-2026-0003",
        [AFFECTED, operating_system],
        operator="AND",
        applies_from="2026-09-01T00:00:00Z",
        applies_until="2026-10-01T00:00:00Z",
    )
    asset = Asset(
        "wls-06", "oracle_weblogic",
        observations=(
            ComponentObservation(AFFECTED, "2026-09-15T00:00:00Z"),
            ComponentObservation(operating_system, "2026-09-16T00:00:00Z"),
        ),
        manifest_complete=True,
    )

    report = assess_retraction(
        [asset], condition,
        InventoryScope(
            approved_families=("oracle_weblogic",),
            coverage={
                "oracle_weblogic": FamilyCoverage(
                    "oracle_weblogic", True, "complete export"),
            },
        ),
        as_of="2026-11-01T00:00:00Z",
    )

    result = report.assessments[0]
    assert result.status is AssessmentStatus.AFFECTED
    assert len(result.matches) == 2
