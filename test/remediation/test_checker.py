from pathlib import Path

import pytest

from pip_audit._remediation.auditreport import read_audit_report
from pip_audit._remediation.lockplan import load_lock_plan
from pip_audit._remediation.report import (
    BASE_GROUP,
    RemediationChecker,
    RemediationCheckError,
    RemediationStatus,
)

ASSETS = Path(__file__).parent.parent / "assets" / "remediation"


@pytest.fixture()
def checker():
    return RemediationChecker(
        before_plan=load_lock_plan(ASSETS / "pylock.before.toml"),
        before_audit=read_audit_report(ASSETS / "audit.before.json"),
        after_plan=load_lock_plan(ASSETS / "pylock.after.toml"),
        after_audit=read_audit_report(ASSETS / "audit.after.json"),
    )


def _finding(report, group, package):
    findings = report.findings_for_group(group)
    matches = [finding for finding in findings if finding.package == package]
    assert len(matches) == 1
    return matches[0]


class TestRemediationChecker:
    def test_report_covers_base_and_declared_groups(self, checker):
        report = checker.check()
        assert [group.name for group in report.groups] == [BASE_GROUP, "plugins"]

    def test_upgraded_package_is_closed(self, checker):
        report = checker.check()
        finding = _finding(report, BASE_GROUP, "legacylib")
        assert finding.status is RemediationStatus.Closed
        assert finding.after_version == "1.2.0"

    def test_short_chain_removed_but_alert_remains_is_moved_chain(self, checker):
        report = checker.check()
        finding = _finding(report, BASE_GROUP, "vulnchain")
        assert finding.status is RemediationStatus.MovedChain
        # The short sharedutils -> troublemaker route was removed, leaving
        # the longer troublemaker-rooted route; the alert is not closed.
        assert finding.before_chains == (("appcore", "sharedutils", "troublemaker", "vulnchain"),)
        assert finding.after_chains == (("troublemaker", "vulnchain"),)

    def test_marker_gated_alert_is_incomplete_evidence(self, checker):
        report = checker.check()
        finding = _finding(report, BASE_GROUP, "markerlib")
        assert finding.status is RemediationStatus.IncompleteEvidence
        assert finding.evidence_notes

    def test_group_specific_chain_unchanged_is_unresolved(self, checker):
        report = checker.check()
        finding = _finding(report, "plugins", "vulnchain")
        assert finding.status is RemediationStatus.Unresolved
        assert finding.after_chains == (("plugintool", "vulnchain"),)

    def test_group_filter_keeps_base(self, checker):
        report = checker.check(only_groups=["plugins"])
        assert [group.name for group in report.groups] == [BASE_GROUP, "plugins"]

    def test_unknown_group_raises(self, checker):
        with pytest.raises(RemediationCheckError, match="unknown optional group"):
            checker.check(only_groups=["nope"])

    def test_exit_code_reflects_open_alert(self, checker):
        assert checker.check().exit_code == 1

    def test_environment_markers_are_reported(self, checker):
        report = checker.check()
        assert report.before_environments == (
            "sys_platform == 'linux'",
            "sys_platform == 'darwin'",
        )
