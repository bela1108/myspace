import json
from pathlib import Path

from pip_audit._remediation.auditreport import read_audit_report
from pip_audit._remediation.format import (
    RemediationColumnsFormat,
    RemediationFormatChoice,
    RemediationJsonFormat,
)
from pip_audit._remediation.lockplan import load_lock_plan
from pip_audit._remediation.report import RemediationChecker

ASSETS = Path(__file__).parent.parent / "assets" / "remediation"


def _report():
    return RemediationChecker(
        before_plan=load_lock_plan(ASSETS / "pylock.before.toml"),
        before_audit=read_audit_report(ASSETS / "audit.before.json"),
        after_plan=load_lock_plan(ASSETS / "pylock.after.toml"),
        after_audit=read_audit_report(ASSETS / "audit.after.json"),
    ).check()


class TestRemediationJsonFormat:
    def test_is_valid_json_with_all_statuses(self):
        payload = json.loads(RemediationJsonFormat().format(_report()))

        base = next(group for group in payload["groups"] if group["group"] == "base")
        statuses = {finding["status"] for finding in base["findings"]}
        assert {"closed", "moved-chain", "incomplete-evidence"} <= statuses
        assert base["summary"]["moved_chain"] == 1

    def test_carries_chains_and_environments(self):
        payload = json.loads(RemediationJsonFormat().format(_report()))

        assert payload["before_environments"]
        moved = next(
            finding
            for group in payload["groups"]
            if group["group"] == "base"
            for finding in group["findings"]
            if finding["status"] == "moved-chain"
        )
        assert moved["after_chains"] == [["troublemaker", "vulnchain"]]


class TestRemediationColumnsFormat:
    def test_renders_group_sections_and_statuses(self):
        text = RemediationColumnsFormat().format(_report())

        assert "[base]" in text
        assert "[plugins]" in text
        assert "moved-chain" in text
        assert "incomplete-evidence" in text
        assert "troublemaker -> vulnchain" in text


class TestRemediationFormatChoice:
    def test_str_and_resolution(self):
        assert str(RemediationFormatChoice.Json) == "json"
        assert isinstance(RemediationFormatChoice.Columns.to_format(), RemediationColumnsFormat)
        assert isinstance(RemediationFormatChoice.Json.to_format(), RemediationJsonFormat)
