import json
from pathlib import Path

import pytest

from pip_audit._remediation.auditreport import AuditReportError, read_audit_report

ASSETS = Path(__file__).parent.parent / "assets" / "remediation"


class TestReadAuditReport:
    def test_reads_vulnerabilities(self):
        report = read_audit_report(ASSETS / "audit.before.json")

        vulnchain = report.vulnerabilities["vulnchain"]
        assert len(vulnchain) == 1
        assert vulnchain[0].id == "GHSA-vuln-chain-0001"
        assert vulnchain[0].fix_versions == ("4.1.0",)
        assert "CVE-2030-0001" in vulnchain[0].id_aliases

    def test_clean_packages_have_no_vulnerabilities(self):
        report = read_audit_report(ASSETS / "audit.after.json")

        assert report.vulnerabilities["legacylib"] == []
        assert "legacylib" not in report.skipped

    def test_skipped_package_is_recorded(self, tmp_path):
        manifest = {
            "dependencies": [{"name": "editable-pkg", "skip_reason": "no version specified"}]
        }
        path = tmp_path / "audit.json"
        path.write_text(json.dumps(manifest))

        report = read_audit_report(path)
        assert report.skipped == {"editable-pkg": "no version specified"}

    def test_missing_file(self):
        with pytest.raises(AuditReportError, match="not found"):
            read_audit_report(ASSETS / "missing.json")

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "audit.json"
        path.write_text("{not json")
        with pytest.raises(AuditReportError, match="invalid JSON"):
            read_audit_report(path)

    def test_manifest_without_dependencies(self, tmp_path):
        path = tmp_path / "audit.json"
        path.write_text(json.dumps({"fixes": []}))
        with pytest.raises(AuditReportError, match="not a pip-audit JSON manifest"):
            read_audit_report(path)

    def test_malformed_dependency_entry(self, tmp_path):
        path = tmp_path / "audit.json"
        path.write_text(json.dumps({"dependencies": [{"vulns": []}]}))
        with pytest.raises(AuditReportError, match="malformed dependency entry"):
            read_audit_report(path)

    def test_malformed_vulnerability_entry(self, tmp_path):
        path = tmp_path / "audit.json"
        path.write_text(
            json.dumps({"dependencies": [{"name": "pkg", "vulns": [{"fix_versions": []}]}]})
        )
        with pytest.raises(AuditReportError, match="malformed vulnerability entry"):
            read_audit_report(path)
