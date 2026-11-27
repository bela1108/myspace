from __future__ import annotations

import json

from packaging.version import Version

import pip_audit._cli as cli
from pip_audit._audit import Auditor
from pip_audit._dependency_source.interface import DependencySource
from pip_audit._format.json import JsonFormat
from pip_audit._service.interface import (
    ConnectionError,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)

FOO = ResolvedDependency(name="foo", version=Version("1.0.0"))
BAR = ResolvedDependency(name="bar", version=Version("2.0.0"))
BAZ = ResolvedDependency(name="baz", version=Version("3.0.0"))


class ListSource(DependencySource):
    def __init__(self, dependencies):
        self._dependencies = dependencies

    def collect(self):
        return iter(self._dependencies)

    def fix(self, fix_version):
        return None


class FixedZeroService(VulnerabilityService):
    source_name = "fixed-zero"

    def __init__(self, omit=()):
        self.omit = set(omit)

    def query(self, spec):
        return spec, []

    def query_all(self, specs):
        for spec in specs:
            if spec.canonical_name not in self.omit:
                yield spec, []


class BrokenService(VulnerabilityService):
    source_name = "broken"

    def query(self, spec):
        raise ConnectionError("fixed source is unavailable")


def _proof_json(dependencies):
    report = Auditor(FixedZeroService()).audit_report(ListSource(dependencies))
    return report, json.loads(JsonFormat(True, True).format(report, []))


def test_zero_findings_keep_the_audited_set_and_scope():
    report, output = _proof_json([FOO, BAR])

    assert dict(report) == {FOO: [], BAR: []}
    assert report.denominator == 2
    assert report.complete

    proof = output["negative_proof"]
    assert proof["kind"] == "negative"
    assert proof["denominator"] == 2
    assert proof["audited_count"] == 2
    assert proof["unchecked_count"] == 0
    assert proof["complete"] is True
    assert proof["finding_count"] == 0
    assert proof["zero_findings"] is True
    assert {item["name"] for item in proof["audited"]} == {"foo", "bar"}
    for item in proof["audited"]:
        assert item["vulns"] == []
        assert item["advisory_scope"]["source"] == "fixed-zero"
        assert item["advisory_scope"]["package"] == item["name"]
        assert item["advisory_scope"]["version"] == item["version"]

    # The legacy list keeps its old shape and does not grow proof-only fields.
    assert output["dependencies"] == [
        {"name": "foo", "version": "1.0.0", "vulns": []},
        {"name": "bar", "version": "2.0.0", "vulns": []},
    ]


def test_missing_roster_entry_is_listed_as_unchecked():
    report = Auditor(FixedZeroService(omit={"bar"})).audit_report(ListSource([FOO, BAR]))
    output = json.loads(JsonFormat(True, True).format(report, []))

    assert dict(report) == {FOO: []}
    proof = output["negative_proof"]
    assert proof["denominator"] == 2
    assert proof["audited_count"] == 1
    assert proof["unchecked_count"] == 1
    assert proof["complete"] is False
    assert proof["unchecked"] == [
        {
            "name": "bar",
            "version": "2.0.0",
            "audited": False,
            "vulns": None,
            "finding_count": None,
            "advisory_scope": None,
            "reason": "vulnerability service returned no result for this dependency",
        }
    ]


def test_same_zero_conclusion_reports_the_denominator_difference():
    short_report, short_output = _proof_json([FOO, BAR])
    long_report, long_output = _proof_json([FOO, BAR, BAZ])

    assert short_output["negative_proof"]["audited"] == [
        item.to_dict() for item in short_report.audited
    ]
    assert short_output["negative_proof"]["audited_count"] == 2
    assert long_output["negative_proof"]["audited_count"] == 3
    assert short_output["negative_proof"]["denominator"] == 2
    assert long_output["negative_proof"]["denominator"] == 3
    assert len(short_output["dependencies"]) == 2
    assert len(long_output["dependencies"]) == 3
    assert short_output["negative_proof"]["complete"] is True
    assert long_output["negative_proof"]["complete"] is True


def test_unanswered_source_leaves_scope_and_findings_blank():
    report = Auditor(BrokenService()).audit_report(ListSource([FOO]))
    output = json.loads(JsonFormat(True, True).format(report, []))

    proof = output["negative_proof"]
    assert proof["denominator"] == 1
    assert proof["audited_count"] == 0
    assert proof["unchecked_count"] == 1
    assert proof["advisory_scope"] is None
    assert proof["unchecked"][0]["name"] == "foo"
    assert proof["unchecked"][0]["vulns"] is None
    assert proof["unchecked"][0]["advisory_scope"] is None
    assert "fixed source is unavailable" in proof["unchecked"][0]["reason"]


def test_legacy_json_dependency_entries_remain_unchanged():
    result = {
        FOO: [
            VulnerabilityResult(
                id="VULN-0",
                description="not part of the proof test",
                fix_versions=[Version("1.1.0")],
                aliases=set(),
            )
        ],
        BAR: [],
    }
    output = json.loads(JsonFormat(False, False).format(result, []))

    assert output == {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0.0",
                "vulns": [{"id": "VULN-0", "fix_versions": ["1.1.0"]}],
            },
            {"name": "bar", "version": "2.0.0", "vulns": []},
        ],
        "fixes": [],
    }


def test_cli_json_export_carries_the_proof(monkeypatch, capsys):
    source = ListSource([FOO, BAR])
    service = FixedZeroService(omit={"bar"})

    monkeypatch.setattr(cli, "PipSource", lambda *args, **kwargs: source)
    monkeypatch.setattr(cli, "PyPIService", lambda *args, **kwargs: service)
    parser = cli._parser()
    monkeypatch.setattr(
        cli,
        "_parse_args",
        lambda *args: parser.parse_args(
            ["-f", "json", "--progress-spinner", "off", "--output", "stdout"]
        ),
    )

    cli.audit()
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["negative_proof"]["denominator"] == 2
    assert payload["negative_proof"]["audited_count"] == 1
    assert payload["negative_proof"]["unchecked"][0]["name"] == "bar"
    assert "audit is incomplete" in captured.err
