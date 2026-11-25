import itertools
import json

import pretend  # type: ignore
import pytest
from packaging.version import Version

from pip_audit import _audit as audit
from pip_audit._audit import AuditOptions, Auditor
from pip_audit._dependency_source.interface import DependencySource
from pip_audit._format.json import JsonFormat
from pip_audit._service.interface import (
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


def test_audit(vuln_service, dep_source):
    service = vuln_service()
    source = dep_source()

    auditor = Auditor(service)
    results = auditor.audit(source)

    assert next(results) == (
        next(source.collect()),
        [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.1.0")],
                aliases=set(),
            )
        ],
    )

    with pytest.raises(StopIteration):
        next(results)


def test_audit_dry_run(monkeypatch, vuln_service, dep_source):
    service = vuln_service()
    source = dep_source()

    auditor = Auditor(service, options=AuditOptions(dry_run=True))
    service = pretend.stub(query_all=pretend.call_recorder(lambda s: None))
    logger = pretend.stub(info=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(auditor, "_service", service)
    monkeypatch.setattr(audit, "logger", logger)

    # dict-construct here to consume the iterator, causing the effects below.
    _ = dict(auditor.audit(source))

    # In dry-run mode, no calls should be made the the vuln service,
    # but an appropriate number of logging calls should be made.
    assert service.query_all.calls == []
    assert len(logger.info.calls) == len(list(source.collect()))


@pytest.mark.parametrize(
    "vulns",
    itertools.permutations(
        [
            VulnerabilityResult(
                id="PYSEC-0",
                description="fake",
                fix_versions=[Version("1.1.0")],
                aliases={"alias-1"},
            ),
            VulnerabilityResult(
                id="FAKE-1",
                description="fake",
                fix_versions=[Version("1.1.0")],
                aliases={"alias-1", "alias-2"},
            ),
        ]
    ),
)
def test_audit_dedupes_aliases(dep_source, vulns):
    class Service(VulnerabilityService):
        def query(self, spec):
            return spec, vulns

    service = Service()
    source = dep_source()

    auditor = Auditor(service)
    results = list(auditor.audit(source))

    # One dependency, one unique vulnerability result for that dependency.
    assert len(results) == 1
    assert len(results[0][1]) == 1
    assert results[0][1][0].id == "PYSEC-0"


@pytest.mark.parametrize(
    "vulns",
    itertools.permutations(
        [
            VulnerabilityResult(
                id="PYSEC-0",
                description="fake",
                fix_versions=[Version("1.1.0")],
                aliases={"CVE-XXXX-YYYYY"},
            ),
            VulnerabilityResult(
                id="FAKE-1",
                description="fake",
                fix_versions=[Version("1.1.0")],
                aliases={"CVE-XXXX-YYYYY"},
            ),
            VulnerabilityResult(
                id="CVE-XXXX-YYYYY",
                description="fake",
                fix_versions=[Version("1.1.0")],
                aliases={"FAKE-1"},
            ),
        ]
    ),
)
def test_audit_dedupes_aliases_by_id(dep_source, vulns):
    class Service(VulnerabilityService):
        def query(self, spec):
            return spec, vulns

    service = Service()
    source = dep_source()

    auditor = Auditor(service)
    results = list(auditor.audit(source))

    # One dependency, one unique vulnerability result for that dependency.
    assert len(results) == 1
    assert len(results[0][1]) == 1
    assert results[0][1][0].id == "PYSEC-0"

    # The result contains the merged alias set for all aliases.
    assert results[0][1][0].aliases == {"FAKE-1", "CVE-XXXX-YYYYY"}


def test_audit_dedupes_matching_pysec_ids(dep_source):
    class Service(VulnerabilityService):
        def query(self, spec):
            return spec, [
                VulnerabilityResult(
                    id="PYSEC-2025-1",
                    description="first description",
                    fix_versions=[Version("1.1.0")],
                    aliases={"CVE-2025-0001"},
                ),
                VulnerabilityResult(
                    id="PYSEC-2025-1",
                    description="second description",
                    fix_versions=[Version("1.1.0")],
                    aliases={"GHSA-abcd-1234"},
                ),
            ]

    service = Service()
    source = dep_source()

    auditor = Auditor(service)
    results = list(auditor.audit(source))

    assert len(results) == 1
    assert len(results[0][1]) == 1
    assert results[0][1][0].id == "PYSEC-2025-1"
    assert results[0][1][0].aliases == {"CVE-2025-0001", "GHSA-abcd-1234"}


def test_audit_report_recheck_distinguishes_empty_reply_from_unexecuted_query(tmp_path):
    empty_dep = ResolvedDependency(name="Northwind_Empty", version=Version("1.4.0"))
    advisory_dep = ResolvedDependency(
        name="Northwind_Advisory", version=Version("2.1.0")
    )
    advisory = VulnerabilityResult(
        id="FAKE-2026-0001",
        description="in-process advisory fixture",
        fix_versions=[Version("2.1.1")],
        aliases={"FAKE-CVE-2026-0001"},
    )

    existing_report = {
        "dependencies": [
            {
                "name": empty_dep.canonical_name,
                "version": str(empty_dep.version),
                "vulns": [],
            },
            {
                "name": advisory_dep.canonical_name,
                "version": str(advisory_dep.version),
                "vulns": [
                    {
                        "id": advisory.id,
                        "fix_versions": [
                            str(fix_version) for fix_version in advisory.fix_versions
                        ],
                        "aliases": sorted(advisory.aliases),
                        "description": advisory.description,
                    }
                ],
            },
        ],
        "fixes": [],
    }
    report_path = tmp_path / "existing-pip-audit-report.json"
    report_path.write_text(json.dumps(existing_report))

    class Source(DependencySource):
        def collect(self):
            yield empty_dep
            yield advisory_dep

        def fix(self, _fix_version) -> None:
            raise NotImplementedError

    class RecordingAdvisoryService(VulnerabilityService):
        def __init__(self):
            self.queries = []
            self.responses = {
                empty_dep.canonical_name: [],
                advisory_dep.canonical_name: [advisory],
            }

        def query(self, spec):
            query = (spec.canonical_name, str(spec.version))
            self.queries.append(query)
            return spec, list(self.responses[spec.canonical_name])

    service = RecordingAdvisoryService()

    def query_state(name):
        if not any(query[0] == name for query in service.queries):
            return "not-executed"
        if service.responses[name] == []:
            return "explicit-empty-response"
        return "advisory-response"

    audit_results = Auditor(service).audit(Source())
    checked_empty_dep, empty_vulns = next(audit_results)

    assert checked_empty_dep == empty_dep
    assert empty_vulns == []
    assert service.queries == [(empty_dep.canonical_name, str(empty_dep.version))]
    assert query_state(empty_dep.canonical_name) == "explicit-empty-response"
    assert query_state(advisory_dep.canonical_name) == "not-executed"

    reread_report = json.loads(report_path.read_text())
    assert reread_report == existing_report
    report_entries = {entry["name"]: entry for entry in reread_report["dependencies"]}
    assert set(report_entries) == {
        empty_dep.canonical_name,
        advisory_dep.canonical_name,
    }
    assert (
        report_entries[advisory_dep.canonical_name]["vulns"][0]["id"] == advisory.id
    )

    remaining_results = list(audit_results)
    assert service.queries == [
        (empty_dep.canonical_name, str(empty_dep.version)),
        (advisory_dep.canonical_name, str(advisory_dep.version)),
    ]
    assert len(remaining_results) == 1
    checked_advisory_dep, advisory_vulns = remaining_results[0]
    assert checked_advisory_dep == advisory_dep
    assert advisory_vulns == [advisory]

    audited_report = dict([(checked_empty_dep, empty_vulns), *remaining_results])
    formatted_report = JsonFormat(output_desc=True, output_aliases=True).format(
        audited_report, []
    )
    rechecked_report_path = tmp_path / "rechecked-pip-audit-report.json"
    rechecked_report_path.write_text(formatted_report)
    reread_rechecked_report = json.loads(rechecked_report_path.read_text())

    assert reread_rechecked_report == existing_report
    assert {entry["name"] for entry in reread_rechecked_report["dependencies"]} == {
        query[0] for query in service.queries
    }
