import json

import pytest

from pip_audit._account import Ledger, LedgerError, project


def _ledger_dict():
    return {
        "release_packages": [
            {
                "id": "web-bundle",
                "dependencies": [
                    {"name": "libfoo", "version": "1.2.3"},
                    {"name": "libsafe", "version": "2.0.0"},
                ],
            },
            {
                "id": "data-bundle",
                "dependencies": [
                    {"name": "libbar", "version": "4.5.6"},
                ],
            },
        ],
        "services": [
            {
                "id": "svc-gateway",
                "uses": [{"package": "web-bundle", "provenance": "shared"}],
            },
            {
                "id": "svc-api",
                "uses": [
                    {"package": "web-bundle", "provenance": "shared"},
                    {"package": "data-bundle", "provenance": "shared"},
                ],
            },
            {
                "id": "svc-worker",
                "uses": [{"package": "data-bundle", "provenance": "repackaged"}],
            },
        ],
        "audit": {
            "dependencies": [
                {
                    "name": "libfoo",
                    "version": "1.2.3",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-0001",
                            "fix_versions": ["1.2.4"],
                            "aliases": ["CVE-2023-10001"],
                        }
                    ],
                },
                {"name": "libsafe", "version": "2.0.0", "vulns": []},
                {
                    "name": "libbar",
                    "version": "4.5.6",
                    "vulns": [{"id": "PYSEC-2024-0042", "fix_versions": ["4.5.7"]}],
                },
            ],
            "fixes": [],
        },
    }


def test_ledger_from_dict():
    ledger = Ledger.from_dict(_ledger_dict())

    assert [pkg.id for pkg in ledger.release_packages] == ["web-bundle", "data-bundle"]
    assert [svc.id for svc in ledger.services] == ["svc-gateway", "svc-api", "svc-worker"]
    # Provenance defaults to shared when not declared.
    assert ledger.services[0].uses[0].provenance == "shared"


def test_project_shared_embedding_is_one_deliverable_unit():
    projection = project(Ledger.from_dict(_ledger_dict()))

    units = {d["id"]: d for d in projection["deliverables"]}
    assert set(units) == {
        "web-bundle#shared",
        "data-bundle#shared",
        "data-bundle#repackaged:svc-worker",
    }
    # web-bundle is embedded in two services but is a single deliverable unit.
    assert units["web-bundle#shared"]["services"] == ["svc-gateway", "svc-api"]


def test_project_repackaging_adds_one_unit_of_responsibility():
    projection = project(Ledger.from_dict(_ledger_dict()))

    units = {d["id"]: d for d in projection["deliverables"]}
    repackaged = units["data-bundle#repackaged:svc-worker"]
    assert repackaged["provenance"] == "repackaged"
    assert repackaged["services"] == ["svc-worker"]
    # The repackaged copy carries the same finding as its own quota item.
    assert [f["name"] for f in repackaged["findings"]] == ["libbar"]
    assert projection["summary"]["repackaged_units"] == 1


def test_project_quota_is_not_multiplied_by_services():
    projection = project(Ledger.from_dict(_ledger_dict()))

    summary = projection["summary"]
    assert summary["deliverable_units"] == 3
    assert summary["deliverable_layer_pending"] == 3
    assert summary["service_layer_pending"] == 4
    # The single shared web-bundle finding is the difference between the
    # per-service ledger and the deliverable quota.
    assert summary["shared_findings"] == 1


def test_project_preserves_version_level_facts():
    ledger_dict = _ledger_dict()
    projection = project(Ledger.from_dict(ledger_dict))

    units = {d["id"]: d for d in projection["deliverables"]}
    # The finding is the exact version-level record from the audit report.
    assert units["web-bundle#shared"]["findings"] == [ledger_dict["audit"]["dependencies"][0]]


def test_project_service_layer_marks_shared_items():
    projection = project(Ledger.from_dict(_ledger_dict()))

    services = {s["id"]: s for s in projection["services"]}
    gateway_item = services["svc-gateway"]["items"][0]
    assert gateway_item["deliverable"] == "web-bundle#shared"
    assert gateway_item["shared_with"] == ["svc-api"]

    worker_item = services["svc-worker"]["items"][0]
    assert worker_item["deliverable"] == "data-bundle#repackaged:svc-worker"
    assert worker_item["shared_with"] == []


def test_project_unaudited_and_clean_dependencies():
    ledger_dict = _ledger_dict()
    ledger_dict["release_packages"][0]["dependencies"].append(
        {"name": "libmystery", "version": "0.1"}
    )
    projection = project(Ledger.from_dict(ledger_dict))

    units = {d["id"]: d for d in projection["deliverables"]}
    # libsafe is clean (no vulns) and libmystery has no audit facts at all.
    assert units["web-bundle#shared"]["findings"] == [ledger_dict["audit"]["dependencies"][0]]
    assert units["web-bundle#shared"]["unaudited"] == ["libmystery==0.1"]


def test_project_ignores_skipped_dependencies_in_report():
    ledger_dict = _ledger_dict()
    ledger_dict["audit"]["dependencies"].append({"name": "libskipped", "skip_reason": "nope"})
    projection = project(Ledger.from_dict(ledger_dict))

    assert projection["summary"]["deliverable_layer_pending"] == 3


def test_project_matches_canonical_names_and_normalized_versions():
    ledger_dict = _ledger_dict()
    ledger_dict["release_packages"][0]["dependencies"][0] = {
        "name": "LibFoo",
        "version": "v1.2.3",
    }
    projection = project(Ledger.from_dict(ledger_dict))

    assert projection["summary"]["deliverable_layer_pending"] == 3


def test_ledger_load(tmp_path):
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(_ledger_dict()))

    ledger = Ledger.load(ledger_path)
    assert len(ledger.release_packages) == 2


def test_ledger_load_external_audit_report(tmp_path):
    ledger_dict = _ledger_dict()
    report = ledger_dict.pop("audit")
    (tmp_path / "report.json").write_text(json.dumps(report))
    ledger_dict["audit_report"] = "report.json"
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger_dict))

    ledger = Ledger.load(ledger_path)
    assert ledger.audit_report == report


def test_ledger_load_missing_file(tmp_path):
    with pytest.raises(LedgerError, match="cannot read ledger"):
        Ledger.load(tmp_path / "missing.json")


def test_ledger_load_invalid_json(tmp_path):
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text("{not json")
    with pytest.raises(LedgerError, match="not valid JSON"):
        Ledger.load(ledger_path)


def test_ledger_load_missing_audit_report_file(tmp_path):
    ledger_dict = _ledger_dict()
    ledger_dict.pop("audit")
    ledger_dict["audit_report"] = "missing.json"
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger_dict))

    with pytest.raises(LedgerError, match="cannot read audit report"):
        Ledger.load(ledger_path)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda d: d.pop("release_packages"), "release_packages"),
        (lambda d: d.pop("services"), "services"),
        (lambda d: d.pop("audit"), "audit"),
        (
            lambda d: d["release_packages"].append(d["release_packages"][0]),
            "duplicate release package",
        ),
        (lambda d: d["services"].append(d["services"][0]), "duplicate service"),
        (
            lambda d: d["services"][0]["uses"].append({"package": "nope"}),
            "unknown release package",
        ),
        (
            lambda d: d["services"][0]["uses"][0].update({"provenance": "vendored"}),
            "provenance must be one of",
        ),
        (lambda d: d.update({"audit": {"dependencies": {}}}), "dependencies"),
    ],
)
def test_ledger_invalid(mutation, match):
    ledger_dict = _ledger_dict()
    mutation(ledger_dict)
    with pytest.raises(LedgerError, match=match):
        Ledger.from_dict(ledger_dict)


def test_ledger_from_dict_not_an_object():
    with pytest.raises(LedgerError, match="must be a JSON object"):
        Ledger.from_dict([1, 2, 3])
