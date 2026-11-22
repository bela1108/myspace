import json
from pathlib import Path

import pytest

from pip_audit._handover import (
    HandoverIntegrityError,
    apply_receipt,
    build_handover,
    load_file,
    new_state,
    reconcile,
    verify_handover,
)
from pip_audit._handover_cli import main

EXAMPLE = Path(__file__).parent.parent / "examples" / "handover"


def _plan(required_evidence=None):
    item = {
        "item_id": "REM-001",
        "package": "requests",
        "target_version": "2.32.4",
        "vulnerability_ids": ["CVE-2024-35195"],
    }
    if required_evidence is not None:
        item["required_evidence"] = required_evidence
    return {"plan_id": "PLAN-DEMO", "items": [item]}


def _audit():
    return {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.31.0",
                "vulns": [{"id": "CVE-2024-35195", "fix_versions": ["2.32.4"]}],
            }
        ]
    }


def _environment():
    return {"packages": [{"name": "requests", "version": "2.31.0"}]}


def _package(required_evidence=None):
    return build_handover(_plan(required_evidence), _audit(), _environment())


def _alias(package):
    return package["items"][0]["receipt_names"][0]


def test_build_binds_inputs_and_redacts_urls_and_paths():
    plan = _plan()
    plan["source"] = {
        "index_url": "https://mirror.internal.example/simple",
        "path": "/srv/remediation/plan.json",
    }
    audit = _audit()
    audit["dependencies"][0]["download_url"] = "https://files.internal.example/x.whl"
    audit["dependencies"][0]["vulns"][0]["description"] = (
        "see https://security.internal.example/advisory"
    )
    audit["fixes"] = [{"path": "/srv/app/lib", "index_url": "https://mirror/x"}]
    environment = _environment()
    environment["source_path"] = "/srv/app/requirements.txt"
    environment["index_url"] = "https://mirror.internal.example/simple"

    package = build_handover(plan, audit, environment)
    verify_handover(package)

    rendered = json.dumps(package)
    assert "http://" not in rendered
    assert "https://" not in rendered
    assert "/srv/" not in rendered
    assert "index_url" not in rendered
    assert "download_url" not in rendered

    item = package["items"][0]
    assert item["target"]["identity"] == "pypi:requests@2.32.4"
    assert item["environment_confirmation"]["version"] == "2.31.0"
    assert item["target"]["version"] == "2.32.4"
    assert item["plan_item_id"] == "REM-001"


def test_name_only_receipt_returns_missing_materials():
    package = _package()
    state = new_state(package)
    receipt = {"receipt_id": "R1", "items": [{"name": _alias(package)}]}

    state, report = apply_receipt(package, state, receipt)

    assert state["items"][0]["state"] == "in_progress"
    assert state["items"][0]["missing_materials"] == [
        "fixed_version",
        "vulnerability_recheck",
    ]
    assert report["status"] == "partial"
    assert report["missing_materials"][0]["materials"] == [
        "fixed_version",
        "vulnerability_recheck",
    ]


def test_duplicate_item_is_idempotent_and_does_not_close_early():
    package = _package(["fixed_version", "artifact_digest"])
    state = new_state(package)
    alias = _alias(package)
    first = {
        "receipt_id": "R1",
        "items": [{"name": alias, "confirmed_version": "2.32.4"}],
    }
    second = {
        "receipt_id": "R2",
        "items": [{"name": alias, "confirmed_version": "2.32.4"}],
    }

    state, first_report = apply_receipt(package, state, first)
    state, second_report = apply_receipt(package, state, second)

    assert first_report["status"] == "partial"
    assert second_report["status"] == "partial"
    assert second_report["duplicate_items"] == [alias]
    assert state["items"][0]["state"] == "in_progress"
    assert state["items"][0]["unique_receipt_lines"] == 1
    assert state["items"][0]["duplicate_lines"] == 1
    assert state["items"][0]["missing_materials"] == ["artifact_digest"]


def test_replayed_receipt_id_does_not_change_state():
    package = _package()
    state = new_state(package)
    receipt = {
        "receipt_id": "R1",
        "items": [
            {
                "name": _alias(package),
                "confirmed_version": "2.32.4",
                "evidence": {
                    "vulnerability_recheck": {
                        "status": "clean",
                        "vulnerability_ids": ["CVE-2024-35195"],
                    }
                },
            }
        ],
    }
    state, report = apply_receipt(package, state, receipt)
    assert report["status"] == "closed"
    before = json.dumps(state, sort_keys=True)

    state, replay = apply_receipt(package, state, receipt)
    assert replay["status"] == "duplicate_receipt"
    assert json.dumps(state, sort_keys=True) == before


def test_tampered_package_is_rejected():
    package = _package()
    package["items"][0]["target"]["version"] = "9.9.9"
    with pytest.raises(HandoverIntegrityError):
        verify_handover(package)


def test_example_three_receipts_end_with_one_item_in_progress():
    package = load_file(EXAMPLE / "handover-package.json")
    receipts = [
        EXAMPLE / "receipt-01-requests-complete.json",
        EXAMPLE / "receipt-02-requests-repeat.json",
        EXAMPLE / "receipt-03-jinja2-partial.json",
    ]
    state, reports = reconcile(package, receipts)
    checked_state = load_file(EXAMPLE / "state.json")

    assert state == checked_state
    assert [report["status"] for report in reports] == [
        "partial",
        "partial",
        "partial",
    ]
    assert reports[1]["duplicate_items"] == ["ha-79e00bff1ecf388213dd"]
    assert state["summary"]["closed"] == 1
    assert state["summary"]["in_progress"] == 1
    assert state["items"][0]["duplicate_lines"] == 1
    assert state["items"][1]["missing_materials"] == [
        "fixed_version",
        "vulnerability_recheck",
    ]


def test_cli_build_and_receive(tmp_path):
    plan_path = tmp_path / "plan.json"
    audit_path = tmp_path / "audit.json"
    env_path = tmp_path / "environment.json"
    package_path = tmp_path / "package.json"
    receipt_path = tmp_path / "receipt.json"
    state_path = tmp_path / "state.json"
    report_path = tmp_path / "report.json"

    plan_path.write_text(json.dumps(_plan()))
    audit_path.write_text(json.dumps(_audit()))
    env_path.write_text(json.dumps(_environment()))

    assert (
        main(
            [
                "build",
                "--plan",
                str(plan_path),
                "--audit",
                str(audit_path),
                "--environment",
                str(env_path),
                "--output",
                str(package_path),
            ]
        )
        == 0
    )
    package = load_file(package_path)
    receipt_path.write_text(
        json.dumps(
            {
                "receipt_id": "R1",
                "items": [
                    {
                        "name": _alias(package),
                        "confirmed_version": "2.32.4",
                        "evidence": {
                            "vulnerability_recheck": {
                                "status": "clean",
                                "vulnerability_ids": ["CVE-2024-35195"],
                            }
                        },
                    }
                ],
            }
        )
    )

    assert (
        main(
            [
                "receive",
                "--package",
                str(package_path),
                "--receipt",
                str(receipt_path),
                "--state",
                str(state_path),
                "--output",
                str(report_path),
            ]
        )
        == 0
    )
    assert load_file(report_path)["status"] == "closed"
    assert load_file(state_path)["summary"]["closed"] == 1


def test_partial_package_returns_missing_environment_material():
    plan = _plan()
    plan["items"].append(
        {
            "item_id": "REM-002",
            "package": "jinja2",
            "target_version": "3.1.5",
        }
    )
    audit = _audit()
    audit["dependencies"].append({"name": "jinja2", "version": "3.1.4"})

    package = build_handover(plan, audit, _environment())

    assert package["status"] == "partial"
    assert {
        "plan_item_id": "REM-002",
        "materials": ["environment_confirmation", "fixed_version", "vulnerability_recheck"],
    } in package["missing_materials"]
    assert package["items"][1]["environment_confirmation"]["status"] == "missing"


def test_name_only_receipt_closes_when_package_has_target_evidence():
    audit = {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.32.4",
                "vulns": [],
            }
        ]
    }
    environment = {"packages": [{"name": "requests", "version": "2.32.4"}]}
    package = build_handover(_plan(), audit, environment)
    state = new_state(package)

    assert package["status"] == "ready"
    assert state["items"][0]["missing_materials"] == ["receipt_acknowledgement"]

    state, report = apply_receipt(
        package,
        state,
        {"receipt_id": "R1", "items": [{"name": _alias(package)}]},
    )

    assert report["status"] == "closed"
    assert state["items"][0]["state"] == "closed"


def test_plain_text_receipt_contains_only_rotated_names():
    package = _package()
    state = new_state(package)

    state, report = apply_receipt(package, state, _alias(package) + "\n")

    assert report["items"][0]["plan_item_id"] == "REM-001"
    assert "receipt_acknowledgement" in state["items"][0]["received_materials"]
