import json
from pathlib import Path

import pytest

from pip_audit.handover import (
    HandoverError,
    build_handover,
    main,
    render_markdown,
    verify_handover,
)

_EXAMPLES = Path(__file__).parent.parent / "examples" / "handover"


def _load_example(name: str):
    return json.loads((_EXAMPLES / name).read_text())


def _sample_material():
    plan = _load_example("remediation-plan.json")
    audit = _load_example("pip-audit-offline.json")
    receipts = [
        _load_example("receipts/RCPT-1001.json"),
        _load_example("receipts/RCPT-1002.json"),
        _load_example("receipts/RCPT-1003.json"),
    ]
    return plan, audit, receipts


def test_sample_handover_reconciles_item_by_item():
    plan, audit, receipts = _sample_material()
    package = build_handover(plan, audit, receipts)

    assert package["schema_version"] == "pip-audit-handover/1"
    assert package["status"] == "in_progress"
    assert package["complete"] is False
    assert package["summary"] == {
        "item_count": 2,
        "closed_items": 1,
        "in_progress_items": 1,
        "receipt_count": 3,
        "duplicate_receipts": 1,
        "unmatched_receipts": 0,
        "missing_material_count": 2,
    }

    by_id = {item["plan_item_id"]: item for item in package["items"]}
    assert by_id["RMD-001"]["status"] == "closed"
    assert by_id["RMD-001"]["missing_materials"] == []
    assert by_id["RMD-002"]["status"] == "in_progress"
    assert by_id["RMD-002"]["missing_materials"] == ["hash_manifest", "vendor_attestation"]
    assert by_id["RMD-002"]["duplicate_receipts"] == [
        {
            "receipt_id": "RCPT-1003",
            "duplicate_of": "RCPT-1002",
            "reason": "same_item_same_material_set",
        }
    ]

    assert package["missing_materials"] == {
        "RMD-001": [],
        "RMD-002": ["hash_manifest", "vendor_attestation"],
    }
    assert package["status_reason"] == "incomplete_evidence"
    assert package["environment"]["confirmed_versions"] == {
        "urllib3": "2.2.2",
        "jinja2": "3.1.4",
    }
    assert package["pending_missing_materials"] == {
        "RMD-002": ["hash_manifest", "vendor_attestation"]
    }
    assert [receipt["receipt_id"] for receipt in package["receipts"]] == [
        "RCPT-1001",
        "RCPT-1002",
        "RCPT-1003",
    ]
    register = {receipt["receipt_id"]: receipt for receipt in package["receipts"]}
    assert register["RCPT-1003"]["duplicate"] is True
    assert register["RCPT-1003"]["duplicate_of"] == "RCPT-1002"
    assert package["signoff"]["ready"] is False
    assert package["signoff"]["ready_items"] == ["RMD-001"]
    assert package["signoff"]["pending_items"] == ["RMD-002"]
    assert verify_handover(package) is True


def test_rotating_aliases_resolve_to_the_same_target():
    plan, audit, receipts = _sample_material()
    package = build_handover(plan, audit, receipts)
    item = next(item for item in package["items"] if item["plan_item_id"] == "RMD-002")

    assert item["target"]["aliases"] == ["HERON-09", "HERON-22"]
    assert [receipt["receipt_id"] for receipt in item["receipts"]] == ["RCPT-1002"]
    assert item["duplicate_receipts"][0]["receipt_id"] == "RCPT-1003"


def test_duplicate_receipt_does_not_close_item_early():
    plan = {
        "plan_id": "P-1",
        "items": [
            {
                "item_id": "I-1",
                "package": "demo",
                "target_version": "2.0",
                "aliases": ["D-ALPHA", "D-BETA"],
                "required_materials": ["version_confirmation", "hash_manifest"],
            }
        ],
    }
    audit = {"dependencies": [{"name": "demo", "version": "2.0", "vulns": []}]}
    receipts = [
        {
            "receipt_id": "R-1",
            "item_id": "D-ALPHA",
            "version": "2.0",
            "materials": ["version_confirmation"],
        },
        {
            "receipt_id": "R-2",
            "item_id": "D-BETA",
            "version": "2.0",
            "materials": ["version_confirmation"],
        },
    ]

    package = build_handover(plan, audit, receipts)
    item = package["items"][0]

    assert item["status"] == "in_progress"
    assert item["missing_materials"] == ["hash_manifest"]
    assert package["duplicates"] == [
        {
            "receipt_id": "R-2",
            "duplicate_of": "R-1",
            "reason": "same_item_same_material_set",
        }
    ]
    assert package["complete"] is False


def test_partial_handover_returns_missing_materials():
    plan = {
        "plan_id": "P-2",
        "items": [
            {
                "item_id": "I-1",
                "package": "demo",
                "target_version": "2.0",
                "required_materials": ["hash_manifest"],
            }
        ],
    }
    audit = {"dependencies": [{"name": "demo", "version": "2.0"}]}

    package = build_handover(plan, audit, [])
    assert package["complete"] is False
    assert package["missing_materials"] == {"I-1": ["hash_manifest"]}
    assert package["next_actions"] == [
        {
            "item_id": "I-1",
            "target_id": "demo@2.0",
            "missing_materials": ["hash_manifest"],
            "action": "request_missing_materials",
        }
    ]


def test_redacts_index_urls_and_internal_paths():
    plan = {
        "plan_id": "P-private",
        "title": "mirror https://packages.internal.example/simple and /srv/repo/pypi",
        "index_url": "https://packages.internal.example/simple",
        "extra_index_urls": ["file:///srv/artifactory/wheels"],
        "items": [
            {
                "item_id": "I-1",
                "package": "demo",
                "target_version": "2.0",
                "notes": "cached at /var/cache/pip/demo.whl",
                "required_materials": [],
            }
        ],
    }
    audit = {"dependencies": [{"name": "demo", "version": "2.0"}]}

    package = build_handover(plan, audit, [])
    rendered = json.dumps(package, sort_keys=True)

    assert "packages.internal.example" not in rendered
    assert "/srv/repo/pypi" not in rendered
    assert "/var/cache/pip" not in rendered
    assert "https://" not in rendered
    assert "file://" not in rendered
    assert "index_url" not in rendered
    assert "extra_index_urls" not in rendered
    assert package["redactions"]["count"] >= 2
    assert package["redactions"]["kinds"]["field"] >= 2
    assert package["redactions"]["kinds"]["url"] >= 1
    assert package["redactions"]["kinds"]["path"] >= 1
    assert verify_handover(package) is True


def test_version_mismatch_leaves_item_in_progress():
    plan = {
        "plan_id": "P-3",
        "items": [
            {
                "item_id": "I-1",
                "package": "demo",
                "target_version": "2.0",
                "required_materials": ["version_confirmation"],
            }
        ],
    }
    audit = {"dependencies": [{"name": "demo", "version": "1.9"}]}
    receipts = [
        {
            "receipt_id": "R-1",
            "item_id": "I-1",
            "version": "2.0",
            "materials": ["version_confirmation"],
        }
    ]

    package = build_handover(plan, audit, receipts)
    item = package["items"][0]

    assert item["status"] == "in_progress"
    assert item["environment"] == {
        "confirmed": False,
        "version": "1.9",
        "target_version": "2.0",
        "match": "exact",
        "source": "pip-audit-offline",
        "evidence_sha256": item["environment"]["evidence_sha256"],
        "vulnerabilities": [],
    }
    assert item["missing_materials"] == ["environment_version"]


def test_unmatched_receipt_is_reported():
    plan = {
        "plan_id": "P-4",
        "items": [
            {
                "item_id": "I-1",
                "package": "demo",
                "target_version": "2.0",
                "required_materials": [],
            }
        ],
    }
    audit = {"dependencies": [{"name": "demo", "version": "2.0"}]}
    receipts = [{"receipt_id": "R-404", "item_id": "UNKNOWN", "materials": ["hash_manifest"]}]

    package = build_handover(plan, audit, receipts)
    assert package["unmatched_receipts"] == [
        {"receipt_id": "R-404", "reason": "unmatched", "refs": ["UNKNOWN"]}
    ]


def test_hmac_signature_round_trip():
    plan, audit, receipts = _sample_material()
    package = build_handover(plan, audit, receipts, signing_key="shared-secret")

    assert package["signoff"]["signature"]["method"] == "hmac-sha256"
    assert verify_handover(package, signing_key="shared-secret") is True
    assert verify_handover(package, signing_key="wrong-secret") is False
    assert verify_handover(package) is False


def test_markdown_is_signable_and_lists_missing_materials():
    plan, audit, receipts = _sample_material()
    package = build_handover(plan, audit, receipts)
    markdown = render_markdown(package)

    assert "# Dependency Remediation Handover" in markdown
    assert "RMD-002" in markdown
    assert "hash_manifest, vendor_attestation" in markdown
    assert "Approver: ______________________________" in markdown
    assert package["signoff"]["payload_sha256"] in markdown


def test_cli_writes_json_and_markdown_pair(tmp_path):
    output_dir = tmp_path / "handover"
    exit_code = main(
        [
            "--plan",
            str(_EXAMPLES / "remediation-plan.json"),
            "--audit",
            str(_EXAMPLES / "pip-audit-offline.json"),
            "--receipt",
            str(_EXAMPLES / "receipts" / "RCPT-1001.json"),
            "--receipt",
            str(_EXAMPLES / "receipts" / "RCPT-1002.json"),
            "--receipt",
            str(_EXAMPLES / "receipts" / "RCPT-1003.json"),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    package = json.loads((output_dir / "handover.json").read_text())
    assert verify_handover(package) is True
    assert (output_dir / "HANDOVER.md").is_file()


def test_cli_fail_on_incomplete(tmp_path):
    exit_code = main(
        [
            "--plan",
            str(_EXAMPLES / "remediation-plan.json"),
            "--audit",
            str(_EXAMPLES / "pip-audit-offline.json"),
            "--receipt",
            str(_EXAMPLES / "receipts" / "RCPT-1001.json"),
            "--output",
            str(tmp_path / "handover.json"),
            "--fail-on-incomplete",
        ]
    )

    assert exit_code == 2


def test_invalid_plan_raises_handover_error():
    with pytest.raises(HandoverError):
        build_handover({"plan_id": "bad"}, {"dependencies": []}, [])


def test_camel_case_inputs_and_material_flags_are_supported():
    plan = {
        "planId": "P-camel",
        "items": [
            {
                "itemId": "I-camel",
                "package": "demo",
                "targetVersion": "2.0",
                "requiredMaterials": ["hashManifest"],
            }
        ],
    }
    audit = {"dependencies": [{"name": "demo", "version": "2.0"}]}
    receipts = [
        {
            "receiptId": "R-camel",
            "itemId": "I-camel",
            "version": "2.0",
            "materials": {"hashManifest": {"provided": False}},
        }
    ]

    package = build_handover(plan, audit, receipts)
    item = package["items"][0]
    assert item["status"] == "in_progress"
    assert item["missing_materials"] == ["hash_manifest"]

    receipts[0]["materials"] = {"hashManifest": {"provided": True, "sha256": "abc"}}
    package = build_handover(plan, audit, receipts)
    assert package["items"][0]["status"] == "closed"


def test_committed_sample_package_is_verifiable():
    package = json.loads((_EXAMPLES / "handover.json").read_text())

    assert verify_handover(package) is True
    assert package["status"] == "in_progress"
    assert package["summary"]["closed_items"] == 1
    assert package["summary"]["in_progress_items"] == 1
    assert package["missing_materials"]["RMD-002"] == ["hash_manifest", "vendor_attestation"]
    assert (_EXAMPLES / "HANDOVER.md").is_file()


def test_single_mapping_receipt_and_audit_map_are_supported():
    plan = {
        "plan_id": "P-single",
        "items": [
            {
                "item_id": "I-1",
                "package": "demo",
                "target_version": "2.0",
                "aliases": ["ROTATED-NAME"],
                "required_materials": ["hash_manifest"],
            }
        ],
    }
    audit = {"dependencies": {"demo": "2.0"}}
    receipts = {
        "receipt_id": "R-single",
        "target": "ROTATED-NAME",
        "materials": ["hash_manifest"],
    }

    package = build_handover(plan, audit, receipts)
    assert package["items"][0]["status"] == "closed"
    assert package["summary"]["receipt_count"] == 1
