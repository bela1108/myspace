import json

from regipy.disposition import (
    STATUS_MATERIALS,
    STATUS_PRESERVE,
    STATUS_READY,
    CaseContext,
    evaluate_case,
    main,
    render_markdown,
)

POLICY = {
    "policy_id": "EP-WIN-2026-11",
    "version": "2026.11.2",
    "evidence_valid_days": 7,
    "requirements": [],
}


def write_case(tmp_path, approvals=None, devices=None, policies=None):
    approval_path = tmp_path / "independent_approvals.json"
    approval_path.write_text(
        json.dumps({"records": approvals or []}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    case = {
        "case_id": "LEGAL-HOLD-WEEK-47",
        "as_of": "2026-11-27T10:00:00+08:00",
        "reviewer": "incident-response",
        "policies": policies if policies is not None else [POLICY],
        "approval_files": [approval_path.name],
        "devices": devices or [],
    }
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(case, ensure_ascii=False, indent=2), encoding="utf-8")
    return case_path, approval_path


def observation(stamp, value, *, event_type=None, version="2026.11.2", compliant=True, key="execution_policy"):
    item = {
        "policy_id": "EP-WIN-2026-11",
        "policy_version": version,
        "assertion_key": key,
        "plugin": "execution_policy",
        "field": "execution_policy",
        "value": value,
        "compliant": compliant,
        "chronology_at": stamp,
        "observed_at": stamp,
        "collected_at": "2026-11-26T09:30:00+08:00",
    }
    if event_type:
        item["event_type"] = event_type
    return item


def two_device_case(tmp_path):
    approvals = [
        {
            "record_id": "APR-RELEASE-002",
            "device_id": "PC-RELEASE-02",
            "policy_id": "EP-WIN-2026-11",
            "policy_version": "2026.11.2",
            "decision": "approved",
            "decided_at": "2026-11-23T18:20:00+08:00",
            "approver": "legal-custodian",
            "reference": "legal-hold-register.md#release-002",
        },
        {
            "record_id": "APR-STALE-001",
            "device_id": "PC-ROLLBACK-01",
            "policy_id": "EP-WIN-2026-11",
            "policy_version": "2026.11.2",
            "decision": "approved",
            "decided_at": "2026-11-25T11:00:00+08:00",
            "reference": "legal-hold-register.md#old-001",
        },
    ]
    devices = [
        {
            "device_id": "PC-RELEASE-02",
            "batch": "first-batch",
            "observations": [
                observation("2026-11-21T09:00:00+08:00", "AllSigned", event_type="apply"),
                observation("2026-11-22T10:00:00+08:00", "RemoteSigned", event_type="overwrite", compliant=False),
                observation("2026-11-23T15:00:00+08:00", "AllSigned", event_type="apply"),
                observation("2026-11-23T15:05:00+08:00", "baseline-sha256:aaaa", key="baseline_hash"),
            ],
        },
        {
            "device_id": "PC-ROLLBACK-01",
            "batch": "second-batch",
            "observations": [
                observation("2026-11-24T09:00:00+08:00", "AllSigned", event_type="apply"),
                observation("2026-11-24T09:05:00+08:00", "baseline-sha256:aaaa", key="baseline_hash"),
                observation(
                    "2026-11-26T20:15:00+08:00",
                    "RemoteSigned",
                    event_type="rollback",
                    version="2026.11.1",
                    compliant=False,
                ),
            ],
        },
    ]
    return write_case(tmp_path, approvals=approvals, devices=devices)


def test_two_device_release_list_explains_rollback_and_approval_source(tmp_path):
    case_path, approval_path = two_device_case(tmp_path)
    report = evaluate_case(json.loads(case_path.read_text(encoding="utf-8")), ctx=CaseContext.from_path(case_path))

    assert report["summary"] == {
        "device_count": 2,
        "ready_for_release": 1,
        "preserve": 1,
        "materials_required": 0,
        "cross_device_duplicate_groups": 3,
    }

    release = report["release_list"][0]
    assert release["device_id"] == "PC-RELEASE-02"
    approval = release["approval_basis"]
    assert approval["record_id"] == "APR-RELEASE-002"
    assert approval["source"]["path"] == approval_path.name
    assert approval["source"]["locator"] == "$.records[0]"
    assert approval["source"]["sha256"]

    rolled_back = next(device for device in report["devices"] if device["device_id"] == "PC-ROLLBACK-01")
    assert rolled_back["status"] == STATUS_PRESERVE
    assert rolled_back["releasable"] is False
    assert "LAST_ROLLBACK_WITHOUT_RECOVERY" in rolled_back["reasons"]
    assert "APPROVAL_BEFORE_LAST_CHANGE" in rolled_back["reasons"]
    assert "APPROVAL_VERSION_MISMATCH" in rolled_back["reasons"]
    assert rolled_back["last_rollback"]["event_type"] == "rollback"

    duplicate_groups = report["duplicate_values"]
    assert {tuple(group["device_ids"]) for group in duplicate_groups} == {
        ("PC-RELEASE-02", "PC-ROLLBACK-01"),
    }
    assert all(len(group["device_ids"]) == 2 for group in duplicate_groups)

    markdown = render_markdown(report)
    assert "PC-RELEASE-02" in markdown
    assert "APR-RELEASE-002" in markdown
    assert approval_path.name in markdown
    assert "PC-ROLLBACK-01" in markdown
    assert "最后回滚" in markdown
    assert "跨设备重复值" in markdown


def test_missing_policy_version_requests_specific_materials(tmp_path):
    devices = [
        {
            "device_id": "PC-MISSING-VERSION",
            "observations": [
                {
                    "policy_id": "EP-WIN-2026-11",
                    "assertion_key": "execution_policy:ExecutionPolicy",
                    "plugin": "execution_policy",
                    "field": "execution_policy",
                    "value": "AllSigned",
                    "compliant": True,
                    "chronology_at": "2026-11-26T15:00:00+08:00",
                    "collected_at": "2026-11-26T15:30:00+08:00",
                }
            ],
        }
    ]
    case_path, _ = write_case(tmp_path, approvals=[], devices=devices)
    report = evaluate_case(json.loads(case_path.read_text(encoding="utf-8")), ctx=CaseContext.from_path(case_path))
    device = report["devices"][0]

    assert device["status"] == STATUS_MATERIALS
    assert device["disposition"] == "preserve"
    assert "MISSING_POLICY_VERSION" in device["reasons"]
    codes = {material["code"] for material in report["materials_required"]}
    assert "MISSING_POLICY_VERSION" in codes
    assert "MISSING_VERSIONED_APPROVAL" in codes
    missing_material = next(item for item in report["materials_required"] if item["code"] == "MISSING_POLICY_VERSION")
    assert "ADMX" in missing_material["material"]
    assert "regipy-plugins-run" in missing_material["suggested_command"]


def test_expired_evidence_blocks_release(tmp_path):
    old_observation = observation("2026-11-10T09:00:00+08:00", "AllSigned", event_type="apply")
    old_observation["collected_at"] = "2026-11-10T09:30:00+08:00"
    devices = [{"device_id": "PC-EXPIRED", "observations": [old_observation]}]
    approvals = [
        {
            "record_id": "APR-EXPIRED-EVIDENCE",
            "device_id": "PC-EXPIRED",
            "policy_id": "EP-WIN-2026-11",
            "policy_version": "2026.11.2",
            "decision": "approved",
            "decided_at": "2026-11-10T12:00:00+08:00",
        }
    ]
    case_path, _ = write_case(tmp_path, approvals=approvals, devices=devices)
    report = evaluate_case(json.loads(case_path.read_text(encoding="utf-8")), ctx=CaseContext.from_path(case_path))

    assert report["devices"][0]["status"] == STATUS_MATERIALS
    assert "EVIDENCE_EXPIRED" in report["devices"][0]["reasons"]


def test_missing_explicit_collection_time_blocks_release(tmp_path):
    item = observation("2026-11-26T09:00:00+08:00", "AllSigned", event_type="apply")
    item.pop("collected_at")
    devices = [{"device_id": "PC-NO-COLLECTION-TIME", "observations": [item]}]
    approvals = [
        {
            "record_id": "APR-NO-COLLECTION-TIME",
            "device_id": "PC-NO-COLLECTION-TIME",
            "policy_id": "EP-WIN-2026-11",
            "policy_version": "2026.11.2",
            "decision": "approved",
            "decided_at": "2026-11-26T12:00:00+08:00",
        }
    ]
    case_path, _ = write_case(tmp_path, approvals=approvals, devices=devices)
    report = evaluate_case(json.loads(case_path.read_text(encoding="utf-8")), ctx=CaseContext.from_path(case_path))

    device = report["devices"][0]
    assert device["releasable"] is False
    assert "EVIDENCE_TIME_OR_TTL_UNVERIFIABLE" in device["reasons"]


def test_regipy_plugin_json_snapshot_is_extracted(tmp_path):
    plugin_json = tmp_path / "PC-plugin-output.json"
    plugin_json.write_text(
        json.dumps(
            {
                "execution_policy": [
                    {
                        "type": "powershell_policy",
                        "key_path": r"\Policies\Microsoft\Windows\PowerShell",
                        "execution_policy": "AllSigned",
                        "last_write": "2026-11-23T15:00:00+08:00",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy = {
        "policy_id": "EP-WIN-2026-11",
        "version": "2026.11.2",
        "evidence_valid_days": 7,
        "requirements": [
            {
                "plugin": "execution_policy",
                "field": "execution_policy",
                "where": {"type": "powershell_policy"},
                "expected": "AllSigned",
            }
        ],
    }
    devices = [
        {
            "device_id": "PC-PLUGIN-JSON",
            "evidence_snapshots": [
                {
                    "id": "snapshot-2026-11-26",
                    "collected_at": "2026-11-26T09:30:00+08:00",
                    "policy_id": "EP-WIN-2026-11",
                    "policy_version": "2026.11.2",
                    "plugin_output": plugin_json.name,
                }
            ],
        }
    ]
    approvals = [
        {
            "record_id": "APR-PLUGIN-JSON",
            "device_id": "PC-PLUGIN-JSON",
            "policy_id": "EP-WIN-2026-11",
            "policy_version": "2026.11.2",
            "decision": "approved",
            "decided_at": "2026-11-24T10:00:00+08:00",
        }
    ]
    case_path, _ = write_case(tmp_path, approvals=approvals, devices=devices, policies=[policy])
    report = evaluate_case(json.loads(case_path.read_text(encoding="utf-8")), ctx=CaseContext.from_path(case_path))
    device = report["devices"][0]

    assert device["releasable"] is True
    assert device["status"] == STATUS_READY
    assert device["observations"][0]["plugin_name"] == "execution_policy"
    assert device["observations"][0]["compliant"] is True


def test_cli_writes_markdown_and_json(tmp_path):
    case_path, _ = two_device_case(tmp_path)
    markdown_path = tmp_path / "release-list.md"
    json_path = tmp_path / "release-list.json"
    exit_code = main([str(case_path), "-o", str(markdown_path), "--json-output", str(json_path)])

    assert exit_code == 0
    assert markdown_path.exists()
    assert json_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["ready_for_release"] == 1

    strict_code = main([str(case_path), "--strict", "-o", str(tmp_path / "strict.md")])
    assert strict_code == 1


def test_live_regipy_hive_adapter_runs_named_plugin(software_hive):
    from regipy.disposition import _run_hive_snapshot

    plugin_results = _run_hive_snapshot(
        {"hive_path": software_hive, "plugins": ["execution_policy"]},
        {},
        CaseContext(),
    )
    assert isinstance(plugin_results, dict)
    assert "execution_policy" in plugin_results or plugin_results == {}
