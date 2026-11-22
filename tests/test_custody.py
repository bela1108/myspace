import json
import subprocess
import sys
from pathlib import Path

from Evtx.Custody import (
    NOT_ACCEPTED,
    REVIEWABLE,
    SUMMARY_ONLY,
    reconcile_custody,
    sanitize_external,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "custody"


def statuses(report, evidence_id=None):
    result = []
    for evidence in report["evidence"]:
        if evidence_id and evidence["evidence_id"] != evidence_id:
            continue
        for segment in evidence["segments"]:
            result.append((segment["start"], segment["end"], segment["status"], segment["reason"]))
    return result


def base_case(**overrides):
    case = {
        "custodian": {"id": "custodian", "permissions": [{"access": "full"}]},
        "evidence": [{"evidence_id": "e", "ranges": ["1-3"]}],
        "receipts": [
            {
                "receipt_id": "r1",
                "kind": "handover",
                "signer_id": "u-b",
                "signed_at": "2026-01-02T00:00:00Z",
                "scope": ["1-3"],
            }
        ],
        "external_manifest": [{"evidence_id": "e", "start": 1, "end": 3, "receipt_id": "r1"}],
        "responsibility": [{"principal_id": "u-b", "actual_name": "Li Na", "role": "custodian"}],
    }
    case.update(overrides)
    return case


def test_sample_custody_partitions():
    report = reconcile_custody(str(SAMPLE / "case.json"))
    assert report["summary"]["reviewable_records"] == 4
    assert report["summary"]["summary_only_records"] == 1
    assert report["summary"]["not_accepted_records"] == 1
    assert statuses(report, "system-short.evtx") == [
        (12049, 12050, REVIEWABLE, "signed_scope_and_full_access"),
        (12051, 12051, SUMMARY_ONLY, "custodian_has_summary_only"),
    ]
    assert statuses(report, "security-short.evtx") == [
        (1, 2, REVIEWABLE, "signed_scope_and_full_access"),
        (3, 3, NOT_ACCEPTED, "signed_after_deadline"),
    ]
    assert report["signer_verification"]["internal_table_used"] is True
    assert report["signer_verification"]["prior_holder_possession_ignored"] is True
    assert report["signer_verification"]["actual_signer"]["actual_name"] == "Li Na"
    assert report["handover_scope"]["scope_check"]["scope_matches"] is False


def test_possession_is_not_transfer():
    case = base_case(receipts=[], previous_holder={"id": "u-a", "still_holds_copy": True})
    report = reconcile_custody(case)
    assert statuses(report) == [(1, 3, NOT_ACCEPTED, "prior_holder_possession_not_transfer")]
    assert report["summary"]["reviewable_records"] == 0


def test_transferor_signature_only_is_not_acceptance():
    case = base_case(
        receipts=[
            {
                "receipt_id": "r1",
                "kind": "handover",
                "from_principal": "u-a",
                "to_principal": "u-b",
                "signer_id": "u-a",
                "signed_at": "2026-01-02T00:00:00Z",
                "scope": ["1-3"],
            }
        ]
    )
    report = reconcile_custody(case)
    assert statuses(report) == [(1, 3, NOT_ACCEPTED, "transferor_signature_only")]


def test_supplemental_receipt_cures_unsigned_handover():
    case = base_case(
        receipts=[
            {
                "receipt_id": "r1",
                "kind": "handover",
                "from_principal": "u-a",
                "to_principal": "u-b",
                "signer_id": "u-a",
                "status": "unsigned",
                "scope": ["1-3"],
            },
            {
                "receipt_id": "r2",
                "kind": "supplemental",
                "amends": "r1",
                "signer_id": "u-b",
                "signed_at": "2026-01-05T00:00:00Z",
                "scope": ["1-3"],
            },
        ]
    )
    report = reconcile_custody(case)
    assert statuses(report) == [(1, 3, REVIEWABLE, "signed_scope_and_full_access")]
    segment = report["evidence"][0]["segments"][0]
    assert segment["receipt_id"] == "r2"
    assert segment["signer"]["actual_name"] == "Li Na"


def test_late_receipt_is_not_accepted():
    case = base_case(
        archive_deadline="2026-01-01T00:00:00Z",
        receipts=[
            {
                "receipt_id": "r1",
                "kind": "handover",
                "signer_id": "u-b",
                "signed_at": "2026-01-02T00:00:00Z",
                "scope": ["1-3"],
            }
        ],
    )
    report = reconcile_custody(case)
    assert statuses(report) == [(1, 3, NOT_ACCEPTED, "signed_after_deadline")]
    assert report["signer_verification"]["signers"] == []


def test_permission_full_summary_and_denied():
    case = base_case(
        evidence=[{"evidence_id": "e", "ranges": ["1-2", "3-3", "4-4"]}],
        custodian={
            "id": "custodian",
            "permissions": [
                {"start": 1, "end": 2, "access": "full"},
                {"start": 3, "end": 3, "access": "summary"},
                {"start": 4, "end": 4, "access": "none"},
            ],
        },
        receipts=[
            {
                "receipt_id": "r1",
                "kind": "handover",
                "signer_id": "u-b",
                "signed_at": "2026-01-02T00:00:00Z",
                "scope": ["1-4"],
            }
        ],
        external_manifest=[{"evidence_id": "e", "start": 1, "end": 4, "receipt_id": "r1"}],
    )
    report = reconcile_custody(case)
    assert statuses(report) == [
        (1, 2, REVIEWABLE, "signed_scope_and_full_access"),
        (3, 3, SUMMARY_ONLY, "custodian_has_summary_only"),
        (4, 4, NOT_ACCEPTED, "permission_denied"),
    ]


def test_manifest_scope_mismatch_is_reported():
    case = base_case(external_manifest=[{"evidence_id": "e", "start": 1, "end": 1, "receipt_id": "r1"}])
    report = reconcile_custody(case)
    assert statuses(report) == [
        (1, 1, REVIEWABLE, "signed_scope_and_full_access"),
        (2, 3, NOT_ACCEPTED, "outside_external_manifest"),
    ]
    assert report["handover_scope"]["scope_check"]["receipt_without_manifest"] == 1
    assert report["handover_scope"]["scope_check"]["scope_matches"] is False


def test_signer_scope_mismatch_is_not_accepted():
    case = base_case(
        responsibility=[{"principal_id": "u-b", "actual_name": "Li Na", "scope": ["1-2"]}]
    )
    report = reconcile_custody(case)
    assert statuses(report) == [(1, 3, NOT_ACCEPTED, "signer_scope_mismatch")]


def test_missing_evtx_record_and_missing_source():
    case = base_case(
        evidence=[
            {
                "evidence_id": "e",
                "path": str(SAMPLE / "system-short.evtx"),
                "ranges": ["12048-12050"],
            }
        ],
        receipts=[
            {
                "receipt_id": "r1",
                "kind": "handover",
                "signer_id": "u-b",
                "signed_at": "2026-01-02T00:00:00Z",
                "scope": ["12048-12050"],
            }
        ],
        external_manifest=[{"evidence_id": "e", "start": 12048, "end": 12050, "receipt_id": "r1"}],
    )
    report = reconcile_custody(case)
    assert statuses(report) == [
        (12048, 12048, NOT_ACCEPTED, "record_missing"),
        (12049, 12050, REVIEWABLE, "signed_scope_and_full_access"),
    ]

    missing = base_case(
        evidence=[{"evidence_id": "e", "path": "/no/such/file.evtx", "ranges": ["1-3"]}]
    )
    report = reconcile_custody(missing)
    assert statuses(report) == [(1, 3, NOT_ACCEPTED, "source_unreadable")]


def test_record_time_cutoff_splits_range():
    case = base_case(
        evidence=[
            {
                "evidence_id": "e",
                "path": str(SAMPLE / "system-short.evtx"),
                "ranges": ["12049-12051"],
            }
        ],
        receipts=[
            {
                "receipt_id": "r1",
                "kind": "handover",
                "signer_id": "u-b",
                "signed_at": "2012-03-14T04:30:00Z",
                "scope": ["12049-12051"],
            }
        ],
        external_manifest=[{"evidence_id": "e", "start": 12049, "end": 12051, "receipt_id": "r1"}],
    )
    report = reconcile_custody(case, use_record_timestamps=True)
    assert statuses(report) == [
        (12049, 12050, REVIEWABLE, "signed_scope_and_full_access"),
        (12051, 12051, NOT_ACCEPTED, "record_after_signature"),
    ]


def test_external_report_omits_sensitive_fields_and_names():
    case = base_case(
        external_manifest=[
            {
                "evidence_id": "e",
                "start": 1,
                "end": 3,
                "receipt_id": "r1",
                "hostname": "HOST-SECRET",
                "summary": "secret summary",
                "actual_name": "Li Na",
                "path": "/secret/place/e.evtx",
            }
        ]
    )
    report = reconcile_custody(case)
    external = report.external_dict()
    serialized = json.dumps(external, ensure_ascii=False)
    assert "HOST-SECRET" not in serialized
    assert "secret summary" not in serialized
    assert "Li Na" not in serialized
    assert "/secret/place" not in serialized
    assert external["sensitive_fields_omitted"] is True
    assert report["warnings"]


def test_sanitize_external_keeps_safe_fields():
    result = sanitize_external(
        {
            "evidence_id": "e",
            "start": 1,
            "end": 2,
            "sha256": "abc",
            "hostname": "hidden",
            "actual_name": "hidden",
        }
    )
    assert result == {"evidence_id": "e", "start": 1, "end": 2, "sha256": "abc"}


def test_cli_json_and_external_outputs(tmp_path):
    command = [
        sys.executable,
        "-m",
        "evtx_scripts.evtx_custody_reconcile",
        str(SAMPLE / "case.json"),
    ]
    completed = subprocess.run(command + ["--json"], cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["summary"]["reviewable_records"] == 4

    external_path = tmp_path / "external.json"
    internal_path = tmp_path / "internal.json"
    completed = subprocess.run(
        command + ["--external-out", str(external_path), "--internal-out", str(internal_path), "--quiet"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    external = json.loads(external_path.read_text(encoding="utf-8"))
    internal = json.loads(internal_path.read_text(encoding="utf-8"))
    assert external["actual_signer"]["role"] == "long-term custodian"
    assert "Li Na" not in json.dumps(external, ensure_ascii=False)
    assert internal["signer_verification"]["actual_signer"]["actual_name"] == "Li Na"

    completed = subprocess.run(command + ["--strict"], cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 1


def test_manifest_summary_flag_marks_summary_only():
    case = base_case(
        external_manifest=[
            {
                "evidence_id": "e",
                "start": 1,
                "end": 3,
                "receipt_id": "r1",
                "summary_only": True,
            }
        ]
    )
    report = reconcile_custody(case)
    assert statuses(report) == [(1, 3, SUMMARY_ONLY, "manifest_carries_summary_only")]
    assert report["evidence"][0]["segments"][0]["summary_only"] is True


def test_internal_table_overrides_receipt_display_name():
    case = base_case(
        receipts=[
            {
                "receipt_id": "r1",
                "kind": "handover",
                "signer_id": "u-b",
                "signer_name": "archive delegate",
                "signed_at": "2026-01-02T00:00:00Z",
                "scope": ["1-3"],
            }
        ],
        responsibility=[
            {
                "receipt_id": "r1",
                "signer_id": "u-b",
                "actual_name": "Li Na",
                "role": "long-term custodian",
            }
        ],
    )
    report = reconcile_custody(case)
    assert report["actual_signer"]["actual_name"] == "Li Na"
    segment = report["evidence"][0]["segments"][0]
    assert segment["signer"]["actual_name"] == "Li Na"
    assert segment["signer"]["declared_name"] == "archive delegate"


def test_csv_external_manifest_is_loaded_offline(tmp_path):
    manifest = tmp_path / "external.csv"
    manifest.write_text(
        "evidence_id,record_start,record_end,receipt_id,hostname\n"
        "e,1,3,r1,HOST-SECRET\n",
        encoding="utf-8",
    )
    case = base_case(external_manifest=str(manifest))
    report = reconcile_custody(case)
    assert statuses(report) == [(1, 3, REVIEWABLE, "signed_scope_and_full_access")]
    assert "HOST-SECRET" not in report.external_json()


def test_require_responsibility_rejects_unverified_signer():
    case = base_case()
    case.pop("responsibility")
    report = reconcile_custody(case, require_responsibility=True)
    assert statuses(report) == [(1, 3, NOT_ACCEPTED, "signer_not_in_responsibility_table")]
