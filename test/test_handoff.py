"""Tests for offline vulnerability handoff reconciliation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pip_audit._handoff import (
    HandoffLedger,
    build_reopen_list,
    main,
    reconcile_handoffs,
)

ASSET = Path(__file__).parent / "assets" / "handoff_records.json"


def test_fake_batch_reopens_only_targeted_remediation() -> None:
    report = reconcile_handoffs(ASSET)

    assert [item.fragment_id for item in report.reopened] == ["DSP-A-REM-12"]
    reopened = report.reopened[0]
    assert reopened.advisory_id == "PYSEC-FAKE-0001"
    assert reopened.scope == "remediation"
    assert reopened.reason == "remediation_withdrawn"
    assert reopened.withdrawal_ids == ("WD-A-REM12",)

    preserved = {item.fragment_id: item for item in report.preserved}
    assert set(preserved) == {"DSP-A-REM-1X", "DSP-B-REM-20"}
    assert preserved["DSP-A-REM-1X"].preserved_by == "E-IMPACT-A1X"
    assert preserved["DSP-A-REM-1X"].evidence_ids == ("E-IMPACT-A1X", "E-SIG-OSV")
    assert preserved["DSP-B-REM-20"].preserved_by == "E-IMPACT-B20"
    assert "E-SIG-OSV" in preserved["DSP-B-REM-20"].evidence_ids
    assert report.common_evidence == "E-SIG-OSV"
    assert report["common_evidence_ids"] == ["E-SIG-OSV"]


def test_fake_batch_deduplicates_submissions_and_reports_missing_context() -> None:
    report = reconcile_handoffs(ASSET)

    assert report.duplicate_submissions == ("SUB-SIG-OSV", "SUB-WD-A12")
    codes = {item.code for item in report.unresolved}
    assert {
        "missing_remediation_context",
        "missing_evidence_id",
        "missing_fragment_id",
    } <= codes
    missing_withdrawal = next(
        item for item in report.unresolved if item.record_id == "WD-MISSING-CONTEXT"
    )
    assert missing_withdrawal.code == "missing_remediation_context"


def test_reopen_list_helper_returns_json_dicts() -> None:
    items = build_reopen_list(ASSET)

    assert items == [
        {
            "fragment_id": "DSP-A-REM-12",
            "advisory_id": "PYSEC-FAKE-0001",
            "scope": "remediation",
            "reason": "remediation_withdrawn",
            "withdrawal_ids": ["WD-A-REM12"],
            "remediation_id": "REM-A-12",
            "release_line": "1.2.x",
        }
    ]


def test_untyped_shorthand_records_are_inferred() -> None:
    report = reconcile_handoffs(
        [
            {
                "evidence_id": "E-S",
                "source_id": "fake-source",
                "advisory_ids": ["A1"],
            },
            {"fragment_id": "D1", "advisory_id": "A1", "fix_id": "R1"},
            {
                "withdrawal_id": "W1",
                "advisory_id": "A1",
                "scope": "fix",
                "fix_id": "R1",
            },
        ]
    )

    assert [item.fragment_id for item in report.reopened] == ["D1"]
    assert report.preserved == ()


def test_advisory_scope_withdrawal_reopens_every_advisory_fragment() -> None:
    report = reconcile_handoffs(
        {
            "records": [
                _signoff(),
                _fragment("D1", advisory_id="A1", remediation_id="R1", line="1.2"),
                _fragment("D2", advisory_id="A1", scope="release_line", line="2.x"),
                _fragment("D3", advisory_id="A2", remediation_id="R3", line="3.x"),
                {
                    "record_type": "withdrawal",
                    "withdrawal_id": "W-ALL",
                    "advisory_id": "A1",
                    "scope": "whole_advisory",
                },
            ]
        }
    )

    assert [item.fragment_id for item in report.reopened] == ["D1", "D2"]
    assert all(item.reason == "advisory_withdrawn" for item in report.reopened)
    assert [item.fragment_id for item in report.preserved] == ["D3"]
    assert report.preserved[0].preserved_by == "E-SRC"


def test_release_line_withdrawal_only_reopens_matching_line() -> None:
    report = reconcile_handoffs(
        {
            "records": [
                _signoff(),
                _fragment("D1", advisory_id="A1", remediation_id="R12", line="1.2.x"),
                _fragment("D2", advisory_id="A1", remediation_id="R1X", line="1.x"),
                {
                    "record_type": "withdrawal",
                    "withdrawal_id": "W-LINE",
                    "advisory_id": "A1",
                    "scope": "release_branch",
                    "branch": "1.2",
                },
            ]
        }
    )

    assert [item.fragment_id for item in report.reopened] == ["D1"]
    assert report.reopened[0].reason == "release_line_withdrawn"
    assert [item.fragment_id for item in report.preserved] == ["D2"]


def test_unbound_withdrawal_never_reopens_signed_fragment() -> None:
    report = reconcile_handoffs(
        {
            "records": [
                _signoff(),
                _fragment("D1", advisory_id="A1", remediation_id="R1"),
                {
                    "record_type": "withdrawal",
                    "withdrawal_id": "W-UNKNOWN",
                    "scope": "remediation",
                },
            ]
        }
    )

    assert report.reopened == ()
    assert [item.fragment_id for item in report.preserved] == ["D1"]
    assert any(item.record_id == "W-UNKNOWN" for item in report.unresolved)


def test_release_line_can_be_resolved_from_version_impact() -> None:
    report = reconcile_handoffs(
        {
            "version_impacts": [
                {
                    "evidence_id": "E-IMPACT",
                    "advisory_id": "A1",
                    "remediation_id": "R1",
                    "release_line": "1.2",
                }
            ],
            "fragments": [
                {
                    "fragment_id": "D1",
                    "advisory_id": "A1",
                    "scope": "remediation",
                    "remediation_id": "R1",
                }
            ],
            "withdrawals": [
                {
                    "withdrawal_id": "W-LINE",
                    "advisory_id": "A1",
                    "scope": "release_line",
                    "release_line": "1.2.x",
                }
            ],
        }
    )

    assert [item.fragment_id for item in report.reopened] == ["D1"]
    assert report.reopened[0].reason == "release_line_withdrawn"


def test_invalid_withdrawal_and_revoked_evidence_do_not_break_case() -> None:
    report = reconcile_handoffs(
        {
            "records": [
                _signoff(valid=False),
                {
                    "record_type": "version_impact",
                    "evidence_id": "E-IMPACT",
                    "advisory_id": "A1",
                    "remediation_id": "R1",
                    "status": "active",
                },
                _fragment(
                    "D1",
                    advisory_id="A1",
                    remediation_id="R1",
                    evidence_ids=["E-SRC", "E-IMPACT"],
                ),
                {
                    "record_type": "withdrawal",
                    "withdrawal_id": "W-REVOKED",
                    "advisory_id": "A1",
                    "scope": "remediation",
                    "remediation_id": "R1",
                    "status": "cancelled",
                },
            ]
        }
    )

    assert report.reopened == ()
    preserved = report.preserved[0]
    assert preserved.preserved_by == "E-IMPACT"
    assert "E-SRC" not in preserved.evidence_ids
    assert any(item.code == "invalid_withdrawal_ignored" for item in report.unresolved)


def test_ledger_save_and_report_mapping_access(tmp_path: Path) -> None:
    ledger = HandoffLedger.from_batch(ASSET)
    normalized = tmp_path / "ledger.json"
    saved = ledger.save_json(normalized)

    assert saved == normalized
    payload = json.loads(normalized.read_text(encoding="utf-8"))
    assert payload["source_signoffs"][0]["evidence_id"] == "E-SIG-OSV"

    report = ledger.reconcile()
    assert report["reopen_list"][0]["fragment_id"] == "DSP-A-REM-12"
    assert report["preserved"][0]["preserved_by"].startswith("E-")
    assert report.get("missing") is None


def test_cli_outputs_markdown(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "report.md"
    code = main([str(ASSET), "--format", "markdown", "--output", str(output)])

    assert code == 0
    assert "DSP-A-REM-12" in output.read_text(encoding="utf-8")
    capsys.readouterr()


def _signoff(valid: bool = True) -> dict[str, object]:
    record: dict[str, object] = {
        "record_type": "source_signoff",
        "evidence_id": "E-SRC",
        "advisory_ids": ["A1", "A2"],
    }
    if not valid:
        record["status"] = "revoked"
    return record


def _fragment(
    fragment_id: str,
    *,
    advisory_id: str,
    scope: str = "remediation",
    remediation_id: str | None = None,
    line: str | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "record_type": "disposition",
        "fragment_id": fragment_id,
        "advisory_id": advisory_id,
        "scope": scope,
        "evidence_ids": evidence_ids or ["E-SRC"],
    }
    if remediation_id is not None:
        record["remediation_id"] = remediation_id
    if line is not None:
        record["release_line"] = line
    return record
