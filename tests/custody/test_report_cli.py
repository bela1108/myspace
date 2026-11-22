import json
import os
import sys

from custody_audit.audit import CustodyState
from custody_audit.cli import main as cli_main
from custody_audit.report import render_report

from conftest import SAMPLE_DIR


def test_report_contains_three_sections(sample_result):
    text = render_report(sample_result)
    assert "EVTX 离线保管核对报告" in text
    assert "可继续复查" in text
    assert "仅剩摘要" in text
    assert "尚未被承接" in text
    assert "R-04" in text and "R-01" in text and "R-02" in text
    assert "被否决的回执" in text
    assert "C001" in text


def test_report_never_contains_sensitive_xml(sample_result):
    text = render_report(sample_result)
    assert "<Event" not in text
    assert "<EventData" not in text
    assert "EventData" not in text


def test_cli_end_to_end(sample_paths, capsys):
    exit_code = cli_main([
        "--evtx-dir", sample_paths["evtx_dir"],
        "--config", sample_paths["config"],
        "--roster", sample_paths["roster"],
        "--manifest", sample_paths["manifest"],
        "--receipts", sample_paths["receipts"],
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "存在阻断性差异" in captured.out
    assert "实际签收人 C002" in captured.out


def test_cli_writes_report_file(sample_paths):
    report_path = os.path.join(SAMPLE_DIR, "_tmp_report.txt")
    try:
        cli_main([
            "--evtx-dir", sample_paths["evtx_dir"],
            "--config", sample_paths["config"],
            "--roster", sample_paths["roster"],
            "--manifest", sample_paths["manifest"],
            "--receipts", sample_paths["receipts"],
            "--report", report_path,
        ])
        with open(report_path, "r", encoding="utf-8") as handle:
            text = handle.read()
        assert "外部清单编号: EXT-MANIFEST-2017-009" in text
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)


def test_cli_clean_handovers_returns_zero(loaded, sample_paths, tmp_path):
    clean_receipts = {
        "receipts": [
            {
                "receipt_id": "R-01",
                "receipt_type": "shift_change",
                "evtx_file": "security_short.evtx",
                "first_record": 1,
                "last_record": 1,
                "mode": "full",
                "signer_id": "C002",
                "signed_at": "2017-07-03T09:30:00+08:00",
                "predecessor_id": "C001",
            },
            {
                "receipt_id": "R-02",
                "receipt_type": "shift_change",
                "evtx_file": "dns_short.evtx",
                "first_record": 1,
                "last_record": 1,
                "mode": "summary",
                "signer_id": "C003",
                "signed_at": "2017-07-03T10:00:00+08:00",
                "predecessor_id": "C001",
            },
        ]
    }
    manifest = {
        "manifest_id": "EXT-CLEAN",
        "evtx_files": ["security_short.evtx", "dns_short.evtx"],
        "entries": [e for e in loaded["manifest"]["entries"] if not (e["evtx_file"] == "dns_short.evtx" and e["first_record"] >= 2)],
    }
    config = {
        "archive_cutoff": loaded["config"]["archive_cutoff"],
        "scope": {
            "security_short.evtx": [{"first_record": 1, "last_record": 1}],
            "dns_short.evtx": [{"first_record": 1, "last_record": 1}],
        },
    }
    receipts_path = tmp_path / "receipts.json"
    manifest_path = tmp_path / "manifest.json"
    config_path = tmp_path / "config.json"
    receipts_path.write_text(json.dumps(clean_receipts, ensure_ascii=False), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    exit_code = cli_main([
        "--evtx-dir", sample_paths["evtx_dir"],
        "--config", str(config_path),
        "--roster", sample_paths["roster"],
        "--manifest", str(manifest_path),
        "--receipts", str(receipts_path),
    ])
    assert exit_code == 0
