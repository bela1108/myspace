"""End-to-end CLI behaviour including the two-ABI review."""

from __future__ import annotations

import json
import sys

from abi_layout_audit.cli import main

from .conftest import make_abi


DECLARATIONS = (
    "struct block {"
    " unsigned int magic;"
    " unsigned short flags;"
    " unsigned long watchdog;"
    " unsigned long long sequence;"
    " unsigned int internal_token; };"
)


def _config(tmp_path, name, pointer, long_size, ranges):
    config = make_abi(name, pointer=pointer, long_size=long_size)
    data = {
        "abi": {
            "name": config.name,
            "pointer_size": config.pointer_size,
            "pointer_alignment": config.pointer_alignment,
            "enum_size": 4,
            "enum_alignment": 4,
            "primitive_types": dict(config.primitive_types),
        },
        "audit": {
            "type": "block",
            "public_fields": ["magic", "flags", "watchdog", "sequence"],
            "export_ranges": ranges,
        },
    }
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_declarations(tmp_path):
    path = tmp_path / "block.pp.c"
    path.write_text(DECLARATIONS, encoding="utf-8")
    return path


def test_dual_abi_review_exits_review(tmp_path, capsys):
    declarations = _write_declarations(tmp_path)
    ilp32 = _config(tmp_path, "ilp32", 4, 4,
                    [{"label": "gap", "range": "12-15"}])
    lp64 = _config(tmp_path, "lp64", 8, 8,
                   [{"label": "gap", "range": "12-15"}])
    code = main([str(declarations), "--config", str(ilp32),
                 "--config", str(lp64)])
    output = capsys.readouterr().out
    assert code == 2
    assert "ilp32" in output and "lp64" in output
    assert "block.c" in output or str(declarations) in output


def test_json_report_contains_locations(tmp_path):
    declarations = _write_declarations(tmp_path)
    config = _config(tmp_path, "ilp32", 4, 4,
                     [{"label": "head", "range": "0-3"}])
    output_path = tmp_path / "report.json"
    code = main([str(declarations), "--config", str(config),
                 "--format", "json", "--output", str(output_path)])
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert code == 0
    finding = payload[0]["verdicts"][0]["findings"][0]
    assert finding["classification"] == "public"
    assert finding["location"]["line"] >= 1


def test_mismatched_public_fields_is_config_error(tmp_path):
    declarations = _write_declarations(tmp_path)
    first = _config(tmp_path, "ilp32", 4, 4, [])
    second_config = json.loads(first.read_text(encoding="utf-8"))
    second_config["abi"]["name"] = "lp64"
    second_config["audit"]["public_fields"] = ["magic"]
    second = tmp_path / "lp64.json"
    second.write_text(json.dumps(second_config), encoding="utf-8")
    code = main([str(declarations), "--config", str(first),
                 "--config", str(second)])
    assert code == 1
