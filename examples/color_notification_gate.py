#!/usr/bin/env python3
"""Generate the color-notification format and counterexample exports.

Run from the repository root::

    .venv/bin/python examples/color_notification_gate.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from plyara.roundtrip_gate import (  # noqa: E402
    UNCERTAIN_CAPABILITIES,
    compare_yara_texts,
    condition_change_records,
    format_difference_records,
    render_condition_changes_markdown,
    uncertain_records,
)


def write_json(path: Path, value: object) -> None:
    """Write stable, indented JSON."""
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Run both color-rule comparisons and write separate report classes."""
    rule_dir = REPO_ROOT / "rules" / "color_notifications"
    output_dir = REPO_ROOT / "reports" / "color_notifications"
    output_dir.mkdir(parents=True, exist_ok=True)

    baseline_path = rule_dir / "baseline" / "color_notifications.yar"
    formatted_path = rule_dir / "formatted" / "color_notifications.yar"
    changed_path = rule_dir / "changed" / "color_notifications.yar"

    baseline = baseline_path.read_text(encoding="utf-8")
    formatted = formatted_path.read_text(encoding="utf-8")
    changed = changed_path.read_text(encoding="utf-8")

    format_report = compare_yara_texts(
        baseline,
        formatted,
        baseline_label=str(baseline_path.relative_to(REPO_ROOT)),
        candidate_label=str(formatted_path.relative_to(REPO_ROOT)),
    )
    changed_report = compare_yara_texts(
        baseline,
        changed,
        baseline_label=str(baseline_path.relative_to(REPO_ROOT)),
        candidate_label=str(changed_path.relative_to(REPO_ROOT)),
    )

    format_records = format_difference_records(format_report)
    condition_records = condition_change_records(changed_report)
    uncertain = uncertain_records(format_report) + uncertain_records(changed_report)

    format_diff = "\n".join(record["diff"] for record in format_records) + "\n"
    (output_dir / "format_differences.diff").write_text(format_diff, encoding="utf-8")
    write_json(output_dir / "format_differences.json", format_records)
    write_json(output_dir / "condition_changes.json", condition_records)
    write_json(
        output_dir / "uncertain_capabilities.json",
        {"notification_color": "amber", "capabilities": UNCERTAIN_CAPABILITIES, "rules": uncertain},
    )
    (
        output_dir / "condition_changes.md"
    ).write_text(render_condition_changes_markdown(condition_records), encoding="utf-8")
    write_json(output_dir / "formatted_gate_report.json", format_report)
    write_json(output_dir / "changed_gate_report.json", changed_report)

    summary = {
        "format_report_status": format_report["status"],
        "changed_report_status": changed_report["status"],
        "format_difference_count": len(format_records),
        "condition_change_count": len(condition_records),
        "exports": {
            "format_differences_diff": "reports/color_notifications/format_differences.diff",
            "format_differences_json": "reports/color_notifications/format_differences.json",
            "condition_changes_json": "reports/color_notifications/condition_changes.json",
            "condition_changes_markdown": "reports/color_notifications/condition_changes.md",
            "uncertain_capabilities_json": "reports/color_notifications/uncertain_capabilities.json",
        },
    }
    write_json(output_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
