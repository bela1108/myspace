"""File output writers for attestation batches."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .intake import _json_text, write_json, write_ledger_csv


NL = chr(10)
BLANK = NL + NL


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    separator = "|" + "|".join("---" for _ in headers) + "|"
    lines = ["| " + " | ".join(headers) + " |", separator]
    for row in rows:
        cells = [str(cell).replace("|", "/").replace(chr(10), "<br>") for cell in row]
        lines.append("| " + " | ".join(cells) + " |")
    return NL.join(lines)


def write_reports(result: dict[str, Any], output_dir: str | Path) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    write_json(out / "ledger.json", result)
    write_ledger_csv(out / "ledger.csv", result["claims"])
    write_json(out / "transcription-notes.json", result["transcription_notes"])
    write_json(out / "protection-differences.json", result["protection_differences"])
    write_json(out / "reapproval-queue.json", result["reapproval_queue"])
    write_json(out / "review-cases.json", result["review_cases"])
    write_json(out / "artifact-checks.json", result["artifact_checks"])
    write_json(out / "source-conflicts.json", result.get("source_conflicts", []))
    write_json(out / "rejected-claims.json", result.get("rejected_claims", []))

    note_rows = []
    for note in result["transcription_notes"]:
        raw_forms = "<br>".join(
            form["source_id"] + ": " + _json_text(form["recorded_value"])
            for form in note["raw_forms"]
        )
        note_rows.append(
            [
                note["package_id"],
                note["field"],
                _json_text(note["canonical_value"]),
                raw_forms,
                "<br>".join(note["rule_ids"]),
            ]
        )
    notes_markdown = (
        "# 纯转写/记法说明"
        + BLANK
        + "以下各项的原始记法不同，但规范化后的保护属性相同；只需转写说明，不触发补签。"
        + BLANK
        + (_table(["包", "参数", "规范值", "各来源原始记录值", "接受规则"], note_rows) if note_rows else "无。")
        + NL
    )
    (out / "transcription-notes.md").write_text(notes_markdown, encoding="utf-8")

    diff_rows = []
    for diff in result["protection_differences"]:
        diff_rows.append(
            [
                diff["package_id"],
                diff["field"],
                _json_text(diff.get("approved_value")),
                _json_text(diff.get("observed_value") or diff.get("canonical_values")),
                diff.get("approval_id", ""),
                diff["status"],
                diff.get("required_action", diff.get("conclusion", "")),
            ]
        )
    differences_markdown = (
        "# 保护属性实际差异"
        + BLANK
        + "以下差异在应用明确规范化规则后仍然存在，属于真实保护属性变化。"
        + BLANK
        + (
            _table(
                ["包", "参数", "批准值", "实测值", "批准单", "状态", "处理要求"],
                diff_rows,
            )
            if diff_rows
            else "无。"
        )
        + NL
    )
    (out / "protection-differences.md").write_text(differences_markdown, encoding="utf-8")

    queue_rows = [
        [
            item["package_id"],
            item["field"],
            _json_text(item["approved_value"]),
            _json_text(item["observed_value"]),
            item["approval_id"],
        ]
        for item in result["reapproval_queue"]
    ]
    queue_markdown = (
        "# 待补签批准队列"
        + BLANK
        + (_table(["包", "参数", "旧批准值", "当前实测值", "原批准单"], queue_rows) if queue_rows else "无。")
        + NL
    )
    (out / "reapproval-queue.md").write_text(queue_markdown, encoding="utf-8")

    case_rows = [
        [
            case["case_id"],
            case["package_id"],
            case["expected_disposition"],
            case["actual_disposition"],
            "是" if case["verified"] else "否",
            case.get("summary", ""),
        ]
        for case in result["review_cases"]
    ]
    checks = result["summary"]
    report_lines = [
        f"# {result['title']}",
        "",
        f"- 批次：{result['batch_id']}",
        f"- 规则集：{result['ruleset_id']} — {result['ruleset']['label']}",
        "- 明文接触：否；未调用 load_key()，未生成解密文件",
        f"- 保护包：{checks['package_count']}",
        f"- 证词条目：{checks['claim_count']}",
        f"- 文件哈希核验：{checks['artifact_check_count']}",
        f"- 记法等价项：{checks['transcription_note_count']}",
        f"- 实际保护差异：{checks['protection_difference_count']}",
        f"- 待补签：{checks['reapproval_required_count']}",
        f"- 来源规范冲突：{checks.get('source_conflict_count', 0)}",
        f"- 未接受证词：{checks.get('rejected_claim_count', 0)}",
        f"- 复核案例全部验证：{'是' if checks['review_cases_verified'] else '否'}",
        "",
        "## 档案员重点",
        "",
        _table(["案例", "包", "预期判定", "实际判定", "验证", "说明"], case_rows),
        "",
        "## 分类输出",
        "",
        "- 纯记法/转写说明：transcription-notes.md 与 transcription-notes.json",
        "- 实际保护属性差异：protection-differences.md 与 protection-differences.json",
        "- 待补签队列：reapproval-queue.md 与 reapproval-queue.json",
        "- 全量逐项证词台账：ledger.csv 与 ledger.json",
        "- 哈希完整性核验：artifact-checks.json",
        "- 复核案例机读结果：review-cases.json",
        "",
        "## 规范化兼容性",
        "",
        "新版 archivist-rules-2026.2 用 hash.v1_canonical_compat 接受 2024.1 批准单中的 SHA-1/SHA-512 历史连字符值，并转写为 Office/msoffcrypto 使用的 SHA1/SHA512 令牌。length.bytes_to_bits 明确处理 16 字节到 128 位这类长度单位换算。规则目录未列出的单位或算法别名会被标记为 normalization_rejected，而不会被静默猜测。",
        "",
    ]
    (out / "report.md").write_text(NL.join(report_lines), encoding="utf-8")
