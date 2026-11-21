#!/usr/bin/env python3
"""离线核对：吊销记录 x detect-secrets 扫描结果 x 可发布载体清单。

输入中的 marker_token 为调用方提供的不透明标记，本工具只在内部使用，
输出（report.json / report.md / 控制台）一律使用生成的标签 MK-01、MK-02 …，
绝不回显标记原值；写出前会做脱敏自检。

判定规则（针对每一条跨扫描聚合后的告警）：
1. 标记不在吊销记录中            -> out_of_scope（仅记录，不下结论）
2. 任一扫描出现缺少来源信息       -> pending_review（缺来源）
3. 告警证据时间区间与吊销时间区间
   不交叉                        -> pending_review（时间区间不交叉）
4. 其余                          -> confirmed（生产构件携带已停用标记）

吊销记录中没有任何告警命中的标记 -> not_detected（未发现携带）。
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
REPORT_JSON = Path(__file__).resolve().parent / "report.json"
REPORT_MD = Path(__file__).resolve().parent / "report.md"

SCAN_FILES = ["scan_2026_09_10.json", "scan_2026_11_05.json"]

STATUS_TEXT = {
    "confirmed": "确认携带",
    "pending_review": "待复核",
    "out_of_scope": "不在吊销范围",
    "not_detected": "未发现携带",
}


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def build_labels(revocation: dict, scans: list[dict]) -> dict[str, str]:
    """按固定顺序为不透明标记生成对外标签，原值不出现在任何输出中。"""
    labels: dict[str, str] = {}

    def assign(token: str) -> None:
        if token not in labels:
            labels[token] = f"MK-{len(labels) + 1:02d}"

    for entry in revocation["entries"]:
        assign(entry["marker_token"])
    for scan in scans:
        for finding in scan["findings"]:
            assign(finding["marker_token"])
    return labels


def group_findings(scans: list[dict]) -> dict[tuple, dict]:
    """按 (构件, 文件, 行号, 标记) 聚合两次扫描，得到证据时间区间与新旧属性。"""
    groups: dict[tuple, dict] = {}
    for scan in scans:
        seen_at = parse_ts(scan["generated_at"])
        for finding in scan["findings"]:
            key = (
                finding["artifact_id"],
                finding["file"],
                finding["line_number"],
                finding["marker_token"],
            )
            group = groups.setdefault(
                key,
                {
                    "artifact_id": finding["artifact_id"],
                    "file": finding["file"],
                    "line_number": finding["line_number"],
                    "type": finding["type"],
                    "marker_token": finding["marker_token"],
                    "first_seen": seen_at,
                    "last_seen": seen_at,
                    "scan_ids": [],
                    "has_source": True,
                },
            )
            group["first_seen"] = min(group["first_seen"], seen_at)
            group["last_seen"] = max(group["last_seen"], seen_at)
            group["scan_ids"].append(scan["scan_id"])
            if not finding.get("source_commit") or not finding.get("source_committed_at"):
                group["has_source"] = False
    return groups


def intersects(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> bool:
    return a_start <= b_end and b_start <= a_end


def evaluate(groups: dict[tuple, dict], revocation: dict, labels: dict[str, str]) -> list[dict]:
    revoked = {entry["marker_token"]: entry for entry in revocation["entries"]}
    results = []
    for group in sorted(groups.values(), key=lambda g: (g["artifact_id"], g["file"], g["line_number"])):
        token = group["marker_token"]
        entry = revoked.get(token)
        item = {
            "label": labels[token],
            "artifact_id": group["artifact_id"],
            "file": group["file"],
            "line_number": group["line_number"],
            "type": group["type"],
            "alert_kind": "legacy" if len(set(group["scan_ids"])) > 1 else "new",
            "evidence_window": {
                "first_seen": group["first_seen"].isoformat().replace("+00:00", "Z"),
                "last_seen": group["last_seen"].isoformat().replace("+00:00", "Z"),
            },
            "seen_in_scans": sorted(set(group["scan_ids"])),
        }
        if entry is None:
            item["status"] = "out_of_scope"
            item["reason"] = "标记不在吊销记录中，仅登记不下结论"
        elif not group["has_source"]:
            item["status"] = "pending_review"
            item["reason"] = "缺来源：扫描证据缺少 source_commit，无法确认引入途径"
        else:
            window = entry["revocation_window"]
            revoked_start, revoked_end = parse_ts(window["start"]), parse_ts(window["end"])
            item["revocation_window"] = window
            if not intersects(group["first_seen"], group["last_seen"], revoked_start, revoked_end):
                item["status"] = "pending_review"
                item["reason"] = "时间区间不交叉：告警证据区间与吊销区间无重叠，需人工复核"
            else:
                item["status"] = "confirmed"
                item["reason"] = "证据区间与吊销区间交叉，构件在标记停用后仍携带该标记"
        results.append(item)
    return results


def find_not_detected(revocation: dict, groups: dict[tuple, dict], labels: dict[str, str]) -> list[dict]:
    seen_tokens = {group["marker_token"] for group in groups.values()}
    return [
        {"label": labels[entry["marker_token"]], "status": "not_detected"}
        for entry in revocation["entries"]
        if entry["marker_token"] not in seen_tokens
    ]


def render_markdown(manifest: dict, results: list[dict], not_detected: list[dict]) -> str:
    lines = [
        "# 发布审核离线核对报告",
        "",
        f"- 载体清单：`{manifest['manifest_id']}`（{manifest['generated_at']}）",
        f"- 吊销记录：`REV-2026-11-20`；扫描证据：`scan-2026-09-10`、`scan-2026-11-05`",
        "- 说明：报告只使用生成标签，不含调用方不透明标记原值",
        "",
        "## 逐条结论",
        "",
        "| 标签 | 构件 | 位置 | 告警 | 证据区间 | 结论 | 依据 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    kind_text = {"legacy": "遗留", "new": "新增"}
    for item in results:
        window = f"{item['evidence_window']['first_seen'][:10]} ~ {item['evidence_window']['last_seen'][:10]}"
        location = f"{item['file']}:{item['line_number']}"
        lines.append(
            "| {label} | {artifact} | `{loc}` | {kind} | {window} | {status} | {reason} |".format(
                label=item["label"],
                artifact=item["artifact_id"],
                loc=location,
                kind=kind_text[item["alert_kind"]],
                window=window,
                status=STATUS_TEXT[item["status"]],
                reason=item["reason"],
            )
        )
    lines += ["", "## 吊销标记覆盖情况", ""]
    for item in not_detected:
        lines.append(f"- `{item['label']}`：{STATUS_TEXT[item['status']]}，两次扫描均未命中")
    confirmed = sorted({item["artifact_id"] for item in results if item["status"] == "confirmed"})
    lines += ["", "## 构件级结论", ""]
    for artifact in manifest["artifacts"]:
        aid = artifact["artifact_id"]
        verdict = "确认携带已停用标记，阻断发布" if aid in confirmed else "未见确认携带"
        lines.append(f"- `{aid}` {artifact['version']}（{artifact['path']}）：{verdict}")
    lines.append("")
    return "\n".join(lines)


def assert_redacted(payloads: list[str], labels: dict[str, str]) -> None:
    """脱敏自检：任何输出中都不得出现不透明标记原值。"""
    leaked = [token for token in labels for text in payloads if token in text]
    if leaked:
        raise SystemExit(f"脱敏自检失败，输出含标记原值 {len(leaked)} 处")


def main() -> int:
    revocation = load_json(DATA_DIR / "revocation_record.json")
    manifest = load_json(DATA_DIR / "artifact_manifest.json")
    scans = [load_json(DATA_DIR / name) for name in SCAN_FILES]

    production_ids = {a["artifact_id"] for a in manifest["artifacts"] if a["channel"] == "production"}
    for scan in scans:
        scan["findings"] = [f for f in scan["findings"] if f["artifact_id"] in production_ids]

    labels = build_labels(revocation, scans)
    groups = group_findings(scans)
    results = evaluate(groups, revocation, labels)
    not_detected = find_not_detected(revocation, groups, labels)

    report = {
        "manifest_id": manifest["manifest_id"],
        "revocation_record": revocation["record_id"],
        "scans": [scan["scan_id"] for scan in scans],
        "results": results,
        "not_detected": not_detected,
    }
    report_json = json.dumps(report, ensure_ascii=False, indent=2)
    report_md = render_markdown(manifest, results, not_detected)
    assert_redacted([report_json, report_md], labels)

    REPORT_JSON.write_text(report_json + "\n", encoding="utf-8")
    REPORT_MD.write_text(report_md, encoding="utf-8")

    for item in results:
        print(f"{item['label']}  {item['artifact_id']}  {item['file']}:{item['line_number']}  "
              f"{STATUS_TEXT[item['status']]}  ({item['reason']})")
    for item in not_detected:
        print(f"{item['label']}  -  {STATUS_TEXT[item['status']]}")
    print(f"\n报告已写出：{REPORT_JSON.name} / {REPORT_MD.name}（脱敏自检通过）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
