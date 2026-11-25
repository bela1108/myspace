#!/usr/bin/env python3
"""核对合成演练告警摘要：沿用 pySigma 公开规则与两代处理配置解析字段别名。

用法：
    .venv/bin/python drill_audit/audit.py

产出：
    drill_audit/results/audit_report.json   机读结果
    drill_audit/results/audit_report.md     交接报告（安全组 / 运维组）
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parent
GENERATIONS = ("gen1", "gen2")
GEN_LABEL = {"gen1": "上一代配置(gen1)", "gen2": "现行配置(gen2)"}
TEAM_LABEL = {"security": "安全组", "ops": "运维组"}

CONFIRMED = "confirmed"
CANDIDATES = "candidates"  # 多种别名导致的候选
SOURCE_LOST = "source_lost"  # 来源丢失

STATUS_LABEL = {
    CONFIRMED: "已确认",
    CANDIDATES: "候选（待核验）",
    SOURCE_LOST: "来源丢失（待核验）",
}


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_pipelines() -> dict[str, ProcessingPipeline]:
    pipelines = {}
    for gen in GENERATIONS:
        pipelines[gen] = ProcessingPipeline.from_yaml(
            (ROOT / "config" / f"pipeline_{gen}.yml").read_text(encoding="utf-8")
        )
    return pipelines


def probe_rule(field: str) -> SigmaRule:
    """构造一条只含目标字段的合成 Sigma 规则，用于驱动处理配置。"""
    doc = {
        "title": "alias-probe",
        "logsource": {"category": "synthetic_drill"},
        "detection": {"selection": {field: "probe-value"}, "condition": "selection"},
    }
    return SigmaRule.from_yaml(yaml.safe_dump(doc, allow_unicode=True))


def resolve_field(pipelines: dict[str, ProcessingPipeline], field: str) -> dict[str, list[str]]:
    """对每代配置解析字段别名。

    解析结果直接取自 pySigma 的 FieldMappingTracking（pipeline.field_mappings）；
    未被该代配置改写的字段按恒等处理，解析为自身。
    """
    resolved = {}
    for gen, pipeline in pipelines.items():
        pipeline.apply(probe_rule(field))
        targets = pipeline.field_mappings.get(field)
        resolved[gen] = sorted(targets) if targets else [field]
    return resolved


def classify_field(field: str, allowed: list[str], resolved: dict[str, list[str]]) -> dict:
    """按允许字段与两代配置的解析结果对单个字段定级。"""
    if field in allowed:
        return {
            "field": field,
            "status": CONFIRMED,
            "allowed_field": field,
            "support": list(GENERATIONS),
            "note": "规范允许字段，两代配置均无需改写",
            "resolved": resolved,
        }
    support = {
        gen: [target for target in targets if target in allowed]
        for gen, targets in resolved.items()
    }
    support = {gen: targets for gen, targets in support.items() if targets}
    distinct = sorted({target for targets in support.values() for target in targets})
    if len(distinct) > 1:
        return {
            "field": field,
            "status": CANDIDATES,
            "candidates": [
                {
                    "allowed_field": target,
                    "support": [gen for gen, targets in support.items() if target in targets],
                }
                for target in distinct
            ],
            "note": "多种别名/映射指向多个允许字段，保留全部候选",
            "resolved": resolved,
        }
    if len(distinct) == 1:
        target = distinct[0]
        gens = [gen for gen, targets in support.items() if target in targets]
        if len(gens) == 1:
            note = f"仅{GEN_LABEL[gens[0]]}支持该别名"
        else:
            note = "两代配置均支持该别名"
        return {
            "field": field,
            "status": CONFIRMED,
            "allowed_field": target,
            "support": gens,
            "note": note,
            "resolved": resolved,
        }
    mapped = {gen: targets for gen, targets in resolved.items() if targets != [field]}
    if mapped:
        note = "配置可解析但结果不在本组允许字段内：" + "; ".join(
            f"{GEN_LABEL[gen]}->{','.join(targets)}" for gen, targets in mapped.items()
        )
    else:
        note = "两代配置均无此别名，且非规范允许字段"
    return {"field": field, "status": SOURCE_LOST, "note": note, "resolved": resolved}


def support_label(gens: list[str]) -> str:
    return "+".join(GEN_LABEL[gen] for gen in gens)


def audit_items(pipelines, allowed_fields, items, key) -> list[dict]:
    results = []
    for item in items:
        allowed = allowed_fields[item["team"]]
        fields = [
            classify_field(field, allowed, resolve_field(pipelines, field))
            for field in item[key]
        ]
        status = CONFIRMED
        if any(field["status"] == SOURCE_LOST for field in fields):
            status = SOURCE_LOST
        elif any(field["status"] == CANDIDATES for field in fields):
            status = CANDIDATES
        results.append({**item, "field_results": fields, "status": status})
    return results


def render_field_line(field_result: dict) -> str:
    field = field_result["field"]
    status = field_result["status"]
    if status == CONFIRMED:
        return (
            f"`{field}` -> 允许字段 `{field_result['allowed_field']}`，"
            f"支持配置：{support_label(field_result['support'])}"
        )
    if status == CANDIDATES:
        cands = "；".join(
            f"`{cand['allowed_field']}`（{support_label(cand['support'])}）"
            for cand in field_result["candidates"]
        )
        return f"`{field}` -> 候选：{cands}"
    return f"`{field}` -> 来源丢失：{field_result['note']}"


def render_report(summary_results, record_results) -> str:
    lines = []
    lines.append("# 合成演练告警摘要核对报告")
    lines.append("")
    lines.append("核对方法：以 pySigma 公开 API 加载两代处理配置（gen1 换版前 / gen2 现行），")
    lines.append("对每个分组字段与记录字段构造合成 Sigma 规则并应用处理管线，")
    lines.append("解析结果取自管线的 FieldMappingTracking 跟踪（pipeline.field_mappings）。")
    lines.append("")
    lines.append("## 一、已有摘要分组核对")
    lines.append("")
    lines.append("| 摘要 | 接收组 | 分组字段 | 核对结论 |")
    lines.append("| --- | --- | --- | --- |")
    for summary in summary_results:
        conclusions = "<br>".join(render_field_line(f) for f in summary["field_results"])
        lines.append(
            f"| {summary['id']} {summary['title']} | {TEAM_LABEL[summary['team']]} "
            f"| {', '.join(summary['group_by'])} | {conclusions} |"
        )
    lines.append("")
    lines.append("## 二、待确认记录核对")
    lines.append("")
    for record in record_results:
        lines.append(f"### {record['id']}（{TEAM_LABEL[record['team']]}，{record['note']}）")
        lines.append("")
        for field_result in record["field_results"]:
            lines.append(f"- {render_field_line(field_result)}")
        lines.append(f"- 记录结论：{STATUS_LABEL[record['status']]}")
        lines.append("")
    lines.append("## 三、保留结果：多种别名导致的候选")
    lines.append("")
    candidate_items = [
        (item["id"], field_result)
        for item in (*summary_results, *record_results)
        for field_result in item["field_results"]
        if field_result["status"] == CANDIDATES
    ]
    if candidate_items:
        for item_id, field_result in candidate_items:
            lines.append(f"- {item_id}：{render_field_line(field_result)}")
    else:
        lines.append("- 无")
    lines.append("")
    lines.append("## 四、保留结果：来源丢失")
    lines.append("")
    lost_items = [
        (item["id"], field_result)
        for item in (*summary_results, *record_results)
        for field_result in item["field_results"]
        if field_result["status"] == SOURCE_LOST
    ]
    if lost_items:
        for item_id, field_result in lost_items:
            lines.append(f"- {item_id}：{render_field_line(field_result)}")
    else:
        lines.append("- 无")
    lines.append("")
    lines.append("## 五、待核验清单")
    lines.append("")
    pending = [item for item in (*summary_results, *record_results) if item["status"] != CONFIRMED]
    if pending:
        for item in pending:
            lines.append(f"- {item['id']}：{STATUS_LABEL[item['status']]}")
    else:
        lines.append("- 无")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    pipelines = load_pipelines()
    allowed_fields = load_yaml(ROOT / "config" / "allowed_fields.yml")
    summaries = load_yaml(ROOT / "data" / "summaries.yml")["summaries"]
    records = load_yaml(ROOT / "data" / "pending_records.yml")["records"]

    summary_results = audit_items(pipelines, allowed_fields, summaries, "group_by")
    record_results = audit_items(pipelines, allowed_fields, records, "fields")

    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)
    payload = {"summaries": summary_results, "records": record_results}
    (results_dir / "audit_report.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (results_dir / "audit_report.md").write_text(
        render_report(summary_results, record_results), encoding="utf-8"
    )

    all_items = (*summary_results, *record_results)
    confirmed = sum(1 for item in all_items if item["status"] == CONFIRMED)
    candidates = sum(1 for item in all_items if item["status"] == CANDIDATES)
    lost = sum(1 for item in all_items if item["status"] == SOURCE_LOST)
    print(f"摘要 {len(summary_results)} 项、记录 {len(record_results)} 条已核对：")
    print(f"  已确认 {confirmed}，候选（待核验） {candidates}，来源丢失（待核验） {lost}")
    print(f"报告：{results_dir / 'audit_report.md'}")


if __name__ == "__main__":
    main()
