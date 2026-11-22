"""Report rendering for the finance page and the security-review page."""

from __future__ import annotations

import json
from collections import defaultdict

from seal_reconciliation.reconciler import ReconciliationReport


def render_finance_page(report: ReconciliationReport) -> str:
    """Render the last-page finance view: authorized intervals vs. usage."""
    lines = [
        "# 用章对账 · 财务页（授权区间）",
        "",
        "| 签发员 | 声明类别 | 授权区间 | 已结算编号 | 备注 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report.authorizations:
        used = ", ".join(str(number) for number in item.used_numbers) or "-"
        lines.append(
            f"| {item.officer_id} | {item.category} | {item.interval} "
            f"| {used} | {item.note or '-'} |"
        )
    lines.append("")
    lines.append(f"唯一结算用章次数：{len(report.usages)}")
    lines.append(f"区间外用章条数：{len(report.out_of_range)}")
    return "\n".join(lines)


def render_security_page(report: ReconciliationReport) -> str:
    """Render the security view: numbers to freeze and evidence locations."""
    lines = [
        "# 用章对账 · 安全审核页（待冻结编号与原始签章定位）",
        "",
        "## 待冻结编号（同一类别内不同材料共用编号）",
        "",
    ]
    if not report.collisions:
        lines.append("无。")
    for collision in report.collisions:
        lines.append(
            f"- 类别 `{collision.category}` 编号 "
            f"`{collision.seal_number}` 待冻结"
        )
        lines.append("  - 涉及材料摘要：")
        for digest in collision.material_digests:
            lines.append(f"    - `{digest}`")
        lines.append("  - 两份（或多份）原始签章定位：")
        for source in collision.sources:
            lines.append(f"    - {source}")
        lines.append(f"  - 涉及签章密钥：{', '.join(collision.keyids)}")

    lines.extend(["", "## 验签失败声明", ""])
    if not report.invalid_signatures:
        lines.append("无。")
    for item in report.invalid_signatures:
        lines.append(
            f"- `{item.statement_id}`（类别 {item.category} / 编号 "
            f"{item.seal_number}，定位 {item.source}）：{item.reason}"
        )

    lines.extend(["", "## 区间外用章", ""])
    if not report.out_of_range:
        lines.append("无。")
    for usage in report.out_of_range:
        lines.append(
            f"- 类别 `{usage.category}` 编号 `{usage.seal_number}` "
            f"不在任何匹配签发员的授权区间内（定位："
            f"{'; '.join(usage.sources)}）"
        )
    return "\n".join(lines)


def render_json_report(report: ReconciliationReport) -> str:
    """Machine-readable report for downstream tooling."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=True)


def summarize_by_interval(report: ReconciliationReport) -> dict[str, int]:
    """Compact per-interval usage counts, handy for sanity checks."""
    counts: dict[str, int] = defaultdict(int)
    for item in report.authorizations:
        counts[f"{item.officer_id}:{item.category}:{item.interval}"] = len(
            item.used_numbers
        )
    return dict(counts)
