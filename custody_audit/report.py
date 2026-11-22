"""
Render an :class:`AuditResult` as a plain-text offline custody report.

The report is safe for external review: it only prints record metadata and
dispositions, never raw event XML or sensitive event data.
"""
from __future__ import annotations

from custody_audit.audit import (
    AuditResult,
    CustodyState,
    Severity,
)


STATE_TITLES = {
    CustodyState.REVIEWABLE: "可继续复查（原文已完整签收）",
    CustodyState.SUMMARY_ONLY: "仅剩摘要（原始记录不随外部清单流转）",
    CustodyState.NOT_ACCEPTED: "尚未被承接（无有效签收）",
}


def _format_numbers(numbers: tuple[int, ...]) -> str:
    if not numbers:
        return "-"
    ordered = sorted(numbers)
    spans: list[str] = []
    start = prev = ordered[0]
    for num in ordered[1:]: 
        if num == prev + 1:
            prev = num
            continue
        spans.append("%d" % start if start == prev else "%d-%d" % (start, prev))
        start = prev = num
    spans.append("%d" % start if start == prev else "%d-%d" % (start, prev))
    return ", ".join(spans)


def render_report(result: AuditResult) -> str:
    lines: list[str] = []
    lines.append("EVTX 离线保管核对报告")
    lines.append("=" * 60)
    lines.append("外部清单编号: %s" % result.manifest.manifest_id)
    lines.append("")
    for file_result in result.file_results:
        lines.append("源证物: %s" % file_result.evtx_file)
        lines.append("-" * 60)
        for state in (CustodyState.REVIEWABLE, CustodyState.SUMMARY_ONLY, CustodyState.NOT_ACCEPTED):
            dispositions = file_result._by_state(state)
            lines.append("[%s] %d 条" % (STATE_TITLES[state], len(dispositions)))
            for disposition in dispositions:
                receipt = disposition.effective_receipt_id or "无"
                signer = disposition.signer_id or "无"
                lines.append(
                    "  - 记录 %d | 回执 %s | 实际签收人 %s" 
                    % (disposition.record_num, receipt, signer)
                )
                for reason in disposition.reasons:
                    lines.append("      说明: %s" % reason)
            lines.append("")
        lines.append("  记录编号汇总:")
        for state in (CustodyState.REVIEWABLE, CustodyState.SUMMARY_ONLY, CustodyState.NOT_ACCEPTED):
            numbers = tuple(d.record_num for d in file_result._by_state(state))
            lines.append("    %s: %s" % (STATE_TITLES[state], _format_numbers(numbers)))
        lines.append("")
    lines.append("回执效力核对")
    lines.append("-" * 60)
    if result.effective_receipts:
        for key in sorted(result.effective_receipts):
            receipt = result.effective_receipts[key]
            lines.append(
                "  [有效] %s 类型=%s 范围=%s %s 模式=%s 签收人=%s 时间=%s"
                % (
                    receipt.receipt_id,
                    receipt.receipt_type,
                    receipt.evtx_file,
                    receipt.record_range.describe(),
                    receipt.mode.value,
                    receipt.signer_id,
                    receipt.signed_at,
                )
            )
    else:
        lines.append("  无有效回执。")
    if result.rejected_receipts:
        lines.append("")
        lines.append("  被否决的回执:")
        for finding in result.rejected_receipts:
            lines.append("    [否决] %s: %s" % (finding.reference, finding.message))
    lines.append("")

    lines.append("交叉核对发现")
    lines.append("-" * 60)
    if result.findings:
        for finding in result.findings:
            tag = "错误" if finding.severity == Severity.ERROR else "警告"
            lines.append("  [%s] %s %s" % (tag, finding.code, finding.message))
    else:
        lines.append("  未发现差异。")
    lines.append("")
    lines.append("结论: %s" % ("存在阻断性差异，不得完成外部交接" if result.has_blocking_errors else "核对通过，可按上述范围交接"))
    return "\n".join(lines)
