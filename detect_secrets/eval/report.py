"""
Renders evaluation results as per-family text tables and JSON payloads.

The tables deliberately keep one row per (plugin, family) and one row per
family, so a global improvement cannot hide a family-specific regression.
"""
import json
from typing import List
from typing import Sequence

from .metrics import ConfigurationComparison
from .metrics import EvaluationReport
from .metrics import PluginFamilyMetrics


def _format_percent(value: float) -> str:
    return f"{value * 100:5.1f}%"


def _render_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    rendered = [[str(cell) for cell in row] for row in rows]
    widths = [
        max([len(headers[index])] + [len(row[index]) for row in rendered])
        for index in range(len(headers))
    ]

    def format_row(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    lines = [format_row(list(headers)), format_row(["-" * width for width in widths])]
    lines.extend(format_row(row) for row in rendered)
    return "\n".join(lines)

PLUGIN_TABLE_HEADERS = (
    "family", "plugin", "labels", "found", "incremental",
    "duplicate", "false_pos", "missed", "coverage", "precision",
)


def render_plugin_family_table(report: EvaluationReport) -> str:
    """One row per (plugin, family): incremental, duplicate and missed counts."""
    rows = []
    for metrics in report.plugin_family_metrics:
        rows.append(
            (
                metrics.family,
                metrics.plugin,
                metrics.labels,
                metrics.found,
                metrics.incremental,
                metrics.duplicate_hits,
                metrics.false_positives,
                metrics.missed,
                _format_percent(metrics.coverage),
                _format_percent(metrics.precision),
            ),
        )
    return _render_table(PLUGIN_TABLE_HEADERS, rows)


def render_family_summary_table(report: EvaluationReport) -> str:
    """One row per family, including the unmeasurable label identifiers."""
    headers = ("family", "labels", "covered", "unmeasurable", "coverage", "unmeasurable_ids")
    rows = []
    for summary in report.family_summaries:
        unmeasurable_ids = ",".join(summary.unmeasurable_ids) or "-"
        rows.append((
            summary.family,
            summary.labels,
            summary.covered,
            summary.unmeasurable,
            _format_percent(summary.coverage),
            unmeasurable_ids,
        ))
    return _render_table(headers, rows)

def render_comparison_table(comparisons: List[ConfigurationComparison]) -> str:
    """Baseline vs candidate coverage per family; regressing rows are flagged."""
    headers = ("family", "labels", "baseline", "candidate", "delta", "status")
    rows = []
    for comparison in comparisons:
        status = "REGRESSED" if comparison.regressed else "ok"
        rows.append((
            comparison.family,
            comparison.labels,
            _format_percent(comparison.baseline_coverage),
            _format_percent(comparison.candidate_coverage),
            f"{comparison.delta * 100:+.1f}%",
            status,
        ))
    return _render_table(headers, rows)


def render_failure_table(report: EvaluationReport) -> str:
    """Failed plugins are listed separately, never mixed into healthy metrics."""
    headers = ("plugin", "error", "families")
    rows = [
        (failure.plugin, failure.error, ",".join(failure.families) or "-")
        for failure in report.failures
    ]
    if not rows:
        return "no plugin failures"
    return _render_table(headers, rows)


def render_text_report(report: EvaluationReport) -> str:
    """Full human-readable report, with every table kept on family granularity."""
    sections = [
        f"dataset: {report.dataset}",
        "",
        "Plugin x family effectiveness",
        render_plugin_family_table(report),
        "",
        "Family coverage and unmeasurable labels",
        render_family_summary_table(report),
        "",
        "Failed plugins",
        render_failure_table(report),
    ]
    if report.comparisons:
        sections.extend([
            "",
            "Baseline vs candidate (per family)",
            render_comparison_table(report.comparisons),
        ])
    return "\n".join(sections)


def render_json_report(report: EvaluationReport) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)
