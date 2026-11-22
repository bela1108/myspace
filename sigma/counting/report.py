"""Comparison reports for the offline counting contract check.

The report combines two kinds of evidence that must stay distinguishable:

* the static :class:`~sigma.counting.checker.ContractCheckResult` produced
  between parsing and conversion, split by counting basis (counting of events
  vs counting of distinct/unique values); and
* the per-scenario :class:`~sigma.counting.replay.ReplayOutcome` produced by
  replaying the same small event set under single-write, dual-write and
  missing-identity collection.

Reports can be rendered as machine-readable JSON or a human-readable Markdown
document.  Every threshold change is attributed to a concrete alert (rule +
scenario + basis) so a SOC can trace a doubled or collapsed count back to the
branch that caused it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from sigma.counting.checker import (
    ContractCheckResult,
    CountingBasis,
    CountingVerdict,
)
from sigma.counting.replay import ReplayOutcome, ReplayScenario, ReplayVerdict


@dataclass
class CorrelationReportRecord:
    """Everything known about one correlation rule after the offline check."""

    check: ContractCheckResult
    replays: list[ReplayOutcome] = field(default_factory=list)

    @property
    def threshold_changes(self) -> list[ReplayOutcome]:
        """Scenarios where the naive and the contract-aware alert differ."""
        return [
            outcome
            for outcome in self.replays
            if outcome.contract_alert is not None
            and outcome.naive_alert != outcome.contract_alert
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check.to_dict(),
            "replays": [outcome.to_dict() for outcome in self.replays],
            "threshold_changes": [
                {
                    "scenario": outcome.scenario.value,
                    "rule": outcome.rule_name,
                    "counting_basis": outcome.basis.value,
                    "naive_alert": outcome.naive_alert,
                    "contract_alert": outcome.contract_alert,
                }
                for outcome in self.threshold_changes
            ],
        }


class CountingReport:
    """Aggregate report over several correlation rules."""

    def __init__(self, records: list[CorrelationReportRecord] | None = None) -> None:
        self.records: list[CorrelationReportRecord] = list(records or [])

    def add(self, record: CorrelationReportRecord) -> None:
        self.records.append(record)

    @property
    def count_based(self) -> list[CorrelationReportRecord]:
        return [
            record
            for record in self.records
            if record.check.basis is CountingBasis.EVENT_COUNT
        ]

    @property
    def unique_value_based(self) -> list[CorrelationReportRecord]:
        return [
            record
            for record in self.records
            if record.check.basis is CountingBasis.UNIQUE_VALUE
        ]

    @property
    def undetermined_records(self) -> list[CorrelationReportRecord]:
        return [
            record
            for record in self.records
            if record.check.verdict is CountingVerdict.UNDETERMINED
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "rules": len(self.records),
                "determined": len(self.records) - len(self.undetermined_records),
                "undetermined": len(self.undetermined_records),
                "count_based": len(self.count_based),
                "unique_value_based": len(self.unique_value_based),
            },
            "count_based_correlations": [record.to_dict() for record in self.count_based],
            "unique_value_correlations": [
                record.to_dict() for record in self.unique_value_based
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def to_markdown(self) -> str:
        lines: list[str] = []
        summary = self.to_dict()["summary"]
        lines.append("# Counting Contract Check Report")
        lines.append("")
        lines.append(
            f"- Correlation rules checked: {summary['rules']} "
            f"({summary['determined']} determined, {summary['undetermined']} undetermined)"
        )
        lines.append(
            f"- Count-based correlations: {summary['count_based']} | "
            f"unique-value correlations: {summary['unique_value_based']}"
        )
        lines.append("")

        for heading, records in (
            ("Count-based correlations", self.count_based),
            ("Unique-value correlations", self.unique_value_based),
        ):
            lines.append(f"## {heading}")
            lines.append("")
            if not records:
                lines.append("_None._")
                lines.append("")
                continue
            for record in records:
                lines.extend(self._render_record(record))
        return "\n".join(lines)

    def _render_record(self, record: CorrelationReportRecord) -> list[str]:
        check = record.check
        lines = [
            f"### {check.rule_title} (`{check.rule_name}`) — {check.verdict.value}",
            "",
            f"- Location: `{check.location}`",
            f"- Type: `{check.correlation_type}` on basis `{check.basis.value}`",
            f"- Timespan: {check.timespan_seconds}s | threshold: `{json.dumps(check.threshold)}`",
            "",
            "| Branch | Log source | Verdict | Identity fields | Time precision | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for branch in check.branch_verdicts:
            logsource = branch.logsource
            logsource_text = (
                "/".join(
                    part
                    for part in (
                        logsource.category if logsource else None,
                        logsource.product if logsource else None,
                        logsource.service if logsource else None,
                    )
                    if part
                )
                or "n/a"
            )
            lines.append(
                (
                    "| {branch} | {logsource} | {verdict} | {identity} "
                    "| {precision} | {reason} |"
                ).format(
                    branch=branch.branch,
                    logsource=logsource_text,
                    verdict=branch.verdict.value,
                    identity=", ".join(branch.identity_fields) or "n/a",
                    precision=branch.time_precision or "n/a",
                    reason=branch.reason.replace("|", "/"),
                )
            )
        lines.append("")

        if record.replays:
            lines.append(
                (
                    "| Scenario | Verdict | Raw events | De-dup count | "
                    "Unique values | Naive alert | Contract alert |"
                )
            )
            lines.append("| --- | --- | --- | --- | --- | --- | --- |")
            for outcome in record.replays:
                lines.append(
                    (
                        "| {scenario} | {verdict} | {raw} | {dedup} | {unique} "
                        "| {naive} | {contract} |"
                    ).format(
                        scenario=outcome.scenario.value,
                        verdict=outcome.verdict.value,
                        raw=outcome.raw_events,
                        dedup="n/a" if outcome.dedup_count is None else outcome.dedup_count,
                        unique=(
                        "n/a" if outcome.unique_values is None else outcome.unique_values
                    ),
                        naive="yes" if outcome.naive_alert else "no",
                        contract=(
                            "undetermined"
                            if outcome.contract_alert is None
                            else ("yes" if outcome.contract_alert else "no")
                        ),
                    )
                )
            lines.append("")

        changes = record.threshold_changes
        if changes:
            lines.append("**Threshold changes (attributed alerts):**")
            for outcome in changes:
                lines.append(
                    "- Rule `{rule}` in scenario `{scenario}` ({basis}): naive={naive} -> "
                    "contract={contract}.".format(
                        rule=outcome.rule_name,
                        scenario=outcome.scenario.value,
                        basis=outcome.basis.value,
                        naive="alert" if outcome.naive_alert else "no alert",
                        contract="alert" if outcome.contract_alert else "no alert",
                    )
                )
            lines.append("")
        return lines


__all__ = [
    "CorrelationReportRecord",
    "CountingReport",
    "ReplayScenario",
    "ReplayVerdict",
]
