"""Command line entry point for the offline counting contract check.

Runs the full pipeline on a set of Sigma base rules, correlation rules,
counting contracts and one small logical-operation set, then writes JSON and
Markdown comparison reports that separate count-based from unique-value
correlations and attribute every threshold change to a concrete alert.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.counting.checker import CountingContractChecker
from sigma.counting.registry import CountingContractRegistry
from sigma.counting.replay import LogicalOperation, ScenarioRunner
from sigma.counting.report import CorrelationReportRecord, CountingReport


def load_operations(path: Path) -> list[LogicalOperation]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = loaded["operations"] if isinstance(loaded, dict) else loaded
    return [
        LogicalOperation(
            identity=entry["identity"],
            timestamp=float(entry["timestamp"]),
            fields=dict(entry.get("fields", {})),
        )
        for entry in entries
    ]


def build_report(
    base_rules_path: Path,
    correlation_rules_path: Path,
    contracts_path: Path,
    operations_path: Path,
) -> CountingReport:
    base_text = base_rules_path.read_text(encoding="utf-8")
    correlation_text = correlation_rules_path.read_text(encoding="utf-8")
    collection = SigmaCollection.from_yaml(base_text + "\n---\n" + correlation_text)
    for rule in collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            rule.resolve_rule_references(collection)

    registry = CountingContractRegistry.from_file(contracts_path)
    checker = CountingContractChecker(registry)
    operations = load_operations(operations_path)

    report = CountingReport()
    for rule in collection.rules:
        if not isinstance(rule, SigmaCorrelationRule):
            continue
        check = checker.check(rule)
        record = CorrelationReportRecord(check=check)
        branch_contracts = {
            branch.branch: registry.lookup(branch.logsource)
            for branch in check.branch_verdicts
            if branch.logsource is not None
        }
        unique_contracts = list(
            {
                contract.logsource.as_tuple(): contract
                for contract in branch_contracts.values()
                if contract is not None
            }.values()
        )
        if unique_contracts:
            # Replay uses the canonical operation set; the first branch's
            # contract supplies the identity materialization semantics.
            runner = ScenarioRunner(unique_contracts[0])
            record.replays = runner.run_all(rule, operations)
        report.add(record)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).parent / "demo"
    parser.add_argument("--base-rules", type=Path, default=here / "base_rules.yml")
    parser.add_argument("--correlation-rules", type=Path, default=here / "correlation_rules.yml")
    parser.add_argument("--contracts", type=Path, default=here / "contracts.yml")
    parser.add_argument("--operations", type=Path, default=here / "operations.yml")
    parser.add_argument("--json-out", type=Path, default=here / "report.json")
    parser.add_argument("--markdown-out", type=Path, default=here / "report.md")
    args = parser.parse_args(argv)

    report = build_report(
        args.base_rules,
        args.correlation_rules,
        args.contracts,
        args.operations,
    )
    args.json_out.write_text(report.to_json(), encoding="utf-8")
    args.markdown_out.write_text(report.to_markdown(), encoding="utf-8")
    print(f"Wrote {args.json_out} and {args.markdown_out}")
    print(json.dumps(report.to_dict()["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
