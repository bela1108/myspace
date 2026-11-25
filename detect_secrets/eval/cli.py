"""
Command-line entry point for the offline plugin evaluation.

Example:

    python -m detect_secrets.eval.cli \
        --dataset test_data/eval/python_heavy \
        --plugin AWSKeyDetector --plugin GitHubTokenDetector \
        --baseline AWSKeyDetector --candidate GitHubTokenDetector
"""
import argparse
import sys
from typing import List
from typing import Optional
from typing import Sequence

from .dataset import LabeledDataset
from .dataset import load_dataset
from .engine import run_all
from .matching import match_dataset
from .metrics import compare_configurations
from .metrics import evaluate
from .metrics import EvaluationReport
from .report import render_json_report
from .report import render_text_report


def _parse_specs(raw: Sequence[str]) -> List[dict]:
    return [{"name": name} for name in raw]


def evaluate_one(
    dataset: LabeledDataset,
    plugin_names: Sequence[str],
    baseline: Optional[Sequence[str]] = None,
    candidate: Optional[Sequence[str]] = None,
) -> EvaluationReport:
    """Run the plugins on one dataset and build its full report."""
    plugin_hits, failures = run_all(dataset, _parse_specs(plugin_names))
    match_result = match_dataset(dataset, plugin_hits, failures)
    report = evaluate(dataset, match_result)

    if baseline or candidate:
        baseline_names = list(baseline or [])
        candidate_names = list(candidate or [])
        baseline_hits, baseline_failures = run_all(
            dataset, _parse_specs(baseline_names),
        )
        candidate_hits, candidate_failures = run_all(
            dataset, _parse_specs(candidate_names),
        )
        baseline_match = match_dataset(dataset, baseline_hits, baseline_failures)
        candidate_match = match_dataset(dataset, candidate_hits, candidate_failures)
        report.comparisons = compare_configurations(
            dataset, baseline_match, candidate_match,
        )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detect-secrets-eval",
        description="Offline, label-driven evaluation of secret-detection plugins.",
    )
    parser.add_argument(
        "--dataset",
        action="append",
        required=True,
        help="Path to a labelled dataset directory (repeatable).",
    )
    parser.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="Plugin class name to evaluate (repeatable).",
    )
    parser.add_argument(
        "--baseline",
        action="append",
        default=[],
        help="Plugin in the baseline configuration (repeatable).",
    )
    parser.add_argument(
        "--candidate",
        action="append",
        default=[],
        help="Plugin in the candidate configuration (repeatable).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text tables.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.plugin and not (args.baseline and args.candidate):
        print(
            "error: provide at least one --plugin or both --baseline/--candidate",
            file=sys.stderr,
        )
        return 2

    reports = []
    for directory in args.dataset:
        dataset = load_dataset(directory)
        plugin_names = args.plugin or sorted(set(args.baseline + args.candidate))
        reports.append(
            evaluate_one(
                dataset,
                plugin_names,
                baseline=args.baseline,
                candidate=args.candidate,
            ),
        )

    if args.json:
        payload = [report.as_dict() for report in reports]
        print(render_json_report(reports[0]) if len(reports) == 1 else _render_many_json(reports))
    else:
        for index, report in enumerate(reports):
            if index:
                print()
            print(render_text_report(report))
    return 0


def _render_many_json(reports: List[EvaluationReport]) -> str:
    import json
    return json.dumps([report.as_dict() for report in reports], indent=2, sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
