#!/usr/bin/env python3
"""Run the offline handover audit demo and write JSON/Markdown reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sigma.audit.handover import AuditStatus, HandoverAuditConfig, HandoverAuditor
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline


HERE = Path(__file__).resolve().parent


def load_demo():
    config = HandoverAuditConfig.from_yaml_file(HERE / "scenario.yml")
    pipeline = ProcessingPipeline.from_yaml(
        (HERE / "pipeline.yml").read_text(encoding="utf-8"),
        source_path=str(HERE / "pipeline.yml"),
    )
    collection = SigmaCollection.load_ruleset([HERE / "rules"])
    if collection.errors:
        raise RuntimeError(
            "Demo rules failed to parse: "
            + "; ".join(str(error) for error in collection.errors)
        )
    return config, pipeline, collection.rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--status",
        choices=[status.value for status in AuditStatus],
        help="Print only chains with this status.",
    )
    parser.add_argument(
        "--reference-only",
        action="store_true",
        help="Print only reference-only chains that must not be used for release.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail unless the demo contains exactly one reference-only chain and all statuses.",
    )
    args = parser.parse_args(argv)

    config, pipeline, rules = load_demo()
    report = HandoverAuditor(config).audit(rules, pipeline)

    (HERE / "report.json").write_text(report.to_json() + "\n", encoding="utf-8")
    (HERE / "report.md").write_text(report.to_markdown(), encoding="utf-8")

    print(json.dumps(report.summary(), ensure_ascii=False, indent=2))

    if args.reference_only:
        selected = report.reference_only_chains()
    elif args.status:
        selected = report.filter(status=args.status)
    else:
        selected = []

    if selected:
        print(
            json.dumps(
                [chain.to_dict() for chain in selected],
                ensure_ascii=False,
                indent=2,
            )
        )

    if args.check:
        reference_only = report.reference_only_chains()
        statuses = {chain.status for chain in report.chains}
        problems = []
        if len(reference_only) != 1:
            problems.append(
                f"expected exactly one reference-only chain, found {len(reference_only)}"
            )
        missing = {status.value for status in AuditStatus} - {status.value for status in statuses}
        if missing:
            problems.append("missing statuses: " + ", ".join(sorted(missing)))
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 1
        print(
            f"\nOK: {len(report.chains)} chains, exactly one reference-only chain "
            f"({reference_only[0].chain_id})."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
