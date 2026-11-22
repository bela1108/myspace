#!/usr/bin/env python3
"""Run the offline midnight shift handover audit demo."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def prepare_import_path() -> None:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def base_dir() -> Path:
    return Path(__file__).resolve().parent


def load_rules() -> list:
    prepare_import_path()
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaRuleLocation

    rules = []
    for path in sorted((base_dir() / "rules").glob("*.yml")):
        collection = SigmaCollection.from_yaml(
            path.read_text(encoding="utf-8"),
            source=SigmaRuleLocation(path.relative_to(ROOT)),
        )
        rules.extend(collection.rules)
    return rules


def reference_only_json(report) -> str:
    data = report.to_dict()
    reference = report.reference_only_chains
    keys = {chain.identity.key for chain in reference}
    data["audits"] = [audit for audit in data["audits"] if audit["identity"]["key"] in keys]
    data["chains"] = [chain.to_dict() for chain in reference]
    data["reference_only_chains"] = [chain.to_dict() for chain in reference]
    data["filter"] = {"reference_only": True}
    return json.dumps(data, indent=2, ensure_ascii=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference-only",
        action="store_true",
        help="show only notification chains that must not be used as a release basis",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="report format printed to stdout",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the selected report to this file instead of stdout",
    )
    args = parser.parse_args()

    prepare_import_path()
    from sigma.audit.handover import HandoverConfig, audit_from_config
    from sigma.processing.pipeline import ProcessingPipeline

    config = HandoverConfig.from_yaml((base_dir() / "shift.yml").read_text(encoding="utf-8"))
    pipeline = ProcessingPipeline.from_yaml(
        (base_dir() / "pipeline.yml").read_text(encoding="utf-8")
    )
    report = audit_from_config(
        load_rules(),
        config,
        pipeline,
        generated_at=config.shift.starts_at,
    )
    if args.format == "json":
        text = reference_only_json(report) if args.reference_only else report.to_json()
    else:
        text = report.to_markdown(reference_only_only=args.reference_only)
    if args.output is not None:
        args.output.write_text(text, encoding="utf-8")
        print("wrote " + str(args.output))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
