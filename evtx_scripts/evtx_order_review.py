#!/usr/bin/env python
"""Build a source-aware local order review from EVTX acquisitions and a witness table."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Evtx.order_review import (
    load_relations_file,
    load_witness_table,
    observations_from_evtx,
    review_local_order,
)


def _split_acquisition(spec: str) -> tuple[str, str]:
    if "=" in spec:
        acquisition_id, path = spec.split("=", 1)
        return acquisition_id, path
    path = spec
    return Path(path).stem, path


def _load_json_rows(path: str | None, key: str) -> list[dict]:
    if not path:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        return list(data.get(key) or data.get("rows") or data.get("observations") or [])
    return list(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Review local event/segment order with EVTX provenance and witness conflicts."
    )
    parser.add_argument("evtx", nargs="*", help="EVTX acquisition paths; acquisition id defaults to file stem.")
    parser.add_argument(
        "--acquisition",
        action="append",
        default=[],
        metavar="ID=PATH",
        help="Named EVTX acquisition; repeat once per acquisition.",
    )
    parser.add_argument("--witnesses", help="CSV/TSV/JSON witness table.")
    parser.add_argument("--observations", help="Optional JSON observation rows for non-EVTX or pre-extracted cases.")
    parser.add_argument("--acquisition-relations", help="JSON/CSV explicit acquisition relation rows.")
    parser.add_argument("--evidence-relations", help="JSON/CSV additional source-bearing relation rows.")
    parser.add_argument("--node-map", help="JSON map from acquisition-scoped/raw record numbers to operation nodes.")
    parser.add_argument("--max-legal-orders", type=int, default=32, help="Maximum topological orders to enumerate.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("-o", "--output", help="Write report here instead of stdout.")
    parser.add_argument("--no-continuity", action="store_true", help="Do not infer record-number continuity edges.")
    parser.add_argument("--no-physical-order", action="store_true", help="Do not infer traversal physical order edges.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    node_map = json.loads(Path(args.node_map).read_text(encoding="utf-8")) if args.node_map else {}

    observations = _load_json_rows(args.observations, "observations")
    acquisition_specs = list(args.acquisition)
    acquisition_specs.extend(path for path in args.evtx)
    for spec in acquisition_specs:
        acquisition_id, path = _split_acquisition(spec)
        observations.extend(observations_from_evtx(path, acquisition_id, node_map=node_map))

    witnesses = load_witness_table(args.witnesses) if args.witnesses else []
    acquisition_relations = load_relations_file(args.acquisition_relations) if args.acquisition_relations else []
    evidence_relations = load_relations_file(args.evidence_relations) if args.evidence_relations else []

    review = review_local_order(
        observations=observations,
        witnesses=witnesses,
        acquisition_relations=acquisition_relations,
        evidence_relations=evidence_relations,
        continuity=not args.no_continuity,
        physical_order=not args.no_physical_order,
        max_legal_orders=args.max_legal_orders,
    )
    output = review.to_json() if args.format == "json" else review.to_markdown()
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
