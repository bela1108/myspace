"""Command-line entry point for local slot advisory queries."""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict

from .api import serve
from .demo import demo_payload
from .query import query_file, run_query


def _print_json(value: Dict[str, Any], compact: bool = False) -> None:
    if compact:
        print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2))


def _concise(report: Dict[str, Any]) -> Dict[str, Any]:
    slots = []
    for slot in report["slots"]:
        slots.append({
            "slot_id": slot["slot_id"],
            "snapshot_id": slot["snapshot_id"],
            "applicability": [
                {
                    "advisory_id": item["advisory_id"],
                    "verdict": item["verdict"],
                    "closure_scope": item["closure_scope"],
                    "reason_codes": item["reason_codes"],
                    "explanation_zh": item["explanation_zh"],
                }
                for item in slot["applicability"]
            ],
            "other_slot_closure_substitutions": [
                {
                    "closure_id": item["closure_id"],
                    "source_slot_id": item["source_slot_id"],
                    "accepted": item["accepted"],
                    "reason_codes": item["reason_codes"],
                    "explanation_zh": item["explanation_zh"],
                }
                for item in slot["other_slot_closure_substitutions"]
            ],
        })
    return {
        "query_id": report["query_id"],
        "summary": report["summary"],
        "host_aggregation_guard": report["host_aggregation_guard"],
        "slots": slots,
        "created_closures": [
            {
                "closure_id": item["closure_id"],
                "advisory_id": item["advisory_id"],
                "closure_scope": item["closure_scope"],
                "slot_id": item["slot_id"],
                "snapshot_id": item["snapshot_id"],
                "record_hash": item["record_hash"],
                "witness_identities": [
                    {
                        "witness_id": witness["witness_id"],
                        "condition_id": witness["condition_id"],
                        "scope": witness["condition_scope"],
                        "slot_id": witness["slot_id"],
                        "component_id": witness["component_id"],
                        "component_cpe": witness["component_cpe"],
                        "component_version": witness["component_version"],
                        "identity_fingerprint": witness["identity_fingerprint"],
                    }
                    for witness in item["witnesses"]
                ],
            }
            for item in report["created_closures"]
        ],
        "lifecycle_summary": {
            "evidence_supplements": [
                {
                    "scope": item.get("scope"),
                    "slot_id": item.get("slot_id"),
                    "affected_slot_ids": item.get("affected_slot_ids"),
                    "responsibility_change_zh": item.get("responsibility_change_zh"),
                    "closure_id": (item.get("closure") or {}).get("closure_id"),
                }
                for item in report["lifecycle"].get("evidence_supplements", [])
            ],
            "migrations": [
                {
                    "from_slot_id": item["from_slot_id"],
                    "to_slot_id": item["to_slot_id"],
                    "rejected_old_closures": [
                        check["closure_id"]
                        for check in item["old_closure_substitution_checks"]
                        if not check["accepted"]
                    ],
                    "new_closure_id": (item.get("new_slot_closure") or {}).get("closure_id"),
                    "responsibility_change_zh": item["responsibility_change_zh"],
                }
                for item in report["lifecycle"].get("migrations", [])
            ],
        },
        "responsibility_rules": report["responsibility_rules"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m cpe.slot_advisory")
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo", help="run the fictional cabinet example")
    demo_parser.add_argument("--full", action="store_true", help="print the full JSON report")
    demo_parser.add_argument("--compact", action="store_true")

    query_parser = subparsers.add_parser("query", help="query a JSON request file")
    query_parser.add_argument("--file", required=True)
    query_parser.add_argument("--compact", action="store_true")

    serve_parser = subparsers.add_parser("serve", help="start localhost JSON HTTP API")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        httpd = serve(args.host, args.port)
        print("Serving slot advisory query API at http://{}:{}/query".format(args.host, args.port))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return
    if args.command == "query":
        report = query_file(args.file)
        _print_json(report, args.compact)
        return

    report = run_query(demo_payload())
    if args.command == "demo" and args.full:
        _print_json(report, args.compact)
    else:
        _print_json(_concise(report), args.compact)


if __name__ == "__main__":
    main()
