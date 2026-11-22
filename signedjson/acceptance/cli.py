"""Command line interface for the offline acceptance verifier.

Everything works from local JSON files; no network access is required.

Input formats
-------------
keys.json::

    {"signer-name": {"key_id": "ed25519:1", "key": "<base64 verify key>"}}

materials.json::

    {"sha256:...": {"arbitrary": "canonicalisable payload"}}

events.json::

    [{"event_id": "...", "signer": "...", "material_id": "sha256:...",
      "material_digest": "...", "predecessor": null,
      "signatures": {...}}]
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from signedjson.acceptance.store import AcceptanceStore


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _open_store(args: argparse.Namespace) -> AcceptanceStore:
    store = AcceptanceStore.open(args.state)
    if args.keys:
        store.register_keys(_load_json(args.keys))
    if args.materials:
        store.register_materials(_load_json(args.materials))
    return store


def _cmd_init(args: argparse.Namespace) -> int:
    store = _open_store(args)
    store.save()
    print("initialised state at %s" % args.state)
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    store = _open_store(args)
    batch = _load_json(args.events)
    if not isinstance(batch, list):
        print("events file must contain a JSON array", file=sys.stderr)
        return 2
    snapshot = store.run(batch)
    json.dump(snapshot, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    review = snapshot["review_queue"]
    if review and not args.allow_review:
        return 3
    return 0


def _cmd_snapshots(args: argparse.Namespace) -> int:
    store = AcceptanceStore.open(args.state)
    if args.latest:
        latest = store.latest_snapshot()
        payload: Optional[List[Dict[str, Any]]] = [latest] if latest else []
    else:
        payload = store.snapshots
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m signedjson.acceptance",
        description="Offline acceptance of signed delivery events",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="create or refresh a state file")
    init_parser.add_argument("--state", required=True)
    init_parser.add_argument("--keys")
    init_parser.add_argument("--materials")
    init_parser.set_defaults(func=_cmd_init)

    ingest_parser = sub.add_parser("ingest", help="accept one batch of events")
    ingest_parser.add_argument("--state", required=True)
    ingest_parser.add_argument("--events", required=True)
    ingest_parser.add_argument("--keys")
    ingest_parser.add_argument("--materials")
    ingest_parser.add_argument(
        "--allow-review",
        action="store_true",
        help="exit 0 even when the review queue is non-empty",
    )
    ingest_parser.set_defaults(func=_cmd_ingest)

    snap_parser = sub.add_parser(
        "snapshots", help="print the retained node summaries (max three)"
    )
    snap_parser.add_argument("--state", required=True)
    snap_parser.add_argument("--latest", action="store_true")
    snap_parser.set_defaults(func=_cmd_snapshots)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
