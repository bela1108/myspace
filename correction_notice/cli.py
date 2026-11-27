"""Command-line entry point: build local history, process, emit bundles."""

import argparse
import json

from .fixtures import build_history_bundle
from .processor import load_history, process_correction


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Generate a section-A correction notice from local partial "
            "delivery receipts."
        ),
    )
    parser.add_argument(
        "--history-out",
        help="Write the input history bundle (incl. local fake receipts).",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Write the correction result bundle here.",
    )
    args = parser.parse_args(argv)

    history = build_history_bundle()
    if args.history_out:
        with open(args.history_out, "w", encoding="utf-8") as handle:
            handle.write(history.serialize(pretty=True))

    # Round-trip through parse + MemoryStore to prove the workflow reads the
    # STIX object history rather than in-memory Python objects.
    store = load_history(json.loads(history.serialize()))
    result = process_correction(store)

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(result.as_bundle().serialize(pretty=True))

    print("included recipients:", result.scope.included_refs)
    for item in result.scope.excluded:
        print(
            "excluded:",
            item["recipient_ref"],
            "->",
            item["reason"],
        )
    print("wrote", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
