#!/usr/bin/env python3
"""Run the two SMB-signing interpretations against one SYSTEM hive.

Usage:
    python examples/review/demo_smb_signing.py /path/to/SYSTEM
"""

import argparse
import json
from pathlib import Path

from regipy.review import review_hive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hive", help="Path to a SYSTEM hive")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the full review report instead of the summary",
    )
    args = parser.parse_args()

    example_dir = Path(__file__).resolve().parent
    report = review_hive(
        args.hive,
        [
            example_dir / "smb_signing_legacy.json",
            example_dir / "smb_signing_domain_server.json",
        ],
        prior_claims={"smb_signing": "enabled"},
    )

    if args.pretty:
        print(json.dumps(report, indent=2))
        return 0

    result = report["results"]["smb_signing"]
    print(f"subject:    {result['subject']}")
    print(f"status:     {result['status']}")
    print(f"candidates: {', '.join(result['candidates'])}")
    print(f"prior:      {result['prior_claim']['status']}")
    for assumption in result["divergence"]["assumptions"]:
        print(f"diverges on {assumption['dimension']}:")
        for rule_set, statement in assumption["values"].items():
            print(f"  {rule_set}: {statement}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
