# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Read-only forensic comparison for two signed in-toto links."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Optional, Sequence

from in_toto import parameter_audit
from in_toto.common_args import QUIET_ARGS, QUIET_KWARGS
from in_toto.models._signer import load_public_key_from_file

LOG = logging.getLogger("in_toto")


def create_parser() -> argparse.ArgumentParser:
    """Create the ``in-toto-compare-links`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="in-toto-compare-links",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Read-only comparison of normalized commands, material digests, "
            "step identity, signatures, and products for two signed links."
        ),
        epilog=(
            "Exit status:\n"
            "  0  links are provably equivalent\n"
            "  1  audit completed but equivalence is not proven\n"
            "  2  arguments, keys, or metadata could not be loaded\n"
        ),
    )

    parser.add_argument("--left", required=True, metavar="<path>", help="first signed link file")
    parser.add_argument("--right", required=True, metavar="<path>", help="second signed link file")
    parser.add_argument(
        "--verification-key",
        action="append",
        default=[],
        metavar="<path>",
        help="trusted public key PEM; may be passed multiple times",
    )
    parser.add_argument(
        "--config",
        metavar="<path>",
        help="JSON policy with substitutions, aliases, and path aliases",
    )
    parser.add_argument(
        "--report",
        metavar="<path>",
        help="optional path to write the JSON audit report",
    )
    parser.add_argument(
        "--require-signer-overlap",
        action="store_true",
        help="require a common claimed/trusted signing key id",
    )
    parser.add_argument(*QUIET_ARGS, **QUIET_KWARGS)
    return parser


def _load_keys(paths: Sequence[str]) -> list[dict[str, Any]]:
    return [load_public_key_from_file(path) for path in paths]


def run(argv: Optional[Sequence[str]] = None) -> tuple[dict[str, Any], int]:
    """Run the CLI logic and return ``(report, exit_code)``."""
    parser = create_parser()
    args = parser.parse_args(argv)

    keys = _load_keys(args.verification_key)
    policy = parameter_audit.load_audit_policy(args.config) if args.config else None

    report = parameter_audit.audit_links(
        args.left,
        args.right,
        verification_keys=keys,
        policy=policy,
        require_signer_overlap=args.require_signer_overlap,
    )

    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")

    if not args.quiet:
        print(json.dumps(report, indent=2, sort_keys=True))

    return report, 0 if report["equivalent"] else 1


def main(argv: Optional[Sequence[str]] = None) -> None:
    """CLI entry point."""
    try:
        _, exit_code = run(argv)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        LOG.error("parameter audit failed: %s", exc)
        sys.exit(2)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
