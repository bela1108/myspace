# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Command line interface for offline credential-reference review."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from securesystemslib._gpg import functions as gpg_interface

from in_toto import __version__, reviewlib
from in_toto.common_args import (
    GPG_HOME_ARGS,
    GPG_HOME_KWARGS,
    QUIET_ARGS,
    QUIET_KWARGS,
    VERBOSE_ARGS,
    VERBOSE_KWARGS,
    sort_action_groups,
    title_case_action_groups,
)
from in_toto.models._signer import load_public_key_from_file

LOG = logging.getLogger("in_toto")


def create_parser():
    """Create the argument parser for in-toto-review."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Offline review of credential references in signed in-toto Links "
            "against an independent approval manifest. This command does not "
            "execute build or inspection commands."
        ),
    )
    named_args = parser.add_argument_group("required named arguments")

    named_args.add_argument(
        "-l", "--layout", required=True, metavar="<path>",
        help="Path to the signed root layout.",
    )
    named_args.add_argument(
        "-a",
        "--approvals",
        "--approval-manifest",
        "--credential-approvals",
        "--credential-review",
        "--review-approvals",
        dest="approvals",
        required=True,
        metavar="<path>",
        help="Path to the independent JSON approval manifest.",
    )
    parser.add_argument(
        "--verification-keys", nargs="+", metavar="<path>",
        help="Root layout public verification key PEM files.",
    )
    parser.add_argument(
        "-g", "--gpg", nargs="+", metavar="<id>",
        help="GPG key IDs used to verify the root layout.",
    )
    parser.add_argument(
        "--link-dir", default=".", metavar="<path>",
        help="Directory containing step Links and sublayout directories.",
    )
    parser.add_argument(
        "--report", metavar="<path>",
        help="Optional path to write the JSON report; stdout is used otherwise.",
    )
    parser.add_argument(*GPG_HOME_ARGS, **GPG_HOME_KWARGS)
    parser.add_argument(*VERBOSE_ARGS, **VERBOSE_KWARGS)
    parser.add_argument(*QUIET_ARGS, **QUIET_KWARGS)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    title_case_action_groups(parser)
    sort_action_groups(parser)
    return parser


def main(argv=None):
    """Run the offline credential review CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)
    LOG.setLevelVerboseOrQuiet(args.verbose, args.quiet)

    if not (args.gpg or args.verification_keys):
        parser.error("specify at least one '--verification-keys' and/or '--gpg'.")

    try:
        key_dict = {}
        if args.gpg:
            key_dict.update(
                gpg_interface.export_pubkeys(args.gpg, homedir=args.gpg_home)
            )
        for path in args.verification_keys or []:
            key = load_public_key_from_file(path)
            key_dict[key["keyid"]] = key

        report = reviewlib.review_layout(
            layout_path=args.layout,
            approval_path=args.approvals,
            link_dir=args.link_dir,
            layout_key_dict=key_dict,
        )
        payload = json.dumps(report, indent=2, sort_keys=True, default=str)
        if args.report:
            with open(args.report, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
        else:
            print(payload)

        sys.exit(0 if report.approved else 1)
    except Exception as exc:  # noqa: BLE001
        LOG.error("(in-toto-review) %s: %s", type(exc).__name__, exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
