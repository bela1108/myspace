# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  in_toto_verify_switch.py

<Purpose>
  Command line interface for offline, replayable verification of a fallback
  release and the first normal release after recovery.

<Return Codes>
  2 if an exception occurred during argument parsing
  1 if the verdict is quarantine, or verification raised an error
  0 if the release may ship
"""

import argparse
import json
import logging
import sys

from in_toto import __version__, switch_verify
from in_toto.common_args import (
    OPTS_TITLE,
    QUIET_ARGS,
    QUIET_KWARGS,
    VERBOSE_ARGS,
    VERBOSE_KWARGS,
    sort_action_groups,
    title_case_action_groups,
)
from in_toto.models._signer import load_public_key_from_file
from in_toto.models.metadata import Metadata

LOG = logging.getLogger("in_toto")


def _load_keys(paths):
    """Load public keys and return a keyid -> key dictionary."""
    keys = {}
    for path in paths or []:
        key = load_public_key_from_file(path)
        keys[key["keyid"]] = key

    return keys


def create_parser():
    """Create and return the configured ArgumentParser."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
in-toto-verify-switch verifies, fully offline, that a release may ship after
an incident in which a fallback build was used.

The fallback layout and the normal layout are each verified with their own
manual sign-off keys.  Link metadata (signed materials and products) is
replayed against the layout rules.  For a normal release, artifacts produced
by the fallback build that remain in the cache or are consumed by the normal
build are quarantined unless a signed review manifest approves the same path
and digest.

Verification never uses the network, the clock, file modification times, or a
last-written mode marker.  Co-existing concurrent links are all evaluated;
links that disagree on artifacts make verification fail instead of selecting
whichever file was written last.

The command returns 0 for a releasable verdict, 1 for quarantine or an error,
and 2 for invalid arguments.""",
    )

    parser.usage = f"%(prog)s <named arguments> [{OPTS_TITLE.lower()}]"

    named_args = parser.add_argument_group("required named arguments")
    named_args.add_argument(
        "--fallback-layout",
        required=True,
        metavar="<path>",
        help="path to the signed fallback (incident) layout.",
    )
    named_args.add_argument(
        "--fallback-keys",
        required=True,
        nargs="+",
        metavar="<path>",
        help="public keys that must have signed the fallback layout.",
    )

    parser.add_argument(
        "--fallback-link-dir",
        default=".",
        metavar="<path>",
        help="directory with fallback link metadata (default: current dir).",
    )
    parser.add_argument(
        "--normal-layout",
        metavar="<path>",
        help="path to the signed normal (post-recovery) layout.",
    )
    parser.add_argument(
        "--normal-keys",
        nargs="+",
        metavar="<path>",
        help="public keys that must have signed the normal layout.",
    )
    parser.add_argument(
        "--normal-link-dir",
        default=".",
        metavar="<path>",
        help="directory with normal link metadata (default: current dir).",
    )
    parser.add_argument(
        "--review-bom",
        metavar="<path>",
        help=(
            "signed link metadata whose materials list the junction artifacts"
            " explicitly approved by a human reviewer."
        ),
    )
    parser.add_argument(
        "--review-keys",
        nargs="+",
        metavar="<path>",
        help="public keys for the review manifest.",
    )
    parser.add_argument(
        "--review-threshold",
        type=int,
        default=1,
        metavar="<int>",
        help="number of valid review signatures required (default: 1).",
    )
    parser.add_argument(
        "--cache-bom",
        metavar="<path>",
        help=(
            "signed link metadata whose materials list the cache contents at"
            " the junction.  If omitted, all fallback products are treated as"
            " remaining cached."
        ),
    )
    parser.add_argument(
        "--cache-keys",
        nargs="+",
        metavar="<path>",
        help="public keys for the cache manifest.",
    )
    parser.add_argument(
        "--cache-threshold",
        type=int,
        default=1,
        metavar="<int>",
        help="number of valid cache signatures required (default: 1).",
    )
    parser.add_argument(
        "--mode-marker",
        metavar="<path-or-value>",
        help=(
            "legacy mode marker recorded for audit only.  It never influences"
            " the verdict."
        ),
    )
    parser.add_argument(
        "--require-distinct-layout-signers",
        action="store_true",
        help="require the two layouts to use disjoint sign-off key sets.",
    )
    parser.add_argument(
        "--allow-unsigned-bom",
        action="store_true",
        help=(
            "accept unsigned manifests.  Intended only for local experiments;"
            " never use for a real release."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="print the full replay verdict as JSON.",
    )

    verbosity_args = parser.add_mutually_exclusive_group(required=False)
    verbosity_args.add_argument(*VERBOSE_ARGS, **VERBOSE_KWARGS)
    verbosity_args.add_argument(*QUIET_ARGS, **QUIET_KWARGS)

    parser.add_argument(
        "--version",
        action="version",
        version=f"{parser.prog} {__version__}",
    )

    title_case_action_groups(parser)
    sort_action_groups(parser)

    return parser


def _print_human(verdict):
    """Print a compact human-readable verdict."""
    print(f"switch verification: {verdict.status.upper()} ({verdict.phase})")
    for layout_name in (switch_verify.FALLBACK, switch_verify.NORMAL):
        signoffs = verdict.layout_signoffs.get(layout_name)
        if signoffs is not None:
            print(f"  {layout_name} sign-offs: {', '.join(signoffs)}")

    junction = verdict.junction
    print(
        "  junction: "
        f"residue={len(junction['residue'])}, "
        f"reviewed={len(junction['reviewed'])}, "
        f"unreviewed={len(junction['unreviewed'])}"
    )
    if verdict.concurrent_modes:
        print(f"  concurrent modes: {verdict.concurrent_modes}")
    if verdict.untrusted_mode_hint:
        print(f"  mode marker (untrusted): {verdict.untrusted_mode_hint}")

    for violation in verdict.violations:
        detail = violation.get("path", "")
        suffix = f" ({detail})" if detail else ""
        print(f"  violation: {violation['type']}{suffix}")

    print(f"  replay digest: {verdict.replay_digest}")


def main():
    """Parse arguments and run switch verification."""
    parser = create_parser()
    args = parser.parse_args()

    LOG.setLevelVerboseOrQuiet(args.verbose, args.quiet)

    if args.normal_layout and not args.normal_keys:
        parser.error(
            "--normal-layout requires at least one --normal-keys path."
        )
    if args.review_bom and not args.review_keys and not args.allow_unsigned_bom:
        parser.error("--review-bom requires --review-keys.")
    if args.cache_bom and not args.cache_keys and not args.allow_unsigned_bom:
        parser.error("--cache-bom requires --cache-keys.")

    try:
        fallback_layout = Metadata.load(args.fallback_layout)
        normal_layout = (
            Metadata.load(args.normal_layout) if args.normal_layout else None
        )
        review_bom = Metadata.load(args.review_bom) if args.review_bom else None
        cache_bom = Metadata.load(args.cache_bom) if args.cache_bom else None

        verdict = switch_verify.verify_switch_release(
            fallback_layout,
            _load_keys(args.fallback_keys),
            args.fallback_link_dir,
            normal_layout,
            _load_keys(args.normal_keys),
            args.normal_link_dir if normal_layout is not None else None,
            review_bom=review_bom,
            review_keys=_load_keys(args.review_keys),
            cache_bom=cache_bom,
            cache_keys=_load_keys(args.cache_keys),
            review_threshold=args.review_threshold,
            cache_threshold=args.cache_threshold,
            require_distinct_layout_signers=(
                args.require_distinct_layout_signers
            ),
            mode_marker=args.mode_marker,
            allow_unsigned_bom=args.allow_unsigned_bom,
        )

    except Exception as e:  # noqa: BLE001
        LOG.error("(in-toto-verify-switch) %s: %s", type(e).__name__, e)
        sys.exit(1)

    if args.output_json:
        print(json.dumps(verdict.to_dict(), indent=2, sort_keys=True))
    else:
        _print_human(verdict)

    sys.exit(0 if verdict.is_release else 1)


if __name__ == "__main__":
    main()
