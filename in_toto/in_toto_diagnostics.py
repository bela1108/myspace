# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  in_toto_diagnostics.py

<Purpose>
  Command line interface for the offline threshold diagnostics in
  ``in_toto.diagnostics``. It explains why the links of a release step do not
  satisfy threshold verification, by classifying link signatures, grouping
  links with provably consistent materials/products and reporting minimal
  conflicting fields between threshold-meeting groups.

<Return Codes>
  2 if an exception occurred during argument parsing
  1 if a step has conflicting artifact views or insufficient evidence
  0 if every step has a single consistent view meeting its threshold

"""

import argparse
import json
import logging
import os
import sys

import in_toto.models.link
from in_toto import __version__
from in_toto.common_args import (
    OPTS_TITLE,
    sort_action_groups,
    title_case_action_groups,
)
from in_toto.diagnostics import (
    VERDICT_CONFLICT,
    VERDICT_INSUFFICIENT,
    diagnose_layout_links,
)
from in_toto.models._signer import load_public_key_from_file
from in_toto.models.metadata import Metadata
from in_toto.verifylib import verify_metadata_signatures

# Command line interfaces should use in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger("in_toto")


def _load_links_for_step(layout, step, link_dir):
    """Load every available link file for a step from ``link_dir``.

    Unlike ``verifylib.load_links_for_layout`` this does not require a minimum
    number of links: missing evidence is itself part of the diagnostic.
    """
    links = {}
    for authorized_keyid in step.pubkeys:
        key = layout.keys.get(authorized_keyid, {})
        subkey_ids = list(key.get("subkeys", {}).keys())
        for keyid in [authorized_keyid] + subkey_ids:
            filename = in_toto.models.link.FILENAME_FORMAT.format(
                step_name=step.name, keyid=keyid
            )
            filepath = os.path.join(link_dir, filename)
            if os.path.exists(filepath):
                links[keyid] = Metadata.load(filepath)
    return links


def _load_extra_links(link_paths):
    """Load explicitly passed link files, keyed by their signer keyid.

    These may be links whose signer is not authorized for any step (e.g. a
    second batch from an unknown functionary), so that the diagnostic can
    classify them as unauthorized instead of silently ignoring them.
    """
    extra_links = {}
    for path in link_paths or []:
        metadata = Metadata.load(path)
        link = metadata.get_payload()
        extra_links[link.name] = extra_links.get(link.name, {})
        signer_keyids = [
            signature["keyid"] for signature in metadata.signatures
        ]
        for keyid in signer_keyids:
            extra_links[link.name][keyid] = metadata
    return extra_links


def create_parser():
    """Create and return configured ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
in-toto-diagnostics is an offline release review tool. For each step of the
passed layout, it classifies the available link signatures (valid,
unauthorized, invalid signature, expired key), groups validly signed links
that report provably identical materials and products, and reports the minimal
conflicting fields when at least two groups independently meet the step
threshold.

The diagnostic never executes inspections and never contacts a network or key
server. It only reads the passed layout and link metadata and prints a
deterministic JSON report to stdout, which can be embedded into in-toto review
tooling.""",
    )

    parser.usage = f"%(prog)s <named arguments> [{OPTS_TITLE.lower()}]"

    named_args = parser.add_argument_group("required named arguments")
    named_args.add_argument(
        "-l",
        "--layout",
        type=str,
        required=True,
        metavar="<path>",
        help="path to the layout whose steps should be diagnosed.",
    )

    named_args.add_argument(
        "-k",
        "--verification-keys",
        dest="verification_keys",
        type=str,
        nargs="+",
        metavar="<path>",
        help=(
            "paths to public key files used to verify the layout's own"
            " signatures before running the offline diagnostic."
        ),
    )

    parser.add_argument(
        "--link-dir",
        dest="link_dir",
        type=str,
        metavar="<path>",
        default=".",
        help=(
            "directory from which '<step>.<keyid prefix>.link' files are"
            " loaded for authorized functionaries. Defaults to the current"
            " working directory."
        ),
    )

    parser.add_argument(
        "--links",
        type=str,
        nargs="+",
        metavar="<path>",
        help=(
            "additional link metadata files to include in the diagnostic,"
            " e.g. links from a second batch of functionaries. Links signed"
            " by unauthorized keys are classified but never grouped."
        ),
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        metavar="<path>",
        help=(
            "write the JSON diagnostic report to this file instead of stdout."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{parser.prog} {__version__}",
    )

    title_case_action_groups(parser)
    sort_action_groups(parser)

    return parser


def build_report(
    layout_path,
    link_dir=".",
    extra_link_paths=None,
    verification_key_paths=None,
):
    """Load metadata from disk and build the diagnostic report."""
    layout_metadata = Metadata.load(layout_path)
    layout = layout_metadata.get_payload()

    if verification_key_paths:
        layout_key_dict = {}
        for path in verification_key_paths:
            key = load_public_key_from_file(path)
            layout_key_dict[key["keyid"]] = key
        verify_metadata_signatures(layout_metadata, layout_key_dict)

    steps_metadata = {}
    for step in layout.steps:
        steps_metadata[step.name] = _load_links_for_step(layout, step, link_dir)

    for step_name, links in _load_extra_links(extra_link_paths).items():
        if step_name in steps_metadata:
            steps_metadata[step_name].update(links)
        else:
            steps_metadata[step_name] = links

    return diagnose_layout_links(layout, steps_metadata)


def main():
    """Parse arguments, run diagnostics and print the report."""
    parser = create_parser()
    args = parser.parse_args()

    try:
        report = build_report(
            args.layout,
            link_dir=args.link_dir,
            extra_link_paths=args.links,
            verification_key_paths=args.verification_keys,
        )
        rendered = json.dumps(report, indent=2, sort_keys=True)
        if args.output and args.output != "-":
            with open(args.output, "w", encoding="utf8") as fp:
                fp.write(rendered)
        else:
            print(rendered)

    except Exception as e:  # noqa: BLE001
        LOG.error("(in-toto-diagnostics) %s: %s", type(e).__name__, e)
        sys.exit(2)

    verdicts = [
        step_report["verdict"] for step_report in report["steps"].values()
    ]
    if VERDICT_CONFLICT in verdicts or VERDICT_INSUFFICIENT in verdicts:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
