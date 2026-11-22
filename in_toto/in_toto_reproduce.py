"""CLI for adjudicating two independent in-toto builds."""

import argparse
import logging
import sys

from securesystemslib._gpg import functions as gpg_interface

from in_toto import verifylib
from in_toto.common_args import (
    GPG_HOME_ARGS,
    GPG_HOME_KWARGS,
    VERBOSE_ARGS,
    VERBOSE_KWARGS,
)
from in_toto.models._signer import load_public_key_from_file
from in_toto.models.metadata import Metadata
from in_toto.reproducibility import verify_reproducibility

LOG = logging.getLogger("in_toto")


def create_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Compare two independently produced, signed in-toto links or link "
            "directories after applying the layout reproducibility policy."
        )
    )
    parser.add_argument("-l", "--layout", required=True)
    parser.add_argument(
        "--verification-keys", nargs="+", metavar="<path>"
    )
    parser.add_argument("--gpg", nargs="+", metavar="<id>")
    parser.add_argument(
        "--link", action="append", dest="links", metavar="<path>"
    )
    parser.add_argument(
        "--link-dir", action="append", dest="link_dirs", metavar="<path>"
    )
    parser.add_argument(
        "--allow-difference", action="append", dest="allow_differences"
    )
    parser.add_argument(
        "--require-identical", action="append", dest="required_identical"
    )
    parser.add_argument(*GPG_HOME_ARGS, **GPG_HOME_KWARGS)
    parser.add_argument(*VERBOSE_ARGS, **VERBOSE_KWARGS)
    return parser


def _layout_keys(args):
    keys = {}
    if args.gpg:
        keys.update(
            gpg_interface.export_pubkeys(args.gpg, homedir=args.gpg_home)
        )
    for path in args.verification_keys or []:
        key = load_public_key_from_file(path)
        keys[key["keyid"]] = key
    return keys


def main():  # noqa: C901
    parser = create_parser()
    args = parser.parse_args()
    LOG.setLevelVerboseOrQuiet(args.verbose, False)

    metadata = Metadata.load(args.layout)
    keys = _layout_keys(args)

    try:
        if args.links:
            if len(args.links) != 2:
                parser.error("--link must be passed exactly twice")
            left = Metadata.load(args.links[0])
            right = Metadata.load(args.links[1])
            if keys:
                last_error = None
                for key in keys.values():
                    try:
                        metadata.verify_signature(key)
                        break
                    except Exception as error:  # noqa: BLE001
                        last_error = error
                else:
                    raise last_error
            layout = metadata.get_payload()
            verify_reproducibility(
                layout,
                left,
                right,
                keys=keys or None,
                allow_differences=args.allow_differences,
                required_identical=args.required_identical,
            )
            return 0

        if not args.link_dirs or len(args.link_dirs) != 2:
            parser.error(
                "pass two --link files or two --link-dir directories"
            )

        if keys:
            verifylib.in_toto_verify(
                metadata,
                keys,
                link_dir_path=args.link_dirs[0],
                reproducibility_link_dir=args.link_dirs[1],
                allow_differences=args.allow_differences,
                required_identical=args.required_identical,
                persist_inspection_links=False,
            )
            return 0

        layout = metadata.get_payload()
        left = verifylib.load_links_for_layout(
            layout, args.link_dirs[0], threshold_check=False
        )
        right = verifylib.load_links_for_layout(
            layout, args.link_dirs[1], threshold_check=False
        )
        for name, links in right.items():
            target = left.setdefault(name, {})
            for keyid, value in links.items():
                unique = keyid
                suffix = 2
                while unique in target:
                    unique = f"{keyid}#{suffix}"
                    suffix += 1
                target[unique] = value
        verify_reproducibility(
            layout,
            left,
            allow_differences=args.allow_differences,
            required_identical=args.required_identical,
        )
        return 0

    except Exception as error:  # noqa: BLE001
        LOG.error("(in-toto-reproduce) %s: %s", type(error).__name__, error)
        return 1


if __name__ == "__main__":
    sys.exit(main())
