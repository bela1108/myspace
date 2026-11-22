"""Command-line entry point for local source-independence checks."""

import argparse
import json
import sys

from .independence import (
    CUSTODIAN_VIEW,
    PUBLIC_VIEW,
    check_independence,
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m stix2.provenance",
        description=(
            "Check local source independence in a STIX 2 bundle. "
            "The public view redacts restricted observations."
        ),
    )
    parser.add_argument(
        "input",
        help="path to a STIX 2 bundle JSON file, or '-' for stdin",
    )
    parser.add_argument(
        "--view",
        choices=(PUBLIC_VIEW, CUSTODIAN_VIEW),
        default=PUBLIC_VIEW,
        help="public (default) or custodian",
    )
    parser.add_argument(
        "--restricted-marking",
        action="append",
        default=[],
        metavar="MARKING_ID",
        help="marking-definition ID treated as custodian-only (repeatable)",
    )
    parser.add_argument(
        "--relationship-type",
        action="append",
        default=None,
        metavar="TYPE",
        help="relationship type treated as a collection link (repeatable)",
    )
    parser.add_argument(
        "--citation-property",
        action="append",
        default=None,
        metavar="PROPERTY",
        help="observation property holding self-reported citations",
    )
    parser.add_argument(
        "--no-external-references",
        action="store_true",
        help="do not read STIX IDs from external_references",
    )
    args = parser.parse_args(argv)

    if args.input == "-":
        data = json.load(sys.stdin)
    else:
        with open(args.input, encoding="utf-8") as handle:
            data = json.load(handle)

    kwargs = {
        "restricted_markings": args.restricted_marking or None,
        "use_external_references": not args.no_external_references,
    }
    if args.relationship_type:
        kwargs["collection_relationship_types"] = args.relationship_type
    if args.citation_property:
        kwargs["citation_properties"] = args.citation_property

    result = check_independence(data, view=args.view, **kwargs)
    json.dump(
        result.as_dict(),
        sys.stdout,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
