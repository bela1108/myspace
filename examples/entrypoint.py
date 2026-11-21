#!/usr/bin/env python
"""Inspect a .NET CLI entry-point declaration.

The same CLI-header value can mean a MethodDef token, a File token, or a
native RVA.  This example prints the resolved category together with the raw
declaration and the evidence used to verify it.
"""
import argparse
import json

import dnfile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help=".NET PE file to inspect")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a text report")
    args = parser.parse_args()

    pe = dnfile.dnPE(args.path)
    result = pe.get_entry_point()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(dnfile.entrypoint.describe_entry_point(pe))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
