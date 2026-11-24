#!/usr/bin/env python
#    This file is part of python-evtx.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Offline rebuttal entry point.

Reduce a documented case claim to finite event-identity, ordering and field
assertions, scan one or more EVTX files, and report the shortest credible
material that rebuts each assertion - while keeping merely unconfirmable
material separate.  Optionally apply a template proof: a record whose
resident template version is not confirmed is excluded from the deciding
material, which can only make a conclusion unconfirmable, never rebutted.
"""
import argparse
import json
import sys

import Evtx.rebuttal as rebuttal


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Rebut a documented case claim against offline EVTX material."
    )
    parser.add_argument("evtx", nargs="+", help="Path(s) to Windows EVTX event log file(s)")
    parser.add_argument("--claim", required=True, help="JSON file describing the finite case claim")
    parser.add_argument(
        "--template-proof",
        default=None,
        help="Optional JSON file mapping event identities to authoritative template GUIDs",
    )
    parser.add_argument("--json", dest="as_json", action="store_true", help="Emit the report as JSON")
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        claim = rebuttal.CaseClaim.from_file(args.claim)
        proof = (
            rebuttal.TemplateProof.from_file(args.template_proof) if args.template_proof else None
        )
        report = rebuttal.analyze_paths(args.evtx, claim, proof)
    except (rebuttal.RebuttalError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return rebuttal.EXIT_ERROR

    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(rebuttal.render_text_report(report))

    if report["overall"] == rebuttal.REBUTTED:
        return rebuttal.EXIT_REBUTTED
    if report["overall"] == rebuttal.UNCONFIRMABLE:
        return rebuttal.EXIT_UNCONFIRMABLE
    return rebuttal.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

