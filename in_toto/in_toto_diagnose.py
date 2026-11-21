# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""CLI for offline artifact-rule order diagnostics."""

import argparse
import glob
import json
import os
import sys

from in_toto import __version__
from in_toto.models.metadata import Metadata
from in_toto.rule_diagnostics import diagnose_steps


def create_parser():
    """Create and return the diagnostic argument parser."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Explain which offline artifacts every layout rule really consumed "
            "and find mandatory MATCH rules that a preceding rule hollowed out."
        ),
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "-l",
        "--layout",
        metavar="<path>",
        help="layout metadata file with steps/inspections to diagnose.",
    )
    source.add_argument(
        "-s",
        "--scenario",
        metavar="<path>",
        help=(
            "JSON file containing steps and an offline artifact set. See "
            "the API documentation for the accepted shape."
        ),
    )

    parser.add_argument(
        "--link-dir",
        metavar="<path>",
        default=".",
        help="directory with offline link metadata for --layout (default: .).",
    )
    parser.add_argument(
        "--links",
        metavar="<path>",
        nargs="+",
        help="explicit offline link metadata files for --layout.",
    )
    parser.add_argument(
        "--step",
        metavar="<name>",
        action="append",
        help="only diagnose the named step/inspection (repeatable).",
    )
    parser.add_argument(
        "--source-type",
        choices=["materials", "products"],
        help="only diagnose this artifact side.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the complete report as JSON.",
    )
    parser.add_argument(
        "--output",
        metavar="<path>",
        help="write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="exit zero even when hollowed constraints are found.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{parser.prog} {__version__}",
    )
    return parser


def _load_json(path):
    with open(path, encoding="utf8") as file:
        return json.load(file)


def _load_layout_links(layout, link_dir):
    """Load the first offline link for every step/inspection."""
    links = {}
    for item in list(layout.steps) + list(layout.inspect):
        patterns = [
            os.path.join(link_dir, f"{item.name}.link"),
            os.path.join(link_dir, f"{item.name}.*.link"),
        ]
        paths = []
        for pattern in patterns:
            paths.extend(glob.glob(pattern))
        if not paths:
            continue
        metadata = Metadata.load(sorted(paths)[0])
        links[item.name] = metadata
    return links


def _load_link_paths(paths):
    """Load explicit link metadata paths."""
    links = {}
    for path in paths:
        metadata = Metadata.load(path)
        links[metadata.signed.name] = metadata
    return links


def _scenario_steps(scenario):  # noqa: C901
    """Normalize supported scenario shapes into steps plus offline links."""
    steps = scenario.get("steps")
    links = scenario.get("links", scenario.get("artifacts", {}))

    if steps is None and all(
        isinstance(value, dict) for value in scenario.values()
    ):
        steps = []
        for name, value in scenario.items():
            if not (
                isinstance(value.get("expected_materials"), list)
                or isinstance(value.get("expected_products"), list)
            ):
                continue
            item = dict(value)
            item.setdefault("name", name)
            steps.append(item)

    if steps is None:
        raise ValueError("scenario must contain a 'steps' list")

    links = dict(links)
    for step in steps:
        name = step.get("name")
        if name and name not in links:  # noqa: SIM102
            if "materials" in step or "products" in step:
                links[name] = {
                    "name": name,
                    "materials": step.get("materials", {}),
                    "products": step.get("products", {}),
                }

    top_materials = scenario.get("materials")
    if isinstance(top_materials, dict):
        for name, artifacts in top_materials.items():
            if name in links or not isinstance(artifacts, dict):
                continue
            if "materials" in artifacts or "products" in artifacts:
                links[name] = {"name": name, **artifacts}

    return steps, links


def _render_rule(rule_report):
    rule = " ".join(rule_report["rule"])
    consumed = ", ".join(rule_report["consumed"]) or "-"
    shadowed = ", ".join(rule_report["shadowed"]) or "-"
    return (
        f"  [{rule_report['index']}] {rule}\n"
        f"      consumed: {consumed}\n"
        f"      shadowed: {shadowed}\n"
        f"      state: {rule_report['state']}"
    )


def _render_report(report):
    lines = [
        f"Rule diagnostics for {report['source_name']} "
        f"({report['source_type']})",
        f"Verdict: {report['verdict']}",
    ]
    lines.extend(_render_rule(item) for item in report["rules"])

    if report["leftovers"]:
        lines.append("Unconsumed: " + ", ".join(report["leftovers"]))

    lines.append("Hollowed constraints (declared order):")
    if not report["hollow_rules"]:
        lines.append("  none")
    else:
        for finding in report["hollow_rules"]:
            rule = " ".join(finding["rule"])
            artifacts = ", ".join(finding["shadowed"])
            lines.append(f"  [{finding['index']}] {rule}: {artifacts}")

    conclusion = report.get("conclusion", {})
    shadow_findings = conclusion.get("hollowed_constraints", [])
    if shadow_findings and not report["hollow_rules"]:
        lines.append("Hollowed constraints (shadowing experiment):")
        for finding in shadow_findings:
            rule = " ".join(finding["rule"])
            artifacts = ", ".join(finding["shadowed"])
            lines.append(f"  [{finding['index']}] {rule}: {artifacts}")

    lines.append("Minimum ordering repairs:")
    repairs = conclusion.get("minimum_ordering", report["minimum_ordering"])
    if not repairs:
        lines.append("  none")
    else:
        lines.extend(
            f"  [{relation['before']}] before "
            f"[{relation['after']}]: {relation['artifacts']}"
            for relation in repairs
        )

    lines.append("Order experiments:")
    for name, experiment in report["experiments"].items():
        lines.append(
            f"  {name}: order={experiment['order']}, "
            f"verdict={experiment['verdict']}, "
            f"hollow={len(experiment['hollow_rules'])}"
        )
    return "\n".join(lines)


def _render_diagnose(report):
    parts = [
        _render_report(item[source_type])
        for item in report["items"]
        for source_type in ("materials", "products")
        if source_type in item
    ]
    if not parts:
        return "No rules to diagnose."
    return "\n\n".join(parts)


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.layout:
        layout = Metadata.load(args.layout).signed
        if args.links:
            links = _load_link_paths(args.links)
        else:
            links = _load_layout_links(layout, args.link_dir)
        steps = list(layout.steps) + list(layout.inspect)
    else:
        steps, links = _scenario_steps(_load_json(args.scenario))

    if args.step:
        wanted = set(args.step)
        steps = [
            step
            for step in steps
            if (step.get("name") if isinstance(step, dict) else step.name)
            in wanted
        ]

    report = diagnose_steps(steps, links)

    if args.source_type:
        for item in report["items"]:
            item.pop(
                "materials" if args.source_type == "products" else "products",
                None,
            )

    rendered = (
        json.dumps(report, indent=2) if args.json else _render_diagnose(report)
    )
    if args.output:
        with open(args.output, "w", encoding="utf8") as file:
            file.write(rendered + "\n")
    else:
        print(rendered)

    if not report["passed"] and not args.no_fail:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
