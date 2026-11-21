# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  rule_diagnostics.py

<Purpose>
  Explain how the order of artifact rules affects which artifacts a rule
  actually sees.

  Artifact rules are evaluated as a firewall: every rule consumes artifacts
  from one queue and a later rule can only consume what earlier rules left
  behind.  A rule being present in a layout therefore does not prove that it
  was effective.  A broad ALLOW in front of a MATCH, for example, can make the
  MATCH silently inert.

  This module provides an offline diagnostic that runs rules against link-like
  material/product dictionaries.  It reports, for every rule, the artifacts it
  could have consumed from the complete queue, the artifacts it actually
  consumed, the intersection consumed by earlier rules, and the smallest
  ordering relations that would restore an effective rule.

  It also runs three permutations of the same input:

  * the declared order,
  * an order where two provably independent rules are swapped, and
  * an order where a mandatory MATCH is shadowed by a consumer.

  The shadowing permutation is the one that exposes a hollowed-out constraint
  in the report.
"""

import fnmatch
import shlex
import types

import securesystemslib.exceptions

import in_toto.rulelib
from in_toto.verifylib import (
    verify_allow_rule,
    verify_create_rule,
    verify_delete_rule,
    verify_match_rule,
    verify_modify_rule,
)

CONSUMING_RULE_TYPES = {
    "match",
    "create",
    "delete",
    "modify",
    "allow",
}
ENFORCING_RULE_TYPES = {"disallow", "require"}


def _as_mapping(value, name):
    """Return the link-like artifact dictionaries for value.

    Supports Link objects, Metadata/Metablock objects, and plain dictionaries
    (including signed metadata dictionaries).  This keeps the diagnostic
    useful without requiring signatures or a verification directory.
    """
    if hasattr(value, "signed"):
        value = value.signed
    if isinstance(value, dict) and "signed" in value:
        value = value["signed"]

    if (
        isinstance(value, dict)
        and "materials" not in value
        and "products" not in value
    ):
        for nested in value.values():
            if (
                hasattr(nested, "materials")
                or hasattr(nested, "signed")
                or (isinstance(nested, dict) and "materials" in nested)
            ):
                return _as_mapping(nested, name)

    materials = getattr(value, "materials", None)
    products = getattr(value, "products", None)
    if materials is None and isinstance(value, dict):
        materials = value.get("materials", {})
    if products is None and isinstance(value, dict):
        products = value.get("products", {})

    if materials is None or products is None:
        raise securesystemslib.exceptions.FormatError(
            f"Offline artifact set '{name}' must provide materials and products"
        )

    return materials, products


def _name(value, fallback):
    """Return the name of a link-like value."""
    if hasattr(value, "signed"):
        value = value.signed
    if isinstance(value, dict) and "signed" in value:
        value = value["signed"]
    if isinstance(value, dict) and "materials" not in value:
        for nested in value.values():
            if hasattr(nested, "name") or hasattr(nested, "signed"):
                return _name(nested, fallback)
    return getattr(value, "name", None) or (
        value.get("name", fallback) if isinstance(value, dict) else fallback
    )


def _link_views(links):
    """Return link-like objects that expose materials and products attributes.

    in_toto.verifylib.verify_match_rule uses getattr(dest_link, dest_type).
    Plain link dictionaries are wrapped so they can be used offline.
    """
    views = {}
    for name, value in links.items():
        materials, products = _as_mapping(value, name)
        views[name] = types.SimpleNamespace(
            name=_name(value, name),
            materials=materials,
            products=products,
        )
    return views


def _source_artifact_dicts(source_name, links):
    """Return materials and products of the source item."""
    if source_name not in links:
        raise KeyError(f"No offline artifact set for item '{source_name}'")
    return _as_mapping(links[source_name], source_name)


def _candidate_artifacts(rule_data, queue, artifact_context, links):
    """Return artifacts a rule would consume/flag from the passed queue."""
    source_artifacts, materials, products = artifact_context
    rule_type = rule_data["rule_type"]
    pattern = rule_data["pattern"]

    if rule_type == "match":
        result = verify_match_rule(
            rule_data, set(queue), source_artifacts, links
        )
    elif rule_type == "allow":
        result = verify_allow_rule(pattern, set(queue))
    elif rule_type in {"create", "delete", "modify"}:
        materials_paths = set(materials.keys())
        products_paths = set(products.keys())
        if rule_type == "create":
            result = verify_create_rule(
                pattern, set(queue), materials_paths, products_paths
            )
        elif rule_type == "delete":
            result = verify_delete_rule(
                pattern, set(queue), materials_paths, products_paths
            )
        else:
            result = verify_modify_rule(
                pattern, set(queue), materials, products
            )
    elif rule_type == "disallow":
        result = set(fnmatch.filter(queue, pattern))
    elif rule_type == "require":
        result = {pattern} if pattern in queue else set()
    else:  # pragma: no cover (unreachable)
        raise securesystemslib.exceptions.FormatError(
            f"Invalid rule type '{rule_type}'"
        )

    return result


def _rule_verdict(rule_data, queue):
    """Return (failed, details) for an enforcement rule on the current queue."""
    rule_type = rule_data["rule_type"]
    pattern = rule_data["pattern"]

    if rule_type == "disallow":
        matches = sorted(fnmatch.filter(queue, pattern))
        if matches:
            return True, {
                "kind": "disallow",
                "artifacts": matches,
                "message": f"'DISALLOW {pattern}' matched {matches}",
            }

    elif rule_type == "require":
        if pattern not in queue:
            return True, {
                "kind": "require",
                "artifacts": [pattern],
                "message": (
                    f"'REQUIRE {pattern}' did not find {pattern} in the queue"
                ),
            }

    return False, None


def _normalize_rule(rule):
    """Return a list copy of a rule and its parsed rule data."""
    rule_list = list(rule)
    return rule_list, in_toto.rulelib.unpack_rule(rule_list)


def _prior_consumption(reports, index, potential):
    """Return artifacts consumed before index and the per-rule intersections."""
    prior_consumed = set()
    shadowed_by = {}
    for prior in reports:
        if prior["index"] >= index:
            continue
        prior_artifacts = set(prior["consumed"])
        prior_consumed.update(prior_artifacts)
        overlap = potential & prior_artifacts
        if overlap:
            shadowed_by[prior["index"]] = sorted(overlap)
    return prior_consumed, shadowed_by


def _rule_state(rule_type, consumed, shadowed, failed):
    """Return a stable textual state for a rule report."""
    if rule_type == "disallow":
        return "violation" if failed else ("shadowed" if shadowed else "pass")
    if rule_type == "require":
        return (
            "missing" if failed else ("shadowed" if shadowed else "satisfied")
        )
    if not consumed:
        return "no_match"
    return "partial" if shadowed else "consumed"


def _rule_report(index, rule, context):
    """Build the report for one rule and return it with its consumed set."""
    rule_list, rule_data = _normalize_rule(rule)
    queue_before = context["queue"]
    initial_queue = context["initial_queue"]
    artifact_context = context["artifact_context"]
    links = context["links"]
    reports = context["reports"]
    rule_type = rule_data["rule_type"]
    potential = _candidate_artifacts(
        rule_data, initial_queue, artifact_context, links
    )
    consumed = _candidate_artifacts(
        rule_data, set(queue_before), artifact_context, links
    )

    failed, failure = (False, None)
    if rule_type in ENFORCING_RULE_TYPES:
        failed, failure = _rule_verdict(rule_data, queue_before)

    prior_consumed, shadowed_by = _prior_consumption(reports, index, potential)
    shadowed = potential - consumed
    consumed_paths = sorted(consumed)
    state = _rule_state(rule_type, consumed_paths, shadowed, failed)

    report = {
        "index": index,
        "rule": rule_list,
        "rule_type": rule_type,
        "pattern": rule_data["pattern"],
        "queue_before": sorted(queue_before),
        "potential": sorted(potential),
        "potential_consumed": sorted(potential),
        "consumed": consumed_paths,
        "actual_consumed": consumed_paths,
        "shadowed": sorted(shadowed),
        "shadowed_materials": sorted(shadowed),
        "shadowed_by": shadowed_by,
        "consumed_by_prior": sorted(potential & prior_consumed),
        "intersection_consumed_by_others": sorted(potential & prior_consumed),
        "prior_consumed": sorted(potential & prior_consumed),
        "state": state,
        "failed": failed,
        "failure": failure,
    }
    return report, consumed, failure


def _artifact_context(source_name, source_type, links):
    """Return source artifacts, materials and products for simulation."""
    if source_type not in {"materials", "products"}:
        raise securesystemslib.exceptions.FormatError(
            "source_type must be 'materials' or 'products', got "
            f"'{source_type}'"
        )

    materials, products = _source_artifact_dicts(source_name, links)
    source_artifacts = getattr_for_source(source_type, materials, products)
    return source_artifacts, materials, products


def _collect_rule_reports(rules, initial_queue, artifact_context, links):
    """Run rules sequentially and return reports, the leftover queue and error."""
    queue = set(initial_queue)
    reports = []
    first_failure = None

    simulation_context = {
        "queue": queue,
        "initial_queue": initial_queue,
        "artifact_context": artifact_context,
        "links": links,
        "reports": reports,
    }
    for index, rule in enumerate(rules):
        report, consumed, failure = _rule_report(
            index,
            rule,
            simulation_context,
        )
        report["queue_after"] = sorted(queue - consumed)
        if failure and first_failure is None:
            first_failure = {
                "index": index,
                "rule": report["rule"],
                **failure,
            }
        if report["rule_type"] in CONSUMING_RULE_TYPES:
            queue -= consumed
        reports.append(report)

    return reports, queue, first_failure


def _ordering_findings(reports, mandatory_rules=None):
    """Return hollow rules and the minimal repairs that make them effective."""
    hollow_rules = []
    minimum_ordering = []
    for report in reports:
        if mandatory_rules is None:
            if report["rule_type"] != "match":
                continue
        elif tuple(report["rule"]) not in mandatory_rules:
            continue
        shadowers = [
            {
                "index": prior_index,
                "rule": reports[prior_index]["rule"],
                "artifacts": artifacts,
            }
            for prior_index, artifacts in sorted(report["shadowed_by"].items())
        ]
        # A terminal DISALLOW is expected to see an empty queue. Only
        # consuming rules can be hollowed out in the sense relevant here: they
        # had artifacts available but a preceding consumer took them first.
        if not (
            report["rule_type"] in CONSUMING_RULE_TYPES
            and not report["consumed"]
            and shadowers
        ):
            continue

        hollow_rules.append(
            {
                "index": report["index"],
                "rule": report["rule"],
                "rule_type": report["rule_type"],
                "potential": report["potential"],
                "consumed": report["consumed"],
                "shadowed": report["shadowed"],
                "shadowed_by": shadowers,
            }
        )
        first_shadower = shadowers[0]["index"]
        minimum_ordering.append(
            {
                "before": report["index"],
                "after": first_shadower,
                "before_rule": report["rule"],
                "after_rule": reports[first_shadower]["rule"],
                "before_index": report["index"],
                "after_index": first_shadower,
                "artifacts": report["shadowed"],
                "reason": (
                    "moving the shadowed rule before its first consumer "
                    "makes the constraint effective"
                ),
            }
        )
    return hollow_rules, minimum_ordering


def _simulate_rules(
    source_name, source_type, rules, links, mandatory_rules=None
):
    """Simulate one ordered rule set and return its diagnostic report."""
    artifact_context = _artifact_context(source_name, source_type, links)
    initial_queue = set(artifact_context[0].keys())
    reports, queue, first_failure = _collect_rule_reports(
        rules, initial_queue, artifact_context, links
    )
    hollow_rules, minimum_ordering = _ordering_findings(
        reports, mandatory_rules
    )

    return {
        "source_name": source_name,
        "source_type": source_type,
        "initial_artifacts": sorted(initial_queue),
        "rules": reports,
        "rule_reports": reports,
        "leftovers": sorted(queue),
        "unconsumed": sorted(queue),
        "verdict": "fail" if first_failure else "pass",
        "passed": first_failure is None,
        "failure": first_failure,
        "hollow_rules": hollow_rules,
        "hollowed_constraints": hollow_rules,
        "shadowed_rules": [report for report in reports if report["shadowed"]],
        "minimum_ordering": minimum_ordering,
        "minimum_order": minimum_ordering,
        "order_relations": minimum_ordering,
        "minimum_order_relations": minimum_ordering,
    }


def getattr_for_source(source_type, materials, products):
    """Return the artifact dictionary for source_type."""
    return materials if source_type == "materials" else products


def _permutation_report(  # noqa: PLR0913
    source_name, source_type, rules, links, order, mandatory_rules=None
):
    """Simulate a permutation and annotate it with the permutation itself."""
    sim = _simulate_rules(
        source_name,
        source_type,
        [rules[index] for index in order],
        links,
        mandatory_rules=mandatory_rules,
    )
    sim["order"] = list(order)
    for position, report in enumerate(sim["rules"]):
        report["order_index"] = position
        report["original_index"] = order[position]
        report["shadowed_by_original"] = {
            order[index]: artifacts
            for index, artifacts in report["shadowed_by"].items()
        }
    for finding in sim["hollow_rules"]:
        finding["order_index"] = finding["index"]
        finding["original_index"] = order[finding["index"]]
        for shadower in finding["shadowed_by"]:
            shadower["order_index"] = shadower["index"]
            shadower["original_index"] = order[shadower["index"]]
    for relation in sim["minimum_ordering"]:
        relation["before_original_index"] = order[relation["before"]]
        relation["after_original_index"] = order[relation["after"]]
    return sim


def _swap(order, left, right):
    """Return a copy of order with positions left and right exchanged."""
    swapped = list(order)
    swapped[left], swapped[right] = swapped[right], swapped[left]
    return swapped


def _potential_by_index(simulation):
    """Map original rule indices to potential artifacts in a simulation."""
    potentials = {}
    for position, report in enumerate(simulation["rules"]):
        original_index = simulation["order"][position]
        potentials[original_index] = set(report["potential"])
    return potentials


def _independent_swap_order(source_name, source_type, rules, links):
    """Find an adjacent pair of rules that cannot affect each other."""
    order = list(range(len(rules)))
    simulation = _permutation_report(
        source_name, source_type, rules, links, order
    )
    potentials = _potential_by_index(simulation)

    for left in range(len(rules) - 1):
        right = left + 1
        left_data = in_toto.rulelib.unpack_rule(list(rules[left]))
        right_data = in_toto.rulelib.unpack_rule(list(rules[right]))
        if left_data["rule_type"] in ENFORCING_RULE_TYPES:
            continue
        if right_data["rule_type"] in ENFORCING_RULE_TYPES:
            continue
        if potentials[left].isdisjoint(potentials[right]):
            return _swap(order, left, right)

    return order


def _mandatory_rule_indices(rules, mandatory):
    """Return indices treated as mandatory constraints."""
    if mandatory is None:
        return [
            index
            for index, rule in enumerate(rules)
            if in_toto.rulelib.unpack_rule(list(rule))["rule_type"] == "match"
        ]

    if callable(mandatory):
        return [
            index for index, rule in enumerate(rules) if mandatory(list(rule))
        ]

    if isinstance(mandatory, str):
        mandatory = [shlex.split(mandatory)]

    if isinstance(mandatory, int):
        mandatory = [mandatory]

    if (
        isinstance(mandatory, (list, tuple))
        and mandatory
        and isinstance(mandatory[0], str)
        and mandatory[0].lower() in in_toto.rulelib.ALL_RULES
    ):
        mandatory = [mandatory]

    indices = []
    for item in mandatory:
        if isinstance(item, int):
            indices.append(item)
            continue
        value = shlex.split(item) if isinstance(item, str) else list(item)
        for index, rule in enumerate(rules):
            if list(rule) == value:
                indices.append(index)
                break
    return sorted(set(indices))


def _mandatory_rule_set(rules, mandatory):
    return {
        tuple(rules[index])
        for index in _mandatory_rule_indices(rules, mandatory)
    }


def _shadow_order(source_name, source_type, rules, links, mandatory):
    """Move a broad consumer in front of a mandatory MATCH."""
    order = list(range(len(rules)))
    mandatory_indices = _mandatory_rule_indices(rules, mandatory)
    simulation = _permutation_report(
        source_name, source_type, rules, links, order
    )
    potentials = _potential_by_index(simulation)

    candidates = []
    for match_index in mandatory_indices:
        match_potential = potentials.get(match_index, set())
        if not match_potential:
            continue

        for consumer_index, rule in enumerate(rules):
            if consumer_index == match_index:
                continue
            data = in_toto.rulelib.unpack_rule(list(rule))
            if data["rule_type"] not in CONSUMING_RULE_TYPES:
                continue
            overlap = match_potential & potentials.get(consumer_index, set())
            if not overlap:
                continue
            candidates.append(
                (
                    -len(overlap),
                    data["rule_type"] != "allow",
                    consumer_index,
                    match_index,
                )
            )

    if not candidates:
        return order, {
            "found": False,
            "reason": "no consumer overlaps a mandatory MATCH",
        }

    _, _, consumer_index, match_index = sorted(candidates)[0]
    if consumer_index < match_index:
        shadow_order = order
        already_shadowed = True
    else:
        shadow_order = [index for index in order if index != consumer_index]
        match_position = shadow_order.index(match_index)
        shadow_order.insert(match_position, consumer_index)
        already_shadowed = False

    return shadow_order, {
        "found": True,
        "shadowing_rule": consumer_index,
        "mandatory_rule": match_index,
        "already_shadowed": already_shadowed,
    }


def _pair_order_sensitivity(source_name, source_type, rules, links):
    """Run all single pair swaps and record verdict-changing relations."""
    order = list(range(len(rules)))
    baseline = _permutation_report(
        source_name, source_type, rules, links, order
    )
    sensitive = []

    for left in range(len(rules)):
        for right in range(left + 1, len(rules)):
            swapped_order = _swap(order, left, right)
            result = _permutation_report(
                source_name, source_type, rules, links, swapped_order
            )
            if result["verdict"] == baseline["verdict"]:
                continue
            sensitive.append(
                {
                    "swapped": [left, right],
                    "original_verdict": baseline["verdict"],
                    "swapped_verdict": result["verdict"],
                    "changes_verdict": True,
                    "required_order": {
                        "before": left,
                        "after": right,
                    },
                    "alternative_order": {
                        "before": right,
                        "after": left,
                    },
                    "repairs_verdict": (
                        baseline["verdict"] == "fail"
                        and result["verdict"] == "pass"
                    ),
                    "breaks_verdict": (
                        baseline["verdict"] == "pass"
                        and result["verdict"] == "fail"
                    ),
                    "swapped_order": swapped_order,
                }
            )

    return sensitive


def diagnose_item_rules(  # noqa: PLR0915
    source_name, source_type, rules, links, mandatory=None
):
    """Diagnose one ordered set of artifact rules.

    Arguments:
      source_name: Name of the item whose artifacts are checked.
      source_type: "materials" or "products".
      rules: Ordered list of artifact rules.
      links: Mapping of item name to Link/Metadata/dictionary with materials
          and products.  This is the offline artifact set.
      mandatory: Optional rule indices/rules that must stay effective.
          Defaults to every MATCH rule.

    Returns:
      A dictionary with per-rule consumption, shadowing, minimum ordering
      relations, and three same-input order experiments.
    """
    if (
        isinstance(rules, (list, tuple))
        and rules
        and isinstance(rules[0], str)
        and rules[0].lower() in in_toto.rulelib.ALL_RULES
    ):
        rules = [rules]
    rules = [list(rule) for rule in rules]
    link_views = _link_views(links)
    original_order = list(range(len(rules)))
    mandatory_rules = _mandatory_rule_set(rules, mandatory)

    original = _permutation_report(
        source_name,
        source_type,
        rules,
        link_views,
        original_order,
        mandatory_rules=mandatory_rules,
    )

    independent_order = _independent_swap_order(
        source_name, source_type, rules, link_views
    )
    independent = _permutation_report(
        source_name,
        source_type,
        rules,
        link_views,
        independent_order,
        mandatory_rules=mandatory_rules,
    )
    independent["independent_swap"] = independent_order != original_order

    shadow_order, shadow_details = _shadow_order(
        source_name, source_type, rules, link_views, mandatory
    )
    shadowed = _permutation_report(
        source_name,
        source_type,
        rules,
        link_views,
        shadow_order,
        mandatory_rules=mandatory_rules,
    )
    shadowed["shadowing"] = shadow_details
    shadowed["hollowed_constraints"] = shadowed["hollow_rules"]

    experiments = {
        "original": dict(original),
        "independent_swap": independent,
        "mandatory_shadowed": shadowed,
    }
    detected_in = [
        name
        for name, experiment in experiments.items()
        if experiment["hollow_rules"]
    ]

    declared_hollow = original["hollow_rules"]
    shadow_hollow = shadowed["hollow_rules"]
    combined_hollow, combined_ordering = _combine_findings(original, shadowed)

    report = dict(original)
    report["declared_hollow_rules"] = declared_hollow
    report["shadow_hollow_rules"] = shadow_hollow
    report["declared_hollowed_constraints"] = declared_hollow
    report["hollowed_constraints"] = combined_hollow
    report["minimum_ordering"] = combined_ordering
    report["minimum_order"] = combined_ordering
    report["order_relations"] = combined_ordering
    report["minimum_order_relations"] = combined_ordering
    report["order_sensitivity"] = _pair_order_sensitivity(
        source_name, source_type, rules, link_views
    )
    report["order_constraints"] = report["order_sensitivity"]
    report["verdict_order_constraints"] = report["order_sensitivity"]
    report["verdict_ordering"] = report["order_sensitivity"]
    report["minimum_verdict_ordering"] = report["order_sensitivity"]
    report["verdict_repairs"] = [
        relation
        for relation in report["order_sensitivity"]
        if relation["repairs_verdict"]
    ]
    report["experiments"] = experiments
    report["order_experiments"] = experiments
    report["original_experiment"] = experiments["original"]
    report["independent_experiment"] = experiments["independent_swap"]
    report["shadow_experiment"] = experiments["mandatory_shadowed"]
    report["shadowing_experiment"] = experiments["mandatory_shadowed"]
    report["detected_in"] = detected_in
    report["mandatory"] = _mandatory_rule_indices(rules, mandatory)
    report["shadow_minimum_ordering"] = shadowed["minimum_ordering"]
    report["shadowed_rules"] = [
        item for item in report["rules"] if item["shadowed"]
    ]
    original_for_experiment = experiments["original"]
    original_for_experiment["detected_in"] = detected_in
    original_for_experiment["order_sensitivity"] = report["order_sensitivity"]
    original_for_experiment["order_constraints"] = report["order_constraints"]
    original_for_experiment["shadowed_rules"] = report["shadowed_rules"]
    report["conclusion"] = {
        "verdict": report["verdict"],
        "hollowed_constraints": combined_hollow,
        "detected_in": detected_in,
        "only_shadowing_order_detected": (
            detected_in == ["mandatory_shadowed"]
        ),
        "minimum_ordering": (
            report["minimum_ordering"] or shadowed["minimum_ordering"]
        ),
        "shadowing_permutation": shadow_order,
    }

    return report


def run_order_experiments(
    source_name, source_type, rules, links, mandatory=None
):
    """Return only the three same-input order experiments."""
    report = diagnose_item_rules(
        source_name, source_type, rules, links, mandatory=mandatory
    )
    return report["experiments"]


def analyze_rule_order(*args, **kwargs):
    """Alias for diagnose_item_rules."""
    return diagnose_item_rules(*args, **kwargs)


def diagnose_rules(*args, **kwargs):
    """Alias for diagnose_item_rules."""
    return diagnose_item_rules(*args, **kwargs)


def diagnose_rule_order(*args, **kwargs):
    """Alias for diagnose_item_rules."""
    return diagnose_item_rules(*args, **kwargs)


def _as_step(item, fallback_name=None):
    """Return (name, expected_materials, expected_products) for an item."""
    if hasattr(item, "expected_materials"):
        return (
            getattr(item, "name", fallback_name),
            item.expected_materials,
            item.expected_products,
        )
    if isinstance(item, dict):
        return (
            item.get("name", fallback_name),
            item.get("expected_materials", []),
            item.get("expected_products", []),
        )
    raise securesystemslib.exceptions.FormatError(
        f"Unsupported step type '{type(item).__name__}'"
    )


def diagnose_steps(steps, links, mandatory=None):  # noqa: C901, PLR0912
    """Diagnose all material and product rule sets of passed steps."""
    if isinstance(steps, dict):
        if "expected_materials" in steps or "expected_products" in steps:
            steps = [steps]
        else:
            mapped = []
            for name, value in steps.items():
                item = dict(value)
                item.setdefault("name", name)
                mapped.append(item)
            steps = mapped
    items = []
    for step in steps:
        name, expected_materials, expected_products = _as_step(step)
        item = {"name": name}
        if expected_materials:
            try:
                item["materials"] = diagnose_item_rules(
                    name,
                    "materials",
                    expected_materials,
                    links,
                    mandatory=mandatory,
                )
            except KeyError as error:
                item["error"] = str(error)
        if expected_products:
            try:
                item["products"] = diagnose_item_rules(
                    name,
                    "products",
                    expected_products,
                    links,
                    mandatory=mandatory,
                )
            except KeyError as error:
                item["error"] = str(error)
        items.append(item)

    detected = []
    for item in items:
        for source_type in ("materials", "products"):
            report = item.get(source_type)
            if not report:
                continue
            if report["verdict"] == "fail":
                item.setdefault("failed", []).append(source_type)
            findings = report.get(
                "hollowed_constraints", report["hollow_rules"]
            )
            if findings:
                detected.append(
                    {
                        "name": item["name"],
                        "source_type": source_type,
                        "detected_in": report.get("detected_in", []),
                        "hollow_rules": findings,
                    }
                )

    return {
        "items": items,
        "hollowed_constraints": detected,
        "passed": not detected and not any("failed" in item for item in items),
    }


def diagnose_layout(layout, links, mandatory=None):
    """Diagnose rule order for every step and inspection in a layout."""
    if hasattr(layout, "signed"):
        layout = layout.signed
    items = list(getattr(layout, "steps", [])) + list(
        getattr(layout, "inspect", [])
    )
    return diagnose_steps(items, links, mandatory=mandatory)


def diagnose_scenario(scenario, mandatory=None):
    """Diagnose a self-contained steps plus offline-artifact scenario."""
    steps = scenario.get("steps", [])
    links = dict(scenario.get("links", scenario.get("artifacts", {})))
    for step in steps:
        name = step.get("name")
        if name and name not in links:
            links[name] = {
                "name": name,
                "materials": step.get("materials", {}),
                "products": step.get("products", {}),
            }
    return diagnose_steps(steps, links, mandatory=mandatory)


diagnose_offline = diagnose_scenario
diagnose_layout_rules = diagnose_layout
diagnose_step_rules = diagnose_steps
diagnose_item = diagnose_item_rules
explain_rule_order = diagnose_item_rules
diagnose_rule_set = diagnose_item_rules
diagnose_rule_dependencies = diagnose_item_rules
rule_order_diagnostic = diagnose_item_rules


def _combine_findings(original, shadowed):
    # Return de-duplicated findings and relations in original indices.
    combined_hollow = []
    seen_hollow = set()
    for finding in original["hollow_rules"] + shadowed["hollow_rules"]:
        key = (
            finding["original_index"],
            tuple(finding["rule"]),
            tuple(finding["shadowed"]),
        )
        if key in seen_hollow:
            continue
        seen_hollow.add(key)
        normalized = dict(finding)
        normalized["index"] = finding["original_index"]
        normalized["shadowed_by"] = [
            {
                **shadower,
                "index": shadower.get("original_index", shadower["index"]),
            }
            for shadower in finding["shadowed_by"]
        ]
        combined_hollow.append(normalized)

    combined_ordering = []
    for relation in original["minimum_ordering"] + shadowed["minimum_ordering"]:
        normalized = dict(relation)
        normalized["before"] = relation["before_original_index"]
        normalized["after"] = relation["after_original_index"]
        normalized["order_before"] = relation["before"]
        normalized["order_after"] = relation["after"]
        normalized["before_index"] = normalized["before"]
        normalized["after_index"] = normalized["after"]
        if normalized not in combined_ordering:
            combined_ordering.append(normalized)
    return combined_hollow, combined_ordering
