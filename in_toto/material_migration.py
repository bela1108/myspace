# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Module Name>
  in_toto/material_migration.py

<Purpose>
  Offline compatibility review for migrations of artifact (material) naming
  conventions in in-toto layouts.

  The review is deliberately *offline*: it never resolves artifacts, executes
  inspections or contacts a key store. It applies the ordered artifact rules of
  already signed layouts to a caller supplied public material vocabulary, and
  reports, per name, which rule first accepted or rejected it.

  Two properties are important for a safe migration:

  1. Rule order matters. Artifact rules are applied like a firewall: the first
     rule that matches a name consumes it, so a DISALLOW placed before an
     otherwise valid ALLOW/MATCH changes the result.

  2. A passing sample set is not a proof of coverage. Only names enumerated by
     the caller's vocabulary are approved. Names outside it are reported as
     coverage gaps even when every supplied sample happens to be accepted, and
     accepting rules with wildcard patterns are flagged because they may accept
     names that were never enumerated.

  The module is intentionally read-only: it does not mutate layouts and does
  not change the behaviour of ``verifylib``.
"""

from __future__ import annotations

import fnmatch
import json
import os
import sys
from copy import deepcopy
from typing import Mapping, Sequence

import in_toto.rulelib

ACCEPTING_RULES = {"allow", "create", "delete", "modify", "match"}
REJECTING_RULES = {"disallow"}
_WILDCARD_CHARS = ("*", "?", "[")


def _normalize_layout(value):
    """Return ``(layout, metadata)`` for a Layout, Metadata wrapper or dict.

    ``metadata`` is the signed wrapper when one was passed (or when a
    serialized ``Metablock``/``Envelope`` dict was passed), otherwise ``None``.
    """
    from in_toto.models.layout import Layout
    from in_toto.models.metadata import Metadata

    metadata = None
    if isinstance(value, Metadata):
        metadata = value
        value = value.get_payload()

    if isinstance(value, Layout):
        return value, metadata

    if isinstance(value, Mapping):
        data = deepcopy(dict(value))
        if "signed" in data and "signatures" in data:
            metadata = Metadata.from_dict(data)
            return metadata.get_payload(), metadata

        data.setdefault("steps", [])
        data.setdefault("inspect", [])
        return Layout.read(data), metadata

    raise TypeError(
        "expected a Layout, signed Metadata object or dict, "
        f"got {type(value).__name__}"
    )


def _normalize_rule_steps(value):
    """Normalize a caller supplied rule-step description.

    Accepted forms:

    * a Layout / signed Metadata / serialized layout dict, in which case the
      ordered ``steps`` followed by ``inspect`` items and their
      ``expected_materials`` are used;
    * an iterable of ``(item_name, rules)`` pairs;
    * an iterable of dicts with ``item``/``kind``/``rules`` keys;
    * a single iterable of rules (anonymous item).

    Returns a list of ``{"item", "kind", "rules"}`` dictionaries.
    """
    if value is None:
        return None

    if (
        isinstance(value, Mapping)
        and "signed" not in value
        and "steps" not in value
    ):
        # An explicit {"item": ..., "rules": [...]} description.
        if "rules" in value:
            return [
                {
                    "item": value.get("item", value.get("name")),
                    "kind": value.get("kind", "step"),
                    "rules": [list(rule) for rule in value["rules"]],
                }
            ]

    if isinstance(value, (Mapping,)) and (
        "signed" in value or "steps" in value or "inspect" in value
    ):
        layout, _ = _normalize_layout(value)
        return _layout_rule_steps(layout)

    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise TypeError("rule_steps must be a layout or a sequence")

    value = list(value)
    if not value:
        return []

    # A plain sequence of rules, e.g. [["ALLOW", "foo"]]
    if isinstance(value[0], Sequence) and not isinstance(
        value[0], (str, bytes)
    ):
        if all(
            isinstance(elem, str)
            for elem in value[0]
        ):
            return [
                {
                    "item": None,
                    "kind": "step",
                    "rules": [list(rule) for rule in value],
                }
            ]

    steps = []
    for entry in value:
        if isinstance(entry, Mapping):
            steps.append(
                {
                    "item": entry.get("item", entry.get("name")),
                    "kind": entry.get("kind", "step"),
                    "rules": [list(rule) for rule in entry.get("rules", [])],
                }
            )
        elif isinstance(entry, Sequence) and len(entry) == 2:
            item, rules = entry
            steps.append(
                {
                    "item": item,
                    "kind": "step",
                    "rules": [list(rule) for rule in rules],
                }
            )
        else:
            raise TypeError(f"invalid rule_steps entry: {entry!r}")

    return steps


def _layout_rule_steps(layout, fields=("materials",)):
    """Extract ordered material rules from a Layout's items.

    Steps are visited before inspections, matching ``verify_all_item_rules``.
    """
    steps = []
    items = [(step, "step") for step in layout.steps]
    items += [(inspection, "inspection") for inspection in layout.inspect]

    for item, kind in items:
        rules = []
        for field in fields:
            rules.extend(
                [list(rule) for rule in getattr(item, f"expected_{field}")]
            )
        steps.append(
            {"item": getattr(item, "name", None), "kind": kind, "rules": rules}
        )

    return steps


def _rule_is_literal(rule_data):
    """Return True if the rule's pattern cannot match unenumerated names."""
    pattern = rule_data.get("pattern", "")
    return not any(char in pattern for char in _WILDCARD_CHARS)


def _rule_matches_name(rule_data, name):
    """Return whether a parsed rule matches ``name`` at the naming level.

    For MATCH rules this reproduces the source-prefix handling of
    ``verifylib.verify_match_rule``: the prefix is stripped before globbing so
    that wildcards cannot leak into the prefix.

    Hash equality and destination-set membership are intentionally not
    evaluated here. This is a *naming* review; it answers which ordered rule
    first claims a name, which is the question that matters when a naming
    convention is migrated.
    """
    rule_type = rule_data["rule_type"]
    pattern = rule_data["pattern"]

    if rule_type == "require":
        return name == pattern

    candidate = name
    if rule_type == "match" and rule_data["source_prefix"]:
        normalized_prefix = os.path.join(
            rule_data["source_prefix"], ""
        ).replace("\\", "/")
        if not name.startswith(normalized_prefix):
            return False
        candidate = name[len(normalized_prefix) :]

    return fnmatch.fnmatchcase(candidate, pattern)


def _decision(accepted, item, kind, rule_index, rule):
    if accepted is True:
        outcome = "accept"
    elif accepted is False:
        outcome = "reject"
    else:
        outcome = "uncovered"

    return {
        "outcome": outcome,
        "item": item,
        "kind": kind,
        "rule_index": rule_index,
        "rule": list(rule) if rule is not None else None,
    }


def first_deciding_rule(name, rule_steps):
    """Return the first rule that accepts or rejects ``name``.

    Rules are applied in the order given. An accepting rule (ALLOW, CREATE,
    DELETE, MODIFY, MATCH) consumes the name; a DISALLOW rejects it. REQUIRE
    does not consume artifacts in in-toto and is therefore skipped for the
    disposition decision.

    If no rule matches, the result has ``"outcome": "uncovered"``, which is a
    coverage gap rather than an implicit acceptance.
    """
    for step in rule_steps:
        for rule_index, rule in enumerate(step["rules"]):
            rule_data = in_toto.rulelib.unpack_rule(rule)
            if not _rule_matches_name(rule_data, name):
                continue

            rule_type = rule_data["rule_type"]
            if rule_type in REJECTING_RULES:
                return _decision(
                    False, step.get("item"), step.get("kind"), rule_index, rule
                )

            if rule_type in ACCEPTING_RULES:
                return _decision(
                    True, step.get("item"), step.get("kind"), rule_index, rule
                )

            # REQUIRE confirms presence but does not consume; keep looking for
            # the rule that actually decides the disposition.

    return _decision(None, None, None, None, None)


def _has_unbounded_accept(rule_steps):
    """Return True if an accepting rule may accept unenumerated names."""
    for step in rule_steps:
        for rule in step["rules"]:
            rule_data = in_toto.rulelib.unpack_rule(rule)
            accepts = rule_data["rule_type"] in ACCEPTING_RULES
            if accepts and not _rule_is_literal(rule_data):
                return True
    return False


def _apply_prefix_mapping(name, path_mappings):
    """Translate ``name`` through a prefix mapping.

    ``path_mappings`` may be a dict/sequence of ``(new_prefix, old_prefix)``
    pairs or a callable. The longest matching prefix wins. This is used to map
    a post-migration (new) name back to its pre-migration (old) spelling for
    comparison against the old layout.
    """
    if path_mappings is None:
        return name

    if callable(path_mappings):
        return path_mappings(name)

    if isinstance(path_mappings, Mapping):
        items = list(path_mappings.items())
    else:
        items = list(path_mappings)

    best_source = None
    best_target = None
    for source, target in items:
        source = str(source)
        if not source:
            # An empty source is the catch-all prefix.
            if best_source is None:
                best_source, best_target = source, str(target)
            continue

        normalized_source = source.rstrip("/")
        if name == normalized_source or name.startswith(
            normalized_source + "/"
        ):
            if best_source is None or len(normalized_source) > len(
                best_source.rstrip("/")
            ):
                best_source, best_target = source, str(target)

    if best_source is None:
        return name

    source = best_source
    target = best_target

    if not source:
        # Empty prefix: append the target prefix verbatim.
        return target + name if target.endswith("/") else target + name

    normalized_source = source.rstrip("/")
    remainder = name[len(normalized_source) :].lstrip("/")

    if target and not target.endswith("/"):
        target += "/"

    return target + remainder


def _verify_signatures(metadata, verification_keys):
    """Verify all supplied keys against a signed metadata wrapper."""
    if verification_keys is None:
        return None
    if metadata is None:
        raise ValueError(
            "signature verification requested but no signed metadata was passed"
        )
    if len(verification_keys) < 1:
        raise ValueError("at least one verification key is required")

    for key in verification_keys.values():
        metadata.verify_signature(key)
    return True


def _decision_signature(decision):
    if decision["outcome"] == "uncovered":
        return "uncovered after all rules"
    return (
        f"{decision['outcome']} at item {decision['item']!r} "
        f"rule #{decision['rule_index']} {decision['rule']}"
    )


def review_material_migration(  # noqa: PLR0913
    old_layout,
    new_layout,
    material_vocabulary,
    *,
    rule_steps=None,
    path_mappings=None,
    observed_materials=None,
    verification_keys=None,
    fields=("materials",),
):
    """Perform an offline material-naming migration compatibility review.

    Arguments:
      old_layout: The previously approved layout (Layout, signed Metadata or
          serialized layout dict).
      new_layout: The candidate layout with valid signatures.
      material_vocabulary: The caller supplied public material vocabulary,
          expressed in the *new* naming convention. Only these names can be
          approved; anything else is a coverage gap.
      rule_steps: Optional replacement/substitution for the rule steps used in
          both layouts. Use a ``{"old": ..., "new": ...}`` mapping to supply
          different rule steps per side. See ``_normalize_rule_steps``.
      path_mappings: Map from new-convention name/prefix to old-convention
          name/prefix, e.g. ``{"src/": ""}``. Used to compare a migrated name
          against the old approved layout.
      observed_materials: Additional names seen in evidence (for example a
          backup or a product listing). Names outside the vocabulary are
          reported as coverage gaps, never as approvals.
      verification_keys: Optional public key dict. When supplied, both signed
          metadata wrappers are verified. Signature validity is recorded but
          does not by itself widen the approved material set.
      fields: Which rule fields to evaluate. Defaults to ``("materials",)``.

    Returns:
      A JSON-serializable report dictionary.
    """
    old_layout_obj, old_metadata = _normalize_layout(old_layout)
    new_layout_obj, new_metadata = _normalize_layout(new_layout)

    vocabulary = list(dict.fromkeys(material_vocabulary))
    observed = list(dict.fromkeys(observed_materials or []))

    per_side_rule_steps = None
    if isinstance(rule_steps, Mapping) and set(rule_steps).issuperset(
        {"old", "new"}
    ):
        per_side_rule_steps = {
            "old": _normalize_rule_steps(rule_steps["old"]),
            "new": _normalize_rule_steps(rule_steps["new"]),
        }
    else:
        normalized = _normalize_rule_steps(rule_steps)
        per_side_rule_steps = {"old": normalized, "new": normalized}

    old_rules = per_side_rule_steps["old"] or _layout_rule_steps(
        old_layout_obj, fields=fields
    )
    new_rules = per_side_rule_steps["new"] or _layout_rule_steps(
        new_layout_obj, fields=fields
    )

    signatures = {
        "old": _verify_signatures(old_metadata, verification_keys),
        "new": _verify_signatures(new_metadata, verification_keys),
    }

    materials = {}
    flips = []
    expansion = []
    lost = []
    coverage_gaps = []

    for new_name in vocabulary:
        old_name = _apply_prefix_mapping(new_name, path_mappings)

        old_decision = first_deciding_rule(old_name, old_rules)
        new_decision = first_deciding_rule(new_name, new_rules)
        # Same literal name on both sides: this is what makes a rename visible
        # as a reject -> accept flip in the old rule set.
        legacy_decision = first_deciding_rule(new_name, old_rules)

        approved_by_old = old_decision["outcome"] == "accept"
        accepted_by_new = new_decision["outcome"] == "accept"

        is_flip = (
            legacy_decision["outcome"] != "accept" and accepted_by_new
        )

        if approved_by_old and not accepted_by_new:
            lost.append(new_name)

        if accepted_by_new and not approved_by_old:
            expansion.append(new_name)

        if old_decision["outcome"] == "uncovered":
            coverage_gaps.append(
                {
                    "material": new_name,
                    "old_name": old_name,
                    "side": "old",
                    "reason": "no old rule decided the name",
                }
            )
        if new_decision["outcome"] == "uncovered":
            coverage_gaps.append(
                {
                    "material": new_name,
                    "old_name": old_name,
                    "side": "new",
                    "reason": "no new rule decided the name",
                }
            )

        entry = {
            "material": new_name,
            "old_name": old_name,
            "approved_by_old": approved_by_old,
            "accepted_by_new": accepted_by_new,
            "old": old_decision,
            "new": new_decision,
            "legacy": legacy_decision,
            "flip": is_flip,
        }
        materials[new_name] = entry

        if is_flip:
            flips.append(
                {
                    "material": new_name,
                    "old_name": old_name,
                    "old_side": legacy_decision,
                    "new_side": new_decision,
                }
            )

    # Names seen in evidence but never enumerated are gaps, not approvals.
    for observed_name in observed:
        if observed_name in vocabulary:
            continue
        observed_old_name = _apply_prefix_mapping(
            observed_name, path_mappings
        )
        observed_decision = first_deciding_rule(observed_name, new_rules)
        coverage_gaps.append(
            {
                "material": observed_name,
                "old_name": observed_old_name,
                "side": "new",
                "reason": "name is outside the approved public vocabulary",
                "new": observed_decision,
            }
        )
        if observed_decision["outcome"] == "accept":
            expansion.append(observed_name)

    unbounded_accept = _has_unbounded_accept(new_rules)
    if unbounded_accept:
        coverage_gaps.append(
            {
                "material": None,
                "side": "new",
                "reason": (
                    "an accepting rule uses a wildcard and may accept names "
                    "that were never enumerated"
                ),
            }
        )

    migration_allowed = not (
        expansion or lost or coverage_gaps or unbounded_accept
    )

    return {
        "signatures": signatures,
        "material_vocabulary": vocabulary,
        "materials": materials,
        "flips": flips,
        "expansion": expansion,
        "lost": lost,
        "coverage_gaps": coverage_gaps,
        "unbounded_accept": unbounded_accept,
        "migration_allowed": migration_allowed,
    }


def find_flipped_materials(report):
    """Return the reject/uncovered -> accept flips from a review report."""
    return list(report.get("flips", []))


def format_report(report):
    """Render a review report as human readable text."""
    lines = []
    lines.append("Material naming migration review (offline)")
    lines.append(
        "Signatures: old={old!r} new={new!r}".format(
            **report.get("signatures", {"old": None, "new": None})
        )
    )
    lines.append(f"Migration allowed: {report['migration_allowed']}")

    for name, entry in report["materials"].items():
        lines.append("")
        lines.append(f"Material: {name} (old spelling: {entry['old_name']})")
        lines.append(f"  old layout: {_decision_signature(entry['old'])}")
        lines.append(f"  new layout: {_decision_signature(entry['new'])}")
        if entry["flip"]:
            lines.append(
                "  flip with same literal name: "
                f"{_decision_signature(entry['legacy'])} -> "
                f"{_decision_signature(entry['new'])}"
            )

    if report["flips"]:
        lines.append("")
        lines.append("Reject -> accept flips:")
        for flip in report["flips"]:
            lines.append(
                f"  {flip['material']}: "
                f"old side {_decision_signature(flip['old_side'])}; "
                f"new side {_decision_signature(flip['new_side'])}"
            )

    if report["coverage_gaps"]:
        lines.append("")
        lines.append("Coverage gaps:")
        for gap in report["coverage_gaps"]:
            lines.append(
                f"  {gap.get('material')!r} [{gap['side']}]: {gap['reason']}"
            )

    if report["expansion"]:
        lines.append("")
        lines.append(f"Unauthorized expansion: {report['expansion']}")

    if report["lost"]:
        lines.append("")
        lines.append(f"Approved names no longer accepted: {report['lost']}")

    return "\n".join(lines)


def main(argv=None):
    """Minimal JSON-in/JSON-out CLI for offline review.

    The input file must contain a JSON object with ``old_layout``,
    ``new_layout``, ``material_vocabulary`` and optionally ``rule_steps``,
    ``path_mappings``, ``observed_materials`` and ``verification_keys``.
    """
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m in_toto.material_migration SPEC.json")
        return 2

    with open(argv[0]) as f:
        spec = json.load(f)

    report = review_material_migration(
        spec["old_layout"],
        spec["new_layout"],
        spec["material_vocabulary"],
        rule_steps=spec.get("rule_steps"),
        path_mappings=spec.get("path_mappings"),
        observed_materials=spec.get("observed_materials"),
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
