# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  layout_compat.py

<Purpose>
  Provide a read-only, offline compatibility review for artifact rules during
  a layout material-naming migration.

  The review is intentionally separate from verification. It does not fetch
  metadata, execute inspections, modify layouts, or change the behavior of the
  normal verifier. Instead, it evaluates an explicit, caller supplied material
  vocabulary against the ordered material rules of two already validated
  layouts.

  Two properties are important:

  * Rules are evaluated in order. The first rule that decides an artifact is
    reported for each side.
  * The supplied vocabulary is a hard boundary. A name outside it remains a
    coverage gap even when a sample happens to match an ALLOW or MATCH rule.
    Passing known samples must not be interpreted as permission to accept a
    broader set of names.
"""

from __future__ import annotations

import fnmatch
import posixpath
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import in_toto.models.layout
import in_toto.rulelib
from in_toto.exceptions import CompatibilityReviewError
from in_toto.models.metadata import Metadata

ACCEPTING_RULES = frozenset({"allow", "create", "delete", "modify", "match"})
GLOB_CHARS = frozenset("*?[")

__all__ = [
    "ArtifactFacts",
    "CompatibilityGap",
    "CompatibilityReport",
    "CompatibilityReviewError",
    "CoverageGap",
    "Decision",
    "LayoutCompatibilityReport",
    "MaterialDecision",
    "MaterialReview",
    "PathMapping",
    "RuleDecision",
    "audit_layout_compatibility",
    "check_layout_compatibility",
    "evaluate_material_rules",
    "offline_compatibility_review",
    "review_layout_compatibility",
    "review_material_compatibility",
    "verify_layout_compatibility",
]


def _normalize_path(path: str) -> str:
    """Return a stable POSIX-style path representation."""
    if not isinstance(path, str) or not path:
        raise CompatibilityReviewError(
            f"artifact paths must be non-empty strings, got {path!r}"
        )

    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]

    if ".." in normalized.split("/"):
        raise CompatibilityReviewError(
            f"artifact paths must not contain ..: {path!r}"
        )

    normalized = posixpath.normpath(normalized)
    if normalized == ".":
        return ""
    return normalized


def _normalize_pattern(pattern: str) -> str:
    """Normalize a glob pattern without resolving its wildcard parts."""
    if not isinstance(pattern, str) or not pattern:
        raise CompatibilityReviewError(
            f"rule patterns must be non-empty strings, got {pattern!r}"
        )

    normalized = pattern.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _join(prefix: str, path: str) -> str:
    """Join two path-like strings using forward slashes."""
    if not prefix:
        return _normalize_path(path) if path else ""
    if not path:
        return _normalize_path(prefix)
    return _normalize_path(f"{prefix.rstrip('/')}/{path.lstrip('/')}")


def _is_glob(pattern: str) -> bool:
    """Return True if a pattern can match more than one literal name."""
    return any(char in GLOB_CHARS for char in pattern)


def _matches(path: str, pattern: str) -> bool:
    """Match a path against an in-toto artifact rule pattern."""
    return fnmatch.fnmatchcase(
        _normalize_path(path), _normalize_pattern(pattern)
    )


def _strip_prefix(path: str, prefix: str) -> str | None:
    """Return the part of path below prefix, or None if it is elsewhere."""
    if not prefix:
        return _normalize_path(path)

    normalized_prefix = _normalize_path(prefix).rstrip("/")
    normalized_path = _normalize_path(path)
    if normalized_path == normalized_prefix:
        return ""
    marker = f"{normalized_prefix}/"
    if normalized_path.startswith(marker):
        return normalized_path[len(marker) :]
    return None


class PathMapping:
    """A longest-prefix mapping between old and new artifact namespaces.

    Mapping pairs are interpreted as ``old_prefix -> new_prefix``. Prefixes are
    matched as path components, so ``lib -> pkg`` maps ``lib/foo`` to
    ``pkg/foo`` but does not map ``library/foo``.
    """

    def __init__(
        self,
        mappings: PathMapping
        | Mapping[str, str]
        | Iterable[Sequence[str]]
        | None = None,
    ):
        if isinstance(mappings, PathMapping):
            self._pairs = list(mappings._pairs)  # noqa: SLF001
            self._reverse_pairs = list(mappings._reverse_pairs)  # noqa: SLF001
        else:
            pairs = []
            if mappings is not None:
                items = (
                    mappings.items()
                    if isinstance(mappings, Mapping)
                    else mappings
                )
                for item in items:
                    if not isinstance(item, Sequence) or len(item) != 2:
                        raise CompatibilityReviewError(
                            "path mappings must contain (old, new) pairs"
                        )
                    old, new = item
                    if not isinstance(old, str) or not isinstance(new, str):
                        raise CompatibilityReviewError(
                            "path mapping endpoints must be strings"
                        )
                    old = _normalize_path(old)
                    new = _normalize_path(new)
                    if old:
                        pairs.append((old, new))

            self._pairs = sorted(
                pairs, key=lambda pair: len(pair[0]), reverse=True
            )
            self._reverse_pairs = sorted(
                pairs, key=lambda pair: len(pair[1]), reverse=True
            )

    def __bool__(self) -> bool:
        return bool(self._pairs)

    def __iter__(self):
        return iter(self._pairs)

    def map(self, path: str) -> str:
        """Map an old-namespace path (or pattern) to the new namespace."""
        normalized = _normalize_path(path)
        for old, new in self._pairs:
            if normalized == old:
                return new
            marker = f"{old}/"
            if normalized.startswith(marker):
                return _join(new, normalized[len(marker) :])
        return normalized

    def unmap(self, path: str) -> str:
        """Map a new-namespace path (or pattern) to the old namespace."""
        normalized = _normalize_path(path)
        for old, new in self._reverse_pairs:
            if normalized == new:
                return old
            marker = f"{new}/"
            if normalized.startswith(marker):
                return _join(old, normalized[len(marker) :])
        return normalized

    def to_dict(self) -> dict[str, str]:
        """Return mapping pairs as a JSON-serializable dictionary."""
        return dict(self._pairs)


@dataclass(frozen=True)
class ArtifactFacts:
    """Optional artifact evidence used to evaluate consuming rules.

    A missing field means "not known", not "empty". This distinction keeps
    the review conservative: unknown hash or product information produces an
    unresolved decision or a coverage gap instead of an assumed acceptance.
    """

    materials: frozenset[str] | None = None
    products: frozenset[str] | None = None
    material_hashes: Mapping[str, Mapping[str, str]] | None = None
    product_hashes: Mapping[str, Mapping[str, str]] | None = None


@dataclass(frozen=True)
class Decision:
    """The first rule that decides one artifact on one side of the review."""

    outcome: str
    rule_index: int | None
    rule: tuple[str, ...] | None
    step: str | None
    reason: str
    implicit: bool = False

    @property
    def decision(self) -> str:
        """Alias for outcome, convenient for report consumers."""
        return self.outcome

    @property
    def first_deciding_rule(self) -> tuple[str, ...] | None:
        """Alias for the rule that made the decision."""
        return self.rule

    @property
    def first_deciding_step(self) -> str | None:
        """Return the step name of the deciding rule, if available."""
        return self.step

    @property
    def decision_point(self) -> str:
        """Return a compact human-readable rule location."""
        if self.implicit:
            return "implicit-terminal-allow"
        step = self.step if self.step is not None else "<caller>"
        return f"{step}[{self.rule_index}]"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "outcome": self.outcome,
            "rule_index": self.rule_index,
            "rule": list(self.rule) if self.rule else None,
            "step": self.step,
            "reason": self.reason,
            "implicit": self.implicit,
            "decision_point": self.decision_point,
            "first_deciding_step": self.step,
            "first_deciding_rule": list(self.rule) if self.rule else None,
        }


@dataclass(frozen=True)
class CoverageGap:
    """A name or pattern that the approved vocabulary does not cover."""

    side: str
    reason: str
    name: str | None = None
    pattern: str | None = None
    rule_index: int | None = None
    step: str | None = None
    may_accept_outside_vocabulary: bool = False
    introduced: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "side": self.side,
            "name": self.name,
            "pattern": self.pattern,
            "rule_index": self.rule_index,
            "step": self.step,
            "reason": self.reason,
            "may_accept_outside_vocabulary": (
                self.may_accept_outside_vocabulary
            ),
            "introduced": self.introduced,
        }


@dataclass(frozen=True)
class MaterialReview:
    """Old/new decisions for one material identity."""

    material: str
    old_name: str
    new_name: str
    in_vocabulary: bool
    old: Decision
    new: Decision
    status: str
    migration_allowed: bool

    @property
    def name(self) -> str:
        """Return the reviewed material name."""
        return self.material

    @property
    def old_decision(self) -> Decision:
        """Return the old-layout decision."""
        return self.old

    @property
    def new_decision(self) -> Decision:
        """Return the new-layout decision."""
        return self.new

    @property
    def first_old_decision(self) -> Decision:
        """Return the earliest deciding rule on the old side."""
        return self.old

    @property
    def first_new_decision(self) -> Decision:
        """Return the earliest deciding rule on the new side."""
        return self.new

    @property
    def old_rule_index(self) -> int | None:
        """Return the old-side deciding rule index."""
        return self.old.rule_index

    @property
    def new_rule_index(self) -> int | None:
        """Return the new-side deciding rule index."""
        return self.new.rule_index

    @property
    def first_deciding_steps(self) -> tuple[str | None, str | None]:
        """Return the earliest deciding step on both sides."""
        return self.old.step, self.new.step

    @property
    def old_decision_point(self) -> str:
        """Return the old-side deciding rule location."""
        return self.old.decision_point

    @property
    def new_decision_point(self) -> str:
        """Return the new-side deciding rule location."""
        return self.new.decision_point

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "material": self.material,
            "name": self.material,
            "old_name": self.old_name,
            "new_name": self.new_name,
            "in_vocabulary": self.in_vocabulary,
            "old": self.old.to_dict(),
            "new": self.new.to_dict(),
            "old_rule_index": self.old.rule_index,
            "new_rule_index": self.new.rule_index,
            "old_decision_point": self.old.decision_point,
            "new_decision_point": self.new.decision_point,
            "old_first_deciding_step": self.old.step,
            "new_first_deciding_step": self.new.step,
            "old_first_deciding_rule": (
                list(self.old.rule) if self.old.rule else None
            ),
            "new_first_deciding_rule": (
                list(self.new.rule) if self.new.rule else None
            ),
            "status": self.status,
            "migration_allowed": self.migration_allowed,
        }


@dataclass(frozen=True)
class CompatibilityReport:
    """Result of an offline layout material-naming compatibility review."""

    old_label: str
    new_label: str
    vocabulary: tuple[str, ...]
    materials: tuple[MaterialReview, ...]
    gaps: tuple[CoverageGap, ...]
    approved_for_migration: bool
    compatible: bool
    old_signature_count: int | None = None
    new_signature_count: int | None = None

    @property
    def reviews(self) -> tuple[MaterialReview, ...]:
        """Alias for the per-material reviews."""
        return self.materials

    @property
    def coverage_gaps(self) -> tuple[CoverageGap, ...]:
        """Alias for the detected coverage gaps."""
        return self.gaps

    @property
    def blocking_gaps(self) -> tuple[CoverageGap, ...]:
        """Return gaps that prevent migration approval."""
        return tuple(gap for gap in self.gaps if gap.introduced)

    @property
    def approved(self) -> bool:
        """Alias for approved_for_migration."""
        return self.approved_for_migration

    @property
    def ok(self) -> bool:
        """Alias for compatible."""
        return self.compatible

    @property
    def both_signed(self) -> bool:
        """Return True if both inputs carried at least one signature."""
        return bool(self.old_signature_count) and bool(self.new_signature_count)

    def get(self, material: str) -> MaterialReview | None:
        """Return the review for a material name, if it was reviewed."""
        normalized = _normalize_path(material)
        for review in self.materials:
            if normalized in {review.old_name, review.new_name}:
                return review
        return None

    def __getitem__(self, material: str) -> MaterialReview:
        review = self.get(material)
        if review is None:
            raise KeyError(material)
        return review

    def __iter__(self):
        return iter(self.materials)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "old_label": self.old_label,
            "new_label": self.new_label,
            "vocabulary": list(self.vocabulary),
            "materials": [review.to_dict() for review in self.materials],
            "gaps": [gap.to_dict() for gap in self.gaps],
            "blocking_gaps": [gap.to_dict() for gap in self.blocking_gaps],
            "approved_for_migration": self.approved_for_migration,
            "compatible": self.compatible,
            "old_signature_count": self.old_signature_count,
            "new_signature_count": self.new_signature_count,
        }


def _coerce_rule(rule: Any) -> tuple[str, ...]:
    """Return a rule as a string tuple and validate its syntax."""
    if isinstance(rule, str):
        parsed = tuple(shlex.split(rule))
    elif isinstance(rule, Sequence):
        parsed = tuple(str(part) for part in rule)
    else:
        raise CompatibilityReviewError(
            f"artifact rule must be a string or sequence, got {rule!r}"
        )

    if not parsed:
        raise CompatibilityReviewError("artifact rule must not be empty")

    in_toto.rulelib.unpack_rule(list(parsed))
    return parsed


def _looks_like_rule(value: Any) -> bool:
    """Return True if value looks like one rule instead of a rule list."""
    if not isinstance(value, Sequence) or isinstance(value, str):
        return False
    if len(value) < 2:
        return False
    return str(value[0]).lower() in in_toto.rulelib.ALL_RULES


def _coerce_rule_list(rules: Any) -> list[tuple[str, ...]]:
    """Return a list of rules from a single rule or list of rules."""
    if rules is None:
        return []
    if isinstance(rules, str) or _looks_like_rule(rules):
        return [_coerce_rule(rules)]
    if isinstance(rules, Mapping):
        raise CompatibilityReviewError("expected a rule list, got a mapping")

    try:
        return [_coerce_rule(rule) for rule in rules]
    except TypeError as error:
        raise CompatibilityReviewError(
            f"invalid rule list: {rules!r}"
        ) from error


def _normalize_rule_spec(  # noqa: C901
    spec: Any,
) -> list[tuple[str | None, tuple[str, ...]]]:
    """Normalize caller supplied rules into (step, rule) pairs."""
    if spec is None:
        return []

    if isinstance(spec, Mapping):
        if "materials" in spec:
            spec = spec["materials"]
        else:
            steps = []
            for step_name, step_rules in spec.items():
                material_rules = (
                    step_rules.get("materials", [])
                    if isinstance(step_rules, Mapping)
                    else step_rules
                )
                steps.extend(
                    (str(step_name), rule)
                    for rule in _coerce_rule_list(material_rules)
                )
            return steps

    if isinstance(spec, str) or _looks_like_rule(spec):
        return [(None, _coerce_rule(spec))]

    steps = []
    try:
        for item in spec:
            if (
                isinstance(item, Sequence)
                and not isinstance(item, str)
                and len(item) == 2
                and isinstance(item[0], str)
                and not _looks_like_rule(item)
            ):
                step_name, rules = item
                steps.extend(
                    (step_name, rule) for rule in _coerce_rule_list(rules)
                )
            elif isinstance(item, Mapping) and "rules" in item:
                step_name = item.get("name")
                for rule in _coerce_rule_list(item["rules"]):
                    steps.append((step_name, rule))
            else:
                steps.append((None, _coerce_rule(item)))
    except TypeError as error:
        raise CompatibilityReviewError(
            f"invalid rule steps: {spec!r}"
        ) from error

    return steps


def _as_layout(value: Any) -> Any:
    """Return a Layout-like object from supported caller inputs."""
    if isinstance(value, in_toto.models.layout.Layout):
        return value

    if isinstance(value, (str, Path)):
        value = Metadata.load(str(value))

    if isinstance(value, Metadata):
        signed = value.signed
        if isinstance(signed, in_toto.models.layout.Layout):
            return signed
        raise CompatibilityReviewError("metadata does not contain a layout")

    if isinstance(value, Mapping):
        data = value.get("signed", value)
        if not isinstance(data, Mapping):
            raise CompatibilityReviewError("invalid layout mapping")
        data = dict(data)
        data.setdefault("_type", "layout")
        data.setdefault("steps", [])
        data.setdefault("inspect", [])
        data.setdefault("keys", {})
        data.setdefault("readme", "")
        return in_toto.models.layout.Layout.read(data)

    if hasattr(value, "steps") and hasattr(value, "inspect"):
        return value

    raise CompatibilityReviewError(f"unsupported layout input: {value!r}")


def _signature_count(value: Any) -> int | None:
    """Return the number of signatures carried by a metadata input."""
    if isinstance(value, (str, Path)):
        try:
            value = Metadata.load(str(value))
        except (OSError, ValueError):
            return None

    if isinstance(value, Metadata):
        return len(value.signatures)
    if isinstance(value, Mapping):
        signatures = value.get("signatures")
        if isinstance(signatures, Sequence):
            return len(signatures)
    return None


def _collect_layout_steps(
    layout: Any,
) -> list[tuple[str | None, tuple[str, ...]]]:
    """Collect ordered material rules from a layout's steps and inspections."""
    return [
        (item.name, _coerce_rule(rule))
        for item in list(layout.steps) + list(layout.inspect)
        for rule in item.expected_materials
    ]


def _split_side_spec(
    spec: Any, old_label: str, new_label: str
) -> tuple[Any, Any]:
    """Split a per-side rule specification, if one was supplied."""
    if isinstance(spec, Mapping):
        old_keys = {old_label, "old", "approved"}
        new_keys = {new_label, "new", "candidate"}
        if old_keys & set(spec) or new_keys & set(spec):
            old_spec = next(
                (spec[key] for key in old_keys if key in spec), None
            )
            new_spec = next(
                (spec[key] for key in new_keys if key in spec), None
            )
            return old_spec, new_spec
    return spec, spec


def _normalize_hash_dict(
    hashes: Mapping[str, Mapping[str, str]] | None,
) -> dict[str, dict[str, str]] | None:
    """Normalize a path-to-hash mapping."""
    if hashes is None:
        return None
    normalized = {}
    for path, hash_dict in hashes.items():
        normalized[_normalize_path(path)] = dict(hash_dict)
    return normalized


def _normalize_facts(value: Any) -> ArtifactFacts | None:
    """Convert supported artifact evidence inputs to ArtifactFacts."""
    if value is None:
        return None
    if isinstance(value, ArtifactFacts):
        return value

    if isinstance(value, Mapping):
        materials = value.get("materials")
        products = value.get("products")
        material_hashes = value.get("material_hashes")
        product_hashes = value.get("product_hashes")
    elif hasattr(value, "materials") and hasattr(value, "products"):
        materials = value.materials
        products = value.products
        material_hashes = getattr(value, "material_hashes", None)
        product_hashes = getattr(value, "product_hashes", None)
    else:
        raise CompatibilityReviewError(
            f"unsupported artifact evidence input: {value!r}"
        )

    if isinstance(materials, Mapping) and material_hashes is None:
        material_hashes = materials
    if isinstance(products, Mapping) and product_hashes is None:
        product_hashes = products

    return ArtifactFacts(
        materials=(
            frozenset(_normalize_path(path) for path in materials)
            if materials is not None
            else None
        ),
        products=(
            frozenset(_normalize_path(path) for path in products)
            if products is not None
            else None
        ),
        material_hashes=_normalize_hash_dict(material_hashes),
        product_hashes=_normalize_hash_dict(product_hashes),
    )


def _facts_for(artifacts: Any, step: str | None) -> ArtifactFacts | None:
    """Return evidence for a step from a global or per-step input."""
    if artifacts is None:
        return None
    if isinstance(artifacts, ArtifactFacts):
        return artifacts
    if isinstance(artifacts, Mapping):
        if step in artifacts:
            return _normalize_facts(artifacts[step])
        if "materials" in artifacts or "products" in artifacts:
            return _normalize_facts(artifacts)
    return _normalize_facts(artifacts)


def _hash_for(
    hashes: Mapping[str, Mapping[str, str]] | None, path: str
) -> Mapping[str, str] | None:
    """Return a hash dict for a path, if known."""
    if hashes is None:
        return None
    return hashes.get(path)


def _consume_verdict(  # noqa: C901, PLR0911, PLR0912
    rule_data: Mapping[str, Any],
    name: str,
    artifacts: Any,
    step: str | None,
) -> bool | None:
    """Return True, False, or None (unknown) for a consuming rule."""
    rule_type = rule_data["rule_type"]
    facts = _facts_for(artifacts, step)
    if facts is None:
        facts = ArtifactFacts(materials=frozenset({name}))

    if rule_type == "create":
        materials = (
            facts.materials
            if facts.materials is not None
            else frozenset({name})
        )
        if facts.products is None:
            return False if name in materials else None
        return name in facts.products and name not in materials

    if rule_type == "delete":
        materials = (
            facts.materials
            if facts.materials is not None
            else frozenset({name})
        )
        if facts.products is None:
            return None
        return name in materials and name not in facts.products

    if rule_type == "modify":
        if (
            facts.materials is None
            or facts.products is None
            or facts.material_hashes is None
            or facts.product_hashes is None
        ):
            return None
        if name not in facts.materials or name not in facts.products:
            return False
        source = _hash_for(facts.material_hashes, name)
        dest = _hash_for(facts.product_hashes, name)
        if source is None or dest is None:
            return None
        return source != dest

    if rule_type == "match":
        remainder = _strip_prefix(name, rule_data["source_prefix"])
        if remainder is None:
            return False
        if not _matches(remainder, rule_data["pattern"]):
            return False

        dest_facts = _facts_for(artifacts, rule_data["dest_name"])
        if dest_facts is None:
            return None

        dest_path = _join(rule_data["dest_prefix"], remainder)
        if rule_data["dest_type"] == "materials":
            dest_paths = dest_facts.materials
            dest_hashes = dest_facts.material_hashes
        else:
            dest_paths = dest_facts.products
            dest_hashes = dest_facts.product_hashes

        if dest_paths is not None and dest_path not in dest_paths:
            return False

        source_hashes = facts.material_hashes
        source = _hash_for(source_hashes, name)
        dest = _hash_for(dest_hashes, dest_path)
        if source is None or dest is None:
            return None
        return source == dest

    return False


def _evaluate_steps(  # noqa: C901, PLR0912
    name: str,
    steps: Sequence[tuple[str | None, tuple[str, ...]]],
    artifacts: Any,
) -> Decision:
    """Evaluate ordered rules for one material name on one side."""
    accepted_by = None
    unknown_by = None

    for index, (step_name, rule) in enumerate(steps):
        rule_data = in_toto.rulelib.unpack_rule(list(rule))
        rule_type = rule_data["rule_type"]
        pattern = rule_data["pattern"]

        # Once an artifact has been consumed, in-toto removes it from the
        # queue. Later matching rules cannot see it anymore. REQUIRE is the
        # exception: it fails when the named artifact is no longer queued.
        if accepted_by is not None:
            if rule_type == "require" and _normalize_path(pattern) == name:
                return Decision(
                    "rejected",
                    index,
                    rule,
                    step_name,
                    "REQUIRE names an artifact already consumed earlier",
                )
            continue

        if rule_type == "allow":
            if _matches(name, pattern):
                # Continue scanning for a later REQUIRE rule, which can still
                # invalidate the decision in in-toto's queue model.
                accepted_by = (
                    index,
                    rule,
                    step_name,
                    "ALLOW matched the material name",
                )

        elif rule_type == "disallow":
            if _matches(name, pattern):
                # If an earlier consuming rule could have removed the
                # artifact, this later DISALLOW only applies on the branch
                # where it was not consumed. The result stays unresolved.
                if unknown_by is not None:
                    continue
                return Decision(
                    "rejected",
                    index,
                    rule,
                    step_name,
                    "DISALLOW matched the material name",
                )

        elif rule_type == "require":
            # A REQUIRE before consumption is satisfied by the presence of the
            # artifact under review. Absence of unrelated required artifacts is
            # a layout-wide concern, not a decision about this material.
            continue

        else:
            if rule_type == "match":
                remainder = _strip_prefix(name, rule_data["source_prefix"])
                rule_matches = remainder is not None and _matches(
                    remainder, pattern
                )
            else:
                rule_matches = _matches(name, pattern)

            if not rule_matches:
                continue

            verdict = _consume_verdict(rule_data, name, artifacts, step_name)
            if verdict is True and accepted_by is None:
                accepted_by = (
                    index,
                    rule,
                    step_name,
                    "the rule consumed the material; later rules cannot "
                    "reject it",
                )
            elif verdict is None and unknown_by is None:
                unknown_by = (index, rule, step_name)

    if accepted_by is not None:
        index, rule, step_name, reason = accepted_by
        return Decision(
            "accepted",
            index,
            rule,
            step_name,
            reason,
        )

    if unknown_by is not None:
        index, rule, step_name = unknown_by
        return Decision(
            "unknown",
            index,
            rule,
            step_name,
            "the rule could consume the material but evidence is missing",
        )

    return Decision(
        "accepted",
        None,
        None,
        None,
        "no rule consumed or rejected the material; in-toto applies an "
        "implicit terminal ALLOW",
        implicit=True,
    )


def _iter_reachable_steps(
    steps: Sequence[tuple[str | None, tuple[str, ...]]],
) -> Iterable[tuple[int, str | None, tuple[str, ...]]]:
    """Yield rules up to and including the first catch-all DISALLOW."""
    for index, (step_name, rule) in enumerate(steps):
        yield index, step_name, rule
        rule_data = in_toto.rulelib.unpack_rule(list(rule))
        if rule_data["rule_type"] == "disallow" and _is_catch_all(
            rule_data["pattern"]
        ):
            return


def _is_catch_all(pattern: str) -> bool:
    """Return True for the common catch-all DISALLOW patterns."""
    return _normalize_pattern(pattern).strip() in {"*", "**"}


def _effective_pattern(rule_data: Mapping[str, Any]) -> str:
    """Return the source-side artifact pattern of a rule."""
    if rule_data["rule_type"] == "match":
        return _join(rule_data["source_prefix"], rule_data["pattern"])
    return _normalize_pattern(rule_data["pattern"])


def _exact_names(rule_data: Mapping[str, Any]) -> list[str]:
    """Return exact artifact names mentioned by a rule."""
    pattern = _effective_pattern(rule_data)
    if _is_glob(pattern):
        return []
    return [_normalize_path(pattern)]


def _collect_gaps(
    side: str,
    steps: Sequence[tuple[str | None, tuple[str, ...]]],
    vocabulary: frozenset[str],
    strict_vocabulary: bool,
) -> list[CoverageGap]:
    """Collect coverage gaps for one side of the review."""
    gaps = []
    closed = False

    for index, step_name, rule in _iter_reachable_steps(steps):
        rule_data = in_toto.rulelib.unpack_rule(list(rule))
        rule_type = rule_data["rule_type"]
        pattern = _effective_pattern(rule_data)

        if rule_type == "disallow" and _is_catch_all(rule_data["pattern"]):
            closed = True

        if rule_type in ACCEPTING_RULES:
            if _is_glob(pattern):
                if strict_vocabulary:
                    gaps.append(
                        CoverageGap(
                            side=side,
                            pattern=pattern,
                            rule_index=index,
                            step=step_name,
                            reason=(
                                "accepting rule has a glob pattern; known "
                                "samples cannot prove coverage of the approved "
                                "vocabulary"
                            ),
                            may_accept_outside_vocabulary=True,
                        )
                    )
            else:
                name = _normalize_path(pattern)
                if name not in vocabulary:
                    gaps.append(
                        CoverageGap(
                            side=side,
                            name=name,
                            pattern=pattern,
                            rule_index=index,
                            step=step_name,
                            reason=(
                                "accepting rule names an artifact outside the "
                                "approved vocabulary"
                            ),
                            may_accept_outside_vocabulary=True,
                        )
                    )

        elif rule_type == "require":
            name = _normalize_path(pattern)
            if name not in vocabulary:
                gaps.append(
                    CoverageGap(
                        side=side,
                        name=name,
                        pattern=pattern,
                        rule_index=index,
                        step=step_name,
                        reason=(
                            "REQUIRE names an artifact outside the approved "
                            "vocabulary"
                        ),
                    )
                )

    if not closed:
        gaps.append(
            CoverageGap(
                side=side,
                reason=(
                    "no reachable catch-all DISALLOW; names not consumed by "
                    "earlier rules are implicitly accepted"
                ),
                may_accept_outside_vocabulary=True,
            )
        )

    return gaps


def _gap_signature(
    gap: CoverageGap, mapping: PathMapping, map_old: bool
) -> tuple[str | None, str | None]:
    """Return a namespace-independent signature for gap comparison."""
    if gap.name is not None:
        value = gap.name
        if map_old:
            value = mapping.map(value)
        return ("name", value)
    if gap.pattern is not None:
        value = gap.pattern
        if map_old:
            value = mapping.map(value)
        return ("pattern", value)
    return ("implicit", None)


def _candidate_pairs(
    vocabulary: Sequence[str],
    mapping: PathMapping,
    vocabulary_side: str,
    old_steps: Sequence[tuple[str | None, tuple[str, ...]]],
    new_steps: Sequence[tuple[str | None, tuple[str, ...]]],
) -> list[tuple[str, str]]:
    """Build old/new name pairs for the vocabulary and exact rule names."""
    pairs = []
    seen = set()

    def add(old_name: str, new_name: str) -> None:
        old_name = _normalize_path(old_name)
        new_name = _normalize_path(new_name)
        key = (old_name, new_name)
        if key not in seen:
            seen.add(key)
            pairs.append(key)

    for name in vocabulary:
        normalized = _normalize_path(name)
        if vocabulary_side == "new":
            add(mapping.unmap(normalized), normalized)
        else:
            add(normalized, mapping.map(normalized))

    for _, rule in _iter_accepting_rules(old_steps):
        rule_data = in_toto.rulelib.unpack_rule(list(rule))
        for name in _exact_names(rule_data):
            add(name, mapping.map(name))

    for _, rule in _iter_accepting_rules(new_steps):
        rule_data = in_toto.rulelib.unpack_rule(list(rule))
        for name in _exact_names(rule_data):
            add(mapping.unmap(name), name)

    return pairs


def _iter_accepting_rules(
    steps: Sequence[tuple[str | None, tuple[str, ...]]],
) -> Iterable[tuple[int, tuple[str, ...]]]:
    """Yield reachable rules that can accept or require an artifact."""
    for index, _, rule in _iter_reachable_steps(steps):
        rule_data = in_toto.rulelib.unpack_rule(list(rule))
        if (
            rule_data["rule_type"] in ACCEPTING_RULES
            or rule_data["rule_type"] == "require"
        ):
            yield index, rule


def evaluate_material_rules(
    material: str,
    rules: Any,
    artifacts: Any = None,
) -> Decision:
    """Evaluate ordered rules for one material name.

    This helper is useful on its own and is also used by the two-layout review.
    ``rules`` may be a single rule, a list of rules, or a list of
    ``(step_name, rules)`` pairs.
    """
    normalized = _normalize_path(material)
    steps = _normalize_rule_spec(rules)
    return _evaluate_steps(normalized, steps, artifacts)


def review_layout_compatibility(  # noqa: C901, PLR0912, PLR0913, PLR0915
    old_layout: Any,
    new_layout: Any,
    material_vocabulary: Any,
    rule_steps: Any = None,
    path_mappings: Any = None,
    *,
    vocabulary_side: str = "old",
    artifacts: Any = None,
    strict_vocabulary: bool = True,
    old_label: str = "old",
    new_label: str = "new",
) -> CompatibilityReport:
    """Review whether a new layout stays within an approved material set.

    Arguments:
      old_layout: The approved layout, or signed metadata containing it.
      new_layout: The candidate layout, or signed metadata containing it.
      material_vocabulary: Literal public material names approved by the
          release group. Wildcards are treated as literal names here; they are
          never expanded into permission.
      rule_steps: Optional caller supplied ordered material rules. When omitted,
          rules are taken from both layouts. A mapping keyed by ``old``/``new``
          (or the passed labels) can provide different rules per side.
      path_mappings: Optional ``old_prefix -> new_prefix`` mapping used to
          compare material identities across naming conventions.
      vocabulary_side: ``"old"`` (default) interprets vocabulary names in the
          approved namespace; ``"new"`` interprets them in the candidate
          namespace.
      artifacts: Optional evidence for CREATE/DELETE/MODIFY/MATCH rules. It may
          be a global ArtifactFacts, a mapping of step names to evidence, or a
          mapping keyed by ``old``/``new``.
      strict_vocabulary: If True (default), an accepting glob rule is reported
          as a coverage gap even when every supplied sample matches it. Set to
          False only for an explicitly non-security review.
      old_label: Label used for the approved side in the report.
      new_label: Label used for the candidate side in the report.

    Returns:
      A CompatibilityReport with per-material decisions, first deciding rules,
      and coverage gaps.
    """
    if vocabulary_side not in {"old", "new"}:
        raise CompatibilityReviewError("vocabulary_side must be 'old' or 'new'")

    if isinstance(material_vocabulary, Mapping):
        material_vocabulary = list(material_vocabulary)
    elif isinstance(material_vocabulary, str):
        material_vocabulary = [material_vocabulary]
    elif isinstance(material_vocabulary, (set, frozenset)):
        material_vocabulary = sorted(material_vocabulary)

    vocabulary = tuple(_normalize_path(name) for name in material_vocabulary)
    if len(set(vocabulary)) != len(vocabulary):
        raise CompatibilityReviewError(
            "material vocabulary must not contain duplicates"
        )

    mapping = (
        path_mappings
        if isinstance(path_mappings, PathMapping)
        else PathMapping(path_mappings)
    )

    old_rules_spec, new_rules_spec = _split_side_spec(
        rule_steps, old_label, new_label
    )

    old_layout_obj = _as_layout(old_layout)
    new_layout_obj = _as_layout(new_layout)

    old_steps = (
        _normalize_rule_spec(old_rules_spec)
        if old_rules_spec is not None
        else _collect_layout_steps(old_layout_obj)
    )
    new_steps = (
        _normalize_rule_spec(new_rules_spec)
        if new_rules_spec is not None
        else _collect_layout_steps(new_layout_obj)
    )

    old_artifacts, new_artifacts = _split_side_spec(
        artifacts, old_label, new_label
    )

    if vocabulary_side == "new":
        old_vocabulary = frozenset(mapping.unmap(name) for name in vocabulary)
        new_vocabulary = frozenset(vocabulary)
    else:
        old_vocabulary = frozenset(vocabulary)
        new_vocabulary = frozenset(mapping.map(name) for name in vocabulary)

    vocabulary_pairs = {
        (old_name, mapping.map(old_name)) for old_name in old_vocabulary
    }

    old_gaps = _collect_gaps(
        old_label, old_steps, old_vocabulary, strict_vocabulary
    )
    new_gaps = _collect_gaps(
        new_label, new_steps, new_vocabulary, strict_vocabulary
    )

    old_signatures = {
        _gap_signature(gap, mapping, map_old=True) for gap in old_gaps
    }
    marked_gaps = tuple(
        CoverageGap(
            side=gap.side,
            reason=gap.reason,
            name=gap.name,
            pattern=gap.pattern,
            rule_index=gap.rule_index,
            step=gap.step,
            may_accept_outside_vocabulary=(gap.may_accept_outside_vocabulary),
            introduced=(
                _gap_signature(gap, mapping, map_old=False)
                not in old_signatures
            ),
        )
        for gap in old_gaps + new_gaps
    )

    pairs = _candidate_pairs(
        vocabulary,
        mapping,
        vocabulary_side,
        old_steps,
        new_steps,
    )

    reviews = []
    for old_name, new_name in pairs:
        old_decision = _evaluate_steps(old_name, old_steps, old_artifacts)
        new_decision = _evaluate_steps(new_name, new_steps, new_artifacts)
        in_vocabulary = (old_name, new_name) in vocabulary_pairs

        old_accepts = old_decision.outcome == "accepted"
        new_accepts = new_decision.outcome == "accepted"
        unknown = (
            old_decision.outcome == "unknown"
            or new_decision.outcome == "unknown"
        )

        if not in_vocabulary:
            status = "coverage_gap"
        elif unknown:
            status = "unknown"
        elif old_accepts and new_accepts:
            status = "unchanged_allowed"
        elif not old_accepts and new_accepts:
            status = "newly_allowed"
        elif old_accepts and not new_accepts:
            status = "regression"
        else:
            status = "unchanged_rejected"

        migration_allowed = in_vocabulary and new_accepts and not unknown
        material = new_name if vocabulary_side == "new" else old_name
        reviews.append(
            MaterialReview(
                material=material,
                old_name=old_name,
                new_name=new_name,
                in_vocabulary=in_vocabulary,
                old=old_decision,
                new=new_decision,
                status=status,
                migration_allowed=migration_allowed,
            )
        )

    unapproved_acceptance = any(
        not review.in_vocabulary and review.new.outcome == "accepted"
        for review in reviews
    )
    blocking_new_gaps = any(
        gap.side == new_label
        and gap.introduced
        and gap.may_accept_outside_vocabulary
        for gap in marked_gaps
    )
    approved_for_migration = not (unapproved_acceptance or blocking_new_gaps)
    compatible = approved_for_migration and not any(
        review.status == "regression" for review in reviews
    )

    return CompatibilityReport(
        old_label=old_label,
        new_label=new_label,
        vocabulary=vocabulary,
        materials=tuple(reviews),
        gaps=marked_gaps,
        approved_for_migration=approved_for_migration,
        compatible=compatible,
        old_signature_count=_signature_count(old_layout),
        new_signature_count=_signature_count(new_layout),
    )


# Descriptive aliases for callers that prefer a different verb.
check_layout_compatibility = review_layout_compatibility
offline_compatibility_review = review_layout_compatibility
review_material_compatibility = review_layout_compatibility
audit_layout_compatibility = review_layout_compatibility
verify_layout_compatibility = review_layout_compatibility

# Short aliases for the report value objects.
MaterialDecision = Decision
RuleDecision = Decision
CompatibilityGap = CoverageGap
LayoutCompatibilityReport = CompatibilityReport
