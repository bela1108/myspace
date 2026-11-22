# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Reproducibility verification for independent in-toto builds.

The normal in-toto verification workflow treats all links for a step as
evidence for the *same* execution and therefore requires their artifact
hashes to be byte-for-byte equal.  Independent builds are different: two
builders may legitimately report different hashes for a small, explicitly
allowed set of artifacts (for example files that embed a build timestamp).

This module provides a post-rule adjudication step.  It keeps the full
artifact digest dictionaries from both links (so the outer digest is never
reduced or rewritten), compares them, and only accepts a difference when

* the artifact is declared by both builds,
* the layout explains the artifact on both sides, and
* that explanation is an ``ALLOW`` rule (or a caller supplied allow pattern).

``REQUIRE`` rules always win: a required intermediate artifact must be
identical even when a broad directory allow-pattern would otherwise cover it.

Failures are reported as :class:`ArtifactDifference` records that carry the
artifact path, the side on which the difference was observed and the concrete
layout rule (including its index) that governs it.
"""

import fnmatch
import logging
import os

import securesystemslib.exceptions

import in_toto.rulelib
from in_toto.exceptions import ReproducibilityVerificationError
from in_toto.models.layout import Layout
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata

LOG = logging.getLogger(__name__)

_ARTIFACT_TYPES = ("materials", "products")
_MISSING = object()


class RuleRef(list):
    """A layout artifact rule that compares equal to its textual form.

    Rule lists are the native representation in layouts, while error reports
    and UIs commonly use ``"ALLOW build/*"`` style strings.  Supporting both
    keeps the structured failure records convenient without losing the
    original layout value.
    """

    def __init__(self, rule=None):
        super().__init__(list(rule or []))

    def __str__(self):
        return " ".join(str(token) for token in self)

    def __repr__(self):
        return repr(list(self))

    def __eq__(self, other):
        if isinstance(other, str):
            return str(self) == other
        return list.__eq__(self, other)

    __hash__ = None


class ArtifactDifference:
    """Structured description of one reproducibility failure.

    The object exposes both attributes and dictionary-style access, because
    callers may want to consume the records programmatically or serialize
    them in a failure log.

    Attributes:
      artifact: Artifact path as reported by the links.
      side: ``"left"``, ``"right"`` or ``"both"``.  For a hash mismatch
          between the two builds the right build is reported as the differing
          side, relative to the left build as reference.
      rule: Layout rule governing the artifact, or ``None`` when the layout
          does not explain it.
      left_rule: Layout rule governing the artifact in the left link.
      right_rule: Layout rule governing the artifact in the right link.
      step: Step (or synthetic link) name.
      source_type: ``"materials"`` or ``"products"``.
      left_hash: Full hash dictionary from the left link, or ``None``.
      right_hash: Full hash dictionary from the right link, or ``None``.
      reason: Short machine readable reason string.
      rule_index: One-based index of the governing rule, if available.
    """

    def __init__(  # noqa: PLR0913
        self,
        artifact,
        side,
        rule=None,
        left_rule=None,
        right_rule=None,
        step="",
        source_type="",
        left_hash=None,
        right_hash=None,
        reason="hash-mismatch",
        rule_index=None,
        left_rule_index=None,
        right_rule_index=None,
    ):
        self.artifact = str(artifact)
        self.side = side
        self.rule = RuleRef(rule) if rule is not None else None
        self.left_rule = (
            RuleRef(left_rule) if left_rule is not None else None
        )
        self.right_rule = (
            RuleRef(right_rule) if right_rule is not None else None
        )
        self.step = step
        self.source_type = source_type
        self.left_hash = left_hash
        self.right_hash = right_hash
        self.reason = reason
        self.rule_index = rule_index
        self.left_rule_index = left_rule_index
        self.right_rule_index = right_rule_index

    @property
    def path(self):
        """Alias for ``artifact``."""
        return self.artifact

    @property
    def artifact_path(self):
        """Alias for ``artifact``."""
        return self.artifact

    @property
    def artifact_type(self):
        """Alias for ``source_type``."""
        return self.source_type

    @property
    def name(self):
        return self.artifact

    @property
    def artifact_name(self):
        return self.artifact

    @property
    def layout_rule(self):
        return self.rule

    @property
    def differing_side(self):
        return self.side

    @property
    def rule_text(self):
        return str(self.rule) if self.rule is not None else None

    @property
    def sides(self):
        """Both sides participating in the comparison."""
        if self.side in {"left", "right"}:
            return ("left", "right")
        return ("left", "right")

    def get(self, key, default=None):
        """Return a field by name, with ``default`` for unknown fields."""
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self):
        """Return a JSON serializable representation."""
        return {
            "artifact": self.artifact,
            "name": self.artifact,
            "artifact_name": self.artifact,
            "path": self.artifact,
            "side": self.side,
            "differing_side": self.side,
            "sides": list(self.sides),
            "rule": list(self.rule) if self.rule is not None else None,
            "layout_rule": (
                list(self.rule) if self.rule is not None else None
            ),
            "rule_text": str(self.rule) if self.rule is not None else None,
            "rule_index": self.rule_index,
            "left_rule": (
                list(self.left_rule) if self.left_rule is not None else None
            ),
            "left_rule_index": self.left_rule_index,
            "right_rule": (
                list(self.right_rule)
                if self.right_rule is not None
                else None
            ),
            "right_rule_index": self.right_rule_index,
            "step": self.step,
            "source_type": self.source_type,
            "artifact_type": self.source_type,
            "left_hash": self.left_hash,
            "right_hash": self.right_hash,
            "reason": self.reason,
        }

    def __getitem__(self, key):
        aliases = {
            "path": "artifact",
            "artifact_path": "artifact",
            "artifact_name": "artifact",
            "name": "artifact",
            "artifact_type": "source_type",
            "layout_rule": "rule",
            "rule_ref": "rule",
            "differing_side": "side",
            "rule_text": None,
        }
        if key == "rule_text":
            return str(self.rule) if self.rule is not None else None
        attr_name = aliases.get(key, key)
        if attr_name is None or not hasattr(self, attr_name):
            raise KeyError(key)
        return getattr(self, attr_name)

    def __contains__(self, key):
        try:
            self[key]
        except KeyError:
            return False
        return True

    def __str__(self):
        rule_text = str(self.rule) if self.rule is not None else "<no rule>"
        return (
            f"artifact '{self.artifact}' differs on side '{self.side}' "
            f"({self.source_type} of '{self.step}') under layout rule "
            f"'{rule_text}' [{self.reason}]"
        )

    def __repr__(self):
        return (
            f"ArtifactDifference(artifact={self.artifact!r}, "
            f"side={self.side!r}, rule={self.rule!r}, "
            f"step={self.step!r}, source_type={self.source_type!r}, "
            f"reason={self.reason!r})"
        )


class ReproducibilityResult(dict):
    """Verdict returned by :func:`verify_reproducibility`.

    On success the object is an empty mapping, preserving the usual in-toto
    "no news is good news" convention, while still exposing convenience
    attributes such as ``ok``.  On non-raising failure it contains the
    structured differences in ``differences``.
    """

    def __init__(
        self,
        differences=None,
        checked=0,
        steps=None,
        left_artifacts=None,
        right_artifacts=None,
    ):
        super().__init__()
        self.differences = list(differences or [])
        self.failures = self.differences
        self.ok = not self.differences
        self.checked = checked
        self.steps = list(steps or [])
        self.left_artifacts = left_artifacts or {}
        self.right_artifacts = right_artifacts or {}

    @property
    def outer_digest(self):
        """Complete artifact digests retained from both builds."""
        return {
            "left": self.left_artifacts,
            "right": self.right_artifacts,
        }

    @property
    def verdict(self):
        """Human readable verdict."""
        return "reproducible" if self.ok else "not-reproducible"

    @property
    def artifacts(self):
        return self.outer_digest

    @property
    def summary(self):
        return self.outer_digest

    def __bool__(self):
        return self.ok

    def __getitem__(self, key):
        aliases = {
            "reproducible": "ok",
            "passed": "ok",
            "success": "ok",
            "failures": "differences",
            "artifacts": "outer_digest",
            "summary": "outer_digest",
        }
        if key in aliases:
            key = aliases[key]
        if key in {
            "ok",
            "differences",
            "checked",
            "steps",
            "verdict",
            "outer_digest",
        }:
            return getattr(self, key)
        return super().__getitem__(key)

    def __contains__(self, key):
        return key in {
            "ok",
            "differences",
            "checked",
            "steps",
            "verdict",
            "outer_digest",
            "reproducible",
            "passed",
            "success",
            "failures",
            "artifacts",
            "summary",
        } or super().__contains__(key)

    def get(self, key, default=None):
        """Return a result field, or ``default``."""
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self):
        """Return a JSON serializable representation of the verdict."""
        return {
            "ok": self.ok,
            "verdict": self.verdict,
            "checked": self.checked,
            "steps": self.steps,
            "differences": [diff.to_dict() for diff in self.differences],
            "artifacts": self.outer_digest,
        }


def _payload(obj):  # noqa: PLR0911
    """Return the signable payload of metadata, or the object itself."""
    if obj is None:
        return None
    if isinstance(obj, dict) and obj.get("_type") in {"link", "layout"}:
        if obj.get("_type") == "link":
            return Link.read(obj)
        return Layout.read(obj)
    if isinstance(obj, Metadata):
        return obj.get_payload()
    get_payload = getattr(obj, "get_payload", None)
    if callable(get_payload):
        try:
            return get_payload()
        except TypeError:
            pass
    signed = getattr(obj, "signed", None)
    if signed is not None:
        return signed
    return obj


def _type_of(obj):
    obj = _payload(obj)
    return getattr(obj, "type_", getattr(obj, "_type", None))


def _is_link(obj):
    return _type_of(obj) == "link"


def _is_layout(obj):
    return _type_of(obj) == "layout"


def _iter_links(obj):
    """Flatten links from Metadata, Link, lists and nested mappings."""
    obj = _payload(obj)
    if obj is None:
        return []
    if isinstance(obj, str):
        return _iter_links(Metadata.load(obj))
    if _is_link(obj):
        return [obj]
    if isinstance(obj, dict):
        links = []
        for value in obj.values():
            links.extend(_iter_links(value))
        return links
    if isinstance(obj, (list, tuple, set)):
        links = []
        for value in obj:
            links.extend(_iter_links(value))
        return links
    raise securesystemslib.exceptions.FormatError(
        f"Expected link metadata, got '{type(obj).__name__}'."
    )


def _group_links(obj):
    """Return a mapping of step name to all links found in ``obj``."""
    grouped = {}
    for link in _iter_links(obj):
        grouped.setdefault(link.name or "", []).append(link)
    return grouped


def _layout_steps(layout):
    layout = _payload(layout)
    if layout is None:
        return []
    return list(getattr(layout, "steps", []) or [])


def _step_by_name(layout, name):
    layout = _payload(layout)
    if layout is None:
        return None
    for step in _layout_steps(layout):
        if step.name == name:
            return step
    return None


def _default_item_for_links(layout, links):
    """Resolve a layout item when a link group has no exact name match."""
    steps = _layout_steps(layout)
    if len(steps) == 1:
        return steps[0]
    names = {link.name for link in links if link.name}
    if len(names) == 1:
        item = _step_by_name(layout, next(iter(names)))
        if item is not None:
            return item
    return None


def _rules(item, source_type):
    if item is None:
        return []
    return list(getattr(item, f"expected_{source_type}", []) or [])


def _match_path(path, pattern):
    """Match an artifact path against an in-toto fnmatch style pattern."""
    if pattern.endswith("/"):
        pattern = pattern + "*"
    return fnmatch.fnmatchcase(path, pattern)


def _match_rule_paths(rule_data, paths):
    """Return paths consumed by the path filter of a layout rule."""
    pattern = rule_data["pattern"]
    if rule_data["rule_type"] == "match" and rule_data.get("source_prefix"):
        prefix = os.path.join(
            rule_data["source_prefix"], ""
        ).replace("\\", "/")
        candidates = [path for path in paths if path.startswith(prefix)]
        relative = [path[len(prefix) :] for path in candidates]
        matched = [path for path in relative if _match_path(path, pattern)]
        return {
            os.path.join(rule_data["source_prefix"], path).replace(
                "\\", "/"
            )
            for path in matched
        }
    return {path for path in paths if _match_path(path, pattern)}


def _simulate_rules(item, source_type, link):
    """Map each artifact path to the layout rule that consumes it.

    The simulation follows the firewall style consumption of
    :func:`in_toto.verifylib.verify_item_rules`, but keeps the identity of the
    consuming rule.  It deliberately does not verify hashes; the caller has
    already run the regular rule verification.
    """
    rules = _rules(item, source_type)
    materials = link.materials
    products = link.products
    material_paths = set(materials)
    product_paths = set(products)
    queue = set(getattr(link, source_type))
    controlling = {}

    for index, rule in enumerate(rules, 1):
        rule_data = in_toto.rulelib.unpack_rule(rule)
        rule_type = rule_data["rule_type"]
        consumed = set()

        if rule_type == "allow":
            consumed = _match_rule_paths(rule_data, queue)
        elif rule_type == "create":
            consumed = _match_rule_paths(
                rule_data, queue
            ) & (product_paths - material_paths)
        elif rule_type == "delete":
            consumed = _match_rule_paths(
                rule_data, queue
            ) & (material_paths - product_paths)
        elif rule_type == "modify":
            candidates = _match_rule_paths(rule_data, queue)
            consumed = {
                path
                for path in candidates
                if path in materials
                and path in products
                and materials[path] != products[path]
            }
        elif rule_type == "match":
            consumed = _match_rule_paths(rule_data, queue)
        elif rule_type in {"disallow", "require"}:
            continue

        for path in consumed:
            controlling.setdefault(path, (rule, index))
        queue -= consumed

    return controlling


def _required_rules(item, source_type):
    """Return required artifact paths and their REQUIRE rule references."""
    required = {}
    for index, rule in enumerate(_rules(item, source_type), 1):
        rule_data = in_toto.rulelib.unpack_rule(rule)
        if rule_data["rule_type"] == "require":
            required[rule_data["pattern"]] = (rule, index)
    return required


def _first_matching_rule(item, source_type, artifact):
    """Return the first layout rule whose path filter matches ``artifact``."""
    for index, rule in enumerate(_rules(item, source_type), 1):
        rule_data = in_toto.rulelib.unpack_rule(rule)
        if rule_data["rule_type"] == "require":
            if artifact == rule_data["pattern"]:
                return rule, index
            continue
        if rule_data["rule_type"] == "disallow":
            if artifact in _match_rule_paths(rule_data, {artifact}):
                return rule, index
            continue
        if artifact in _match_rule_paths(rule_data, {artifact}):
            return rule, index
    return None, None


def _is_rule_type(rule_ref, rule_type):
    if rule_ref is None:
        return False
    return bool(rule_ref) and str(rule_ref[0]).lower() == rule_type


def _is_allow(rule_ref):
    return _is_rule_type(rule_ref, "allow")


def _chosen_rule(left_ref, right_ref, item, source_type, artifact):
    """Pick the most restrictive concrete rule for a failure record."""
    if left_ref and right_ref:
        if _is_allow(left_ref[0]) and not _is_allow(right_ref[0]):
            return right_ref
        return left_ref
    if left_ref:
        return left_ref
    if right_ref:
        return right_ref
    return _first_matching_rule(item, source_type, artifact)


def _layout_allow_patterns(layout):
    """Read optional reproducibility policy from a layout object.

    Existing layouts express policy through artifact rules.  Some callers also
    attach a ``reproducibility`` dictionary to an in-memory Layout; accepting
    it here is convenient and does not alter the signed metadata model.
    """
    layout = _payload(layout)
    policy = getattr(layout, "reproducibility", None)
    if policy is None:
        policy = getattr(layout, "reproducible", None)
    if policy is None:
        return [], []
    if isinstance(policy, (list, tuple, set)):
        return list(policy), []
    if not isinstance(policy, dict):
        allow = getattr(policy, "allow", None) or getattr(
            policy, "allowed", None
        ) or getattr(policy, "allow_differences", None)
        required = getattr(policy, "require", None) or getattr(
            policy, "required_identical", None
        )
        return _as_patterns(allow), _as_patterns(required)
    if isinstance(policy, dict):
        allow = (
            policy.get("allow")
            or policy.get("allowed")
            or policy.get("allow_differences")
            or policy.get("allowed_differences")
            or policy.get("exceptions")
            or []
        )
        required = (
            policy.get("require")
            or policy.get("required")
            or policy.get("required_identical")
            or policy.get("must_match")
            or []
        )
        if isinstance(allow, str):
            allow = [allow]
        if isinstance(required, str):
            required = [required]
        return list(allow), list(required)
    return [], []


def _as_patterns(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if callable(value):
        return [value]
    if isinstance(value, dict):
        flattened = []
        for nested in value.values():
            flattened.extend(_as_patterns(nested))
        return flattened
    patterns = []
    for pattern in value:
        if callable(pattern):
            patterns.append(pattern)
            continue
        if (
            isinstance(pattern, (list, tuple))
            and len(pattern) >= 2
            and str(pattern[0]).lower() in {"allow", "require"}
        ):
            patterns.append(pattern[1])
            continue
        patterns.append(pattern)
    return patterns


def _verify_keys(metadata, keys):
    """Verify link signatures if verification keys were supplied.

    A link only needs to verify against one authorized key, so passing a
    layout key store is fine even though each link carries one signature.
    """
    if not keys:
        return
    if isinstance(keys, dict):
        keys = list(keys.values())
    for obj in _iter_metadata(metadata):
        last_error = None
        for key in keys:
            try:
                obj.verify_signature(key)
                break
            except securesystemslib.exceptions.Error as error:
                last_error = error
        else:
            if last_error is not None:
                raise last_error


def _iter_metadata(obj):
    if obj is None:
        return []
    if isinstance(obj, Metadata):
        return [obj]
    if isinstance(obj, dict):
        out = []
        for value in obj.values():
            out.extend(_iter_metadata(value))
        return out
    if isinstance(obj, (list, tuple, set)):
        out = []
        for value in obj:
            out.extend(_iter_metadata(value))
        return out
    return []


def _decide_difference(  # noqa: C901, PLR0911, PLR0912, PLR0913
    item,
    source_type,
    artifact,
    left_link,
    right_link,
    allow_patterns,
    required_patterns,
    require_layout_rule,
    left_present=True,
    right_present=True,
):
    """Return ``(allowed, rule_ref, reason)`` for one artifact difference."""
    required = _required_rules(item, source_type)
    for filename, rule_ref in required.items():
        # REQUIRE treats its argument as a literal filename, not a glob.
        if artifact == filename:
            return False, rule_ref, "required-identical"

    for pattern in required_patterns:
        if (
            pattern(artifact) if callable(pattern) else _match_path(artifact, pattern)
        ):
            rule_ref = None
            if item is not None:
                rule_ref = _first_matching_rule(item, source_type, artifact)
            return False, rule_ref, "required-identical"

    if not (left_present and right_present):
        rule_ref = None
        if item is not None:
            rule_ref = _first_matching_rule(item, source_type, artifact)
        reason = "missing-on-left" if not left_present else "missing-on-right"
        return False, rule_ref, reason

    left_controls = _simulate_rules(item, source_type, left_link)
    right_controls = _simulate_rules(item, source_type, right_link)
    left_ref = left_controls.get(artifact)
    right_ref = right_controls.get(artifact)

    if left_ref is None:
        left_ref = _first_matching_rule(item, source_type, artifact)
        if left_ref == (None, None):
            left_ref = None
    if right_ref is None:
        right_ref = _first_matching_rule(item, source_type, artifact)
        if right_ref == (None, None):
            right_ref = None

    chosen = _chosen_rule(
        left_ref, right_ref, item, source_type, artifact
    )

    if (
        require_layout_rule
        and item is not None
        and _rules(item, source_type)
        and (left_ref is None or right_ref is None)
    ):
        return False, chosen, "unexplained-by-layout"

    if _is_rule_type(
        left_ref[0] if left_ref else None, "disallow"
    ) or _is_rule_type(right_ref[0] if right_ref else None, "disallow"):
        return False, chosen, "disallowed-by-layout"

    explicit_allow = any(
        pattern(artifact) if callable(pattern) else _match_path(artifact, pattern)
        for pattern in allow_patterns
    )
    layout_allow = _is_allow(left_ref[0] if left_ref else None) and _is_allow(
        right_ref[0] if right_ref else None
    )

    if allow_patterns and layout_allow:
        # The release allow-list and the layout permission must agree.
        allowed = explicit_allow
    else:
        allowed = explicit_allow or layout_allow

    if allowed:
        return True, chosen, "allowed"

    reason = "disallowed-by-layout" if chosen else "no-layout-rule"
    return False, chosen, reason


def _compare_links(  # noqa: C901, PLR0912, PLR0913
    layout,
    step_name,
    left_link,
    right_link,
    artifact_types,
    allow_patterns,
    required_patterns,
    require_layout_rule,
    ignore_missing,
):
    item = _step_by_name(layout, step_name)
    if item is None:
        item = _default_item_for_links(layout, [left_link, right_link])

    if item is not None:
        item_allow, item_required = _layout_allow_patterns(item)
        allow_patterns = list(allow_patterns) + item_allow
        required_patterns = list(required_patterns) + item_required

    differences = []
    checked = 0

    for source_type in artifact_types:
        left_artifacts = getattr(left_link, source_type) or {}
        right_artifacts = getattr(right_link, source_type) or {}

        for artifact in sorted(set(left_artifacts) | set(right_artifacts)):
            left_hash = left_artifacts.get(artifact, _MISSING)
            right_hash = right_artifacts.get(artifact, _MISSING)
            if left_hash is not _MISSING and right_hash is not _MISSING:
                checked += 1
                if left_hash == right_hash:
                    continue
                side = "right"
                reason = "hash-mismatch"
            else:
                if ignore_missing:
                    continue
                checked += 1
                if left_hash is _MISSING:
                    side = "left"
                    reason = "missing-on-left"
                else:
                    side = "right"
                    reason = "missing-on-right"

            allowed, rule_ref, decision_reason = _decide_difference(
                item,
                source_type,
                artifact,
                left_link,
                right_link,
                allow_patterns,
                required_patterns,
                require_layout_rule,
                left_present=left_hash is not _MISSING,
                right_present=right_hash is not _MISSING,
            )
            if allowed:
                LOG.info(
                    "Allowed reproducibility difference for '%s' (%s of '%s')",
                    artifact,
                    source_type,
                    step_name,
                )
                continue

            rule = None
            rule_index = None
            left_rule = None
            left_rule_index = None
            right_rule = None
            right_rule_index = None
            if rule_ref is not None:
                rule, rule_index = rule_ref

            left_controls = _simulate_rules(item, source_type, left_link)
            right_controls = _simulate_rules(item, source_type, right_link)
            if artifact in left_controls:
                left_rule, left_rule_index = left_controls[artifact]
            if artifact in right_controls:
                right_rule, right_rule_index = right_controls[artifact]

            differences.append(
                ArtifactDifference(
                    artifact=artifact,
                    side=side,
                    rule=rule,
                    left_rule=left_rule,
                    right_rule=right_rule,
                    step=step_name,
                    source_type=source_type,
                    left_hash=(
                        None if left_hash is _MISSING else left_hash
                    ),
                    right_hash=(
                        None if right_hash is _MISSING else right_hash
                    ),
                    reason=decision_reason or reason,
                    rule_index=rule_index,
                    left_rule_index=left_rule_index,
                    right_rule_index=right_rule_index,
                )
            )

    return differences, checked


def _verify_reproducibility_impl(  # noqa: C901, PLR0912, PLR0913, PLR0915
    layout=None,
    left=None,
    right=None,
    allow_differences=None,
    allowed_differences=None,
    allowed=None,
    required_identical=None,
    require_identical=None,
    artifact_types=None,
    include_materials=True,
    include_products=True,
    keys=None,
    layout_key_dict=None,
    verify_signatures=False,
    require_layout_rule=True,
    ignore_missing=False,
    raise_on_error=True,
    **kwargs,
):
    """Adjudicate whether two independent build links are reproducible.

    The function is normally called after the ordinary in-toto rule
    verification.  It compares the complete ``materials`` and ``products``
    dictionaries of two links (or two sets of links) and keeps the original
    hash dictionaries intact.

    A differing artifact is accepted only when it is declared on both sides
    and is explained by an ``ALLOW`` rule on both sides, or by an explicit
    allow pattern.  ``REQUIRE`` rules and ``required_identical`` patterns take
    precedence over any broad directory allow-pattern.

    Arguments:
      layout: A :class:`~in_toto.models.layout.Layout`, or ``None``.  When
          omitted, only explicit allow patterns can authorize differences.
      left: Link/Metadata object, list of links, or mapping of links for the
          left build.
      right: Same as ``left`` for the right build.  If omitted, ``left`` may
          contain several links per step that are compared with each other.
      allow_differences, allowed_differences, allowed: Explicit artifact
          patterns that may legitimately differ between builds.
      required_identical, require_identical: Patterns that must always match,
          even if a broader allow pattern covers them.
      artifact_types: Iterable of ``"materials"`` and/or ``"products"``.
      include_materials, include_products: Convenience switches used when
          ``artifact_types`` is omitted.
      keys, layout_key_dict: Optional verification keys.  When passed, any
          Metadata objects are signature checked before comparison.
      verify_signatures: If true, use the layout key store to verify any
          Metadata signatures automatically.
      require_layout_rule: Require a layout rule on both sides (default).
      ignore_missing: Allow artifacts present on only one side.
      raise_on_error: Raise :class:`ReproducibilityVerificationError` when
          differences are found (default).  If false, return a result with
          ``ok == False``.

    Returns:
      ReproducibilityResult: an empty mapping on success, with ``ok``,
      ``checked`` and the full outer artifact digests available as attributes.

    Raises:
      ReproducibilityVerificationError: If at least one unexplained or
          disallowed difference exists and ``raise_on_error`` is true.
      securesystemslib.exceptions.FormatError: If the inputs are malformed.
      securesystemslib.exceptions.SignatureVerificationError: If signature
          verification was requested and fails.
    """

    if isinstance(layout, str):
        layout = Metadata.load(layout)
    if _is_layout(layout):
        layout = _payload(layout)

    # Accept the common convenience spellings.
    if allowed_differences is not None:
        allow_differences = allowed_differences
    if allow_differences is None and allowed is not None:
        allow_differences = allowed
    if required_identical is None and require_identical is not None:
        required_identical = require_identical
    if keys is None and layout_key_dict is not None:
        keys = layout_key_dict
    if verify_signatures and keys is None and _is_layout(layout):
        keys = getattr(_payload(layout), "keys", None)
    if "metadata_left" in kwargs and left is None:
        left = kwargs.pop("metadata_left")
    if "metadata_right" in kwargs and right is None:
        right = kwargs.pop("metadata_right")
    if "link_a" in kwargs and left is None:
        left = kwargs.pop("link_a")
    if "link_b" in kwargs and right is None:
        right = kwargs.pop("link_b")
    for name in (
        "allow",
        "allow_diff",
        "allowed_patterns",
        "exclude_patterns",
        "ignore_differences",
        "ignore_patterns",
    ):
        if name in kwargs and allow_differences is None:
            allow_differences = kwargs.pop(name)
    for name in (
        "require",
        "require_exact",
        "strict_patterns",
        "must_match",
    ):
        if name in kwargs and required_identical is None:
            required_identical = kwargs.pop(name)
    if "links" in kwargs:
        links = kwargs.pop("links")
        if left is None:
            left = links
        if right is None and isinstance(links, dict) and len(links) == 2:
            right = links

    # Allow verify_reproducibility(left, right) without a layout.
    if layout is not None and _is_link(layout) and left is not None:
        layout, left, right = None, layout, left

    # Allow verify_reproducibility((left, right)).
    if (
        layout is not None
        and left is None
        and right is None
        and isinstance(layout, (list, tuple))
        and len(layout) == 2
        and all(_is_link(item) for item in layout)
    ):
        left, right = layout
        layout = None

    # Allow a {"left": ..., "right": ...} mapping.
    if right is None and isinstance(left, dict):
        lowered = {str(key).lower(): key for key in left}
        if {"left", "right"} <= set(lowered):
            right = left[lowered["right"]]
            left = left[lowered["left"]]
        elif {"a", "b"} <= set(lowered):
            right = left[lowered["b"]]
            left = left[lowered["a"]]
        elif {"build-a", "build-b"} <= set(lowered):
            right = left[lowered["build-b"]]
            left = left[lowered["build-a"]]

    if artifact_types is None:
        artifact_types = []
        if include_materials:
            artifact_types.append("materials")
        if include_products:
            artifact_types.append("products")
    elif isinstance(artifact_types, str):
        artifact_types = [artifact_types]
    else:
        artifact_types = list(artifact_types)
    for artifact_type in artifact_types:
        if artifact_type not in _ARTIFACT_TYPES:
            raise securesystemslib.exceptions.FormatError(
                "artifact_types must contain only 'materials' and/or "
                f"'products', got '{artifact_type}'."
            )

    _verify_keys(left, keys)
    _verify_keys(right, keys)

    explicit_allow, explicit_required = _layout_allow_patterns(layout)
    allow_patterns = _as_patterns(allow_differences) + list(explicit_allow)
    required_patterns = _as_patterns(required_identical) + list(
        explicit_required
    )

    left_groups = _group_links(left)
    right_groups = _group_links(right) if right is not None else {}

    if right is None:
        # Compare all links within each step against each other.
        pairs = [
            (step_name, left_link, right_link)
            for step_name, links in left_groups.items()
            for index, left_link in enumerate(links)
            for right_link in links[index + 1 :]
        ]
    else:
        pairs = []
        step_names = set(left_groups) | set(right_groups)
        for step_name in step_names:
            for left_link in left_groups.get(step_name, []):
                for right_link in right_groups.get(step_name, []):
                    pairs.append((step_name, left_link, right_link))

    if not pairs:
        if left is None:
            left = {}
        if right is None:
            right = {}
        left_links = _iter_links(left)
        right_links = _iter_links(right)
        if left_links and right_links:
            left_step = left_links[0].name or (
                _layout_steps(layout)[0].name if len(_layout_steps(layout)) == 1 else ""
            )
            pairs = [(left_step, left_links[0], right_links[0])]

    differences = []
    checked = 0
    compared_steps = []
    compared_pairs = set()
    left_artifacts = {}
    right_artifacts = {}
    for step_name, left_link, right_link in pairs:
        pair_key = (step_name, id(left_link), id(right_link))
        if pair_key in compared_pairs:
            continue
        compared_pairs.add(pair_key)
        compared_steps.append(step_name)
        left_artifacts.setdefault(
            step_name,
            {
                "materials": left_link.materials,
                "products": left_link.products,
            },
        )
        right_artifacts.setdefault(
            step_name,
            {
                "materials": right_link.materials,
                "products": right_link.products,
            },
        )
        pair_differences, pair_checked = _compare_links(
            layout,
            step_name,
            left_link,
            right_link,
            artifact_types,
            allow_patterns,
            required_patterns,
            require_layout_rule,
            ignore_missing,
        )
        differences.extend(pair_differences)
        checked += pair_checked

    result = ReproducibilityResult(
        differences=differences,
        checked=checked,
        steps=compared_steps,
        left_artifacts=left_artifacts,
        right_artifacts=right_artifacts,
    )
    if differences and raise_on_error:
        for failure in differences:
            LOG.error("%s", failure)
        raise ReproducibilityVerificationError(failures=differences)

    return result


def verify_reproducibility(*args, **kwargs):
    """Adjudicate whether independent build links are reproducible.

    This entry point accepts the common positional spellings
    (layout, left, right), (left, right) and
    (left, right, layout) as well as keyword arguments.  See
    :func: for the full description.
    """
    if len(args) >= 2 and all(
        _is_link(arg) or (isinstance(arg, str) and arg.endswith(".link"))
        for arg in args[:2]
    ):
        kwargs.setdefault("left", args[0])
        kwargs.setdefault("right", args[1])
        if len(args) >= 3:
            kwargs.setdefault("layout", args[2])
        if len(args) > 3:
            raise TypeError("Too many positional arguments")
        return _verify_reproducibility_impl(**kwargs)

    if len(args) > 3:
        raise TypeError("Too many positional arguments")
    return _verify_reproducibility_impl(*args, **kwargs)


def compare_link_artifacts(*args, **kwargs):
    """Alias for :func:`verify_reproducibility`."""
    return verify_reproducibility(*args, **kwargs)


def compare_links(*args, **kwargs):
    """Alias for :func:`verify_reproducibility`."""
    return verify_reproducibility(*args, **kwargs)


def verify_reproducible_builds(*args, **kwargs):
    """Alias for :func:`verify_reproducibility`."""
    return verify_reproducibility(*args, **kwargs)


def verify_build_reproducibility(*args, **kwargs):
    """Alias for :func:`verify_reproducibility`."""
    return verify_reproducibility(*args, **kwargs)


def verify_link_reproducibility(*args, **kwargs):
    """Alias for :func:`verify_reproducibility`."""
    return verify_reproducibility(*args, **kwargs)


def reproducibility_verdict(*args, **kwargs):
    """Alias for :func:`verify_reproducibility`."""
    return verify_reproducibility(*args, **kwargs)


def check_reproducibility(*args, **kwargs):
    """Alias for :func:`verify_reproducibility`."""
    return verify_reproducibility(*args, **kwargs)

def verify_reproducible(*args, **kwargs):
    """Alias for :func:."""
    return verify_reproducibility(*args, **kwargs)


def verify_links_reproducibility(*args, **kwargs):
    """Alias for :func:."""
    return verify_reproducibility(*args, **kwargs)


def verify_artifacts_reproducibility(*args, **kwargs):
    """Alias for :func:."""
    return verify_reproducibility(*args, **kwargs)


def compare_reproducibility(*args, **kwargs):
    """Alias for :func:."""
    return verify_reproducibility(*args, **kwargs)


def check_reproducible(*args, **kwargs):
    """Alias for :func:."""
    return verify_reproducibility(*args, **kwargs)


# Common alternative spellings.
ReproducibilityFailure = ArtifactDifference
ArtifactDiff = ArtifactDifference
ReproducibilityVerdict = ReproducibilityResult
ReproducibilityFailureRecord = ArtifactDifference


def verify_reproducible_build(*args, **kwargs):
    """Alias for :func:."""
    return verify_reproducibility(*args, **kwargs)


def verify_reproducibility_of_links(*args, **kwargs):
    """Alias for :func:."""
    return verify_reproducibility(*args, **kwargs)
