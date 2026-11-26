# Copyright 2025 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Three-way semantic review for YARA drafts.

The approved ruleset is the common base.  Two maintainers may each submit a
complete offline draft.  This module compares both drafts with the approved
base and produces three useful buckets:

* changes that can be merged independently (metadata and tags),
* changes that change matching behaviour and therefore require a new approval
  or signature (conditions, string identities, dependencies, and rules), and
* explicit items that a human must adjudicate because the expression cannot be
  judged statically or because two drafts interact semantically.

The review is deliberately conservative.  It never pretends to understand an
expression it cannot classify; those expressions remain visible as manual review
items instead of being silently treated as equivalent.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
import sys
import types
from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence

from plyara.core import Parser, Plyara
from plyara.utils import rebuild_yara_rule


MERGEABLE = 'mergeable'
REISSUE = 'reissue'
MANUAL_REVIEW = 'manual_review'
CONFLICT = 'conflict'


_MISSING = object()
_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_STRING_TERM = re.compile(r'^([$#@!])([A-Za-z0-9_]*)(\*?)$')
_NUMBER = re.compile(r'^(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?)$')

_PUNCTUATION = {
    '(', ')', '[', ']', '{', '}', ',', ':', '.', '\\',
    '==', '=', '!=', '>', '<', '>=', '<=', '+', '-', '*', '/', '%',
    '|', '&', '^', '~', '>>', '<<', '..'
}

_STRING_STRUCTURE = {
    '$': '<string>',
    '#': '<string-count>',
    '@': '<string-offset>',
    '!': '<string-length>',
}


@dataclasses.dataclass(frozen=True)
class StringIdentity:
    """The matching identity of one local string."""

    key: str
    name: str
    type: str
    value: str
    modifiers: tuple[str, ...] = ()
    occurrence: int = 0

    @property
    def body(self) -> tuple[str, str, tuple[str, ...]]:
        """Return the identity fields that are independent of the string name."""
        return self.type, self.value, self.modifiers

    @property
    def digest(self) -> str:
        """Return a stable digest of the full string identity."""
        payload = '\x00'.join((self.name, self.type, self.value, *self.modifiers))
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of the identity."""
        return {
            'key': self.key,
            'name': self.name,
            'type': self.type,
            'value': self.value,
            'modifiers': list(self.modifiers),
            'digest': self.digest,
        }


@dataclasses.dataclass
class ConditionAnalysis:
    """The explainable structure and dependency view of a condition."""

    terms: tuple[str, ...]
    structure: tuple[str, ...]
    string_refs: tuple[str, ...]
    resolved_string_refs: tuple[str, ...]
    wildcard_refs: tuple[str, ...]
    rule_refs: tuple[str, ...]
    module_refs: tuple[str, ...]
    opaque_terms: tuple[str, ...]
    issues: tuple[str, ...]
    uses_all_strings: bool
    digest: str

    @property
    def expression(self) -> str:
        """Return a readable rendering of the condition tokens."""
        return _render_terms(self.terms)

    def dependencies(self) -> frozenset[tuple[str, str]]:
        """Return dependency edges that can be compared across drafts."""
        edges = {('string', name) for name in self.resolved_string_refs}
        edges.update(('string', name) for name in self.string_refs)
        edges.update(('rule', name) for name in self.rule_refs)
        edges.update(('module', name) for name in self.module_refs)
        if self.uses_all_strings:
            edges.add(('string', '$*'))
        return frozenset(edges)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of the analysis."""
        return {
            'terms': list(self.terms),
            'structure': list(self.structure),
            'string_refs': list(self.string_refs),
            'resolved_string_refs': list(self.resolved_string_refs),
            'wildcard_refs': list(self.wildcard_refs),
            'rule_refs': list(self.rule_refs),
            'module_refs': list(self.module_refs),
            'opaque_terms': list(self.opaque_terms),
            'issues': list(self.issues),
            'uses_all_strings': self.uses_all_strings,
            'digest': self.digest,
        }


@dataclasses.dataclass
class Change:
    """One explainable change relative to the approved base."""

    rule: str
    kind: str
    action: str
    side: str
    summary: str
    disposition: str
    reason: str = ''
    detail: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def mergeable(self) -> bool:
        """Return whether the change can be merged without a new signature."""
        return self.disposition == MERGEABLE

    @property
    def requires_reissue(self) -> bool:
        """Return whether the change invalidates the approved rule and needs a reissue."""
        return self.disposition in (REISSUE, CONFLICT)

    @property
    def manual_review(self) -> bool:
        """Return whether a human must adjudicate the change."""
        return self.disposition in (MANUAL_REVIEW, CONFLICT)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of the change."""
        return {
            'rule': self.rule,
            'kind': self.kind,
            'action': self.action,
            'side': self.side,
            'summary': self.summary,
            'disposition': self.disposition,
            'reason': self.reason,
            'mergeable': self.mergeable,
            'requires_reissue': self.requires_reissue,
            'manual_review': self.manual_review,
            'detail': _jsonable(self.detail),
        }

    def __getitem__(self, key: str) -> Any:
        """Expose the serialized form for mapping-style consumers."""
        return self.to_dict()[key]


@dataclasses.dataclass
class ManualReviewItem:
    """One explicit item that the library cannot decide on its own."""

    rule: str | None
    kind: str
    expression: str
    reason: str
    side: str = 'combined'
    detail: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of the item."""
        return {
            'rule': self.rule,
            'kind': self.kind,
            'expression': self.expression,
            'reason': self.reason,
            'side': self.side,
            'detail': _jsonable(self.detail),
        }

    def __getitem__(self, key: str) -> Any:
        """Expose the serialized form for mapping-style consumers."""
        return self.to_dict()[key]


@dataclasses.dataclass
class RuleReview:
    """Review result for one rule name."""

    rule_name: str
    base_present: bool
    left_present: bool
    right_present: bool
    changes: list[Change] = dataclasses.field(default_factory=list)
    manual_review: list[ManualReviewItem] = dataclasses.field(default_factory=list)
    interactions: list[ManualReviewItem] = dataclasses.field(default_factory=list)
    merged_rule: dict[str, Any] | None = None
    merged_text: str | None = None

    @property
    def mergeable(self) -> list[Change]:
        """Return changes that can be merged independently of the approval process."""
        return [change for change in self.changes if change.disposition == MERGEABLE]

    @property
    def reissue(self) -> list[Change]:
        """Return changes that require the rule to be reissued and re-approved."""
        return [change for change in self.changes if change.disposition == REISSUE]

    @property
    def conflicts(self) -> list[Change]:
        """Return changes that the two drafts made differently."""
        return [change for change in self.changes if change.disposition == CONFLICT]

    @property
    def reissue_changes(self) -> list[Change]:
        """Return the alias for changes that require a reissue."""
        return self.reissue

    @property
    def manual_review_items(self) -> list[ManualReviewItem]:
        """Return the alias for explicit human-review items."""
        return self.manual_review

    @property
    def merged(self) -> dict[str, Any] | None:
        """Return the parser-shaped merge preview for this rule."""
        return self.merged_rule

    @property
    def status(self) -> str:
        """Return the most severe review status for the rule."""
        if self.conflicts:
            return CONFLICT
        if self.manual_review:
            return MANUAL_REVIEW
        if self.reissue:
            return 'requires_reissue'
        if self.mergeable:
            return MERGEABLE
        return 'unchanged'

    @property
    def independent_changes(self) -> list[Change]:
        """Return the alias for independently mergeable changes."""
        return self.mergeable

    @property
    def requires_reissue(self) -> bool:
        """Return whether the merged rule needs a new approval or signature."""
        return bool(self.reissue or self.conflicts)

    @property
    def requires_manual_review(self) -> bool:
        """Return whether a human must decide on at least one item."""
        return bool(self.manual_review or self.conflicts)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of the rule review."""
        return {
            'rule_name': self.rule_name,
            'base_present': self.base_present,
            'left_present': self.left_present,
            'right_present': self.right_present,
            'status': self.status,
            'mergeable': [change.to_dict() for change in self.mergeable],
            'independent_changes': [change.to_dict() for change in self.mergeable],
            'reissue': [change.to_dict() for change in self.reissue],
            'reissue_required': [change.to_dict() for change in self.reissue],
            'conflicts': [change.to_dict() for change in self.conflicts],
            'manual_review': [item.to_dict() for item in self.manual_review],
            'manual_review_items': [item.to_dict() for item in self.manual_review],
            'interactions': [item.to_dict() for item in self.interactions],
            'merged_text': self.merged_text,
        }


@dataclasses.dataclass
class ReviewReport:
    """Aggregate three-way review report for a complete ruleset."""

    base_label: str
    left_label: str
    right_label: str
    rule_reviews: dict[str, RuleReview] = dataclasses.field(default_factory=dict)
    parse_errors: list[ManualReviewItem] = dataclasses.field(default_factory=list)
    merged_rules: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    merged_source: str = ''

    @property
    def merged(self) -> dict[str, dict[str, Any]]:
        """Return the parser-shaped merge preview keyed by rule name."""
        return self.merged_rules

    @property
    def merged_text(self) -> str:
        """Return the rebuilt source of the non-conflicting merge preview."""
        return self.merged_source

    @property
    def rules(self) -> list[RuleReview]:
        """Return rule reviews in deterministic rule-name order."""
        return [self.rule_reviews[name] for name in sorted(self.rule_reviews)]

    @property
    def rules_by_name(self) -> dict[str, RuleReview]:
        """Return rule reviews keyed by rule name."""
        return self.rule_reviews

    @property
    def changes(self) -> list[Change]:
        """Return every change from every rule review."""
        return [change for review in self.rules for change in review.changes]

    @property
    def mergeable(self) -> list[Change]:
        """Return every independently mergeable change."""
        return [change for review in self.rules for change in review.mergeable]

    @property
    def mergeable_changes(self) -> list[Change]:
        """Return the alias for independently mergeable changes."""
        return self.mergeable

    @property
    def reissue(self) -> list[Change]:
        """Return every change that requires a reissue."""
        return [change for review in self.rules for change in review.reissue]

    @property
    def conflicts(self) -> list[Change]:
        """Return every conflicting change."""
        return [change for review in self.rules for change in review.conflicts]

    @property
    def manual_review(self) -> list[ManualReviewItem]:
        """Return all explicit human-review items."""
        items = list(self.parse_errors)
        for review in self.rules:
            items.extend(review.manual_review)
        return items

    @property
    def manual_review_items(self) -> list[ManualReviewItem]:
        """Return the alias for explicit human-review items."""
        return self.manual_review

    @property
    def interactions(self) -> list[ManualReviewItem]:
        """Return cross-draft dependency interactions."""
        return [item for review in self.rules for item in review.interactions]

    @property
    def independent_changes(self) -> list[Change]:
        """Return the alias for independently mergeable changes."""
        return self.mergeable

    @property
    def reissue_changes(self) -> list[Change]:
        """Return the alias for changes that require a reissue."""
        return self.reissue

    @property
    def requires_reissue(self) -> bool:
        """Return whether any merged rule needs a new approval or signature."""
        return bool(self.reissue or self.conflicts)

    @property
    def requires_manual_review(self) -> bool:
        """Return whether a human must adjudicate any item."""
        return bool(self.manual_review or self.conflicts)

    @property
    def status(self) -> str:
        """Return the most severe status in the report."""
        statuses = {review.status for review in self.rules}
        if CONFLICT in statuses:
            return CONFLICT
        if self.parse_errors or MANUAL_REVIEW in statuses:
            return MANUAL_REVIEW
        if 'requires_reissue' in statuses:
            return 'requires_reissue'
        if MERGEABLE in statuses:
            return MERGEABLE
        return 'unchanged'

    def get(self, rule_name: str) -> RuleReview | None:
        """Return the review for one rule name, if present."""
        return self.rule_reviews.get(rule_name)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of the report."""
        return {
            'base': self.base_label,
            'left': self.left_label,
            'right': self.right_label,
            'status': self.status,
            'requires_reissue': self.requires_reissue,
            'requires_manual_review': self.requires_manual_review,
            'mergeable': [change.to_dict() for change in self.mergeable],
            'independent_changes': [change.to_dict() for change in self.mergeable],
            'reissue': [change.to_dict() for change in self.reissue],
            'reissue_required': [change.to_dict() for change in self.reissue],
            'conflicts': [change.to_dict() for change in self.conflicts],
            'manual_review': [item.to_dict() for item in self.manual_review],
            'manual_review_items': [item.to_dict() for item in self.manual_review],
            'parse_errors': [item.to_dict() for item in self.parse_errors],
            'interactions': [item.to_dict() for item in self.interactions],
            'rules': {name: self.rule_reviews[name].to_dict() for name in sorted(self.rule_reviews)},
            'merged_source': self.merged_source,
        }


def review_rules(
    base: str,
    left: str,
    right: str,
    *,
    base_label: str = 'base',
    left_label: str = 'left',
    right_label: str = 'right'
) -> ReviewReport:
    """Review two complete drafts against an approved base ruleset.

    Args:
        base: Approved YARA source that acts as the common ancestor.
        left: Complete draft from the first maintainer.
        right: Complete draft from the second maintainer.
        base_label: Human-readable label for the approved source.
        left_label: Human-readable label for the first draft.
        right_label: Human-readable label for the second draft.

    Returns:
        ReviewReport: Mergeable, reissue-required, conflicting, and manual-review results.
    """
    base_index, base_errors = _parse_ruleset(base, base_label)
    left_index, left_errors = _parse_ruleset(left, left_label)
    right_index, right_errors = _parse_ruleset(right, right_label)

    parse_errors = [*base_errors, *left_errors, *right_errors]

    # A side that cannot be parsed has not actually deleted or changed every
    # rule.  Keep it on the approved baseline so that the parse failure remains
    # a single explicit manual item rather than a cascade of false conflicts.
    if any(item.kind == 'parse_error' for item in left_errors):
        left_index = dict(base_index)
    if any(item.kind == 'parse_error' for item in right_errors):
        right_index = dict(base_index)

    base_names = set(base_index)
    left_names = set(left_index)
    right_names = set(right_index)

    left_changed_rules = _semantically_changed_rule_names(base_index, left_index)
    right_changed_rules = _semantically_changed_rule_names(base_index, right_index)

    names = _ordered_union(base_index, left_index, right_index)
    rule_reviews: dict[str, RuleReview] = {}
    merged_rules: dict[str, dict[str, Any]] = {}

    for name in names:
        review = _review_rule(
            name,
            base_index.get(name),
            left_index.get(name),
            right_index.get(name),
            base_names,
            left_names,
            right_names,
            left_changed_rules,
            right_changed_rules,
            base_label,
            left_label,
            right_label,
        )
        rule_reviews[name] = review
        if review.merged_rule is not None:
            merged_rules[name] = review.merged_rule

    merged_source = ''.join(
        f'{rebuild_yara_rule(merged_rules[name])}\n'
        for name in names
        if name in merged_rules
    )

    return ReviewReport(
        base_label=base_label,
        left_label=left_label,
        right_label=right_label,
        rule_reviews=rule_reviews,
        parse_errors=parse_errors,
        merged_rules=merged_rules,
        merged_source=merged_source,
    )


three_way_review = review_rules
review_drafts = review_rules
compare_drafts = review_rules
review = review_rules


class _CallableReviewModule(types.ModuleType):
    """Allow ``plyara.review(...)`` as a shorthand for the review entry point."""

    def __call__(self, base: str, left: str, right: str, **kwargs: Any) -> ReviewReport:
        """Review two drafts against an approved base."""
        return review_rules(base, left, right, **kwargs)


sys.modules[__name__].__class__ = _CallableReviewModule


def _parse_ruleset(source: str, label: str) -> tuple[dict[str, dict[str, Any]], list[ManualReviewItem]]:
    """Parse one ruleset and return an index, retaining parse failures as review items."""
    index: dict[str, dict[str, Any]] = {}
    items: list[ManualReviewItem] = []

    try:
        rules = Plyara().parse_string(source)
    except Exception as exc:  # noqa: BLE001 - the review must retain parser uncertainty
        items.append(ManualReviewItem(
            rule=None,
            kind='parse_error',
            expression=_source_excerpt(source),
            reason=f'{label} could not be parsed by plyara: {exc}',
            side=label,
            detail={'exception': exc.__class__.__name__},
        ))
        return index, items

    for rule in rules:
        name = rule.get('rule_name')
        if name is None:
            items.append(ManualReviewItem(
                rule=None,
                kind='parse_error',
                expression=_source_excerpt(source),
                reason=f'{label} produced a rule without a name',
                side=label,
            ))
            continue
        if 'condition_terms' not in rule:
            items.append(ManualReviewItem(
                rule=name,
                kind='parse_error',
                expression=_source_excerpt(source),
                reason=f'{label} parsed rule {name!r} without a complete condition',
                side=label,
            ))
        if name in index:
            items.append(ManualReviewItem(
                rule=name,
                kind='duplicate_rule',
                expression=name,
                reason=f'{label} defines rule {name!r} more than once; only the first definition is reviewed',
                side=label,
            ))
            continue
        index[name] = rule

    if not rules and re.search(r'\brule\b', source):
        items.append(ManualReviewItem(
            rule=None,
            kind='parse_error',
            expression=_source_excerpt(source),
            reason=f'{label} contained a rule declaration but plyara produced no complete rule',
            side=label,
        ))

    return index, items


def _review_rule(
    name: str,
    base_rule: dict[str, Any] | None,
    left_rule: dict[str, Any] | None,
    right_rule: dict[str, Any] | None,
    base_rule_names: set[str],
    left_rule_names: set[str],
    right_rule_names: set[str],
    left_changed_rule_names: set[str],
    right_changed_rule_names: set[str],
    base_label: str,
    left_label: str,
    right_label: str,
) -> RuleReview:
    """Build the review for one rule across all three versions."""
    if base_rule is None:
        return _review_new_rule(
            name, left_rule, right_rule, base_rule_names | left_rule_names | right_rule_names,
            left_label, right_label
        )

    if left_rule is None or right_rule is None:
        return _review_deleted_rule(
            name, base_rule, left_rule, right_rule, left_label, right_label
        )

    changes: list[Change] = []
    manual: list[ManualReviewItem] = []
    interactions: list[ManualReviewItem] = []

    metadata, metadata_changes, metadata_manual = _merge_metadata(name, base_rule, left_rule, right_rule)
    changes.extend(metadata_changes)
    manual.extend(metadata_manual)

    tags, tag_changes, tag_manual = _merge_tag_set(name, base_rule, left_rule, right_rule, left_label, right_label)
    changes.extend(tag_changes)
    manual.extend(tag_manual)

    scopes, scope_changes, scope_manual = _merge_structural_set(
        name, base_rule, left_rule, right_rule, 'scope', left_label, right_label
    )
    changes.extend(scope_changes)
    manual.extend(scope_manual)

    imports, import_changes, import_manual = _merge_structural_set(
        name, base_rule, left_rule, right_rule, 'import', left_label, right_label
    )
    changes.extend(import_changes)
    manual.extend(import_manual)

    strings, string_changes, string_manual = _merge_strings(
        name, base_rule, left_rule, right_rule, left_label, right_label
    )
    changes.extend(string_changes)
    manual.extend(string_manual)

    condition_terms, condition_changes, condition_manual = _merge_condition(
        name, base_rule, left_rule, right_rule, left_label, right_label
    )
    changes.extend(condition_changes)
    manual.extend(condition_manual)

    base_strings = _string_map(base_rule)
    left_strings = _string_map(left_rule)
    right_strings = _string_map(right_rule)
    base_analysis = _analyze_condition(base_rule.get('condition_terms', []), base_strings, base_rule_names)
    left_analysis = _analyze_condition(left_rule.get('condition_terms', []), left_strings, left_rule_names)
    right_analysis = _analyze_condition(right_rule.get('condition_terms', []), right_strings, right_rule_names)

    deleted_by_both = names_deleted_by_both(base_rule_names, left_rule_names, right_rule_names)
    merged_rule_names = (base_rule_names | left_rule_names | right_rule_names) - deleted_by_both
    merged_analysis = _analyze_condition(condition_terms, strings, merged_rule_names)

    changes.extend(_dependency_changes(
        name, base_analysis, merged_analysis, left_analysis, right_analysis, left_label, right_label
    ))

    interactions.extend(_dependency_interactions(
        name,
        base_rule,
        left_rule,
        right_rule,
        base_analysis,
        left_analysis,
        right_analysis,
        base_strings,
        left_strings,
        right_strings,
        left_changed_rule_names,
        right_changed_rule_names,
        left_label,
        right_label,
    ))
    for interaction in interactions:
        changes.append(Change(
            rule=name,
            kind='dependency',
            action='interaction',
            side='combined',
            summary=f"combined dependency interaction on {interaction.expression!r}",
            disposition=REISSUE,
            reason=interaction.reason,
            detail=interaction.detail,
        ))
    manual.extend(interactions)
    manual.extend(_analysis_manual_items(name, base_analysis, left_analysis, right_analysis, merged_analysis,
                                         base_label, left_label, right_label))

    merged_rule = _build_merged_rule(
        name,
        metadata,
        tags,
        scopes,
        imports,
        strings,
        condition_terms,
        base_rule,
    )

    manual = _dedupe_manual(manual)
    return RuleReview(
        rule_name=name,
        base_present=True,
        left_present=True,
        right_present=True,
        changes=changes,
        manual_review=manual,
        interactions=_dedupe_manual(interactions),
        merged_rule=merged_rule,
        merged_text=rebuild_yara_rule(merged_rule),
    )


def _review_new_rule(
    name: str,
    left_rule: dict[str, Any] | None,
    right_rule: dict[str, Any] | None,
    rule_names: set[str],
    left_label: str,
    right_label: str,
) -> RuleReview:
    """Review a rule that is absent from the approved base."""
    changes: list[Change] = []
    manual: list[ManualReviewItem] = []

    if left_rule is not None and right_rule is not None:
        if _rule_signature(left_rule) == _rule_signature(right_rule):
            chosen = left_rule
            side = 'both'
            summary = f"rule {name!r} added identically by {left_label} and {right_label}"
        else:
            chosen = left_rule
            side = 'both'
            summary = f"rule {name!r} added differently by {left_label} and {right_label}"
            changes.append(Change(
                rule=name,
                kind='rule',
                action='add',
                side=side,
                summary=summary,
                disposition=CONFLICT,
                reason='two new rules share a name but have different content; a human must choose one',
            ))
            manual.append(ManualReviewItem(
                rule=name,
                kind='rule_conflict',
                expression=name,
                reason='both drafts add this rule with different content',
                side='combined',
            ))
    elif left_rule is not None:
        chosen = left_rule
        side = 'left'
        summary = f"rule {name!r} added by {left_label}"
    else:
        chosen = right_rule
        side = 'right'
        summary = f"rule {name!r} added by {right_label}"

    if not any(change.kind == 'rule' for change in changes):
        changes.append(Change(
            rule=name,
            kind='rule',
            action='add',
            side=side,
            summary=summary,
            disposition=REISSUE,
            reason='a new rule has no approved signature and must be issued through the normal approval flow',
        ))

    merged_rule = _build_merged_rule(
        name,
        _metadata_pairs(chosen),
        tuple(chosen.get('tags', [])),
        tuple(chosen.get('scopes', [])),
        tuple(chosen.get('imports', [])),
        _string_map(chosen),
        tuple(chosen.get('condition_terms', [])),
        chosen,
    )

    analysis = _analyze_condition(
        chosen.get('condition_terms', []),
        _string_map(chosen),
        rule_names,
    )
    for issue in analysis.issues:
        manual.append(ManualReviewItem(
            rule=name,
            kind='expression',
            expression=analysis.expression,
            reason=issue,
            side='combined' if side == 'both' else side,
            detail={
                'opaque_terms': list(analysis.opaque_terms),
                'structure': list(analysis.structure),
            },
        ))

    return RuleReview(
        rule_name=name,
        base_present=False,
        left_present=left_rule is not None,
        right_present=right_rule is not None,
        changes=changes,
        manual_review=_dedupe_manual(manual),
        merged_rule=merged_rule,
        merged_text=rebuild_yara_rule(merged_rule),
    )


def _review_deleted_rule(
    name: str,
    base_rule: dict[str, Any],
    left_rule: dict[str, Any] | None,
    right_rule: dict[str, Any] | None,
    left_label: str,
    right_label: str,
) -> RuleReview:
    """Review a rule deleted by one or both drafts."""
    if left_rule is None and right_rule is None:
        change = Change(
            rule=name,
            kind='rule',
            action='remove',
            side='both',
            summary=f"rule {name!r} removed by both drafts",
            disposition=REISSUE,
            reason='removing an approved rule invalidates the approved ruleset',
        )
        return RuleReview(
            rule_name=name,
            base_present=True,
            left_present=False,
            right_present=False,
            changes=[change],
        )

    remaining_rule = left_rule if left_rule is not None else right_rule
    deleting_label = right_label if left_rule is not None else left_label
    deleting_side = 'right' if left_rule is not None else 'left'

    if _rule_signature(remaining_rule) == _rule_signature(base_rule):
        change = Change(
            rule=name,
            kind='rule',
            action='remove',
            side=deleting_side,
            summary=f"rule {name!r} removed by {deleting_label}",
            disposition=REISSUE,
            reason='removing an approved rule invalidates the approved ruleset',
        )
        return RuleReview(
            rule_name=name,
            base_present=True,
            left_present=left_rule is not None,
            right_present=right_rule is not None,
            changes=[change],
        )

    change = Change(
        rule=name,
        kind='rule',
        action='remove',
        side='combined',
        summary=f"rule {name!r} was deleted by one draft and modified by the other",
        disposition=CONFLICT,
        reason='delete-versus-modify requires a human decision',
    )
    manual = ManualReviewItem(
        rule=name,
        kind='delete_modify_conflict',
        expression=name,
        reason=f"{deleting_label} deletes the rule while the other draft modifies it",
        side='combined',
    )
    merged_rule = _build_merged_rule(
        name,
        _metadata_pairs(base_rule),
        tuple(base_rule.get('tags', [])),
        tuple(base_rule.get('scopes', [])),
        tuple(base_rule.get('imports', [])),
        _string_map(base_rule),
        tuple(base_rule.get('condition_terms', [])),
        base_rule,
    )
    return RuleReview(
        rule_name=name,
        base_present=True,
        left_present=left_rule is not None,
        right_present=right_rule is not None,
        changes=[change],
        manual_review=[manual],
        merged_rule=merged_rule,
        merged_text=rebuild_yara_rule(merged_rule),
    )


def _merge_metadata(
    name: str,
    base_rule: dict[str, Any],
    left_rule: dict[str, Any],
    right_rule: dict[str, Any],
) -> tuple[list[tuple[str, Any]], list[Change], list[ManualReviewItem]]:
    """Merge metadata keys; metadata does not require a reissue."""
    base = _metadata_groups(_metadata_pairs(base_rule))
    left = _metadata_groups(_metadata_pairs(left_rule))
    right = _metadata_groups(_metadata_pairs(right_rule))

    keys = _ordered_union(base, left, right)
    merged: dict[str, tuple[Any, ...]] = {}
    changes: list[Change] = []
    manual: list[ManualReviewItem] = []

    for key in keys:
        conflicted = False
        base_value = base.get(key, _MISSING)
        left_value = left.get(key, _MISSING)
        right_value = right.get(key, _MISSING)

        if _metadata_equal(left_value, base_value) and _metadata_equal(right_value, base_value):
            if base_value is not _MISSING:
                merged[key] = base_value
            continue

        if _metadata_equal(left_value, base_value):
            chosen = right_value
            side = 'right'
        elif _metadata_equal(right_value, base_value):
            chosen = left_value
            side = 'left'
        elif _metadata_equal(left_value, right_value):
            chosen = left_value
            side = 'both'
        else:
            chosen = base_value
            conflicted = True
            changes.append(Change(
                rule=name,
                kind='metadata',
                action='conflict',
                side='combined',
                summary=f"metadata key {key!r} was changed differently by both drafts",
                disposition=CONFLICT,
                reason='conflicting metadata requires a human choice; the approved value was retained in the preview',
                detail={
                    'base': _plain_meta(base_value),
                    'left': _plain_meta(left_value),
                    'right': _plain_meta(right_value),
                },
            ))
            manual.append(ManualReviewItem(
                rule=name,
                kind='metadata_conflict',
                expression=f'meta.{key}',
                reason='both drafts set this metadata key to different values',
                side='combined',
                detail={'key': key},
            ))

        if conflicted:
            if chosen is not _MISSING:
                merged[key] = chosen
            continue

        if chosen is _MISSING:
            changes.append(Change(
                rule=name,
                kind='metadata',
                action='remove',
                side=side,
                summary=f"metadata key {key!r} removed by {_side_label(side)}",
                disposition=MERGEABLE,
                reason='metadata does not change rule matching behaviour and can be merged independently',
                detail={
                    'key': key,
                    'base': _plain_meta(base_value),
                    'left': _plain_meta(left_value),
                    'right': _plain_meta(right_value),
                },
            ))
            continue
        merged[key] = chosen

        if base_value is _MISSING:
            action = 'add'
            summary = f"metadata key {key!r} added by {_side_label(side)}"
        elif chosen is _MISSING:
            action = 'remove'
            summary = f"metadata key {key!r} removed by {_side_label(side)}"
        else:
            action = 'modify'
            summary = f"metadata key {key!r} modified by {_side_label(side)}"

        changes.append(Change(
            rule=name,
            kind='metadata',
            action=action,
            side=side,
            summary=summary,
            disposition=MERGEABLE,
            reason='metadata does not change rule matching behaviour and can be merged independently',
            detail={
                'key': key,
                'base': _plain_meta(base_value),
                'left': _plain_meta(left_value),
                'right': _plain_meta(right_value),
            },
        ))

    pairs: list[tuple[str, Any]] = []
    for key in keys:
        if key in merged:
            pairs.extend((key, value) for value in merged[key])
    return pairs, changes, manual


def _merge_tag_set(
    name: str,
    base_rule: dict[str, Any],
    left_rule: dict[str, Any],
    right_rule: dict[str, Any],
    left_label: str,
    right_label: str,
) -> tuple[tuple[str, ...], list[Change], list[ManualReviewItem]]:
    """Merge tags, which are descriptive and independently mergeable."""
    base = set(base_rule.get('tags', []))
    left = set(left_rule.get('tags', []))
    right = set(right_rule.get('tags', []))
    merged, changes, manual = _merge_presence_set(
        name, base, left, right, 'tag', MERGEABLE,
        'tags do not change rule matching behaviour and can be merged independently',
        left_label, right_label,
    )
    return tuple(sorted(merged)), changes, manual


def _merge_structural_set(
    name: str,
    base_rule: dict[str, Any],
    left_rule: dict[str, Any],
    right_rule: dict[str, Any],
    kind: str,
    left_label: str,
    right_label: str,
) -> tuple[tuple[str, ...], list[Change], list[ManualReviewItem]]:
    """Merge scopes or imports, both of which require a reissue when changed."""
    field = 'scopes' if kind == 'scope' else 'imports'
    base = set(base_rule.get(field, []))
    left = set(left_rule.get(field, []))
    right = set(right_rule.get(field, []))
    merged, changes, manual = _merge_presence_set(
        name, base, left, right, kind, REISSUE,
        f'{kind} changes alter the conditions under which the rule is evaluated and require a reissue',
        left_label, right_label,
    )
    return tuple(sorted(merged)), changes, manual


def _merge_presence_set(
    name: str,
    base: set[str],
    left: set[str],
    right: set[str],
    kind: str,
    disposition: str,
    reason: str,
    left_label: str,
    right_label: str,
) -> tuple[set[str], list[Change], list[ManualReviewItem]]:
    """Merge a set of independent indicators."""
    keys = sorted(base | left | right)
    merged: set[str] = set()
    changes: list[Change] = []
    manual: list[ManualReviewItem] = []

    for key in keys:
        conflicted = False
        base_value = key in base
        left_value = key in left
        right_value = key in right

        if left_value == base_value and right_value == base_value:
            if base_value:
                merged.add(key)
            continue

        if left_value == base_value:
            chosen = right_value
            side = 'right'
        elif right_value == base_value:
            chosen = left_value
            side = 'left'
        elif left_value == right_value:
            chosen = left_value
            side = 'both'
        else:
            chosen = base_value
            conflicted = True
            changes.append(Change(
                rule=name,
                kind=kind,
                action='conflict',
                side='combined',
                summary=f"{kind} {key!r} was changed differently by both drafts",
                disposition=CONFLICT,
                reason='conflicting structural changes require a human decision',
                detail={'key': key, 'base': base_value, 'left': left_value, 'right': right_value},
            ))
            manual.append(ManualReviewItem(
                rule=name,
                kind=f'{kind}_conflict',
                expression=key,
                reason=f'{left_label} and {right_label} disagree about this {kind}',
                side='combined',
                detail={'key': key},
            ))

        if conflicted:
            if chosen:
                merged.add(key)
            continue

        if chosen:
            merged.add(key)

        action = 'add' if chosen else 'remove'
        changes.append(Change(
            rule=name,
            kind=kind,
            action=action,
            side=side,
            summary=f"{kind} {key!r} {'added' if chosen else 'removed'} by {_side_label(side)}",
            disposition=disposition,
            reason=reason,
            detail={'key': key, 'base': base_value, 'left': left_value, 'right': right_value},
        ))

    return merged, changes, manual


def _merge_strings(
    name: str,
    base_rule: dict[str, Any],
    left_rule: dict[str, Any],
    right_rule: dict[str, Any],
    left_label: str,
    right_label: str,
) -> tuple[dict[str, StringIdentity], list[Change], list[ManualReviewItem]]:
    """Merge string identities, reissuing on every local identity change."""
    base = _string_map(base_rule)
    left = _string_map(left_rule)
    right = _string_map(right_rule)

    keys = _ordered_union(base, left, right)
    merged: dict[str, StringIdentity] = {}
    manual: list[ManualReviewItem] = []
    conflict_changes: list[Change] = []
    conflict_keys: set[str] = set()

    for key in keys:
        base_value = base.get(key, _MISSING)
        left_value = left.get(key, _MISSING)
        right_value = right.get(key, _MISSING)

        if left_value == base_value and right_value == base_value:
            if base_value is not _MISSING:
                merged[key] = base_value
            continue

        if left_value == base_value:
            chosen = right_value
        elif right_value == base_value:
            chosen = left_value
        elif left_value == right_value:
            chosen = left_value
        else:
            chosen = base_value
            conflict_keys.add(key)
            conflict_changes.append(Change(
                rule=name,
                kind='string',
                action='conflict',
                side='combined',
                summary=f"string {key!r} was changed differently by both drafts",
                disposition=CONFLICT,
                reason=(
                    'conflicting string identities require a human decision; '
                    'the approved string was retained in the preview'
                ),
                detail={
                    'key': key,
                    'base': _identity_detail(base_value),
                    'left': _identity_detail(left_value),
                    'right': _identity_detail(right_value),
                },
            ))
            manual.append(ManualReviewItem(
                rule=name,
                kind='string_conflict',
                expression=key,
                reason='both drafts change the same string identity differently',
                side='combined',
                detail={'key': key},
            ))
            if chosen is not _MISSING:
                merged[key] = chosen
            continue

        if chosen is not _MISSING:
            merged[key] = chosen

    changes = _string_diff_changes(name, base, left, 'left', left_label, conflict_keys)
    changes.extend(_string_diff_changes(name, base, right, 'right', right_label, conflict_keys))
    changes = _collapse_duplicate_changes(changes)
    changes.extend(conflict_changes)

    return merged, changes, manual


def _string_diff_changes(
    name: str,
    base: Mapping[str, StringIdentity],
    side_map: Mapping[str, StringIdentity],
    side: str,
    side_label: str,
    skip_keys: set[str] | None = None,
) -> list[Change]:
    """Explain the string identity changes made by one draft."""
    skip_keys = skip_keys or set()
    removed = [key for key in base if key not in side_map]
    added = [key for key in side_map if key not in base]
    changed = []
    for key in base:
        if key not in side_map or key in skip_keys:
            continue
        if base[key].body != side_map[key].body:
            changed.append(key)

    changes: list[Change] = []
    used_added: set[str] = set()

    for old_key in removed:
        if old_key in skip_keys:
            continue
        old = base[old_key]
        rename_key = None
        for new_key in added:
            if new_key in used_added or new_key in skip_keys:
                continue
            if side_map[new_key].body == old.body:
                rename_key = new_key
                break
        if rename_key is not None:
            used_added.add(rename_key)
            new = side_map[rename_key]
            changes.append(Change(
                rule=name,
                kind='string',
                action='rename',
                side=side,
                summary=f"local string {old.name!r} renamed to {new.name!r} by {side_label}",
                disposition=REISSUE,
                reason='string names are part of the condition-facing identity; a rename requires a reissue',
                detail={'old': old.to_dict(), 'new': new.to_dict()},
            ))
            continue

        changes.append(Change(
            rule=name,
            kind='string',
            action='remove',
            side=side,
            summary=f"local string {old.name!r} removed by {side_label}",
            disposition=REISSUE,
            reason='removing a string identity changes the rule and requires a reissue',
            detail={'old': old.to_dict()},
        ))

    for new_key in added:
        if new_key in used_added or new_key in skip_keys:
            continue
        new = side_map[new_key]
        changes.append(Change(
            rule=name,
            kind='string',
            action='add',
            side=side,
            summary=f"local string {new.name!r} added by {side_label}",
            disposition=REISSUE,
            reason='adding a string identity changes the rule and requires a reissue',
            detail={'new': new.to_dict()},
        ))

    for key in changed:
        old = base[key]
        new = side_map[key]
        details = _identity_differences(old, new)
        changes.append(Change(
            rule=name,
            kind='string',
            action='modify',
            side=side,
            summary=f"local string {old.name!r} identity changed by {side_label}: {details}",
            disposition=REISSUE,
            reason='string value, type, or modifiers are matching semantics; a change requires a reissue',
            detail={'old': old.to_dict(), 'new': new.to_dict(), 'differences': details},
        ))

    return changes


def _collapse_duplicate_changes(changes: list[Change]) -> list[Change]:
    """Collapse identical changes made by both drafts into one `both` change."""
    collapsed: list[Change] = []
    for change in changes:
        signature = _change_signature(change)
        duplicate = next(
            (
                existing for existing in collapsed
                if existing.side != change.side and _change_signature(existing) == signature
            ),
            None,
        )
        if duplicate is None:
            collapsed.append(change)
            continue
        duplicate.side = 'both'
        duplicate.summary = (
            duplicate.summary
            .replace(' by left', ' by both drafts')
            .replace(' by right', ' by both drafts')
        )
    return collapsed


def _merge_condition(
    name: str,
    base_rule: dict[str, Any],
    left_rule: dict[str, Any],
    right_rule: dict[str, Any],
    left_label: str,
    right_label: str,
) -> tuple[tuple[str, ...], list[Change], list[ManualReviewItem]]:
    """Merge the condition as an indivisible semantic unit."""
    base = tuple(base_rule.get('condition_terms', []))
    left = tuple(left_rule.get('condition_terms', []))
    right = tuple(right_rule.get('condition_terms', []))

    if left == base and right == base:
        return base, [], []

    if left == base:
        chosen = right
        side = 'right'
        label = right_label
    elif right == base:
        chosen = left
        side = 'left'
        label = left_label
    elif left == right:
        chosen = left
        side = 'both'
        label = 'both drafts'
    else:
        change = Change(
            rule=name,
            kind='condition',
            action='conflict',
            side='combined',
            summary=f"condition changed differently by {left_label} and {right_label}",
            disposition=CONFLICT,
            reason='both drafts change the condition; a human must choose or re-author it',
            detail={
                'base': list(base),
                'left': list(left),
                'right': list(right),
            },
        )
        manual = ManualReviewItem(
            rule=name,
            kind='condition_conflict',
            expression=_render_terms(left),
            reason=f'{left_label} and {right_label} both changed the condition differently',
            side='combined',
            detail={'base': _render_terms(base), 'left': _render_terms(left), 'right': _render_terms(right)},
        )
        return base, [change], [manual]

    base_analysis = _analyze_condition(base, {}, set())
    chosen_analysis = _analyze_condition(chosen, {}, set())
    structural = base_analysis.structure != chosen_analysis.structure
    added_refs = sorted(set(chosen_analysis.string_refs) - set(base_analysis.string_refs))
    removed_refs = sorted(set(base_analysis.string_refs) - set(chosen_analysis.string_refs))
    details = _condition_difference_summary(base, chosen)

    if structural:
        reason = 'the condition structure changed, so the approved rule must be reissued'
    elif base_analysis.dependencies() != chosen_analysis.dependencies():
        reason = 'the condition dependencies changed, so the approved rule must be reissued'
    else:
        reason = 'the condition literal or operator tokens changed, so the approved rule must be reissued'

    change = Change(
        rule=name,
        kind='condition',
        action='modify',
        side=side,
        summary=f"condition changed by {label}: {details}",
        disposition=REISSUE,
        reason=reason,
        detail={
            'base': _render_terms(base),
            'chosen': _render_terms(chosen),
            'structure_changed': structural,
            'added_string_refs': added_refs,
            'removed_string_refs': removed_refs,
            'added_terms': _added_terms(base, chosen),
            'removed_terms': _removed_terms(base, chosen),
        },
    )
    return chosen, [change], []


def _dependency_changes(
    name: str,
    base_analysis: ConditionAnalysis,
    merged_analysis: ConditionAnalysis,
    left_analysis: ConditionAnalysis,
    right_analysis: ConditionAnalysis,
    left_label: str,
    right_label: str,
) -> list[Change]:
    """Explain dependencies added or removed by the merged result."""
    base_deps = base_analysis.dependencies()
    merged_deps = merged_analysis.dependencies()
    left_deps = left_analysis.dependencies()
    right_deps = right_analysis.dependencies()
    changes: list[Change] = []

    for action, dependencies in (
        ('add', sorted(merged_deps - base_deps)),
        ('remove', sorted(base_deps - merged_deps)),
    ):
        for kind, dependency in dependencies:
            in_left = (kind, dependency) in left_deps
            in_right = (kind, dependency) in right_deps
            if action == 'add':
                side = 'both' if in_left and in_right else ('left' if in_left else 'right')
            else:
                gone_left = (kind, dependency) not in left_deps
                gone_right = (kind, dependency) not in right_deps
                side = 'both' if gone_left and gone_right else ('left' if gone_left else 'right')

            verb = 'added' if action == 'add' else 'removed'
            summary = f"{kind} dependency {dependency!r} {verb} by {_side_label(side)}"
            changes.append(Change(
                rule=name,
                kind='dependency',
                action=action,
                side=side,
                summary=summary,
                disposition=REISSUE,
                reason='changing a condition dependency changes matching behaviour and requires a reissue',
                detail={'dependency_kind': kind, 'dependency': dependency},
            ))

    return changes


def _dependency_interactions(
    name: str,
    base_rule: dict[str, Any],
    left_rule: dict[str, Any],
    right_rule: dict[str, Any],
    base_analysis: ConditionAnalysis,
    left_analysis: ConditionAnalysis,
    right_analysis: ConditionAnalysis,
    base_strings: Mapping[str, StringIdentity],
    left_strings: Mapping[str, StringIdentity],
    right_strings: Mapping[str, StringIdentity],
    left_changed_rule_names: set[str],
    right_changed_rule_names: set[str],
    left_label: str,
    right_label: str,
) -> list[ManualReviewItem]:
    """Find dependencies whose meaning changes only when both drafts are applied."""
    base_deps = base_analysis.dependencies()
    left_added = left_analysis.dependencies() - base_deps
    right_added = right_analysis.dependencies() - base_deps

    left_targets = _changed_targets(
        base_rule, left_rule, base_strings, left_strings, name, left_changed_rule_names
    )
    right_targets = _changed_targets(
        base_rule, right_rule, base_strings, right_strings, name, right_changed_rule_names
    )

    interactions: list[ManualReviewItem] = []
    interactions.extend(_interaction_items(
        name, left_added, right_targets, left_label, right_label, 'left', 'right'
    ))
    interactions.extend(_interaction_items(
        name, right_added, left_targets, right_label, left_label, 'right', 'left'
    ))
    return interactions


def _interaction_items(
    name: str,
    added_dependencies: Iterable[tuple[str, str]],
    targets: set[tuple[str, str]],
    depending_label: str,
    changed_label: str,
    depending_side: str,
    changed_side: str,
) -> list[ManualReviewItem]:
    """Create manual items for newly coupled condition dependencies."""
    items: list[ManualReviewItem] = []
    for dependency in sorted(added_dependencies):
        if dependency in targets:
            kind, value = dependency
            items.append(ManualReviewItem(
                rule=name,
                kind='dependency_interaction',
                expression=value,
                reason=(
                    f"{depending_label} newly makes the condition depend on {kind} {value!r}, "
                    f"while {changed_label} changes that same target; each draft is individually "
                    'explainable, but the combined draft activates a changed dependency and must be re-reviewed'
                ),
                side='combined',
                detail={
                    'dependency_kind': kind,
                    'dependency': value,
                    'depending_side': depending_side,
                    'changed_side': changed_side,
                },
            ))
    return items


def _changed_targets(
    base_rule: dict[str, Any],
    side_rule: dict[str, Any],
    base_strings: Mapping[str, StringIdentity],
    side_strings: Mapping[str, StringIdentity],
    own_rule_name: str,
    changed_rule_names: set[str],
) -> set[tuple[str, str]]:
    """Return the semantic targets changed by one draft."""
    targets: set[tuple[str, str]] = set()

    for key in set(base_strings) | set(side_strings):
        before = base_strings.get(key)
        after = side_strings.get(key)
        if before == after:
            continue
        if before is not None:
            targets.add(('string', before.name))
        if after is not None:
            targets.add(('string', after.name))
        targets.add(('string', '$*'))

    if set(base_rule.get('imports', [])) != set(side_rule.get('imports', [])):
        targets.add(('module', '*'))
        for module in set(base_rule.get('imports', [])) | set(side_rule.get('imports', [])):
            targets.add(('module', module))

    if _semantic_signature(base_rule) != _semantic_signature(side_rule):
        targets.add(('rule', own_rule_name))
    targets.update(('rule', rule_name) for rule_name in changed_rule_names)

    return targets


def _analysis_manual_items(
    name: str,
    base_analysis: ConditionAnalysis,
    left_analysis: ConditionAnalysis,
    right_analysis: ConditionAnalysis,
    merged_analysis: ConditionAnalysis,
    base_label: str,
    left_label: str,
    right_label: str,
) -> list[ManualReviewItem]:
    """Convert unresolved expression issues into explicit manual review items."""
    grouped: dict[tuple[str, str], ManualReviewItem] = {}
    analyses = (
        (base_label, base_analysis),
        (left_label, left_analysis),
        (right_label, right_analysis),
        ('combined', merged_analysis),
    )
    for label, analysis in analyses:
        for issue in analysis.issues:
            key = (issue, analysis.expression)
            if key in grouped:
                grouped[key].side = 'combined'
                continue
            grouped[key] = ManualReviewItem(
                rule=name,
                kind='expression',
                expression=analysis.expression,
                reason=issue,
                side=label,
                detail={
                    'opaque_terms': list(analysis.opaque_terms),
                    'structure': list(analysis.structure),
                },
            )
    return list(grouped.values())


def _analyze_condition(
    terms: Sequence[str],
    strings: Mapping[str, StringIdentity],
    rule_names: set[str],
) -> ConditionAnalysis:
    """Classify a flat condition token stream and extract explainable dependencies."""
    terms = tuple(terms)
    string_names = {identity.name for identity in strings.values() if identity.name != '$'}
    loop_variables = _loop_variables(terms)

    structure: list[str] = []
    string_refs: set[str] = set()
    resolved: set[str] = set()
    wildcard_refs: list[str] = []
    rule_refs: set[str] = set()
    module_refs: set[str] = set()
    opaque: list[str] = []
    issues: list[str] = []
    uses_all_strings = False

    for term in terms:
        if term in ('them', '$*'):
            uses_all_strings = True
            structure.append('<all-strings>')
            if string_names:
                resolved.update(string_names)
            else:
                issues.append(f'all-string reference {term!r} is used but the rule defines no strings')
            continue

        match = _STRING_TERM.match(term)
        if match:
            symbol, base_name, wildcard = match.groups()
            structure.append(_string_structure(symbol, wildcard))
            if not base_name:
                opaque.append(term)
                issues.append(f'string reference {term!r} cannot be resolved statically')
                continue

            canonical = f'${base_name}'
            string_refs.add(canonical)
            if wildcard:
                wildcard_refs.append(term)
                pattern = re.compile('^' + re.escape(base_name) + '.*$')
                matches = sorted(name for name in string_names if pattern.match(name.lstrip('$')))
                if matches:
                    resolved.update(f'${name}' for name in matches)
                else:
                    issues.append(f'wildcard string reference {term!r} matches no defined string')
            elif canonical in string_names:
                resolved.add(canonical)
            else:
                issues.append(f'string reference {term!r} does not resolve to a defined string')
            continue

        if _IDENTIFIER.match(term):
            if term in loop_variables:
                structure.append('<variable>')
            elif term in Parser.KEYWORDS or term in Parser.FUNCTION_KEYWORDS:
                structure.append(term)
            elif term in rule_names:
                rule_refs.add(term)
                structure.append('<rule>')
            else:
                rule_refs.add(term)
                structure.append('<rule>')
                issues.append(
                    f"identifier {term!r} is not defined as a rule in this ruleset; "
                    'it may be an external variable or a missing rule, which cannot be judged statically'
                )
            continue

        if '.' in term:
            prefix = term.split('.', 1)[0]
            if prefix in Parser.IMPORT_OPTIONS:
                module_refs.add(prefix)
                structure.append('<module>')
            else:
                opaque.append(term)
                structure.append('<opaque>')
                issues.append(f"module expression {term!r} uses an unrecognized module and cannot be judged")
            continue

        if _NUMBER.match(term):
            structure.append('<number>')
            continue

        if _is_literal(term):
            structure.append('<literal>')
            continue

        if term in Parser.KEYWORDS or term in Parser.FUNCTION_KEYWORDS or term in _PUNCTUATION:
            structure.append(term)
            continue

        opaque.append(term)
        structure.append('<opaque>')
        issues.append(f'condition term {term!r} cannot be classified statically')

    digest = hashlib.sha256('\x00'.join(terms).encode('utf-8')).hexdigest()
    return ConditionAnalysis(
        terms=terms,
        structure=tuple(structure),
        string_refs=tuple(sorted(string_refs)),
        resolved_string_refs=tuple(sorted(resolved)),
        wildcard_refs=tuple(wildcard_refs),
        rule_refs=tuple(sorted(rule_refs)),
        module_refs=tuple(sorted(module_refs)),
        opaque_terms=tuple(dict.fromkeys(opaque)),
        issues=tuple(dict.fromkeys(issues)),
        uses_all_strings=uses_all_strings,
        digest=digest,
    )


def _loop_variables(terms: Sequence[str]) -> set[str]:
    """Return identifiers bound by `for ... in` loops."""
    variables: set[str] = set()
    for index, term in enumerate(terms):
        if term != 'for':
            continue
        cursor = index + 1
        if cursor < len(terms) and terms[cursor] in ('any', 'all', 'none'):
            cursor += 1
        if cursor < len(terms) and terms[cursor] == 'of':
            continue
        while cursor < len(terms) and terms[cursor] != 'in':
            candidate = terms[cursor]
            if _IDENTIFIER.match(candidate):
                variables.add(candidate)
            cursor += 1
    return variables


def _string_structure(symbol: str, wildcard: str) -> str:
    """Return a structural marker for a string reference."""
    if symbol == '$' and wildcard:
        return '<string-wildcard>'
    return _STRING_STRUCTURE.get(symbol, '<string>')


def _string_map(rule: dict[str, Any]) -> dict[str, StringIdentity]:
    """Normalize a parsed rule's strings into identity records keyed by name occurrence."""
    occurrences: dict[str, int] = defaultdict(int)
    result: dict[str, StringIdentity] = {}
    for entry in rule.get('strings', []):
        name = entry.get('name', '$')
        occurrence = occurrences[name]
        occurrences[name] += 1
        key = name if occurrence == 0 else f'{name}#{occurrence}'
        result[key] = StringIdentity(
            key=key,
            name=name,
            type=entry.get('type', ''),
            value=_normalize_string_value(entry.get('type', ''), entry.get('value', '')),
            modifiers=tuple(sorted(entry.get('modifiers', []))),
            occurrence=occurrence,
        )
    return result


def _normalize_string_value(string_type: str, value: Any) -> str:
    """Normalize values only where YARA treats the source spelling as irrelevant."""
    text = str(value)
    if string_type == 'byte':
        return re.sub(r'\s+', '', text).lower()
    return text


def _metadata_pairs(rule: dict[str, Any]) -> list[tuple[str, Any]]:
    """Flatten the parser's metadata list into ordered key/value pairs."""
    pairs: list[tuple[str, Any]] = []
    for entry in rule.get('metadata', []):
        for key, value in entry.items():
            pairs.append((key, value))
    return pairs


def _metadata_groups(pairs: Sequence[tuple[str, Any]]) -> dict[str, tuple[Any, ...]]:
    """Group repeated metadata keys while preserving their value order."""
    groups: dict[str, list[Any]] = {}
    for key, value in pairs:
        groups.setdefault(key, []).append(value)
    return {key: tuple(values) for key, values in groups.items()}


def _build_merged_rule(
    name: str,
    metadata: Sequence[tuple[str, Any]],
    tags: Sequence[str],
    scopes: Sequence[str],
    imports: Sequence[str],
    strings: Mapping[str, StringIdentity],
    condition_terms: Sequence[str],
    source_rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a parser-shaped rule dictionary for preview and rebuild."""
    result: dict[str, Any] = {
        'rule_name': name,
        'condition_terms': list(condition_terms),
    }
    if metadata:
        result['metadata'] = [{key: value} for key, value in metadata]
    if tags:
        result['tags'] = list(tags)
    if scopes:
        result['scopes'] = list(scopes)
    if imports:
        result['imports'] = list(imports)

    string_entries: list[dict[str, Any]] = []
    for string in strings.values():
        entry: dict[str, Any] = {
            'name': string.name,
            'value': string.value,
            'type': string.type,
        }
        if string.modifiers:
            entry['modifiers'] = list(string.modifiers)
        string_entries.append(entry)
    if string_entries:
        result['strings'] = string_entries

    for key in ('start_line', 'stop_line'):
        if key in source_rule:
            result[key] = source_rule[key]
    return result


def _rule_signature(rule: dict[str, Any]) -> tuple[Any, ...]:
    """Return a canonical whole-rule signature, ignoring source positions."""
    metadata = tuple(sorted((key, _hashable(value)) for key, value in _metadata_pairs(rule)))
    strings = tuple(sorted(
        (key, identity.body) for key, identity in _string_map(rule).items()
    ))
    return (
        metadata,
        tuple(sorted(rule.get('tags', []))),
        tuple(sorted(rule.get('scopes', []))),
        tuple(sorted(rule.get('imports', []))),
        strings,
        tuple(rule.get('condition_terms', [])),
    )


def _semantic_signature(rule: dict[str, Any]) -> tuple[Any, ...]:
    """Return the rule signature without descriptive metadata and tags."""
    return (
        tuple(sorted(rule.get('scopes', []))),
        tuple(sorted(rule.get('imports', []))),
        tuple(sorted((key, identity.body) for key, identity in _string_map(rule).items())),
        tuple(rule.get('condition_terms', [])),
    )


def _semantically_changed_rule_names(
    base_index: Mapping[str, dict[str, Any]],
    side_index: Mapping[str, dict[str, Any]],
) -> set[str]:
    """Return rule names whose matching semantics differ between two versions."""
    changed: set[str] = set()
    for name in set(base_index) | set(side_index):
        before = base_index.get(name)
        after = side_index.get(name)
        if before is None or after is None:
            changed.add(name)
        elif _semantic_signature(before) != _semantic_signature(after):
            changed.add(name)
    return changed


def _hashable(value: Any) -> Any:
    """Make metadata values usable in canonical signatures."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return type(value).__name__, value
    return type(value).__name__, repr(value)


def _metadata_equal(left: Any, right: Any) -> bool:
    """Compare metadata values without treating booleans and integers as equal."""
    if left is _MISSING or right is _MISSING:
        return left is right
    if len(left) != len(right):
        return False
    return all(type(a) is type(b) and a == b for a, b in zip(left, right))


def _identity_differences(before: StringIdentity, after: StringIdentity) -> str:
    """Describe how a string identity changed."""
    differences: list[str] = []
    if before.type != after.type:
        differences.append(f'type {before.type!r} -> {after.type!r}')
    if before.value != after.value:
        differences.append(f'value {before.value!r} -> {after.value!r}')
    if before.modifiers != after.modifiers:
        differences.append(f'modifiers {list(before.modifiers)!r} -> {list(after.modifiers)!r}')
    return '; '.join(differences) or 'identity changed'


def _condition_difference_summary(base: Sequence[str], chosen: Sequence[str]) -> str:
    """Explain the token-level difference between two conditions."""
    added = _added_terms(base, chosen)
    removed = _removed_terms(base, chosen)
    parts: list[str] = []
    if added:
        parts.append(f'added {", ".join(added)}')
    if removed:
        parts.append(f'removed {", ".join(removed)}')
    if not parts:
        parts.append('tokens reordered')
    return '; '.join(parts)


def _added_terms(base: Sequence[str], chosen: Sequence[str]) -> list[str]:
    """Return tokens present only in the chosen condition."""
    remaining = list(base)
    added: list[str] = []
    for term in chosen:
        if term in remaining:
            remaining.remove(term)
        else:
            added.append(term)
    return added


def _removed_terms(base: Sequence[str], chosen: Sequence[str]) -> list[str]:
    """Return tokens present only in the base condition."""
    remaining = list(chosen)
    removed: list[str] = []
    for term in base:
        if term in remaining:
            remaining.remove(term)
        else:
            removed.append(term)
    return removed


def _change_signature(change: Change) -> tuple[Any, ...]:
    """Return a side-independent signature for duplicate collapse."""
    detail = change.detail
    if change.action == 'rename':
        return change.kind, change.action, detail.get('old', {}).get('key'), detail.get('new', {}).get('key')
    if change.action in ('add', 'remove'):
        identity = detail.get('new') or detail.get('old') or {}
        return change.kind, change.action, identity.get('key')
    return change.kind, change.action, detail.get('old', {}).get('key')


def _ordered_union(*mappings: Mapping[Any, Any] | Iterable[Any]) -> list[Any]:
    """Return keys in first-seen order across mappings or iterables."""
    result: list[Any] = []
    seen: set[Any] = set()
    for mapping in mappings:
        iterable = mapping.keys() if isinstance(mapping, Mapping) else mapping
        for key in iterable:
            if key not in seen:
                seen.add(key)
                result.append(key)
    return result


def names_deleted_by_both(base_names: set[str], left_names: set[str], right_names: set[str]) -> set[str]:
    """Return rule names deleted by both drafts."""
    return {name for name in base_names if name not in left_names and name not in right_names}


def _dedupe_manual(items: Iterable[ManualReviewItem]) -> list[ManualReviewItem]:
    """Deduplicate manual review items while preserving order."""
    result: list[ManualReviewItem] = []
    seen: set[tuple[Any, ...]] = set()
    for item in items:
        signature = (item.rule, item.kind, item.expression, item.reason, item.side)
        if signature in seen:
            continue
        seen.add(signature)
        result.append(item)
    return result


def _side_label(side: str) -> str:
    """Return a readable label for a change side."""
    return {
        'left': 'left',
        'right': 'right',
        'both': 'both drafts',
        'combined': 'the combined drafts',
    }.get(side, side)


def _plain_meta(value: Any) -> Any:
    """Make a metadata sentinel value JSON-safe."""
    if value is _MISSING:
        return None
    if isinstance(value, tuple):
        return list(value)
    return value


def _identity_detail(identity: Any) -> dict[str, Any] | None:
    """Return an identity representation or None for a missing string."""
    return None if identity is _MISSING else identity.to_dict()


def _is_literal(term: str) -> bool:
    """Return whether a condition token is a quoted or regular-expression literal."""
    if len(term) >= 2 and term.startswith('"') and term.endswith('"'):
        return True
    if len(term) >= 2 and term.startswith('/') and term.endswith('/'):
        return True
    return False


def _render_terms(terms: Sequence[str]) -> str:
    """Render condition tokens with conservative spacing."""
    return ' '.join(terms)


def _source_excerpt(source: str, limit: int = 240) -> str:
    """Return a short source excerpt for a parse-failure review item."""
    compact = ' '.join(source.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit - 3] + '...'


def _jsonable(value: Any) -> Any:
    """Convert review values into JSON-compatible objects recursively."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if hasattr(value, 'to_dict'):
            return value.to_dict()
        return dataclasses.asdict(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if value is _MISSING:
        return None
    return value
