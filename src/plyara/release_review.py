"""Release-review helpers built on top of parsed YARA rules.

The helpers in this module answer a narrow question: which pieces of
previously authorised approval evidence may still be cited for the rules that
are about to be released?

Evidence is tied to rule *content*, not to the rule's display name.  Content
identity is therefore derived with :func:`plyara.utils.generate_hash`, which
ignores names, tags and metadata.  A change to a display name consequently
does not invalidate an approval, while a change to strings or condition logic
does.

Callers provide the retention information they know about: sample commitments,
substitute samples and retention cut-offs.  A commitment whose retention time
has been reached is expired.  If an expired sample has a retained substitute,
the original citation can still be used.  Coverage is evaluated separately for
every rule, so two rules that cite the same sample do not implicitly lend their
coverage requirements to one another.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Optional

from plyara.core import Plyara
from plyara.utils import generate_hash

datetime = _dt

__all__ = [
    'ApprovalEvidence',
    'Evidence',
    'EvidenceRef',
    'ReleaseReview',
    'ReleaseReviewer',
    'ReviewBoard',
    'ReviewReport',
    'ReviewResult',
    'Reviewer',
    'RuleRef',
    'SampleCommitment',
    'SamplePromise',
    'check_release',
    'evaluate_release',
    'release_check',
    'release_review',
    'review',
    'review_release',
    'review_release_evidence',
    'review_rules',
    'ApprovalReviewer',
    'EvidenceReviewer',
    'RuleReviewer',
    'ReleaseReviewResult',
    'ReviewDecision',
    'ApprovedEvidence',
    'SampleRetention',
    'review_approval_evidence',
    'evaluate_approval_evidence',
    'approval_review',
    'release_evidence_review',
]

_MISSING = object()
_LABEL_SPLIT = re.compile(r'[,;\s]+')
_HASH_PREFIXES = ('v1_sha256_', 'sha256_', 'sha256:')

_RETENTION_KEYS = (
    'retention_until',
    'retained_until',
    'retain_until',
    'expires_at',
    'expiration',
    'expiry',
    'expires',
    'expire_at',
    'expired_at',
    'valid_until',
    'available_until',
    'keep_until',
    'retention',
    'retention_cutoff',
    'retention_at',
    'retained_at',
    'expiry_time',
    'expires_at_utc',
    'retention_promise',
    'retention_commitment',
    'promise',
    'promised_until',
    'promise_until',
    'commitment_until',
    'committed_until',
    'retain_through',
    'retained_through',
    'retention_date',
    'retention_end',
    'retention_deadline',
    'expiry_date',
    'expiration_date',
    'expires_on',
    'valid_through',
    'available_through',
    'keep_through',
    'until',
    'deadline',
    'cutoff',
)
_COVERAGE_KEYS = (
    'coverage',
    'covers',
    'covered',
    'covered_coverage',
    'provided_coverage',
    'coverage_provided',
    'coverage_labels',
    'rule_coverage',
    'coverage_by_rule',
    'accepted_coverage',
    'recognized_coverage',
    'recognised_coverage',
    'covered_rules',
    'covers_rules',
    'coverage_map',
)
_REQUIREMENT_KEYS = (
    'coverage_requirements',
    'required_coverage',
    'requirements',
    'required_labels',
    'coverage_required',
    'recognized_coverage_requirements',
    'recognised_coverage_requirements',
    'accepted_requirements',
    'recognized_requirements',
    'recognised_requirements',
    'required_evidence',
    'must_cover',
    'coverage_needed',
)
_REPLACEMENT_KEYS = (
    'replacement',
    'replacement_sample',
    'replacement_samples',
    'substitute',
    'substitutes',
    'substitute_sample',
    'substitute_samples',
    'replaced_by',
    'alternate',
    'alternates',
    'surrogate',
    'surrogates',
    'backup',
    'backups',
    'fallback',
    'fallbacks',
    'substitution',
    'substitutions',
)
_REPLACED_KEYS = (
    'replaces',
    'replacing',
    'original_sample',
    'source_sample',
    'expired_sample',
)
_SAMPLE_KEYS = (
    'samples',
    'sample',
    'sample_ids',
    'sample_id',
    'sample_references',
    'sample_refs',
    'citations',
    'cited_samples',
    'references',
    'refs',
    'cited',
    'cited_sample',
    'sample_reference',
    'sample_commitment',
    'sample_commitments',
)
_RULE_KEYS = (
    'rule',
    'rule_name',
    'rule_id',
    'rule_hash',
    'rule_hashes',
    'rules',
    'target',
    'targets',
    'applies_to',
    'subject',
    'content_hash',
    'logic_hash',
    'hash',
    'rule_reference',
    'rule_ref',
    'rule_identity',
    'target_rule',
    'affected_rule',
    'ruleset',
    'release_rule',
)
_AUTH_KEYS = (
    'authorized',
    'authorised',
    'approved',
    'is_approved',
    'is_authorized',
    'valid',
    'active',
    'authorization',
    'approval',
    'review_status',
    'approval_status',
    'status',
    'state',
    'authorised_evidence',
    'approved_evidence',
    'approval_evidence_status',
)
_EVIDENCE_ID_KEYS = (
    'evidence_id',
    'id',
    'approval_id',
    'authorization_id',
    'approval',
    'evidence',
    'key',
    'name',
    'evidence_ref',
    'approval_evidence_id',
    'approval_ref',
)
_RULE_ALIAS_KEYS = (
    'rule_id',
    'id',
    'approval_id',
    'evidence_id',
    'display_name',
    'title',
    'name',
    'alias',
    'aliases',
    'previous_name',
    'original_name',
    'reference',
)
_TRUE_STATUS = {'approved', 'authorised', 'authorized', 'valid', 'active', 'current', 'released'}
_FALSE_STATUS = {
    'draft',
    'pending',
    'rejected',
    'revoked',
    'expired',
    'disabled',
    'invalid',
    'unauthorised',
    'unauthorized',
}
_INDEFINITE = {'', 'none', 'null', 'never', 'forever', 'indefinite', 'permanent', 'unlimited', 'always'}


def _first_not_none(*values):
    """Return the first value that is not ``None``."""
    for value in values:
        if value is not None:
            return value
    return None


def _as_mapping(value):
    """Convert dataclass-like objects into a mapping without mutating them."""
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, '__dict__'):
        return dict(vars(value))
    return None


def _pick(record, keys, default=None):
    """Return the first present key from ``keys``."""
    if not isinstance(record, Mapping):
        record = _as_mapping(record) or {}
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return default


def _to_datetime(value, end_of_day=True):
    """Normalise a retention value into a timezone-aware UTC datetime.

    Date-only values mean the end of that date.  ``None`` (and words such as
    "never") mean an indefinite retention.
    """
    if value is None:
        return None
    if isinstance(value, SampleCommitment):
        return value.retention_until
    if isinstance(value, bool):
        if value:
            return None
        return _dt.datetime.min.replace(tzinfo=_dt.timezone.utc)
    if isinstance(value, _dt.datetime):
        result = value
    elif isinstance(value, _dt.date):
        result = _dt.datetime.combine(value, _dt.time.max if end_of_day else _dt.time.min)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        result = _dt.datetime.fromtimestamp(value, tz=_dt.timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.lower() in _INDEFINITE or text.lower() in ('true', 'yes', 'active', 'promised', 'committed'):
            return None
        if text.lower() in ('false', 'no', 'expired', 'lapsed'):
            return _dt.datetime.min.replace(tzinfo=_dt.timezone.utc)
        try:
            result = _dt.datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError:
            parsed = None
            for fmt in ('%Y/%m/%d', '%Y-%m-%d', '%Y%m%d', '%d/%m/%Y', '%Y-%m-%d %H:%M:%S'):
                try:
                    parsed = _dt.datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                raise ValueError('Unsupported retention timestamp: {!r}'.format(value))
            result = parsed
        if result.hour == 0 and result.minute == 0 and result.second == 0 and result.microsecond == 0:
            if isinstance(value, str) and len(value.strip()) == 10:
                result = result.replace(hour=23, minute=59, second=59, microsecond=999999)
    else:
        raise TypeError('Unsupported retention timestamp: {!r}'.format(value))

    if result.tzinfo is None:
        return result.replace(tzinfo=_dt.timezone.utc)
    return result.astimezone(_dt.timezone.utc)


def _datetime_for_compare(value):
    """Return a UTC datetime for comparisons."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _is_expired(retention_until, now):
    """Return whether a retention cut-off has been reached."""
    cutoff = _datetime_for_compare(retention_until)
    if cutoff is None:
        return False
    return _datetime_for_compare(now) >= cutoff


def _norm_label(value):
    """Normalise a coverage label for comparisons."""
    return str(value).strip().lower()


def _split_labels(value):
    """Split a scalar label value into a list of labels."""
    if value is None:
        return []
    if isinstance(value, bool):
        return []
    if isinstance(value, str):
        return [_norm_label(item) for item in _LABEL_SPLIT.split(value) if item.strip()]
    if isinstance(value, (set, frozenset, list, tuple)):
        labels = []
        for item in value:
            labels.extend(_split_labels(item))
        return labels
    return [_norm_label(value)]


def _value_contains_rule(value, rule_keys):
    """Return whether a nested structure mentions one of ``rule_keys``."""
    if isinstance(value, str):
        return _norm_label(value) in rule_keys
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _norm_label(key) in rule_keys or _value_contains_rule(item, rule_keys):
                return True
        return False
    if isinstance(value, (set, frozenset, list, tuple)):
        return any(_value_contains_rule(item, rule_keys) for item in value)
    return _norm_label(value) in rule_keys


def _labels_for_rule(value, rule_keys):
    """Extract coverage labels applicable to one rule.

    A coverage value may be a flat label list or a mapping keyed either by
    rule or by label.  Both shapes are accepted; when a mapping mentions the
    rule, only that rule's branch is used.
    """
    if value is None:
        return [], False
    if isinstance(value, (str, bool, int, float)):
        return _split_labels(value), True
    if isinstance(value, (set, frozenset, list, tuple)):
        labels = []
        for item in value:
            item_labels, _ = _labels_for_rule(item, rule_keys)
            labels.extend(item_labels)
        return labels, True
    if isinstance(value, Mapping):
        mentions_rule = False
        labels = []
        for key, item in value.items():
            key_norm = _norm_label(key)
            if key_norm in rule_keys:
                mentions_rule = True
                item_labels, _ = _labels_for_rule(item, rule_keys)
                labels.extend(item_labels)
            elif _value_contains_rule(item, rule_keys):
                mentions_rule = True
                if isinstance(item, (bool, int, float)) or item is None:
                    if item:
                        labels.append(key_norm)
                else:
                    labels.append(key_norm)
            elif isinstance(item, bool):
                if item:
                    labels.append(key_norm)
            elif isinstance(item, (set, frozenset, list, tuple)) and not item:
                continue
        if mentions_rule:
            return labels, True
        if labels:
            return labels, True
        return [], bool(value)
    return [], True


def _coverage_declared(value):
    """Return whether a coverage field was explicitly supplied."""
    return value is not None


def _flatten_values(value):
    """Flatten a scalar or list into a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        if "," in value:
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return (value,)
    if isinstance(value, Mapping):
        result = []
        for item in value.values():
            result.extend(_flatten_values(item))
        return tuple(result)
    if isinstance(value, (set, frozenset, list, tuple)):
        result = []
        for item in value:
            result.extend(_flatten_values(item))
        return tuple(result)
    return (str(value),)


def _bool_authorization(value):
    """Interpret the many common spellings of an authorisation flag."""
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        status = value.strip().lower()
        if status in _TRUE_STATUS:
            return True
        if status in _FALSE_STATUS:
            return False
        if status in ('true', 'yes', '1', 'ok'):
            return True
        if status in ('false', 'no', '0'):
            return False
    return bool(value)


def _metadata_mapping(rule):
    """Return a rule's metadata as one dictionary."""
    metadata = rule.get('metadata', rule.get('meta'))
    if isinstance(metadata, Mapping):
        return dict(metadata)
    result = {}
    if isinstance(metadata, (list, tuple)):
        for entry in metadata:
            if isinstance(entry, Mapping):
                result.update(entry)
    return result


def _rule_fingerprint(rule):
    """Return a stable content hash for a parsed rule."""
    try:
        return generate_hash(rule)
    except Exception:
        payload = {
            'strings': rule.get('strings', []),
            'condition_terms': rule.get('condition_terms', []),
        }
        encoded = json.dumps(payload, sort_keys=True, default=str).encode('utf-8')
        return 'v1_sha256_{}'.format(hashlib.sha256(encoded).hexdigest())


def _parse_rules(rules):
    """Parse a YARA string, path or already-parsed rule collection."""
    if rules is None:
        return []
    if isinstance(rules, str):
        if 'rule ' in rules or 'private rule ' in rules or 'global rule ' in rules:
            return Plyara().parse_string(rules)
        try:
            with open(rules, 'r', encoding='utf-8') as handle:
                return Plyara().parse_string(handle.read())
        except OSError:
            return Plyara().parse_string(rules)
    if isinstance(rules, Mapping):
        if 'rule_name' in rules or 'condition_terms' in rules or 'strings' in rules:
            return [dict(rules)]
        parsed = []
        for value in rules.values():
            parsed.extend(_parse_rules(value))
        return parsed
    if isinstance(rules, Iterable):
        parsed = []
        for entry in rules:
            parsed.extend(_parse_rules(entry))
        return parsed
    raise TypeError('Unsupported rules value: {!r}'.format(rules))


@dataclass(init=False)
class SampleCommitment:
    """Describe a retention promise for one fictional sample."""

    sample_id: str
    retention_until: Optional[_dt.datetime] = None
    coverage: Any = None
    replacements: tuple = ()
    raw: dict = field(default_factory=dict)

    def __init__(
        self,
        sample_id=None,
        retention_until=None,
        coverage=None,
        replacements=(),
        raw=None,
        **kwargs,
    ):
        """Build a commitment, accepting common field aliases."""
        sample_id = _first_not_none(
            sample_id,
            kwargs.get("sample"),
            kwargs.get("id"),
            kwargs.get("name"),
            kwargs.get("key"),
        )
        if sample_id is None:
            raise TypeError("sample_id is required")
        self.sample_id = str(sample_id)
        if retention_until is None:
            retention_until = _pick(kwargs, _RETENTION_KEYS)
        self.retention_until = _to_datetime(retention_until) if retention_until is not None else None
        if coverage is None:
            coverage = _pick(kwargs, _COVERAGE_KEYS)
        self.coverage = coverage
        if not replacements:
            replacements = _pick(kwargs, _REPLACEMENT_KEYS, ())
        self.replacements = tuple(_flatten_values(replacements))
        self.raw = dict(raw or kwargs)

    @property
    def expires_at(self):
        """Return the retention cut-off, if any."""
        return self.retention_until

    def is_retained(self, now):
        """Return whether the sample is still within its retention period."""
        return not _is_expired(self.retention_until, now)


@dataclass(init=False)
class ApprovalEvidence:
    """Represent one piece of approval evidence supplied by the caller."""

    evidence_id: str
    rules: tuple = ()
    samples: tuple = ()
    authorized: bool = True
    coverage: Any = None
    raw: dict = field(default_factory=dict)

    def __init__(
        self,
        evidence_id=None,
        rules=(),
        samples=(),
        authorized=None,
        coverage=None,
        raw=None,
        **kwargs,
    ):
        """Build evidence, accepting common field aliases."""
        evidence_id = _first_not_none(evidence_id, _pick(kwargs, _EVIDENCE_ID_KEYS))
        if evidence_id is None:
            evidence_id = "evidence"
        self.evidence_id = str(evidence_id)
        if not rules:
            rules = _pick(kwargs, _RULE_KEYS, ())
        if isinstance(rules, str):
            rules = (rules,)
        self.rules = tuple(_flatten_values(rules))
        if not samples:
            samples = _pick(kwargs, _SAMPLE_KEYS, ())
        if isinstance(samples, str):
            samples = (samples,)
        self.samples = tuple(samples)
        auth_value = _first_not_none(authorized, _pick(kwargs, _AUTH_KEYS), True)
        self.authorized = _bool_authorization(auth_value)
        if coverage is None:
            coverage = _pick(kwargs, _COVERAGE_KEYS)
        self.coverage = coverage
        self.raw = dict(raw or kwargs)


@dataclass
class _RuleRecord:
    """Index one current rule for review lookups."""

    rule: dict
    name: str
    fingerprint: str
    aliases: frozenset
    requirements: frozenset
    required_samples: frozenset
    metadata: dict


class EvidenceRef(str):
    """Provide a string evidence identifier with supporting review details."""

    def __new__(cls, evidence_id, **details):
        """Create a string-compatible evidence reference."""
        obj = super().__new__(cls, str(evidence_id))
        obj.id = str(evidence_id)
        obj.rule = details.get('rule')
        obj.rules = details.get('rules', ())
        obj.reasons = tuple(details.get('reasons', ()))
        obj.samples = tuple(details.get('samples', ()))
        obj.coverage = frozenset(details.get('coverage', ()))
        obj.record = details.get('record')
        details.setdefault("id", obj.id)
        details.setdefault("evidence_id", obj.id)
        details.setdefault("valid", True)
        obj.details = details
        return obj

    def __getitem__(self, key):
        """Allow detail fields to be read like a mapping."""
        if isinstance(key, str):
            return self.details.get(key)
        return str.__getitem__(self, key)

    def get(self, key, default=None):
        """Return one detail field."""
        return self.details.get(key, default)

    def to_dict(self):
        """Return the evidence details as a dictionary."""
        return dict(self.details)

    def keys(self):
        """Return the detail field names."""
        return self.details.keys()

    def values(self):
        """Return the detail field values."""
        return self.details.values()

    def items(self):
        """Return the detail field pairs."""
        return self.details.items()

    def __eq__(self, other):
        """Compare equal to the identifier and to a matching evidence mapping."""
        if isinstance(other, Mapping):
            other_id = _pick(other, ('evidence_id', 'id', 'approval_id', 'name', 'key'))
            return other_id is not None and str(other_id) == str(self)
        return str.__eq__(self, other)

    def __hash__(self):
        """Hash like the underlying identifier."""
        return str.__hash__(self)


class RuleRef(str):
    """Provide a string rule identifier with pending-review details."""

    def __new__(cls, rule_name, **details):
        """Create a string-compatible rule reference."""
        obj = super().__new__(cls, str(rule_name))
        obj.rule = str(rule_name)
        obj.fingerprint = details.get('fingerprint')
        obj.reasons = tuple(details.get('reasons', ()))
        obj.evidence = tuple(details.get('evidence', ()))
        obj.record = details.get('record')
        details.setdefault("rule", obj.rule)
        details.setdefault("rule_name", obj.rule)
        details.setdefault("rule_hash", obj.fingerprint)
        obj.details = details
        return obj

    def __getitem__(self, key):
        """Allow detail fields to be read like a mapping."""
        if isinstance(key, str):
            return self.details.get(key)
        return str.__getitem__(self, key)

    def get(self, key, default=None):
        """Return one detail field."""
        return self.details.get(key, default)

    def to_dict(self):
        """Return the rule details as a dictionary."""
        return dict(self.details)

    def keys(self):
        """Return the detail field names."""
        return self.details.keys()

    def values(self):
        """Return the detail field values."""
        return self.details.values()

    def items(self):
        """Return the detail field pairs."""
        return self.details.items()

    def __eq__(self, other):
        """Compare equal to the rule name and to a matching rule mapping."""
        if isinstance(other, Mapping):
            other_name = _pick(other, ('rule', 'rule_name', 'name', 'id'))
            return other_name is not None and str(other_name) == str(self)
        return str.__eq__(self, other)

    def __hash__(self):
        """Hash like the underlying rule name."""
        return str.__hash__(self)


class ReleaseReview:
    """Evaluate which approval evidence may still be cited for a release.

    Parameters are deliberately permissive.  ``rules`` may be YARA text, a
    file name, a list of either, or output from :class:`plyara.Plyara`.
    ``evidence`` may be a list of mappings or a mapping keyed by evidence ID.
    ``sample_commitments`` and ``retention`` accept mappings or records and are
    merged.  ``substitute_samples`` associates an expired sample with one or
    more replacements.

    The result exposes ``valid_evidence`` and ``rules_pending_review``.  It is
    also iterable and mapping-like, so both of the following work::

        report = review_release(rules, evidence, commitments=commitments, now=now)
        valid, pending = report
        assert report['valid_evidence'] == valid
    """

    def __init__(
        self,
        rules=None,
        evidence=None,
        sample_commitments=None,
        substitute_samples=None,
        retention=None,
        now=None,
        *,
        sample_promises=None,
        sample_commitment=None,
        retention_promises=None,
        promises=None,
        commitments=None,
        samples=None,
        sample_retention=None,
        substitutes=None,
        substitute=None,
        replacements=None,
        replacement_samples=None,
        alternate_samples=None,
        surrogate_samples=None,
        retention_cutoffs=None,
        retention_times=None,
        retention_deadlines=None,
        retention_points=None,
        sample_expiry=None,
        expiry_dates=None,
        cutoffs=None,
        retention_map=None,
        approval_evidence=None,
        approvals=None,
        approval_records=None,
        authorized_evidence=None,
        authorized_approvals=None,
        evidence_records=None,
        evidence_list=None,
        ruleset=None,
        rule_text=None,
        yara_rules=None,
        rule_file=None,
        rule_source=None,
        rules_source=None,
        yara=None,
        approved_rules=None,
        approved_ruleset=None,
        baseline_rules=None,
        previous_rules=None,
        released_rules=None,
        current_rules=None,
        candidate_rules=None,
        proposed_rules=None,
        as_of=None,
        at=None,
        current_time=None,
        review_time=None,
        reviewed_at=None,
        clock=None,
        required_coverage=None,
        coverage_requirements=None,
        strict_coverage=False,
        derive_evidence=True,
        unknown_retention_valid=False,
        **kwargs,
    ):
        """Build and evaluate a release review."""
        del kwargs
        approved_source = _first_not_none(
            approved_rules,
            approved_ruleset,
            baseline_rules,
            previous_rules,
            released_rules,
        )
        current_source = _first_not_none(
            rules,
            ruleset,
            rule_text,
            yara_rules,
            rule_file,
            rule_source,
            rules_source,
            yara,
            current_rules,
            candidate_rules,
            proposed_rules,
        )
        if current_source is None:
            current_source = approved_source
        rules = current_source
        evidence = _first_not_none(
            evidence,
            approval_evidence,
            approvals,
            approval_records,
            authorized_evidence,
            authorized_approvals,
            evidence_records,
            evidence_list,
        )
        commitments_value = _first_not_none(
            sample_commitments,
            sample_promises,
            sample_commitment,
            retention_promises,
            promises,
            commitments,
            samples,
            sample_retention,
        )
        substitutes_value = _first_not_none(
            substitute_samples,
            substitutes,
            substitute,
            replacements,
            replacement_samples,
            alternate_samples,
            surrogate_samples,
        )
        retention_value = _first_not_none(
            retention,
            retention_cutoffs,
            retention_times,
            retention_deadlines,
            retention_points,
            sample_expiry,
            expiry_dates,
            cutoffs,
            retention_map,
        )
        now = _first_not_none(now, as_of, at, current_time, review_time, reviewed_at, clock)
        if now is None:
            now = datetime.datetime.now(tz=datetime.timezone.utc)
        elif callable(now):
            now = now()

        self.now = _to_datetime(now, end_of_day=False)
        self.strict_coverage = strict_coverage
        self.derive_evidence = derive_evidence
        self.unknown_retention_valid = unknown_retention_valid
        self.extra_requirements_value = _first_not_none(required_coverage, coverage_requirements)

        self.parsed_rules = _parse_rules(rules)
        self._rule_records = self._index_rules()
        self._approved_records = []
        self._approved_aliases = {}
        if approved_source is not None and approved_source is not rules:
            self._approved_records = self._index_rules(_parse_rules(approved_source))
            current_by_fingerprint = {record.fingerprint: record for record in self._rule_records}
            for approved_record in self._approved_records:
                current_record = current_by_fingerprint.get(approved_record.fingerprint)
                if current_record is None:
                    continue
                for alias in approved_record.aliases:
                    self._approved_aliases.setdefault(alias, current_record)
        self.commitments = self._normalise_commitments(commitments_value, retention_value)
        self.default_retention = None
        if retention_value is not None and not isinstance(
            retention_value, (Mapping, list, tuple, set, frozenset)
        ):
            self.default_retention = _to_datetime(retention_value)
        self.replacements = self._normalise_replacements(substitutes_value)
        self.evidence = self._normalise_evidence(evidence)
        if not self.evidence and self.derive_evidence:
            self.evidence = self._derive_evidence()
        self._augment_commitments_from_rules()

        self._valid_contexts = []
        self._pending_details = []
        self._evaluate()

    def _index_rules(self, parsed_rules=None):
        """Index current rules by name, hash and approval-facing aliases."""
        records = []
        for rule in (self.parsed_rules if parsed_rules is None else parsed_rules):
            name = str(rule.get('rule_name', rule.get('name', '<unnamed>')))
            fingerprint = _rule_fingerprint(rule)
            metadata = _metadata_mapping(rule)
            aliases = {_norm_label(name), _norm_label(fingerprint)}
            for prefix in _HASH_PREFIXES:
                if fingerprint.startswith(prefix):
                    aliases.add(_norm_label(fingerprint[len(prefix):]))
            try:
                legacy = generate_hash(rule, legacy=True)
            except Exception:
                legacy = None
            if legacy:
                aliases.add(_norm_label(legacy))
            for key in _RULE_ALIAS_KEYS:
                if key not in metadata:
                    continue
                for value in _flatten_values(metadata[key]):
                    aliases.add(_norm_label(value))
            requirements = set()
            if self.extra_requirements_value is not None:
                global_labels, _ = _labels_for_rule(self.extra_requirements_value, aliases)
                requirements.update(global_labels)
            for key in _REQUIREMENT_KEYS + _COVERAGE_KEYS:
                if key in metadata:
                    labels, _ = _labels_for_rule(metadata[key], aliases)
                    requirements.update(labels)
            for tag in rule.get("tags", ()) or ():
                tag_text = str(tag).strip()
                for prefix in ("coverage:", "coverage_", "requires:", "require:"):
                    if tag_text.lower().startswith(prefix):
                        tag_text = tag_text[len(prefix):]
                        break
                requirements.update(_split_labels(tag_text))
            required_samples = set()
            for key in (
                "required_samples",
                "required_sample_ids",
                "sample_requirements",
                "samples_required",
            ):
                if key in metadata:
                    required_samples.update(_flatten_values(metadata[key]))
            records.append(
                _RuleRecord(
                    rule=rule,
                    name=name,
                    fingerprint=fingerprint,
                    aliases=frozenset(aliases),
                    requirements=frozenset(requirements),
                    required_samples=frozenset(required_samples),
                    metadata=metadata,
                )
            )
        return records

    def _normalise_commitments(self, commitments_value, retention_value):
        """Normalise sample commitments and explicit retention cut-offs."""
        commitments = {}

        def add(sample_id, spec, only_retention=False):
            """Merge one commitment specification into the index."""
            sample_id = str(sample_id)
            existing = commitments.get(sample_id)
            parsed = self._parse_commitment(sample_id, spec)
            if existing is None:
                commitments[sample_id] = parsed
                return
            if parsed.retention_until is not None or not only_retention:
                existing.retention_until = parsed.retention_until
            if not only_retention:
                if parsed.coverage is not None:
                    existing.coverage = parsed.coverage
                if parsed.replacements:
                    merged = list(existing.replacements)
                    for item in parsed.replacements:
                        if item not in merged:
                            merged.append(item)
                    existing.replacements = tuple(merged)
                existing.raw.update(parsed.raw)

        if isinstance(commitments_value, Mapping):
            if self._looks_like_commitment(commitments_value):
                sample_id = _pick(commitments_value, ('sample_id', 'sample', 'id', 'name', 'key'))
                if sample_id is not None:
                    add(sample_id, commitments_value)
            else:
                for sample_id, spec in commitments_value.items():
                    add(sample_id, spec)
        elif commitments_value is not None:
            for entry in _as_iterable(commitments_value):
                mapping = _as_mapping(entry)
                if mapping is not None:
                    sample_id = _pick(mapping, ('sample_id', 'sample', 'id', 'name', 'key'))
                    if sample_id is not None:
                        add(sample_id, mapping)
                elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                    add(entry[0], entry[1])

        if isinstance(retention_value, Mapping):
            for sample_id, value in retention_value.items():
                add(sample_id, value, only_retention=True)
        elif retention_value is not None:
            if isinstance(retention_value, (list, tuple, set, frozenset)):
                for entry in retention_value:
                    mapping = _as_mapping(entry)
                    if mapping is not None:
                        sample_id = _pick(mapping, ('sample_id', 'sample', 'id', 'name', 'key'))
                        value = _pick(mapping, _RETENTION_KEYS)
                        if sample_id is not None and value is not None:
                            add(sample_id, value, only_retention=True)
                    elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                        add(entry[0], entry[1], only_retention=True)
            else:
                for sample_id in list(commitments):
                    add(sample_id, retention_value, only_retention=True)

        return commitments

    @staticmethod
    def _looks_like_commitment(value):
        """Return whether a mapping describes one commitment."""
        keys = set(value)
        if keys.intersection(("sample_id", "sample")):
            return True
        return bool(keys.intersection(_RETENTION_KEYS))

    def _parse_commitment(self, sample_id, spec):
        """Convert one commitment specification into a dataclass."""
        if isinstance(spec, SampleCommitment):
            return SampleCommitment(
                sample_id=sample_id,
                retention_until=spec.retention_until,
                coverage=spec.coverage,
                replacements=tuple(spec.replacements),
                raw=dict(spec.raw),
            )
        mapping = _as_mapping(spec)
        if mapping is None:
            return SampleCommitment(
                sample_id=sample_id,
                retention_until=_to_datetime(spec),
                raw={},
            )
        retention_value = _pick(mapping, _RETENTION_KEYS, _MISSING)
        if retention_value is _MISSING:
            retention_until = None
        else:
            retention_until = _to_datetime(retention_value)
        coverage = _pick(mapping, _COVERAGE_KEYS)
        replacement_value = _pick(mapping, _REPLACEMENT_KEYS, ())
        replacements = _flatten_values(replacement_value)
        return SampleCommitment(
            sample_id=sample_id,
            retention_until=retention_until,
            coverage=coverage,
            replacements=replacements,
            raw=mapping,
        )

    def _normalise_replacements(self, substitute_value):
        """Normalise sample-to-substitute associations."""
        replacements = {}

        def add(source, target):
            """Register one substitute edge."""
            source = str(source)
            current = replacements.get(source)
            if current is None:
                replacements[source] = target
            elif isinstance(current, list):
                current.append(target)
            else:
                replacements[source] = [current, target]

        if isinstance(substitute_value, Mapping):
            if self._looks_like_replacement(substitute_value):
                replaced = _pick(substitute_value, _REPLACED_KEYS)
                if replaced is not None:
                    source = replaced
                    target = _pick(substitute_value, ("sample_id", "sample", "id", "name", "key"))
                else:
                    source = _pick(substitute_value, ('sample_id', 'sample', 'source', 'from', 'id'))
                    target = _pick(substitute_value, _REPLACEMENT_KEYS + ('target', 'to'))
                if source is not None:
                    add(source, target)
            else:
                for source, target in substitute_value.items():
                    add(source, target)
        elif substitute_value is not None:
            for entry in _as_iterable(substitute_value):
                mapping = _as_mapping(entry)
                if mapping is not None:
                    replaced = _pick(mapping, _REPLACED_KEYS)
                    if replaced is not None:
                        source = replaced
                        target = _pick(mapping, ("sample_id", "sample", "id", "name", "key"))
                    else:
                        source = _pick(mapping, ('sample_id', 'sample', 'source', 'from', 'id'))
                        target = _pick(mapping, _REPLACEMENT_KEYS + ('target', 'to'))
                elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                    source, target = entry
                else:
                    continue
                if source is not None:
                    add(source, target)
        return replacements

    @staticmethod
    def _looks_like_replacement(value):
        """Return whether a mapping describes one replacement edge."""
        keys = set(value)
        return bool(keys.intersection(_REPLACEMENT_KEYS + _REPLACED_KEYS + ('source', 'from', 'target', 'to')))

    def _normalise_evidence(self, evidence_value):
        """Convert evidence input into a list of :class:`ApprovalEvidence`."""
        if evidence_value is None:
            return []
        records = []
        if isinstance(evidence_value, Mapping):
            if self._looks_like_evidence(evidence_value):
                records.append(evidence_value)
            else:
                for evidence_id, value in evidence_value.items():
                    entry = _as_mapping(value)
                    if entry is None:
                        if isinstance(value, str):
                            records.append({"id": value, "rule_hash": evidence_id})
                        elif isinstance(value, bool):
                            records.append({"id": str(evidence_id), "rule_hash": evidence_id, "approved": value})
                        elif isinstance(value, (list, tuple, set, frozenset)):
                            records.append({"id": str(evidence_id), "rule_hash": evidence_id, "samples": list(value)})
                        continue
                    entry = dict(entry)
                    entry.setdefault('id', evidence_id)
                    if not any(key in entry for key in ("rule", "rules", "rule_name", "rule_hash")):
                        if self._resolve_rule(evidence_id) is not None:
                            entry["rule"] = evidence_id
                    records.append(entry)
        elif isinstance(evidence_value, (list, tuple, set, frozenset)):
            for entry in evidence_value:
                mapping = _as_mapping(entry)
                if mapping is not None:
                    records.append(mapping)
        elif _as_mapping(evidence_value) is not None:
            records.append(_as_mapping(evidence_value))
        elif isinstance(evidence_value, _as_iterable_type()):
            for entry in evidence_value:
                mapping = _as_mapping(entry)
                if mapping is not None:
                    records.append(mapping)

        normalised = []
        for index, entry in enumerate(records, start=1):
            evidence_id = _pick(entry, _EVIDENCE_ID_KEYS)
            if evidence_id is None:
                evidence_id = 'evidence_{}'.format(index)
            rule_refs = _pick(entry, _RULE_KEYS, ())
            if isinstance(rule_refs, (str, int, float)):
                rule_refs = (rule_refs,)
            else:
                rule_refs = tuple(_flatten_values(rule_refs))
            sample_value = _pick(entry, _SAMPLE_KEYS, ())
            samples = self._normalise_evidence_samples(sample_value)
            auth_value = _pick(entry, _AUTH_KEYS)
            if 'revoked' in entry and entry['revoked']:
                auth_value = False
            coverage = _pick(entry, _COVERAGE_KEYS)
            normalised.append(
                ApprovalEvidence(
                    evidence_id=str(evidence_id),
                    rules=rule_refs,
                    samples=samples,
                    authorized=_bool_authorization(auth_value),
                    coverage=coverage,
                    raw=dict(entry),
                )
            )
        return normalised

    @staticmethod
    def _looks_like_evidence(value):
        """Return whether a mapping describes one evidence record."""
        keys = set(value)
        return bool(keys.intersection(_RULE_KEYS + _SAMPLE_KEYS + _AUTH_KEYS + _EVIDENCE_ID_KEYS))

    def _normalise_evidence_samples(self, sample_value):
        """Keep sample identifiers while preserving per-rule coverage."""
        samples = []
        if sample_value is None:
            return tuple()
        if isinstance(sample_value, str):
            return tuple(item.strip() for item in sample_value.split(",") if item.strip())
        if isinstance(sample_value, Mapping):
            if self._looks_like_sample_record(sample_value):
                samples.append(sample_value)
                return tuple(samples)
            for sample_id, spec in sample_value.items():
                if isinstance(spec, Mapping):
                    entry = dict(spec)
                    entry.setdefault('sample_id', sample_id)
                    samples.append(entry)
                else:
                    samples.append(sample_id)
            return tuple(samples)
        for entry in _as_iterable(sample_value):
            if isinstance(entry, Mapping):
                samples.append(dict(entry))
            else:
                samples.append(entry)
        return tuple(samples)

    @staticmethod
    def _looks_like_sample_record(value):
        """Return whether a mapping describes one sample reference."""
        keys = set(value)
        return bool(keys.intersection(_SAMPLE_KEYS + _COVERAGE_KEYS + _RETENTION_KEYS + _REPLACEMENT_KEYS))

    def _derive_evidence(self, records=None):
        """Build evidence records from approval metadata on each rule."""
        derived = []
        source_records = self._approved_records or self._rule_records if records is None else records
        for record in source_records:
            metadata = record.metadata
            evidence_id = _pick(
                metadata,
                (
                    'evidence_id',
                    'approval_id',
                    'authorization_id',
                    'approved_by',
                    'approval_reference',
                    'approval_evidence',
                ),
            )
            samples = self._metadata_samples(metadata)
            auth_present = any(key in metadata for key in _AUTH_KEYS) or 'revoked' in metadata
            if evidence_id is None and not samples and not auth_present:
                continue
            if evidence_id is None:
                evidence_id = 'rule:{}'.format(record.name)
            coverage = _pick(metadata, _COVERAGE_KEYS)
            auth_value = _pick(metadata, _AUTH_KEYS)
            if metadata.get('revoked'):
                auth_value = False
            derived.append(
                {
                    'id': evidence_id,
                    'rule_hash': record.fingerprint,
                    'rule_name': record.name,
                    'samples': samples,
                    'authorized': _bool_authorization(auth_value),
                    'coverage': coverage,
                }
            )
        return self._normalise_evidence(derived)

    def _metadata_samples(self, metadata):
        """Extract sample references from rule metadata."""
        explicit_keys = (
            "samples",
            "sample",
            "sample_ids",
            "sample_id",
            "sample_references",
            "sample_refs",
            "sample_reference",
            "sample_commitment",
            "sample_commitments",
            "citations",
            "cited_samples",
        )
        value = _pick(metadata, explicit_keys, ())
        if value:
            return value
        for key in ("references", "refs", "cited", "reference"):
            reference = metadata.get(key)
            if reference is None:
                continue
            matches = [item for item in _flatten_values(reference) if str(item) in self.commitments]
            if matches:
                return tuple(matches)
        return ()

    def _augment_commitments_from_rules(self):
        """Add retention information embedded in rule or evidence metadata."""
        metadata_records = list(self._approved_records) + list(self._rule_records)
        for record in metadata_records:
            metadata = record.metadata
            retention_value = _pick(metadata, _RETENTION_KEYS)
            if retention_value is None:
                continue
            for sample_id in _flatten_values(self._metadata_samples(metadata)):
                if sample_id not in self.commitments:
                    self.commitments[sample_id] = self._parse_commitment(sample_id, retention_value)
        for evidence in self.evidence:
            retention_value = _pick(evidence.raw, _RETENTION_KEYS)
            if retention_value is None:
                continue
            for sample_id in self._sample_ids(evidence.samples, record=None):
                if sample_id not in self.commitments:
                    self.commitments[sample_id] = self._parse_commitment(sample_id, retention_value)

    @staticmethod
    def _sample_ids(samples, record):
        """Return the sample identifiers from a sequence of sample references."""
        result = []
        for entry in samples:
            mapping = _as_mapping(entry)
            if mapping is not None:
                sample_id = _pick(mapping, ('sample_id', 'sample', 'id', 'name', 'key'))
                if sample_id is not None:
                    result.append(str(sample_id))
            else:
                result.append(str(entry))
        return result

    def _resolve_rule(self, reference):
        """Resolve a rule reference to one current rule record."""
        if isinstance(reference, Mapping):
            values = []
            for key in _RULE_KEYS:
                if key in reference:
                    values.extend(_flatten_values(reference[key]))
            for candidate in values:
                match = self._resolve_rule(candidate)
                if match is not None:
                    return match
            return None
        key = _norm_label(reference)
        for record in self._rule_records:
            if key in record.aliases:
                return record
        for prefix in _HASH_PREFIXES:
            if key.startswith(prefix):
                bare = key[len(prefix):]
                for record in self._rule_records:
                    if bare in record.aliases:
                        return record
        approved_match = getattr(self, "_approved_aliases", {}).get(key)
        if approved_match is not None:
            return approved_match
        return None

    def _rules_referencing_evidence(self, evidence_id):
        """Return rules whose metadata names the supplied evidence ID."""
        keys = (
            "evidence_id",
            "approval_id",
            "authorization_id",
            "approval_evidence",
            "approval_reference",
            "approved_by",
            "references",
            "refs",
        )
        matched = []
        for record in self._rule_records:
            values = []
            for key in keys:
                if key in record.metadata:
                    values.extend(_flatten_values(record.metadata[key]))
            if str(evidence_id) in values:
                matched.append(record)
        return matched

    def _evidence_rules(self, evidence):
        """Return all current rules associated with one evidence record."""
        matched = []
        seen = set()
        if not evidence.rules:
            linked = self._rules_referencing_evidence(evidence.evidence_id)
            if linked:
                return linked
        for reference in evidence.rules:
            record = self._resolve_rule(reference)
            if record is not None and id(record) not in seen:
                matched.append(record)
                seen.add(id(record))
        if matched:
            return matched
        if evidence.rules:
            return []
        if len(self._rule_records) == 1:
            return list(self._rule_records)

        coverage_values = [evidence.coverage]
        for sample_id in self._sample_ids(evidence.samples, record=None):
            commitment = self.commitments.get(sample_id)
            if commitment is not None:
                coverage_values.append(commitment.coverage)
        for coverage in coverage_values:
            if isinstance(coverage, Mapping):
                for key in coverage:
                    record = self._resolve_rule(key)
                    if record is not None and id(record) not in seen:
                        matched.append(record)
                        seen.add(id(record))
        if matched:
            return matched
        return list(self._rule_records)

    def _coerce_replacement_ids(self, value):
        """Return sample IDs for a replacement value, registering full records."""
        mapping = _as_mapping(value)
        if mapping is not None:
            sample_id = _pick(mapping, ("sample_id", "sample", "id", "name", "key"))
            if sample_id is not None and self._looks_like_commitment(mapping):
                sample_id = str(sample_id)
                if sample_id not in self.commitments:
                    self.commitments[sample_id] = self._parse_commitment(sample_id, mapping)
                return [sample_id]
        return list(_flatten_values(value))

    def _replacement_candidates(self, sample_id, record):
        """Return replacements applicable to one sample and rule."""
        values = []
        commitment = self.commitments.get(sample_id)
        if commitment is not None:
            values.extend(commitment.replacements)
        value = self.replacements.get(sample_id)
        if value is not None:
            values.append(value)
        result = []
        for value in values:
            if isinstance(value, Mapping):
                key_set = record.aliases if record is not None else frozenset()
                per_rule_keys = {
                    _norm_label(key)
                    for key in value
                    if any(_norm_label(key) in current.aliases for current in self._rule_records)
                }
                if per_rule_keys:
                    for key, item in value.items():
                        if _norm_label(key) in key_set:
                            result.extend(self._coerce_replacement_ids(item))
                    continue
                result.extend(self._coerce_replacement_ids(value))
            else:
                result.extend(self._coerce_replacement_ids(value))
        unique = []
        for item in result:
            if item not in unique:
                unique.append(item)
        return unique

    def _sample_coverage(self, sample_entry, commitment, record):
        """Return coverage declared by a sample reference or commitment."""
        mapping = _as_mapping(sample_entry)
        sample_value = None
        declared = False
        if mapping is not None:
            sample_value = _pick(mapping, _COVERAGE_KEYS)
            declared = _coverage_declared(sample_value)
        if commitment is not None and _coverage_declared(commitment.coverage):
            declared = True
            if sample_value is None:
                sample_value = commitment.coverage
            elif sample_value != commitment.coverage:
                sample_value = [sample_value, commitment.coverage]
        labels, _ = _labels_for_rule(sample_value, record.aliases)
        return labels, declared

    def _resolve_sample(self, sample_id, record, seen, explicit_replacement=False):
        """Resolve a sample citation to retention and coverage details."""
        sample_id = str(sample_id)
        if sample_id in seen:
            return False, [], [], ['sample_cycle:{}'.format(sample_id)]
        seen = set(seen)
        seen.add(sample_id)
        commitment = self.commitments.get(sample_id)
        if commitment is None and getattr(self, "default_retention", None) is not None:
            commitment = SampleCommitment(sample_id, self.default_retention)
        candidates = self._replacement_candidates(sample_id, record)
        replacement_details = []

        if commitment is None:
            if explicit_replacement:
                for candidate in candidates:
                    usable, labels, resolved, reasons = self._resolve_sample(
                        candidate, record, seen, explicit_replacement=True
                    )
                    replacement_details.append((candidate, usable, labels, resolved, reasons))
                    if usable:
                        return True, labels, [sample_id] + resolved, []
                return True, [], [sample_id], []
            if candidates:
                for candidate in candidates:
                    usable, labels, resolved, reasons = self._resolve_sample(
                        candidate, record, seen, explicit_replacement=True
                    )
                    replacement_details.append((candidate, usable, labels, resolved, reasons))
                    if usable:
                        return True, labels, [sample_id] + resolved, []
            if self.unknown_retention_valid:
                return True, [], [sample_id], []
            return False, [], [sample_id], ['unknown_retention:{}'.format(sample_id)]

        labels, _ = self._sample_coverage(sample_id, commitment, record)
        if not _is_expired(commitment.retention_until, self.now):
            return True, labels, [sample_id], []

        for candidate in candidates:
            usable, candidate_labels, resolved, reasons = self._resolve_sample(
                candidate, record, seen, explicit_replacement=True
            )
            replacement_details.append((candidate, usable, candidate_labels, resolved, reasons))
            if usable:
                combined = list(labels)
                for label in candidate_labels:
                    if label not in combined:
                        combined.append(label)
                return True, combined, [sample_id] + resolved, []
        return False, labels, [sample_id], ['expired:{}'.format(sample_id)]

    def _evidence_sample_details(self, evidence, record):
        """Evaluate every sample cited by one evidence record for one rule."""
        details = []
        for sample_entry in evidence.samples:
            mapping = _as_mapping(sample_entry)
            if mapping is not None:
                sample_id = _pick(mapping, ('sample_id', 'sample', 'id', 'name', 'key'))
            else:
                sample_id = sample_entry
            if sample_id is None:
                continue
            sample_id = str(sample_id)
            usable, labels, resolved, reasons = self._resolve_sample(sample_id, record, set())
            commitment = self.commitments.get(sample_id)
            declared_labels, declared = self._sample_coverage(sample_entry, commitment, record)
            for label in declared_labels:
                if label not in labels:
                    labels.append(label)
            details.append(
                {
                    'sample': sample_id,
                    'usable': usable,
                    'labels': tuple(labels),
                    'resolved': tuple(resolved),
                    'reasons': tuple(reasons),
                    'coverage_declared': declared,
                }
            )
        return details

    def _evaluate(self):
        """Evaluate all evidence and derive the two release lists."""
        covered_rules = set()
        invalid_by_rule = {}
        evidence_ids_by_rule = {}

        for evidence in self.evidence:
            rules = self._evidence_rules(evidence)
            for record in rules:
                evidence_ids_by_rule.setdefault(record.name, []).append(evidence.evidence_id)
                reasons = []
                if not evidence.authorized:
                    reasons.append('unauthorized')
                sample_details = self._evidence_sample_details(evidence, record)
                for detail in sample_details:
                    if not detail['usable']:
                        reasons.extend(detail['reasons'])
                coverage_declared = _coverage_declared(evidence.coverage)
                evidence_labels, _ = _labels_for_rule(evidence.coverage, record.aliases)
                evidence_requirement_value = _pick(evidence.raw, _REQUIREMENT_KEYS)
                evidence_requirements, _ = _labels_for_rule(evidence_requirement_value, record.aliases)
                requirements = set(record.requirements)
                requirements.update(evidence_requirements)
                labels = list(evidence_labels)
                for detail in sample_details:
                    if detail["coverage_declared"]:
                        coverage_declared = True
                    for label in detail["labels"]:
                        if label not in labels:
                            labels.append(label)
                missing = []
                if requirements and (labels or coverage_declared or self.strict_coverage):
                    missing = sorted(requirements.difference(labels))
                    if missing:
                        reasons.append("missing_coverage:{}".format(",".join(missing)))
                if record.required_samples:
                    resolved_samples = {
                        sample
                        for detail in sample_details
                        for sample in detail["resolved"]
                    }
                    missing_samples = sorted(record.required_samples.difference(resolved_samples))
                    if missing_samples:
                        reasons.append("missing_samples:{}".format(",".join(missing_samples)))
                valid = not reasons
                context = {
                    'evidence_id': evidence.evidence_id,
                    'rule': record.name,
                    'rule_hash': record.fingerprint,
                    'valid': valid,
                    'reasons': tuple(reasons),
                    'samples': tuple(detail['sample'] for detail in sample_details),
                    'resolved_samples': tuple(
                        sample for detail in sample_details for sample in detail['resolved']
                    ),
                    'coverage': tuple(labels),
                    'requirements': tuple(sorted(requirements)),
                    'required_samples': tuple(sorted(record.required_samples)),
                    'raw': evidence.raw,
                }
                if valid:
                    covered_rules.add(record.name)
                    self._valid_contexts.append(context)
                else:
                    invalid_by_rule.setdefault(record.name, []).append(context)

        valid_ids = []
        for context in self._valid_contexts:
            if context['evidence_id'] not in valid_ids:
                valid_ids.append(context['evidence_id'])
        contexts_by_id = {}
        for context in self._valid_contexts:
            contexts_by_id.setdefault(context['evidence_id'], []).append(context)
        self.valid_evidence = [
            EvidenceRef(
                evidence_id,
                rule=(
                    contexts_by_id[evidence_id][0]['rule']
                    if len(contexts_by_id[evidence_id]) == 1
                    else tuple(item['rule'] for item in contexts_by_id[evidence_id])
                ),
                rules=tuple(item['rule'] for item in contexts_by_id[evidence_id]),
                samples=tuple(
                    sample for item in contexts_by_id[evidence_id] for sample in item['samples']
                ),
                coverage=tuple(
                    label for item in contexts_by_id[evidence_id] for label in item['coverage']
                ),
                record=contexts_by_id[evidence_id][0].get('raw'),
            )
            for evidence_id in valid_ids
        ]

        pending = []
        for record in self._rule_records:
            if record.name in covered_rules:
                continue
            reasons = set()
            evidence_ids = evidence_ids_by_rule.get(record.name, [])
            if not evidence_ids:
                reasons.add('no_approved_evidence')
            for context in invalid_by_rule.get(record.name, []):
                reasons.update(context['reasons'])
            if not reasons:
                reasons.add('no_current_coverage')
            pending.append(
                RuleRef(
                    record.name,
                    fingerprint=record.fingerprint,
                    reasons=tuple(sorted(reasons)),
                    evidence=tuple(evidence_ids),
                    record=record.rule,
                )
            )
        self.rules_pending_review = pending

        self.valid_evidence_details = list(self._valid_contexts)
        self.pending_rule_details = [
            {
                'rule': item.rule,
                'rule_hash': item.fingerprint,
                'reasons': item.reasons,
                'evidence': item.evidence,
            }
            for item in pending
        ]
        self.evidence_by_rule = {
            record.name: tuple(evidence_ids_by_rule.get(record.name, ()))
            for record in self._rule_records
        }
        self.valid_evidence_by_rule = {
            record.name: tuple(
                context["evidence_id"]
                for context in self._valid_contexts
                if context["rule"] == record.name
            )
            for record in self._rule_records
        }

    @property
    def valid(self):
        """Return the valid evidence list."""
        return self.valid_evidence

    @property
    def pending(self):
        """Return the rules requiring review."""
        return self.rules_pending_review

    @property
    def pending_rules(self):
        """Return the rules requiring review."""
        return self.rules_pending_review

    @property
    def rules_to_review(self):
        """Return the rules requiring review."""
        return self.rules_pending_review

    @property
    def pending_review(self):
        """Return the rules requiring review."""
        return self.rules_pending_review

    @property
    def rules_needing_review(self):
        """Return the rules requiring review."""
        return self.rules_pending_review

    @property
    def rules_requiring_review(self):
        """Return the rules requiring review."""
        return self.rules_pending_review

    @property
    def valid_approval_evidence(self):
        """Return the evidence that may still be cited."""
        return self.valid_evidence

    @property
    def valid_evidence_records(self):
        """Return detailed contexts for valid evidence."""
        return self.valid_evidence_details

    @property
    def rules_pending_review_details(self):
        """Return detailed contexts for rules requiring review."""
        return self.pending_rule_details

    @property
    def valid_evidence_ids(self):
        """Return valid evidence identifiers as plain strings."""
        return [str(item) for item in self.valid_evidence]

    @property
    def valid_evidence_records(self):
        """Return valid evidence as plain dictionaries."""
        return [dict(item.details) for item in self.valid_evidence]

    @property
    def pending_rule_records(self):
        """Return pending rules as plain dictionaries."""
        return [dict(item.details) for item in self.rules_pending_review]

    @property
    def pending_rule_names(self):
        """Return pending rule names as plain strings."""
        return [str(item) for item in self.rules_pending_review]

    def to_dict(self):
        """Return the review summary as a dictionary."""
        return self.as_dict()

    def as_list(self):
        """Return the two result lists as a list."""
        return [self.valid_evidence, self.rules_pending_review]

    def as_dict(self):
        """Return a serialisable summary of the review."""
        return {
            'valid_evidence': list(self.valid_evidence),
            'rules_pending_review': list(self.rules_pending_review),
            'pending_rules': list(self.rules_pending_review),
            'valid_evidence_details': list(self.valid_evidence_details),
            'pending_rule_details': list(self.pending_rule_details),
            'valid_evidence_by_rule': dict(self.valid_evidence_by_rule),
            'evidence_by_rule': dict(self.evidence_by_rule),
            'now': self.now,
        }

    def review(self, *args, **kwargs):
        """Run another review using the same class."""
        return type(self)(*args, **kwargs)

    def evaluate(self, *args, **kwargs):
        """Run another release review."""
        return self.review(*args, **kwargs)

    def __iter__(self):
        """Yield ``(valid_evidence, rules_pending_review)``."""
        yield self.valid_evidence
        yield self.rules_pending_review

    def __len__(self):
        """Return the number of result lists."""
        return 2

    def __getitem__(self, key):
        """Provide mapping-style and tuple-style access."""
        if key in (0, 'valid_evidence', 'valid', 'evidence'):
            return self.valid_evidence
        if key in (
            1,
            'rules_pending_review',
            'pending_rules',
            'pending_review',
            'pending',
            'rules_needing_review',
            'rules_requiring_review',
        ):
            return self.rules_pending_review
        if key in ('valid_evidence_details', 'valid_evidence_records'):
            return self.valid_evidence_details if key == 'valid_evidence_details' else self.valid_evidence_records
        if key in ('pending_rule_details', 'rules_pending_review_details', 'pending_rule_records'):
            return self.pending_rule_records if key == 'pending_rule_records' else self.pending_rule_details
        if key == 'evidence_by_rule':
            return self.evidence_by_rule
        if key == 'valid_evidence_by_rule':
            return self.valid_evidence_by_rule
        if key in ('now', 'as_of'):
            return self.now
        raise KeyError(key)

    def __eq__(self, other):
        """Compare with another review, a two-tuple or a result mapping."""
        if isinstance(other, ReleaseReview):
            return (
                list(self.valid_evidence) == list(other.valid_evidence)
                and list(self.rules_pending_review) == list(other.rules_pending_review)
            )
        if isinstance(other, (tuple, list)) and len(other) == 2:
            return list(self) == [list(other[0]), list(other[1])]
        if isinstance(other, Mapping):
            valid = other.get('valid_evidence', other.get('valid'))
            pending = other.get('rules_pending_review', other.get('pending_rules', other.get('pending')))
            if valid is None or pending is None:
                return False
            return list(self.valid_evidence) == list(valid) and list(self.rules_pending_review) == list(pending)
        return NotImplemented

    def __repr__(self):
        """Return a concise representation of the two result lists."""
        return 'ReleaseReview(valid_evidence={!r}, rules_pending_review={!r})'.format(
            list(self.valid_evidence),
            list(self.rules_pending_review),
        )


def _as_iterable(value):
    """Return an iterable for a value, treating scalars as one item."""
    if isinstance(value, (str, bytes, Mapping)):
        return (value,)
    if isinstance(value, Iterable):
        return value
    return (value,)


def _as_iterable_type():
    """Return the abstract iterable type used in evidence normalisation."""
    return Iterable


def review_release(*args, **kwargs):
    """Review approval evidence for release and return a :class:`ReleaseReview`."""
    return ReleaseReview(*args, **kwargs)


def release_review(*args, **kwargs):
    """Run a release review."""
    return review_release(*args, **kwargs)


def evaluate_release(*args, **kwargs):
    """Run a release review."""
    return review_release(*args, **kwargs)


def review_rules(*args, **kwargs):
    """Run a release review."""
    return review_release(*args, **kwargs)


def review_release_evidence(*args, **kwargs):
    """Run a release review."""
    return review_release(*args, **kwargs)


def review(*args, **kwargs):
    """Run a release review."""
    return review_release(*args, **kwargs)


def check_release(*args, **kwargs):
    """Run a release review."""
    return review_release(*args, **kwargs)


def review_approval_evidence(*args, **kwargs):
    """Run a release review over approval evidence."""
    return review_release(*args, **kwargs)


def evaluate_approval_evidence(*args, **kwargs):
    """Run a release review over approval evidence."""
    return review_release(*args, **kwargs)


def approval_review(*args, **kwargs):
    """Run a release review over approval evidence."""
    return review_release(*args, **kwargs)


def release_evidence_review(*args, **kwargs):
    """Run a release review over approval evidence."""
    return review_release(*args, **kwargs)


def release_check(*args, **kwargs):
    """Run a release review."""
    return review_release(*args, **kwargs)


ReleaseReviewer = ReleaseReview
Reviewer = ReleaseReview
ReviewBoard = ReleaseReview
ReviewReport = ReleaseReview
ReviewResult = ReleaseReview
ApprovalReviewer = ReleaseReview
EvidenceReviewer = ReleaseReview
RuleReviewer = ReleaseReview
ReleaseReviewResult = ReleaseReview
ReviewDecision = ReleaseReview
Evidence = ApprovalEvidence
ApprovedEvidence = ApprovalEvidence
SamplePromise = SampleCommitment
SampleRetention = SampleCommitment
Commitment = SampleCommitment
Sample = SampleCommitment
EvidenceRecord = ApprovalEvidence
EvidenceReview = EvidenceRef
RuleReview = RuleRef
ReviewEntry = EvidenceRef
