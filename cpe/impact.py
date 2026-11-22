#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Retraction-aware CPE impact assessment.

The :mod:`cpe` package knows how to parse CPE Names, match a CPE Name against
a set of known names, and evaluate CPE Language expressions.  This module adds
the small but important layer needed when an advisory has been withdrawn:

* an asset is only ``closed`` when a verified replacement is evidenced, or
  when the complete inventory for its family contains no matching CPE;
* a positive CPE match is enough to keep an asset ``still_affected`` even if
  the rest of its installation manifest is incomplete;
* a non-match from an incomplete inventory is never treated as proof of
  absence.  It yields ``insufficient_evidence`` instead;
* a family can only be excluded when the caller supplied complete inventory
  evidence for that family.  Absence of a matching asset is not evidence.

The public objects intentionally use plain Python values and dataclasses so
that they are easy to persist in a review ticket or feed into a report.
"""

from __future__ import absolute_import, unicode_literals

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple
from xml.sax.saxutils import escape as _xml_escape

from .comp.cpecomp import CPEComponent
from .cpe2_3_fs import CPE2_3_FS
from .cpe2_3_uri import CPE2_3_URI
from .cpe2_3_wfn import CPE2_3_WFN
from .cpelang2_3 import CPELanguage2_3
from .cpeset2_3 import CPESet2_3


class AssessmentStatus(str, Enum):
    """The three permitted outcomes of a retraction review."""

    CLOSED = "closed"
    AFFECTED = "affected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

    # Descriptive aliases used by the review wording.
    CONFIRMED_CLOSED = "closed"
    STILL_AFFECTED = "affected"
    MISSING_EVIDENCE = "insufficient_evidence"

    @property
    def label(self):
        """Return the explicit review label for this outcome."""

        return {
            AssessmentStatus.CLOSED: "confirmed_closed",
            AssessmentStatus.AFFECTED: "still_affected",
            AssessmentStatus.INSUFFICIENT_EVIDENCE: "missing_evidence",
        }[self]


class ReasonCode(str, Enum):
    """Machine-readable reasons supporting an assessment."""

    CPE_MATCH = "cpe_match"
    COMPLETE_INVENTORY_NO_MATCH = "complete_inventory_no_match"
    VERIFIED_REPLACEMENT = "verified_replacement"
    HISTORICAL_MATCH = "historical_match"
    INCOMPLETE_MANIFEST = "incomplete_manifest"
    INCOMPLETE_FAMILY_COVERAGE = "incomplete_family_coverage"
    NO_OBSERVATIONS = "no_observations"
    CONDITION_EVALUATION_UNKNOWN = "condition_evaluation_unknown"
    UNVERIFIED_REPLACEMENT = "unverified_replacement"
    REPLACEMENT_TOO_EARLY = "replacement_too_early"
    REPLACEMENT_STILL_AFFECTED = "replacement_still_affected"
    OUTSIDE_APPROVED_SCOPE = "outside_approved_scope"
    FAMILY_EXCLUDED_WITH_PROOF = "family_excluded_with_proof"
    FAMILY_EXCLUSION_UNPROVEN = "family_exclusion_unproven"


@dataclass(frozen=True)
class Reason:
    """A human-readable justification attached to an assessment."""

    code: ReasonCode
    message: str
    evidence: str = ""

    def to_dict(self):
        return {
            "code": self.code.value,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ConditionResult:
    """Result of evaluating an advisory condition.

    ``value`` is ``True`` when the condition is satisfied, ``False`` when it is
    known not to be satisfied, and ``None`` when the available evidence is not
    sufficient to decide.
    """

    value: Optional[bool]
    matches: Tuple[Dict[str, Any], ...] = ()
    reason: str = ""

    @classmethod
    def unknown(cls, reason):
        return cls(None, (), reason)


def _parse_datetime(value):
    """Normalize a date/datetime/ISO-8601 string to an aware UTC datetime."""

    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise TypeError("expected date, datetime, or ISO-8601 string")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_cpe(value):
    """Parse any supported CPE 2.3 representation into a CPE object."""

    if hasattr(value, "VERSION"):
        return value
    if not isinstance(value, str):
        raise TypeError("CPE must be a string or a CPE object")

    text = value.strip()
    parsers = (CPE2_3_FS, CPE2_3_URI, CPE2_3_WFN)
    last_error = None
    for parser in parsers:
        try:
            return parser(text)
        except (ValueError, NotImplementedError) as exc:
            last_error = exc
    raise ValueError("invalid CPE 2.3 name {0!r}: {1}".format(text, last_error))


def _cpe_attribute(value, attribute):
    """Return a normalized scalar CPE attribute from a CPE or string."""

    parsed = _parse_cpe(value)
    values = parsed.get_attribute_values(attribute)
    if not values:
        return ""
    result = values[0]
    if result is None:
        return ""
    text = str(result).strip().strip('"')
    return "" if text.upper() in ("ANY", "NA", "-") else text.lower()


def _cpe_fact_matches(pattern, candidate):
    """Return True when ``candidate`` satisfies the CPE ``pattern``."""

    pattern_wfn = _unbind_cpe(pattern)
    candidate_wfn = _unbind_cpe(candidate)
    return bool(CPESet2_3.cpe_superset(pattern_wfn, candidate_wfn))


def _unbind_cpe(value):
    """Return a WFN object for any bound or WFN CPE 2.3 value."""

    if isinstance(value, CPE2_3_WFN):
        return value
    if hasattr(value, "as_wfn"):
        return CPE2_3_WFN(value.as_wfn())
    return CPELanguage2_3._unbind(value)


def _same_component(left, right):
    """Compare two CPEs as component identities, accepting wildcard patterns."""

    try:
        return _cpe_fact_matches(left, right) or _cpe_fact_matches(right, left)
    except (TypeError, ValueError, NotImplementedError):
        return str(left).strip().lower() == str(right).strip().lower()

def _component_key(value):
    """Return a stable identity for one installed component."""

    try:
        part = _cpe_attribute(value, CPEComponent.ATT_PART)
        vendor = _cpe_attribute(value, CPEComponent.ATT_VENDOR)
        product = _cpe_attribute(value, CPEComponent.ATT_PRODUCT)
        if product:
            return (part, vendor, product)
    except (TypeError, ValueError, NotImplementedError):
        pass
    return ("cpe", str(value).strip().lower())


def _version_key(value):
    """Produce a stable, best-effort sort key for a version string."""

    text = str(value).strip().lower()
    tokens = re.findall(r"[0-9]+|[a-z]+", text)
    return tuple((0, int(token)) if token.isdigit() else (1, token)
                 for token in tokens)


def _version_in_range(version, start_including=None, start_excluding=None,
                      end_including=None, end_excluding=None):
    """Evaluate an NVD-style version interval.

    A missing version is treated as unknown when an interval is supplied.
    """

    if not any((start_including, start_excluding,
                end_including, end_excluding)):
        return True
    if version in (None, "", "*", "-"):
        return None

    key = _version_key(version)
    if start_including is not None and key < _version_key(start_including):
        return False
    if start_excluding is not None and key <= _version_key(start_excluding):
        return False
    if end_including is not None and key > _version_key(end_including):
        return False
    if end_excluding is not None and key >= _version_key(end_excluding):
        return False
    return True


def _normalize_cpe_list(cpes):
    """Return a tuple of CPE strings/objects from a single name or iterable."""

    if cpes is None:
        return ()
    if isinstance(cpes, (str, bytes)) or hasattr(cpes, "VERSION"):
        return (cpes,)
    try:
        return tuple(cpes)
    except TypeError:
        return (cpes,)


def _xml_condition(cpes, operator):
    """Build a small CPE Language XML expression from CPE Names."""

    op = (operator or "OR").upper()
    if op not in ("AND", "OR"):
        raise ValueError("operator must be AND or OR")

    facts = "".join(
        '<cpe:fact-ref name="{0}" />'.format(_xml_escape(str(cpe), {'"': "&quot;"}))
        for cpe in cpes
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cpe:platform-specification '
        'xmlns:cpe="http://cpe.mitre.org/language/2.0">'
        "<cpe:platform><cpe:logical-test operator=\"{0}\" negate=\"FALSE\">"
        "{1}"
        "</cpe:logical-test></cpe:platform>"
        "</cpe:platform-specification>"
    ).format(op, facts)


@dataclass
class Advisory:
    """An advisory condition together with its applicability interval."""

    advisory_id: str
    expression: Any
    applies_from: Optional[datetime] = None
    applies_until: Optional[datetime] = None
    retracted_at: Optional[datetime] = None
    description: str = ""
    expression_format: str = "auto"
    operator: str = "OR"

    def __post_init__(self):
        self.applies_from = _parse_datetime(self.applies_from)
        self.applies_until = _parse_datetime(self.applies_until)
        self.retracted_at = _parse_datetime(self.retracted_at)
        self.expression_format = (self.expression_format or "auto").lower()

    @classmethod
    def from_cpe_names(cls, advisory_id, cpes, operator="OR", **kwargs):
        """Create an advisory from one or more affected CPE Names."""

        normalized = _normalize_cpe_list(cpes)
        if not normalized:
            raise ValueError("an advisory requires at least one CPE Name")
        return cls(
            advisory_id=advisory_id,
            expression=_xml_condition(normalized, operator),
            expression_format="xml",
            operator=operator,
            **kwargs
        )

    def applies_at(self, moment):
        """Return True when ``moment`` is inside the applicability interval."""

        moment = _parse_datetime(moment)
        if moment is None:
            return True
        if self.applies_from is not None and moment < self.applies_from:
            return False
        if self.applies_until is not None and moment >= self.applies_until:
            return False
        return True

    def evaluate(self, known_cpes):
        """Evaluate the advisory against a collection of known CPE Names."""

        known = _normalize_cpe_list(known_cpes)
        fmt = self.expression_format

        if fmt == "auto":
            if isinstance(self.expression, (list, tuple, dict)):
                fmt = "json"
            elif isinstance(self.expression, str) and \
                    self.expression.lstrip().startswith("{"):
                fmt = "json"
            elif isinstance(self.expression, str) and \
                    self.expression.lstrip().startswith("["):
                fmt = "json"
            elif isinstance(self.expression, str) and \
                    self.expression.lower().endswith(".json"):
                fmt = "json"
            elif isinstance(self.expression, str) and \
                    self.expression.lstrip().startswith("<"):
                fmt = "xml"
            elif isinstance(self.expression, str) and \
                    self.expression.lower().endswith(".xml"):
                fmt = "xml"
            else:
                fmt = "cpe-list"

        if fmt == "xml":
            return _evaluate_xml(self.expression, known)
        if fmt == "json":
            return _evaluate_json(self.expression, known)
        return _evaluate_cpe_list(self.expression, known, self.operator)


def _evaluate_xml(expression, known):
    """Evaluate an XML CPE Language expression with the library matcher."""

    try:
        if isinstance(expression, str) and "<" not in expression:
            language = CPELanguage2_3(expression, isFile=True)
        else:
            language = CPELanguage2_3(expression)
    except Exception as exc:  # pragma: no cover - depends on malformed input
        return ConditionResult.unknown("invalid CPE Language expression: {0}".format(exc))

    try:
        cpeset = CPESet2_3()
        for cpe in known:
            cpeset.append(_parse_cpe(cpe))
        result = language.language_match(cpeset)
    except Exception as exc:  # pragma: no cover - depends on malformed input
        return ConditionResult.unknown("CPE Language evaluation failed: {0}".format(exc))

    if result is True:
        matches = tuple({"cpe": str(cpe)} for cpe in known)
        return ConditionResult(True, matches, "CPE Language expression matched")
    if result is False:
        return ConditionResult(False, (), "CPE Language expression did not match")
    return ConditionResult.unknown("CPE Language expression returned an error")


def _evaluate_cpe_list(expression, known, operator="OR"):
    """Evaluate a list of CPE patterns against the known CPE Names."""

    patterns = _normalize_cpe_list(expression)
    if not patterns:
        return ConditionResult(False, (), "empty advisory condition")

    op = (operator or "OR").upper()
    results = []
    matches = []
    for pattern in patterns:
        matched = False
        unknown = False
        for candidate in known:
            try:
                if _cpe_fact_matches(pattern, candidate):
                    matched = True
                    matches.append({"pattern": str(pattern), "cpe": str(candidate)})
            except (TypeError, ValueError, NotImplementedError):
                unknown = True
        results.append(True if matched else (None if unknown else False))

    if op == "AND":
        if any(result is False for result in results):
            value = False
        elif any(result is None for result in results):
            value = None
        else:
            value = True
    else:
        if any(result is True for result in results):
            value = True
        elif any(result is None for result in results):
            value = None
        else:
            value = False

    if value is True:
        return ConditionResult(True, tuple(matches), "advisory CPE condition matched")
    if value is False:
        return ConditionResult(False, (), "advisory CPE condition did not match")
    return ConditionResult.unknown("could not evaluate one or more CPE Names")


@dataclass(frozen=True)
class _NodeResult:
    value: Optional[bool]
    vulnerable: Optional[bool]


def _as_list(value):
    """Return a list for an optional scalar or sequence value."""

    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _json_nodes(expression):
    """Normalize an NVD-style configuration document to a list of nodes."""

    if isinstance(expression, str):
        if expression.lstrip().startswith(("[", "{")):
            document = json.loads(expression)
        else:
            with open(expression, encoding="utf-8") as handle:
                document = json.load(handle)
    else:
        document = expression

    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        if "nodes" in document:
            return _as_list(document["nodes"])
        if "configurations" in document:
            return _as_list(document["configurations"])
        if "children" in document or "cpe_match" in document:
            return [document]
    return []


def _evaluate_json_match(match, known):
    """Evaluate one NVD ``cpe_match`` object against known CPE Names."""

    pattern = match.get("cpe23Uri") or match.get("criteria") or match.get("cpe")
    if not pattern:
        return _NodeResult(None, None)

    vulnerable_value = match.get("vulnerable", True)
    if isinstance(vulnerable_value, str):
        vulnerable = vulnerable_value.strip().lower() not in (
            "false", "0", "no")
    else:
        vulnerable = bool(vulnerable_value)
    ranges = (
        match.get("versionStartIncluding"),
        match.get("versionStartExcluding"),
        match.get("versionEndIncluding"),
        match.get("versionEndExcluding"),
    )

    saw_unknown = False
    for candidate in known:
        try:
            if not _cpe_fact_matches(pattern, candidate):
                continue
            version = _cpe_attribute(candidate, CPEComponent.ATT_VERSION) or None
            in_range = _version_in_range(version, *ranges)
            if in_range is True:
                return _NodeResult(True, vulnerable)
            if in_range is None:
                saw_unknown = True
        except (TypeError, ValueError, NotImplementedError):
            saw_unknown = True

    if saw_unknown:
        return _NodeResult(None, None if vulnerable else False)
    return _NodeResult(False, False)


def _evaluate_json_node(node, known):
    """Evaluate one NVD configuration node with three-valued logic."""

    operator = (node.get("operator") or "OR").upper()
    negate_value = node.get("negate", False)
    if isinstance(negate_value, str):
        negate = negate_value.strip().lower() in ("true", "1", "yes")
    else:
        negate = bool(negate_value)

    parts = [_evaluate_json_match(match, known)
             for match in _as_list(node.get("cpe_match"))]
    parts.extend(_evaluate_json_node(child, known)
                 for child in _as_list(node.get("children")))

    if not parts:
        value = False
        vulnerable = False
    elif operator == "AND":
        if any(part.value is False for part in parts):
            value = False
        elif any(part.value is None for part in parts):
            value = None
        else:
            value = True
        if value is False:
            vulnerable = False
        elif any(part.vulnerable is True for part in parts):
            vulnerable = True if value is True else None
        else:
            vulnerable = False if value is True else None
    else:
        if any(part.value is True for part in parts):
            value = True
        elif any(part.value is None for part in parts):
            value = None
        else:
            value = False
        if any(part.vulnerable is True for part in parts):
            vulnerable = True
        elif any(part.vulnerable is None for part in parts):
            vulnerable = None
        else:
            vulnerable = False

    if negate:
        value = None if value is None else not value
        # A negated fact can satisfy a platform condition, but it does not
        # itself prove that a vulnerable product is present.
        vulnerable = None if value is None else False

    return _NodeResult(value, vulnerable)


def _evaluate_json(expression, known):
    """Evaluate an NVD-style JSON configuration document."""

    try:
        nodes = _json_nodes(expression)
    except (OSError, ValueError, TypeError) as exc:
        return ConditionResult.unknown("invalid JSON advisory expression: {0}".format(exc))

    if not nodes:
        return ConditionResult.unknown("JSON advisory expression has no nodes")

    results = [_evaluate_json_node(node, known) for node in nodes]
    if any(result.vulnerable is True for result in results):
        return ConditionResult(True, (), "JSON advisory condition matched")
    if any(result.vulnerable is None for result in results):
        return ConditionResult.unknown("JSON advisory condition is undecidable")
    return ConditionResult(False, (), "JSON advisory condition did not match")


@dataclass(frozen=True)
class ComponentObservation:
    """A component CPE observed on an asset at a point in time."""

    cpe: str
    observed_at: Optional[datetime] = None
    source: str = ""

    def __post_init__(self):
        object.__setattr__(self, "cpe", str(self.cpe))
        object.__setattr__(self, "observed_at", _parse_datetime(self.observed_at))

    @classmethod
    def coerce(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            return cls(value)
        if isinstance(value, Mapping):
            return cls(**value)
        if isinstance(value, tuple):
            return cls(*value)
        raise TypeError("cannot coerce {0!r} to ComponentObservation".format(value))


@dataclass(frozen=True)
class ReplacementEvidence:
    """Verified evidence that an affected component was replaced."""

    removed_cpe: str
    installed_cpe: str
    replaced_at: Optional[datetime] = None
    evidence_ref: str = ""
    verified: bool = True
    asset_id: Optional[str] = None
    family: Optional[str] = None

    def __post_init__(self):
        object.__setattr__(self, "removed_cpe", str(self.removed_cpe))
        object.__setattr__(self, "installed_cpe", str(self.installed_cpe))
        object.__setattr__(self, "replaced_at", _parse_datetime(self.replaced_at))

    @classmethod
    def coerce(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            return cls(**value)
        raise TypeError("cannot coerce {0!r} to ReplacementEvidence".format(value))


@dataclass(frozen=True)
class Asset:
    """The evidence available for one asset in the caller-approved scope."""

    asset_id: str
    family: str
    observations: Tuple[ComponentObservation, ...] = ()
    manifest_complete: bool = False
    manifest_evidence: str = ""
    replacement_evidence: Tuple[ReplacementEvidence, ...] = ()

    def __post_init__(self):
        observations = self.observations
        if isinstance(observations, (ComponentObservation, Mapping)):
            observations = (observations,)
        object.__setattr__(self, "observations", tuple(
            ComponentObservation.coerce(observation)
            for observation in _normalize_cpe_list(observations)
        ))
        replacement_evidence = self.replacement_evidence
        if isinstance(replacement_evidence, (ReplacementEvidence, Mapping)):
            replacement_evidence = (replacement_evidence,)
        object.__setattr__(self, "replacement_evidence", tuple(
            ReplacementEvidence.coerce(evidence)
            for evidence in (replacement_evidence or ())
        ))


@dataclass(frozen=True)
class FamilyCoverage:
    """Evidence that inventory coverage for one family is exhaustive."""

    family: str
    complete: bool
    evidence: str = ""
    observed_assets: Tuple[str, ...] = ()

    def __post_init__(self):
        observed = self.observed_assets
        if isinstance(observed, str):
            observed = (observed,)
        object.__setattr__(self, "observed_assets", tuple(observed or ()))

    @classmethod
    def coerce(cls, value, family=None):
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            return cls(family=family or "", complete=value)
        if isinstance(value, Mapping):
            data = dict(value)
            data.setdefault("family", family or "")
            return cls(**data)
        raise TypeError("cannot coerce {0!r} to FamilyCoverage".format(value))


@dataclass(frozen=True)
class FamilyExclusion:
    """Decision about excluding an entire asset family from the review."""

    family: str
    excluded: bool
    basis: Reason
    coverage_complete: Optional[bool] = None

    def to_dict(self):
        return {
            "family": self.family,
            "excluded": self.excluded,
            "basis": self.basis.to_dict(),
            "coverage_complete": self.coverage_complete,
        }


@dataclass
class InventoryScope:
    """Caller-approved inventory scope and family coverage evidence."""

    approved_families: Tuple[str, ...] = ()
    coverage: Dict[str, FamilyCoverage] = field(default_factory=dict)
    requested_exclusions: Tuple[str, ...] = ()

    def __post_init__(self):
        approved = self.approved_families
        if isinstance(approved, str):
            approved = (approved,)
        requested = self.requested_exclusions
        if isinstance(requested, str):
            requested = (requested,)
        self.approved_families = tuple(approved or ())
        self.requested_exclusions = tuple(requested or ())
        normalized = {}
        for family, value in (self.coverage or {}).items():
            normalized[family] = FamilyCoverage.coerce(value, family=family)
        self.coverage = normalized

    def approves(self, family):
        return not self.approved_families or family in self.approved_families

    def coverage_for(self, family):
        return self.coverage.get(family)

    def exclusion_decision(self, family):
        """Return a proof-bearing exclusion decision.

        The decision is deliberately based only on explicit family coverage.
        It never infers coverage from a failed CPE match.
        """

        coverage = self.coverage_for(family)
        if coverage is None:
            return FamilyExclusion(
                family=family,
                excluded=False,
                coverage_complete=None,
                basis=Reason(
                    ReasonCode.FAMILY_EXCLUSION_UNPROVEN,
                    "no inventory coverage evidence was supplied for family "
                    "'{0}'".format(family),
                ),
            )
        if not coverage.complete:
            return FamilyExclusion(
                family=family,
                excluded=False,
                coverage_complete=False,
                basis=Reason(
                    ReasonCode.FAMILY_EXCLUSION_UNPROVEN,
                    "inventory coverage for family '{0}' is incomplete; "
                    "a non-match cannot exclude it".format(family),
                    coverage.evidence,
                ),
            )
        return FamilyExclusion(
            family=family,
            excluded=True,
            coverage_complete=True,
            basis=Reason(
                ReasonCode.FAMILY_EXCLUDED_WITH_PROOF,
                "inventory coverage for family '{0}' is complete".format(family),
                coverage.evidence,
            ),
        )


@dataclass(frozen=True)
class MatchEvidence:
    """A specific observation that satisfied the advisory condition."""

    cpe: str
    observed_at: Optional[datetime]
    source: str = ""
    within_applicability_window: bool = False

    def to_dict(self):
        return {
            "cpe": self.cpe,
            "observed_at": _iso(self.observed_at),
            "source": self.source,
            "within_applicability_window": self.within_applicability_window,
        }


@dataclass
class AssetAssessment:
    """Outcome and supporting evidence for one asset."""

    asset_id: str
    family: str
    status: AssessmentStatus
    reasons: Tuple[Reason, ...]
    matches: Tuple[MatchEvidence, ...]
    latest_match: Optional[MatchEvidence]
    manifest_complete: bool
    family_coverage_complete: Optional[bool]
    replacement_evidence: Optional[ReplacementEvidence] = None
    observations_considered: Tuple[ComponentObservation, ...] = ()

    @property
    def basis(self):
        return tuple(reason.code.value for reason in self.reasons)

    @property
    def status_label(self):
        return self.status.label

    @property
    def rationale(self):
        return self.reasons

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "family": self.family,
            "status": self.status.value,
            "status_label": self.status.label,
            "basis": list(self.basis),
            "reasons": [reason.to_dict() for reason in self.reasons],
            "matches": [match.to_dict() for match in self.matches],
            "latest_match": self.latest_match.to_dict()
            if self.latest_match else None,
            "manifest_complete": self.manifest_complete,
            "family_coverage_complete": self.family_coverage_complete,
            "replacement_evidence": _jsonable(self.replacement_evidence),
            "observations_considered": [
                {
                    "cpe": observation.cpe,
                    "observed_at": _iso(observation.observed_at),
                    "source": observation.source,
                }
                for observation in self.observations_considered
            ],
        }


@dataclass
class ImpactReport:
    """A complete, reviewable result for one advisory retraction."""

    advisory: Advisory
    as_of: datetime
    scope: InventoryScope
    assessments: Tuple[AssetAssessment, ...]
    exclusions: Tuple[FamilyExclusion, ...] = ()
    excluded_assets: Tuple[str, ...] = ()

    @property
    def assets(self):
        return self.assessments

    @property
    def summary(self):
        counts = {status.value: 0 for status in AssessmentStatus}
        for assessment in self.assessments:
            counts[assessment.status.value] += 1
        return counts

    @property
    def status_counts(self):
        return self.summary

    @property
    def summary_by_label(self):
        return {
            "confirmed_closed": self.summary["closed"],
            "still_affected": self.summary["affected"],
            "missing_evidence": self.summary["insufficient_evidence"],
        }

    @property
    def provable_scope(self):
        result = {
            "confirmed_closed": [],
            "still_affected": [],
            "missing_evidence": [],
            "excluded_families": [],
            "unproven_exclusions": [],
        }
        for assessment in self.assessments:
            result[assessment.status.label].append(assessment.asset_id)
        result["insufficient_evidence"] = result["missing_evidence"]
        for exclusion in self.exclusions:
            if exclusion.excluded:
                result["excluded_families"].append(exclusion.family)
            else:
                result["unproven_exclusions"].append(exclusion.family)
        return result

    def to_dict(self):
        return {
            "advisory": {
                "advisory_id": self.advisory.advisory_id,
                "description": self.advisory.description,
                "applies_from": _iso(self.advisory.applies_from),
                "applies_until": _iso(self.advisory.applies_until),
                "retracted_at": _iso(self.advisory.retracted_at),
            },
            "as_of": _iso(self.as_of),
            "scope": {
                "approved_families": list(self.scope.approved_families),
                "requested_exclusions": list(self.scope.requested_exclusions),
                "coverage": {
                    family: {
                        "complete": coverage.complete,
                        "evidence": coverage.evidence,
                        "observed_assets": list(coverage.observed_assets),
                    }
                    for family, coverage in sorted(self.scope.coverage.items())
                },
            },
            "summary": self.summary,
            "summary_by_label": self.summary_by_label,
            "provable_scope": self.provable_scope,
            "excluded_assets": list(self.excluded_assets),
            "family_exclusions": [
                exclusion.to_dict() for exclusion in self.exclusions
            ],
            "assets": [assessment.to_dict() for assessment in self.assessments],
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self):
        lines = [
            "# Advisory retraction impact review",
            "",
            "- Advisory: `{0}`".format(self.advisory.advisory_id),
            "- As of: `{0}`".format(_iso(self.as_of)),
            "- Advisory interval: `{0}` to `{1}`".format(
                _iso(self.advisory.applies_from) or "unbounded",
                _iso(self.advisory.applies_until) or "unbounded",
            ),
            "- Retracted at: `{0}`".format(
                _iso(self.advisory.retracted_at) or "not recorded"
            ),
            "",
            "## Provable scope",
            "",
            "| Outcome | Assets |",
            "| --- | --- |",
            "| Confirmed closed | {0} |".format(
                ", ".join(self.provable_scope["confirmed_closed"]) or "-"
            ),
            "| Still affected | {0} |".format(
                ", ".join(self.provable_scope["still_affected"]) or "-"
            ),
            "| Insufficient evidence | {0} |".format(
                ", ".join(self.provable_scope["missing_evidence"]) or "-"
            ),
            "| Excluded families | {0} |".format(
                ", ".join(self.provable_scope["excluded_families"]) or "-"
            ),
            "| Exclusion not proven | {0} |".format(
                ", ".join(self.provable_scope["unproven_exclusions"]) or "-"
            ),
            "",
            "## Asset assessments",
            "",
        ]
        for assessment in self.assessments:
            lines.extend([
                "### `{0}` ({1})".format(assessment.asset_id, assessment.family),
                "",
                "- Status: **{0}**".format(assessment.status.label),
            ])
            for reason in assessment.reasons:
                evidence = " ({0})".format(reason.evidence) if reason.evidence else ""
                lines.append("- {0}: {1}{2}".format(
                    reason.code.value, reason.message, evidence))
            if assessment.matches:
                lines.append("- Observed matches: {0}".format(", ".join(
                    "`{0}` at `{1}`".format(
                        match.cpe, _iso(match.observed_at))
                    for match in assessment.matches
                )))
            lines.append("")
        if self.exclusions:
            lines.extend(["## Family exclusions", ""])
            for exclusion in self.exclusions:
                lines.append("- `{0}`: {1} — {2}".format(
                    exclusion.family,
                    "excluded" if exclusion.excluded else "not excluded",
                    exclusion.basis.message,
                ))
            lines.append("")
        return "\n".join(lines)


def _iso(value):
    return value.isoformat() if value is not None else None


def _jsonable(value):
    if value is None:
        return None
    if isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "__dict__"):
        return {
            key: _jsonable(item)
            for key, item in value.__dict__.items()
            if not key.startswith("_")
        }
    return str(value)


class RetractionImpactAnalyzer:
    """Assess an asset inventory against a withdrawn advisory."""

    def __init__(self, advisory, scope, replacement_evidence=None, as_of=None):
        self.advisory = advisory
        self.scope = scope
        self.as_of = _parse_datetime(as_of) or datetime.now(timezone.utc)
        self.replacement_evidence = tuple(
            ReplacementEvidence.coerce(evidence)
            for evidence in (replacement_evidence or ())
        )

    def assess(self, assets):
        assets = tuple(assets or ())
        exclusions = tuple(
            self.scope.exclusion_decision(family)
            for family in self.scope.requested_exclusions
        )
        excluded = {
            exclusion.family for exclusion in exclusions if exclusion.excluded
        }

        assessments = []
        excluded_assets = []
        for asset in assets:
            if asset.family in excluded:
                excluded_assets.append(asset.asset_id)
                continue
            assessments.append(self._assess_asset(asset))

        return ImpactReport(
            advisory=self.advisory,
            as_of=self.as_of,
            scope=self.scope,
            assessments=tuple(assessments),
            exclusions=exclusions,
            excluded_assets=tuple(excluded_assets),
        )

    def _assess_asset(self, asset):
        reasons = []
        coverage = self.scope.coverage_for(asset.family)
        coverage_complete = coverage.complete if coverage is not None else None

        if not self.scope.approves(asset.family):
            reasons.append(Reason(
                ReasonCode.OUTSIDE_APPROVED_SCOPE,
                "family '{0}' is outside the caller-approved inventory "
                "scope".format(asset.family),
            ))
            return self._assessment(
                asset, AssessmentStatus.INSUFFICIENT_EVIDENCE, reasons, (), None,
                coverage_complete, None,
            )

        observations = tuple(sorted(
            (
                observation for observation in asset.observations
                if observation.observed_at is None or observation.observed_at <= self.as_of
            ),
            key=lambda observation: observation.observed_at or datetime.min.replace(
                tzinfo=timezone.utc),
        ))

        if not observations:
            if asset.manifest_complete:
                reasons.append(Reason(
                    ReasonCode.COMPLETE_INVENTORY_NO_MATCH,
                    "the complete manifest contains no observed component "
                    "matching the advisory condition",
                    asset.manifest_evidence,
                ))
                return self._assessment(
                    asset, AssessmentStatus.CLOSED, reasons, (), None,
                    coverage_complete, None,
                )
            reasons.append(Reason(
                ReasonCode.NO_OBSERVATIONS,
                "no component observation exists at or before the assessment time",
                asset.manifest_evidence,
            ))
            return self._assessment(
                asset, AssessmentStatus.INSUFFICIENT_EVIDENCE, reasons, (), None,
                coverage_complete, None,
            )

        timeline = [
            (
                observation.observed_at or datetime.min.replace(tzinfo=timezone.utc),
                0,
                observation,
            )
            for observation in observations
        ]
        for evidence in self._replacement_records(asset):
            if evidence.replaced_at is not None and evidence.replaced_at <= self.as_of:
                timeline.append((evidence.replaced_at, 1, evidence))
        timeline.sort(key=lambda item: (item[0], item[1]))

        effective = {}
        matches = []
        evaluation_unknown = False
        latest_result = None
        for _, kind, item in timeline:
            if kind == 0:
                effective[_component_key(item.cpe)] = item
            else:
                if not item.verified:
                    continue
                effective.pop(_component_key(item.removed_cpe), None)
                effective[_component_key(item.installed_cpe)] = ComponentObservation(
                    cpe=item.installed_cpe,
                    observed_at=item.replaced_at,
                    source=item.evidence_ref or "replacement evidence",
                )

            result = self.advisory.evaluate(
                [observation.cpe for observation in effective.values()])
            if result.value is True:
                for observed in effective.values():
                    matches.append(MatchEvidence(
                        cpe=observed.cpe,
                        observed_at=observed.observed_at,
                        source=observed.source,
                        within_applicability_window=(
                            observed.observed_at is None or
                            self.advisory.applies_at(observed.observed_at)
                        ),
                    ))
            elif result.value is None and not evaluation_unknown:
                evaluation_unknown = True
                reasons.append(Reason(
                    ReasonCode.CONDITION_EVALUATION_UNKNOWN,
                    result.reason or "advisory condition could not be evaluated",
                    item.cpe if kind == 0 else item.installed_cpe,
                ))
            latest_result = result

        deduplicated = []
        seen = set()
        for match in matches:
            key = (match.cpe, match.observed_at, match.source)
            if key not in seen:
                seen.add(key)
                deduplicated.append(match)
        matches = deduplicated

        current_match = latest_result is not None and latest_result.value is True
        latest_match = matches[-1] if current_match and matches else None
        historical_match = bool(matches)

        if historical_match:
            reasons.append(Reason(
                ReasonCode.HISTORICAL_MATCH,
                "inventory evidence contains at least one CPE matching the "
                "advisory condition",
                matches[-1].cpe,
            ))

        replacement = self._closing_replacement(
            asset, matches, observations, reasons, current_match
        )
        if replacement is not None:
            reasons.append(Reason(
                ReasonCode.VERIFIED_REPLACEMENT,
                "verified replacement evidence shows the affected component "
                "was replaced at {0}".format(_iso(replacement.replaced_at)),
                replacement.evidence_ref or replacement.installed_cpe,
            ))
            return self._assessment(
                asset, AssessmentStatus.CLOSED, reasons, tuple(matches),
                latest_match, coverage_complete, replacement,
                observations,
            )

        if current_match:
            reasons.append(Reason(
                ReasonCode.CPE_MATCH,
                "the latest observation still matches the advisory condition",
                matches[-1].cpe if matches else "",
            ))
            return self._assessment(
                asset, AssessmentStatus.AFFECTED, reasons, tuple(matches),
                latest_match, coverage_complete, None, observations,
            )

        if evaluation_unknown:
            return self._assessment(
                asset, AssessmentStatus.INSUFFICIENT_EVIDENCE, reasons, tuple(matches),
                latest_match, coverage_complete, None, observations,
            )

        inventory_complete = bool(asset.manifest_complete)
        if inventory_complete:
            reasons.append(Reason(
                ReasonCode.COMPLETE_INVENTORY_NO_MATCH,
                "complete manifest contains no matching component",
                asset.manifest_evidence or (
                    coverage.evidence if coverage is not None else ""
                ),
            ))
            return self._assessment(
                asset, AssessmentStatus.CLOSED, reasons, tuple(matches),
                latest_match, coverage_complete, None, observations,
            )

        if not asset.manifest_complete:
            reasons.append(Reason(
                ReasonCode.INCOMPLETE_MANIFEST,
                "the asset manifest is incomplete; a non-match cannot prove "
                "the component is absent",
                asset.manifest_evidence,
            ))
        if coverage_complete is not True:
            reasons.append(Reason(
                ReasonCode.INCOMPLETE_FAMILY_COVERAGE,
                "family inventory coverage is incomplete; a non-match cannot "
                "exclude the family",
                coverage.evidence if coverage is not None else "",
            ))
        if not reasons:
            reasons.append(Reason(
                ReasonCode.NO_OBSERVATIONS,
                "available evidence does not establish either presence or "
                "absence of the affected component",
            ))
        return self._assessment(
            asset, AssessmentStatus.INSUFFICIENT_EVIDENCE, reasons, tuple(matches),
            latest_match, coverage_complete, None, observations,
        )

    def _assessment(self, asset, status, reasons, matches, latest_match,
                    coverage_complete, replacement, observations=()):
        return AssetAssessment(
            asset_id=asset.asset_id,
            family=asset.family,
            status=status,
            reasons=tuple(reasons),
            matches=tuple(matches),
            latest_match=latest_match,
            manifest_complete=bool(asset.manifest_complete),
            family_coverage_complete=coverage_complete,
            replacement_evidence=replacement,
            observations_considered=tuple(observations),
        )

    def _replacement_records(self, asset):
        for evidence in tuple(asset.replacement_evidence) + \
                tuple(self.replacement_evidence):
            if evidence.asset_id is not None and evidence.asset_id != asset.asset_id:
                continue
            if evidence.asset_id is None and evidence.family is not None and \
                    evidence.family != asset.family:
                continue
            yield evidence

    def _closing_replacement(self, asset, matches, observations, reasons,
                             current_match=False):
        for evidence in self._replacement_records(asset):
            if not evidence.verified:
                reasons.append(Reason(
                    ReasonCode.UNVERIFIED_REPLACEMENT,
                    "replacement evidence was supplied but is not verified",
                    evidence.evidence_ref,
                ))
                continue
            if evidence.replaced_at is None or evidence.replaced_at > self.as_of:
                reasons.append(Reason(
                    ReasonCode.REPLACEMENT_TOO_EARLY,
                    "replacement is not effective at the assessment time",
                    evidence.evidence_ref,
                ))
                continue

            removed_matches = [
                match for match in matches
                if _same_component(evidence.removed_cpe, match.cpe)
            ]
            if not removed_matches:
                removed_result = self.advisory.evaluate([evidence.removed_cpe])
                if removed_result.value is not True:
                    continue
            last_removed = None
            if removed_matches:
                last_removed = max(
                    removed_matches,
                    key=lambda match: match.observed_at or datetime.min.replace(
                        tzinfo=timezone.utc),
                )
            if last_removed is not None and \
                    last_removed.observed_at is not None and \
                    evidence.replaced_at < last_removed.observed_at:
                reasons.append(Reason(
                    ReasonCode.REPLACEMENT_TOO_EARLY,
                    "replacement predates the last observation of the affected "
                    "component",
                    evidence.evidence_ref,
                ))
                continue

            later_matches = [
                match for match in matches
                if match.observed_at is not None and
                match.observed_at > evidence.replaced_at and
                _same_component(evidence.removed_cpe, match.cpe)
            ]
            if later_matches:
                reasons.append(Reason(
                    ReasonCode.REPLACEMENT_STILL_AFFECTED,
                    "an observation after the recorded replacement still "
                    "matches the advisory condition",
                    later_matches[-1].cpe,
                ))
                continue

            installed = self.advisory.evaluate([evidence.installed_cpe])
            if installed.value is True:
                reasons.append(Reason(
                    ReasonCode.REPLACEMENT_STILL_AFFECTED,
                    "the installed replacement component still matches the "
                    "advisory condition",
                    evidence.evidence_ref,
                ))
                continue
            if installed.value is None:
                reasons.append(Reason(
                    ReasonCode.CONDITION_EVALUATION_UNKNOWN,
                    "the replacement component could not be evaluated",
                    evidence.installed_cpe,
                ))
                continue
            if current_match:
                reasons.append(Reason(
                    ReasonCode.REPLACEMENT_STILL_AFFECTED,
                    "the latest inventory snapshot still satisfies the "
                    "advisory condition",
                    evidence.evidence_ref,
                ))
                continue
            return evidence
        return None


def assess_retraction(assets, advisory, scope, replacement_evidence=None,
                      as_of=None):
    """Convenience wrapper for :class:`RetractionImpactAnalyzer`."""

    return RetractionImpactAnalyzer(
        advisory=advisory,
        scope=scope,
        replacement_evidence=replacement_evidence,
        as_of=as_of,
    ).assess(assets)


def analyze_retraction(*args, **kwargs):
    """Alias for :func:`assess_retraction`."""

    return assess_retraction(*args, **kwargs)


ImpactAnalyzer = RetractionImpactAnalyzer
RetractionReport = ImpactReport


__all__ = [
    "Advisory",
    "Asset",
    "AssetAssessment",
    "AssessmentStatus",
    "ComponentObservation",
    "ConditionResult",
    "FamilyCoverage",
    "FamilyExclusion",
    "ImpactAnalyzer",
    "ImpactReport",
    "InventoryScope",
    "MatchEvidence",
    "Reason",
    "ReasonCode",
    "ReplacementEvidence",
    "RetractionImpactAnalyzer",
    "RetractionReport",
    "analyze_retraction",
    "assess_retraction",
]
