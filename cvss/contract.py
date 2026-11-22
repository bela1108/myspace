"""
Offline release-contract checks for CVSS scores at a business decision boundary.

The CVSS scoring classes return scores rounded to one decimal place.  That is the
right precision for display, but it is not always enough to decide whether a
release is on one side of a business threshold.  This module keeps the historical
display precision untouched and makes the evidence behind a decision explicit.

A complete CVSS vector is authoritative: the score is recomputed locally with the
matching CVSS implementation.  When only a display score is available, the score
is treated as an interval implied by its stored precision and rounding rule.  A
missing vector or a missing rounding rule therefore produces a possible range and
an indeterminate decision whenever the range crosses the threshold.
"""

from __future__ import unicode_literals

from collections.abc import Mapping
from decimal import ROUND_HALF_UP
from decimal import Decimal as D

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSError

DECISION_RELEASE = "release"
DECISION_STOP = "stop"
DECISION_INDETERMINATE = "indeterminate"

RELEASE = DECISION_RELEASE
STOP = DECISION_STOP
INDETERMINATE = DECISION_INDETERMINATE
UNKNOWN = DECISION_INDETERMINATE

EVIDENCE_COMPLETE_VECTOR = "complete_vector"
EVIDENCE_DISPLAY_SCORE = "display_score"
EVIDENCE_DISPLAY_SCORE_ONLY = "display_score_only"
EVIDENCE_INSUFFICIENT = "insufficient"

ROUNDING_HALF_UP = "half_up"
ROUNDING_HALF_EVEN = "half_even"
ROUNDING_CEILING = "ceiling"
ROUNDING_FLOOR = "floor"
ROUNDING_EXACT = "exact"

SERIALIZATION_RULES = {
    "2.0": {"precision": 1, "rounding": ROUNDING_HALF_UP},
    "3.0": {"precision": 1, "rounding": ROUNDING_CEILING},
    "3.1": {"precision": 1, "rounding": ROUNDING_CEILING},
    "4.0": {"precision": 1, "rounding": ROUNDING_HALF_UP},
}

_VECTOR_KEYS = ("vectorString", "vector", "cvssVector", "cvss_vector")
_SCORE_KEYS = ("baseScore", "base_score", "score", "displayScore", "display_score")
_PRECISION_KEYS = (
    "scorePrecision",
    "score_precision",
    "precision",
    "decimalPlaces",
    "decimal_places",
)
_ROUNDING_KEYS = ("rounding", "roundingRule", "rounding_rule", "serializationRounding")

_ROUNDING_ALIASES = {
    "half_up": ROUNDING_HALF_UP,
    "round_half_up": ROUNDING_HALF_UP,
    "half-up": ROUNDING_HALF_UP,
    "half_even": ROUNDING_HALF_EVEN,
    "round_half_even": ROUNDING_HALF_EVEN,
    "bankers": ROUNDING_HALF_EVEN,
    "ceiling": ROUNDING_CEILING,
    "ceil": ROUNDING_CEILING,
    "round_ceiling": ROUNDING_CEILING,
    "round_up": ROUNDING_CEILING,
    "floor": ROUNDING_FLOOR,
    "round_floor": ROUNDING_FLOOR,
    "truncate": ROUNDING_FLOOR,
    "exact": ROUNDING_EXACT,
}

_OPERATOR_ALIASES = {
    ">=": ">=",
    "ge": ">=",
    "at_or_above": ">=",
    "at-least": ">=",
    "minimum": ">=",
    ">": ">",
    "gt": ">",
    "above": ">",
}


class CVSSContractError(CVSSError):
    """
    Raised for an invalid release-contract configuration.
    """

    pass


def _to_decimal(value, field):
    if isinstance(value, bool):
        raise CVSSContractError('Invalid {0}: "{1}"'.format(field, value))
    if isinstance(value, D):
        result = value
    elif isinstance(value, (int, float)):
        result = D(str(value))
    elif isinstance(value, str):
        try:
            result = D(value.strip())
        except Exception:
            raise CVSSContractError('Invalid {0}: "{1}"'.format(field, value))
    else:
        raise CVSSContractError('Invalid {0}: "{1}"'.format(field, value))
    if not result.is_finite():
        raise CVSSContractError('Invalid {0}: "{1}"'.format(field, value))
    return result


def _normalise_rounding(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise CVSSContractError('Invalid rounding rule: "{0}"'.format(value))
    key = value.strip().lower().replace(" ", "_").replace("-", "_")
    if key == "":
        return None
    if key in ("none", "not_defined", "unavailable", "unknown"):
        return None
    try:
        return _ROUNDING_ALIASES[key]
    except KeyError:
        raise CVSSContractError('Unknown rounding rule: "{0}"'.format(value))


def _normalise_operator(value):
    if value is None:
        return ">="
    if not isinstance(value, str):
        raise CVSSContractError('Invalid decision operator: "{0}"'.format(value))
    key = value.strip().lower().replace(" ", "_")
    try:
        return _OPERATOR_ALIASES[key]
    except KeyError:
        raise CVSSContractError('Unknown decision operator: "{0}"'.format(value))


def _normalise_precision(value):
    if value is None:
        return None
    if isinstance(value, bool):
        raise CVSSContractError('Invalid display precision: "{0}"'.format(value))
    try:
        precision = int(value)
    except (TypeError, ValueError):
        raise CVSSContractError('Invalid display precision: "{0}"'.format(value))
    if precision < 0 or precision > 6:
        raise CVSSContractError("Display precision must be between 0 and 6")
    return precision


def _first_present(data, keys):
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _normalise_material(material):
    if material is None:
        return {}
    if isinstance(material, str):
        text = material.strip()
        try:
            _to_decimal(text, "score")
        except CVSSContractError:
            return {"vectorString": text}
        return {"baseScore": text}
    if isinstance(material, (int, float, D)) and not isinstance(material, bool):
        return {"baseScore": material}
    if hasattr(material, "as_json") and callable(material.as_json):
        try:
            return dict(material.as_json(minimal=True))
        except TypeError:
            return dict(material.as_json())
    if isinstance(material, Mapping):
        data = dict(material)
        for key in _VECTOR_KEYS:
            if isinstance(data.get(key), str):
                data[key] = data[key].strip()
        return data
    data = {}
    for key in _VECTOR_KEYS + _SCORE_KEYS + _PRECISION_KEYS + _ROUNDING_KEYS:
        if hasattr(material, key):
            data[key] = getattr(material, key)
    return data


def _vector_version(vector):
    if vector.startswith("CVSS:4."):
        return "4.0"
    if vector.startswith("CVSS:3.0/"):
        return "3.0"
    if vector.startswith("CVSS:3.1/"):
        return "3.1"
    return "2.0"


def _score_vector(vector):
    version = _vector_version(vector)
    if version.startswith("4."):
        cvss = CVSS4(vector)
    elif version.startswith("3."):
        cvss = CVSS3(vector)
    else:
        cvss = CVSS2(vector)
    score = _to_decimal(cvss.scores()[0], "vector score")
    return cvss, version, score


def _quantum(precision):
    return D(1).scaleb(-precision)


def _quantize(value, precision):
    return value.quantize(_quantum(precision), rounding=ROUND_HALF_UP)


def _display(value, precision):
    return "{0:.{1}f}".format(value, precision)


def _decimal_text(value):
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _range(minimum, maximum, minimum_inclusive=True, maximum_inclusive=True):
    return {
        "minimum": float(minimum),
        "maximum": float(maximum),
        "minimum_inclusive": bool(minimum_inclusive),
        "maximum_inclusive": bool(maximum_inclusive),
        "display": "{0}{1}, {2}{3}".format(
            "[" if minimum_inclusive else "(",
            _decimal_text(minimum),
            _decimal_text(maximum),
            "]" if maximum_inclusive else ")",
        ),
    }


def _point_range(value):
    return _range(value, value, True, True)


def _interval_from_display(score, precision, rounding):
    value = _quantize(score, precision)
    quantum = _quantum(precision)
    half = quantum / 2
    minimum_inclusive = True
    maximum_inclusive = False

    if rounding == ROUNDING_EXACT:
        return value, value, True, True
    elif rounding == ROUNDING_CEILING:
        minimum = value - quantum
        maximum = value
        minimum_inclusive = False
        maximum_inclusive = True
    elif rounding == ROUNDING_FLOOR:
        minimum = value
        maximum = value + quantum
    elif rounding in (ROUNDING_HALF_UP, ROUNDING_HALF_EVEN):
        minimum = value - half
        maximum = value + half
    else:
        minimum = value - quantum
        maximum = value + quantum
        minimum_inclusive = False

    if minimum < D("0"):
        minimum = D("0")
        minimum_inclusive = True
    if maximum > D("10"):
        maximum = D("10")
        maximum_inclusive = True

    return minimum, maximum, minimum_inclusive, maximum_inclusive


def _decisions_for_point(score, threshold, operator):
    if operator == ">=":
        stop = score >= threshold
    else:
        stop = score > threshold
    return (DECISION_STOP,) if stop else (DECISION_RELEASE,)


def _decisions_for_interval(
    minimum, maximum, minimum_inclusive, maximum_inclusive, threshold, operator
):
    if operator == ">=":
        can_stop = maximum > threshold or (maximum == threshold and maximum_inclusive)
        can_release = minimum < threshold or (minimum == threshold and not minimum_inclusive)
    else:
        can_stop = maximum > threshold
        can_release = minimum < threshold or (minimum == threshold and minimum_inclusive)

    decisions = []
    if can_release:
        decisions.append(DECISION_RELEASE)
    if can_stop:
        decisions.append(DECISION_STOP)
    return tuple(decisions)


def _result(
    decision,
    possible_decisions,
    possible_range,
    evidence,
    precision,
    threshold,
    operator,
    score=None,
    vector=None,
    version=None,
    complete_vector=False,
    rounding_rule=None,
    score_matches_archived=None,
    reasons=None,
):
    certain = decision in (DECISION_RELEASE, DECISION_STOP)
    if certain:
        should_stop = decision == DECISION_STOP
    else:
        should_stop = None
    return {
        "decision": decision,
        "certain": certain,
        "is_determinate": certain,
        "supports_determinate_decision": certain,
        "should_stop": should_stop,
        "possible_decisions": list(possible_decisions),
        "possible_range": possible_range,
        "evidence": evidence,
        "complete_vector": complete_vector,
        "rounding_rule": rounding_rule,
        "precision": precision,
        "score": None if score is None else float(score),
        "display_score": None if score is None else _display(score, precision),
        "threshold": float(threshold),
        "operator": operator,
        "vector": vector,
        "version": version,
        "score_matches_archived": score_matches_archived,
        "consistent": score_matches_archived,
        "reasons": list(reasons or []),
    }


class ReleaseContract(object):
    """
    Offline contract for deciding whether a release crosses a business threshold.

    Args:
        threshold: Business-provided decision boundary.  It must be supplied
            explicitly because it is not a property of CVSS itself.
        precision: Historical display precision, one decimal place by default.
        rounding: Optional default rounding rule for score-only material.
        operator: ``">="`` (default) decides stop at or above the threshold;
            ``">"`` decides stop only above the threshold.
    """

    def __init__(self, threshold, precision=1, rounding=None, operator=">="):
        self.threshold = _to_decimal(threshold, "threshold")
        if self.threshold < D("0") or self.threshold > D("10"):
            raise CVSSContractError("Threshold must be between 0 and 10")
        self.precision = _normalise_precision(precision)
        if self.precision is None:
            self.precision = 1
        self.rounding = _normalise_rounding(rounding)
        self.operator = _normalise_operator(operator)

    def evaluate(self, material):
        """
        Evaluate one release material.

        Args:
            material: A mapping, a CVSS object, a vector string, or a numeric
                display score.  Mapping keys follow the CVSS JSON spelling
                (``vectorString`` and ``baseScore``).  ``scorePrecision`` and
                ``rounding`` are optional.

        Returns:
            dict: A JSON-serialisable contract result.
        """
        data = _normalise_material(material)
        vector = _first_present(data, _VECTOR_KEYS)
        archived_score = _first_present(data, _SCORE_KEYS)
        precision = _normalise_precision(_first_present(data, _PRECISION_KEYS))
        if precision is None:
            precision = self.precision
        rounding = _normalise_rounding(_first_present(data, _ROUNDING_KEYS))
        if rounding is None:
            rounding = self.rounding

        reasons = []
        if archived_score is not None:
            try:
                archived_score = _to_decimal(archived_score, "score")
            except CVSSContractError:
                reasons.append("invalid display score")
                archived_score = None
            else:
                if archived_score < D("0") or archived_score > D("10"):
                    reasons.append("invalid display score")
                    archived_score = None

        if vector is not None and not isinstance(vector, str):
            reasons.append("incomplete or malformed vector")
            vector = None

        if vector is not None:
            try:
                cvss, version, vector_score = _score_vector(vector)
            except (CVSSError, KeyError, ValueError, TypeError):
                reasons.append("incomplete or malformed vector")
            else:
                canonical_score = vector_score
                matches = None
                if archived_score is not None:
                    matches = _quantize(archived_score, precision) == _quantize(
                        canonical_score, precision
                    )
                    if not matches:
                        reasons.append("archived display score does not match vector score")
                serialization = SERIALIZATION_RULES.get(version, {})
                rounding_rule = serialization.get("rounding")
                decisions = _decisions_for_point(canonical_score, self.threshold, self.operator)
                decision = decisions[0] if len(decisions) == 1 else DECISION_INDETERMINATE
                return _result(
                    decision,
                    decisions,
                    _point_range(canonical_score),
                    EVIDENCE_COMPLETE_VECTOR,
                    precision,
                    self.threshold,
                    self.operator,
                    score=canonical_score,
                    vector=cvss.clean_vector(),
                    version=version,
                    complete_vector=True,
                    rounding_rule=rounding_rule,
                    score_matches_archived=matches,
                    reasons=reasons,
                )
        else:
            reasons.append("complete vector is missing")

        if archived_score is None:
            reasons.append("display score is missing")
            return _result(
                DECISION_INDETERMINATE,
                (),
                None,
                EVIDENCE_INSUFFICIENT,
                precision,
                self.threshold,
                self.operator,
                reasons=reasons,
            )

        if rounding is None:
            reasons.append("rounding rule is missing")

        display_score = _quantize(archived_score, precision)
        minimum, maximum, minimum_inclusive, maximum_inclusive = _interval_from_display(
            display_score, precision, rounding
        )
        decisions = _decisions_for_interval(
            minimum,
            maximum,
            minimum_inclusive,
            maximum_inclusive,
            self.threshold,
            self.operator,
        )
        decision = decisions[0] if len(decisions) == 1 else DECISION_INDETERMINATE
        evidence = EVIDENCE_DISPLAY_SCORE if rounding is not None else EVIDENCE_DISPLAY_SCORE_ONLY
        return _result(
            decision,
            decisions,
            _range(minimum, maximum, minimum_inclusive, maximum_inclusive),
            evidence,
            precision,
            self.threshold,
            self.operator,
            score=display_score,
            rounding_rule=rounding,
            reasons=reasons,
        )

    def evaluate_many(self, materials):
        """
        Evaluate an iterable of materials and include their input positions.
        """
        results = []
        for index, material in enumerate(materials):
            result = self.evaluate(material)
            result["index"] = index
            results.append(result)
        return results

    def partition(self, materials):
        """
        Split materials into those supporting a determinate decision and the rest.
        """
        determinate = []
        indeterminate = []
        for result in self.evaluate_many(materials):
            if result["certain"]:
                determinate.append(result)
            else:
                indeterminate.append(result)
        return {
            "determinate": determinate,
            "indeterminate": indeterminate,
        }


def evaluate_release(material, threshold, precision=1, rounding=None, operator=">="):
    """
    Convenience wrapper around :class:`ReleaseContract`.
    """
    if isinstance(threshold, ReleaseContract):
        return threshold.evaluate(material)
    contract = ReleaseContract(
        threshold=threshold,
        precision=precision,
        rounding=rounding,
        operator=operator,
    )
    return contract.evaluate(material)


def evaluate_releases(materials, threshold, precision=1, rounding=None, operator=">="):
    """
    Evaluate several release materials with one threshold.
    """
    if isinstance(threshold, ReleaseContract):
        return threshold.evaluate_many(materials)
    contract = ReleaseContract(
        threshold=threshold,
        precision=precision,
        rounding=rounding,
        operator=operator,
    )
    return contract.evaluate_many(materials)


def partition_releases(materials, threshold, precision=1, rounding=None, operator=None):
    """
    Return determinate and indeterminate materials for one contract.
    """
    if isinstance(threshold, ReleaseContract):
        return threshold.partition(materials)
    contract = ReleaseContract(
        threshold=threshold,
        precision=precision,
        rounding=rounding,
        operator=operator,
    )
    return contract.partition(materials)


CVSSContract = ReleaseContract
