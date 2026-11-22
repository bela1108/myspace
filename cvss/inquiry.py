"""
Offline, minimax inquiry planning for CVSS triage.

The planner answers a narrow operational question: given every remaining CVSS
combination that is still possible, a list of questions that can separate those
combinations, the cost of each question, and a release threshold, which
question should be asked first?

The objective is deliberately *not* average information gain or expected cost.
It is a worst-branch criterion:

1. minimize the largest unresolved scenario weight left in any leaf, then
2. minimize the largest inquiry cost paid on any root-to-leaf path.

That ordering means a cheap question cannot hide an unresolved branch behind a
good average.  Budgets are per path and are also part of the decision tree, so
an answer that consumes more budget can lead to a different remainder of the
plan than a cheaper answer.

The public entry point is :func:`plan_inquiries`.  :func:`enumerate_scenarios`
turns a set of fixed and uncertain CVSS metrics into the legal full vectors
accepted by the planner.
"""

from __future__ import unicode_literals

import itertools
import json
from collections import OrderedDict
from decimal import Decimal as D

try:
    from collections.abc import Mapping
except ImportError:  # pragma: no cover - Python 2 compatibility
    from collections import Mapping

from .constants2 import METRICS_ABBREVIATIONS as METRICS2
from .constants3 import METRICS_ABBREVIATIONS as METRICS3
from .constants4 import METRICS as METRICS4
from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSError

OUTCOME_HOLD = "hold"
OUTCOME_NORMAL = "normal"

_SCORE_INDEX = {"base": 0, "temporal": 1, "environmental": 2}
_SEVERITY_RANK = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_VERSION_METRICS = {
    "2.0": list(METRICS2),
    "3.0": list(METRICS3),
    "3.1": list(METRICS3),
    "4.0": list(METRICS4),
}
_KNOWN_METRICS = set(METRICS2) | set(METRICS3) | set(METRICS4)


class InquiryError(CVSSError):
    """Raised when an inquiry-planning input or scenario cannot be evaluated."""


def _decimal(value, name):
    try:
        result = D(str(value))
    except Exception:
        raise InquiryError('{0} must be a finite non-negative number: "{1}"'.format(name, value))
    if not result.is_finite() or result < 0:
        raise InquiryError('{0} must be a finite non-negative number: "{1}"'.format(name, value))
    return result


def _number(value):
    """Return a JSON-friendly int/float without exposing Decimal to callers."""
    value = D(value)
    if value == value.to_integral_value():
        return int(value)
    return float(value)


def _audit_value(value):
    """Make selector values JSON-friendly without hiding callable names."""
    if isinstance(value, D):
        return _number(value)
    if callable(value):
        return getattr(value, "__name__", repr(value))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def _vector_prefix(version):
    if version == "2.0":
        return ""
    if version in ("3.0", "3.1"):
        return "CVSS:{0}/".format(version)
    if version == "4.0":
        return "CVSS:4.0/"
    raise InquiryError('Unsupported CVSS version "{0}"'.format(version))


def _normalize_version(version):
    if version is None:
        return "3.1"
    value = str(version)
    aliases = {"2": "2.0", "2.0": "2.0", "3": "3.1", "3.1": "3.1", "4": "4.0", "4.0": "4.0"}
    if value in aliases:
        return aliases[value]
    if value == "3.0":
        return "3.0"
    raise InquiryError('Unsupported CVSS version "{0}"; use 2.0, 3.0, 3.1, or 4.0'.format(version))


def _version_from_vector(vector):
    if vector.startswith("CVSS:4."):
        return "4.0"
    if vector.startswith("CVSS:3.0/"):
        return "3.0"
    if vector.startswith("CVSS:3.1/"):
        return "3.1"
    if vector.startswith("CVSS:"):
        raise InquiryError('Unsupported CVSS prefix in vector "{0}"'.format(vector))
    return "2.0"


def _parse_cvss(vector):
    try:
        if vector.startswith("CVSS:4."):
            return CVSS4(vector)
        if vector.startswith("CVSS:3."):
            return CVSS3(vector)
        return CVSS2(vector)
    except (CVSSError, KeyError, ValueError) as exc:
        raise InquiryError('Invalid CVSS vector "{0}": {1}'.format(vector, exc))


def _metric_value(cvss, metric):
    if metric in cvss.metrics:
        return cvss.metrics[metric]
    # CVSS2 calls an absent optional metric "ND"; v3/v4 use "X".
    return "ND" if isinstance(cvss, CVSS2) else "X"


def _metric_order(cvss):
    if isinstance(cvss, CVSS2):
        return list(METRICS2)
    if isinstance(cvss, CVSS4):
        return list(METRICS4)
    return list(METRICS3)


def enumerate_scenarios(
    fixed_metrics=None,
    uncertain_metrics=None,
    version=None,
    fixed_vector=None,
    id_prefix="s",
):
    """
    Expand fixed and uncertain CVSS metrics into full, validated vectors.

    Args:
        fixed_metrics (dict): Metrics whose value is known.
        uncertain_metrics (dict): Metric -> iterable of legal remaining values.
            A single string is accepted as one value (e.g. ``"POC"`` is not
            split into characters).
        version (str): ``"2.0"``, ``"3.0"``, ``"3.1"``, or ``"4.0"``.  It is
            inferred from ``fixed_vector`` when provided, otherwise defaults
            to ``"3.1"``.
        fixed_vector (str): Optional partial CVSS vector containing known
            metrics, for example ``"CVSS:3.1/AC:L/UI:N/S:U"``.
        id_prefix (str): Prefix for generated scenario IDs (``s1``, ``s2``...).

    Returns:
        OrderedDict: Stable scenario ID -> full CVSS vector.

    Raises:
        InquiryError: if a metric/version is unknown or a generated vector is
            incomplete or malformed.
    """
    fixed = OrderedDict(fixed_metrics or {})
    uncertain = OrderedDict(uncertain_metrics or {})

    vector_version = None
    if fixed_vector:
        has_prefix = fixed_vector.startswith("CVSS:")
        if has_prefix or version is None:
            vector_version = _version_from_vector(fixed_vector)
        else:
            vector_version = _normalize_version(version)
        body = fixed_vector
        if has_prefix and vector_version != "2.0":
            body = fixed_vector.split("/", 1)[1] if "/" in fixed_vector else ""
        for field in [part for part in body.split("/") if part]:
            try:
                metric, value = field.split(":", 1)
            except ValueError:
                raise InquiryError('Malformed field "{0}" in fixed vector'.format(field))
            if metric in fixed and str(fixed[metric]) != value:
                raise InquiryError(
                    'Conflicting fixed value for metric "{0}": "{1}" vs "{2}"'.format(
                        metric, fixed[metric], value
                    )
                )
            fixed[metric] = value

    if version is None:
        version = vector_version or "3.1"
    version = _normalize_version(version)
    if vector_version is not None and vector_version != version:
        raise InquiryError(
            "fixed_vector is CVSS {0}, but version is {1}".format(vector_version, version)
        )

    order = _VERSION_METRICS[version]
    order_set = set(order)
    for metric in list(fixed) + list(uncertain):
        if metric not in _KNOWN_METRICS:
            raise InquiryError('Unknown CVSS metric "{0}"'.format(metric))
        if metric not in order_set:
            raise InquiryError('Metric "{0}" is not valid for CVSS {1}'.format(metric, version))

    uncertain_order = [metric for metric in order if metric in uncertain]
    value_lists = []
    for metric in uncertain_order:
        values = uncertain[metric]
        if isinstance(values, str):
            values = [values]
        else:
            values = list(values)
        if not values:
            raise InquiryError('Uncertain metric "{0}" has no candidate values'.format(metric))
        value_lists.append(values)

    combinations = itertools.product(*value_lists) if value_lists else [()]
    prefix = _vector_prefix(version)
    result = OrderedDict()
    for index, combination in enumerate(combinations, 1):
        values = OrderedDict(fixed)
        values.update(zip(uncertain_order, combination))
        fields = ["{0}:{1}".format(metric, values[metric]) for metric in order if metric in values]
        vector = prefix + "/".join(fields)
        _parse_cvss(vector)
        result["{0}{1}".format(id_prefix, index)] = vector
    return result


def _resolve_score(cvss, score):
    if callable(score):
        result = score(cvss)
        if result is None:
            raise InquiryError("Score callable returned None for vector {0}".format(cvss.vector))
        return float(result), None

    if isinstance(score, int):
        index = score
    else:
        key = str(score).lower()
        if key not in _SCORE_INDEX:
            raise InquiryError(
                'score must be "base", "temporal", "environmental", an index, or a callable'
            )
        index = _SCORE_INDEX[key]

    scores = cvss.scores()
    if index >= len(scores) or scores[index] is None:
        raise InquiryError(
            'CVSS vector "{0}" does not define the requested score'.format(cvss.vector)
        )
    severities = cvss.severities()
    severity = severities[index] if index < len(severities) else None
    return float(scores[index]), severity


def _outcome_from_score(score, severity, threshold, labels, classifier):
    if classifier is not None:
        return classifier(score)

    if isinstance(threshold, str) and threshold in _SEVERITY_RANK:
        if severity is None:
            raise InquiryError("A severity threshold needs a numeric CVSS score kind")
        if threshold not in _SEVERITY_RANK:
            raise InquiryError(
                'Unknown severity threshold "{0}"; use None, Low, Medium, High, or Critical'.format(
                    threshold
                )
            )
        return labels[0] if _SEVERITY_RANK[severity] >= _SEVERITY_RANK[threshold] else labels[1]

    threshold_value = _decimal(threshold, "threshold")
    if threshold_value > D("10"):
        raise InquiryError("threshold must be between 0 and 10")
    return labels[0] if D(str(score)) >= threshold_value else labels[1]


class Scenario(object):
    """One possible remaining CVSS vector and its triage outcome."""

    def __init__(self, scenario_id, vector, cvss, score, outcome, weight):
        self.id = str(scenario_id)
        self.vector = vector
        self.cvss = cvss
        self.score = score
        self.outcome = outcome
        self.weight = weight
        self.metrics = dict(cvss.metrics)

    def metric_value(self, metric):
        return _metric_value(self.cvss, metric)

    def as_dict(self):
        return {
            "id": self.id,
            "vector": self.vector,
            "score": self.score,
            "outcome": self.outcome,
            "weight": _number(self.weight),
        }


class InquiryQuestion(object):
    """
    A question that partitions the possible scenarios.

    Three construction styles are supported:

    * ``InquiryQuestion(..., metric="AV", answers={"network": ["N"], ...})``
      partitions by metric value.
    * ``InquiryQuestion(..., answers={"yes": ["s1"], "no": ["s2"]})`` uses an
      explicit scenario-ID partition.  An answer value may also be a callable
      receiving a :class:`Scenario`, or a metric-constraint mapping such as
      ``{"AV": ["N", "A"]}``.
    * ``InquiryQuestion(..., split=callable, answers=["yes", "no"])`` derives
      the answer from a callable.  Declared answer labels are optional.

    ``cost`` is the time/money spent on the question.  It is charged on every
    path that asks the question.
    """

    def __init__(self, question_id, prompt, cost, answers=None, metric=None, split=None):
        self.id = str(question_id)
        self.prompt = str(prompt) if prompt is not None else self.id
        self.cost = _decimal(cost, "question cost")
        self.metric = metric
        self.split = split
        self.answers = answers
        self.mode = None
        self._labels = {}
        self._assigned = frozenset()
        self._answer_order = []
        self._declared = OrderedDict()

        if metric is not None and split is not None:
            raise InquiryError('Question "{0}" cannot use both metric and split'.format(self.id))
        if metric is not None:
            self.mode = "metric"
            if not isinstance(answers, Mapping) or not answers:
                raise InquiryError(
                    'Metric question "{0}" needs answers={{label: value_or_values}}'.format(self.id)
                )
            for label, values in answers.items():
                if isinstance(values, str):
                    values = [values]
                else:
                    values = list(values)
                values = list(OrderedDict.fromkeys(values))
                self._declared[label] = values
                self._answer_order.append(label)
        elif split is not None:
            self.mode = "split"
            if answers is None:
                labels = []
            elif isinstance(answers, Mapping):
                labels = list(answers)
            elif isinstance(answers, str):
                labels = [answers]
            else:
                labels = list(answers)
            self._answer_order = labels
            for label in labels:
                self._declared[label] = None
        else:
            self.mode = "partition"
            if not isinstance(answers, Mapping) or not answers:
                raise InquiryError(
                    'Question "{0}" needs a non-empty answers mapping'.format(self.id)
                )
            for label, value in answers.items():
                self._declared[label] = value
                self._answer_order.append(label)

    @classmethod
    def from_metric(cls, question_id, prompt, cost, metric, answers):
        return cls(question_id, prompt, cost, answers=answers, metric=metric)

    @classmethod
    def from_partition(cls, question_id, prompt, cost, answers):
        return cls(question_id, prompt, cost, answers=answers)

    @classmethod
    def from_callable(cls, question_id, prompt, cost, split, answers=None):
        return cls(question_id, prompt, cost, answers=answers, split=split)

    def prepare(self, scenarios):
        """Validate this question against the full scenario set and cache labels."""
        labels = {}
        if self.mode == "metric":
            if self.metric not in _KNOWN_METRICS:
                raise InquiryError('Unknown CVSS metric "{0}"'.format(self.metric))
            value_to_labels = {}
            for label, values in self._declared.items():
                for value in values:
                    value_to_labels.setdefault(value, []).append(label)
            for value, matching in value_to_labels.items():
                if len(matching) > 1:
                    raise InquiryError(
                        'Question "{0}" maps metric value "{1}" to multiple answers: {2}'.format(
                            self.id, value, ", ".join(str(label) for label in matching)
                        )
                    )
            for scenario in scenarios:
                value = scenario.metric_value(self.metric)
                if value not in value_to_labels:
                    raise InquiryError(
                        'Question "{0}" does not assign metric {1}={2} (scenario {3})'.format(
                            self.id, self.metric, value, scenario.id
                        )
                    )
                labels[scenario.id] = value_to_labels[value][0]
        elif self.mode == "split":
            for scenario in scenarios:
                label = self.split(scenario)
                if self._answer_order and label not in self._answer_order:
                    raise InquiryError(
                        'Question "{0}" split returned undeclared answer "{1}"'.format(
                            self.id, label
                        )
                    )
                labels[scenario.id] = label
                if label not in self._answer_order:
                    self._answer_order.append(label)
                    self._declared[label] = None
        else:
            assigned = {}
            for scenario in scenarios:
                matches = []
                for label, answer in self._declared.items():
                    if self._answer_matches(scenario, answer):
                        matches.append(label)
                if len(matches) > 1:
                    raise InquiryError(
                        'Question "{0}" assigns scenario {1} to multiple answers: {2}'.format(
                            self.id, scenario.id, ", ".join(str(label) for label in matches)
                        )
                    )
                if matches:
                    assigned[scenario.id] = matches[0]
            labels = assigned

        self._labels = labels
        self._assigned = frozenset(labels)
        return self

    @staticmethod
    def _answer_matches(scenario, answer):
        if callable(answer):
            return bool(answer(scenario))
        if isinstance(answer, Mapping):
            for metric, allowed in answer.items():
                if isinstance(allowed, str):
                    allowed = [allowed]
                if scenario.metric_value(metric) not in list(allowed):
                    return False
            return True
        if isinstance(answer, str):
            return scenario.id == answer
        try:
            return scenario.id in {str(item) for item in answer}
        except TypeError:
            raise InquiryError('Unsupported answer partition value "{0}"'.format(answer))

    def applies_to(self, scenario_ids):
        return frozenset(scenario_ids).issubset(self._assigned)

    def groups_for(self, scenario_ids, scenario_order):
        groups = OrderedDict()
        wanted = frozenset(scenario_ids)
        for scenario_id in scenario_order:
            if scenario_id not in wanted:
                continue
            label = self._labels[scenario_id]
            groups.setdefault(label, []).append(scenario_id)
        return groups

    def as_dict(self):
        if self.mode == "metric":
            answers = OrderedDict()
            for label, values in self._declared.items():
                answers[label] = list(values)
        elif self.mode == "partition":
            answers = OrderedDict()
            for label, value in self._declared.items():
                if callable(value):
                    answers[label] = getattr(value, "__name__", repr(value))
                elif isinstance(value, Mapping):
                    answers[label] = dict(value)
                elif isinstance(value, str):
                    answers[label] = [value]
                else:
                    try:
                        answers[label] = sorted(str(item) for item in value)
                    except TypeError:
                        answers[label] = repr(value)
        else:
            answers = list(self._answer_order)
        result = OrderedDict(
            [
                ("id", self.id),
                ("prompt", self.prompt),
                ("cost", _number(self.cost)),
                ("mode", self.mode),
                ("answers", answers),
            ]
        )
        if self.metric is not None:
            result["metric"] = self.metric
        return result


def _coerce_question(item):
    if isinstance(item, InquiryQuestion):
        return item
    if not isinstance(item, Mapping):
        raise InquiryError("questions must contain InquiryQuestion objects or dictionaries")
    question_id = item.get("id", item.get("question_id"))
    if question_id is None:
        raise InquiryError('A question is missing its "id"')
    prompt = item.get("prompt", item.get("text", question_id))
    cost = item.get("cost", 0)
    if "split" in item and item["split"] is not None:
        return InquiryQuestion(
            question_id,
            prompt,
            cost,
            answers=item.get("answers"),
            split=item["split"],
        )
    if "metric" in item and item["metric"] is not None:
        return InquiryQuestion(
            question_id,
            prompt,
            cost,
            answers=item.get("answers"),
            metric=item["metric"],
        )
    answers = item.get("answers", item.get("partition"))
    return InquiryQuestion(question_id, prompt, cost, answers=answers)


def _coerce_scenarios(scenarios):
    """Return (original_key, normalized_id, vector) tuples in deterministic order."""
    if isinstance(scenarios, Mapping):
        items = list(scenarios.items())
    elif isinstance(scenarios, str):
        items = [("s1", scenarios)]
    else:
        items = []
        for index, item in enumerate(scenarios, 1):
            if isinstance(item, str):
                items.append(("s{0}".format(index), item))
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                items.append((item[0], item[1]))
            else:
                raise InquiryError(
                    "scenarios must be vector strings, (id, vector) pairs, or a mapping"
                )

    result = []
    seen = set()
    for key, value in items:
        scenario_id = str(key)
        if scenario_id in seen:
            raise InquiryError('Duplicate scenario ID "{0}"'.format(scenario_id))
        seen.add(scenario_id)
        if not isinstance(value, str):
            raise InquiryError('Scenario "{0}" does not contain a CVSS vector string'.format(key))
        result.append((key, scenario_id, value))
    return result


def _weight_for_scenario(key, scenario_id, weights, index, count):
    if weights is None:
        return D("1")
    if isinstance(weights, Mapping):
        if key in weights:
            result = _decimal(weights[key], "scenario weight")
            if result <= 0:
                raise InquiryError("scenario weights must be positive")
            return result
        if scenario_id in weights:
            result = _decimal(weights[scenario_id], "scenario weight")
            if result <= 0:
                raise InquiryError("scenario weights must be positive")
            return result
        return D("1")
    values = list(weights)
    if len(values) != count:
        raise InquiryError("weights must have one entry per scenario")
    result = _decimal(values[index], "scenario weight")
    if result <= 0:
        raise InquiryError("scenario weights must be positive")
    return result


def _counts(scenarios, attribute, outcome_order=None):
    counts = OrderedDict()
    if outcome_order:
        for label in outcome_order:
            counts[label] = 0
    for scenario in scenarios:
        value = getattr(scenario, attribute)
        counts[value] = counts.get(value, 0) + 1
    return OrderedDict((key, value) for key, value in counts.items() if value)


def _weight_counts(scenarios, outcome_order=None):
    counts = OrderedDict()
    if outcome_order:
        for label in outcome_order:
            counts[label] = D("0")
    for scenario in scenarios:
        counts.setdefault(scenario.outcome, D("0"))
        counts[scenario.outcome] += scenario.weight
    return OrderedDict((key, _number(value)) for key, value in counts.items() if value)


def _score_range(scenarios):
    scores = [scenario.score for scenario in scenarios]
    return {"min": min(scores), "max": max(scores)}


def _remaining_metrics(scenarios):
    if not scenarios:
        return OrderedDict()
    ordered = []
    for scenario in scenarios:
        for metric in _metric_order(scenario.cvss):
            if metric not in ordered:
                ordered.append(metric)
    result = OrderedDict()
    for metric in ordered:
        values = sorted({scenario.metric_value(metric) for scenario in scenarios})
        if len(values) > 1:
            result[metric] = values
    return result


class DecisionNode(object):
    """A node in the auditable decision tree."""

    def __init__(
        self,
        kind,
        scenarios,
        cost_so_far,
        worst_cost,
        worst_unresolved_mass,
        outcome_order,
    ):
        self.kind = kind
        self.scenarios = list(scenarios)
        self.scenario_ids = [scenario.id for scenario in scenarios]
        self.scenario_count = len(scenarios)
        self.cost_so_far = cost_so_far
        self.worst_cost = worst_cost
        self.worst_unresolved_mass = worst_unresolved_mass
        self.outcome_counts = _counts(scenarios, "outcome", outcome_order)
        self.outcome_weights = _weight_counts(scenarios, outcome_order)
        self.score_range = _score_range(scenarios)
        self.question = None
        self.answers = OrderedDict()
        self.alternatives = []
        self.decision = None
        self.unresolved = False
        self.missing = None

    @property
    def complete(self):
        return self.worst_unresolved_mass == D("0")

    def as_dict(self, include_scenarios=True):
        result = OrderedDict(
            [
                ("kind", self.kind),
                ("scenario_count", self.scenario_count),
                ("cost_so_far", _number(self.cost_so_far)),
                ("worst_cost", _number(self.worst_cost)),
                ("worst_unresolved_mass", _number(self.worst_unresolved_mass)),
                ("outcome_counts", self.outcome_counts),
                ("outcome_weights", self.outcome_weights),
                ("score_range", self.score_range),
            ]
        )
        if include_scenarios:
            result["scenario_ids"] = list(self.scenario_ids)
        if self.kind == "question":
            result["question"] = self.question.as_dict()
            result["alternatives"] = list(self.alternatives)
            result["answers"] = []
            for label, child in self.answers.items():
                result["answers"].append(
                    OrderedDict(
                        [
                            ("answer", label),
                            ("scenario_count", child.scenario_count),
                            (
                                "scenario_ids",
                                list(child.scenario_ids) if include_scenarios else None,
                            ),
                            ("worst_cost", _number(child.worst_cost)),
                            ("node", child.as_dict(include_scenarios)),
                        ]
                    )
                )
        else:
            result["decision"] = self.decision
            result["unresolved"] = self.unresolved
            if self.missing is not None:
                result["missing"] = self.missing
        return result

    def format_lines(self, indent=0):
        prefix = "  " * indent
        if self.kind == "question":
            lines = [
                "{0}ASK {1} (cost {2}): {3}".format(
                    prefix, self.question.id, _number(self.question.cost), self.question.prompt
                )
            ]
            for label, child in self.answers.items():
                lines.append(
                    "{0}  if {1}: worst cost {2}".format(prefix, label, _number(child.worst_cost))
                )
                lines.extend(child.format_lines(indent + 2))
            return lines
        if self.unresolved:
            outcomes = ", ".join(
                "{0}={1}".format(key, value) for key, value in self.outcome_counts.items()
            )
            return [
                "{0}UNRESOLVED ({1}), worst cost {2}; missing: {3}".format(
                    prefix,
                    outcomes,
                    _number(self.worst_cost),
                    ", ".join(self.missing.get("missing_metrics", [])) or "more evidence",
                )
            ]
        return [
            "{0}DECIDE {1} ({2} scenarios), worst cost {3}".format(
                prefix, self.decision, self.scenario_count, _number(self.worst_cost)
            )
        ]


class InquiryPlan(object):
    """The minimax decision tree plus its audit summary."""

    def __init__(
        self,
        root,
        planner,
    ):
        self.root = root
        self._planner = planner

    @property
    def complete(self):
        return self.root.worst_unresolved_mass == D("0")

    @property
    def worst_case_cost(self):
        return _number(self.root.worst_cost)

    @property
    def worst_unresolved_mass(self):
        return _number(self.root.worst_unresolved_mass)

    @property
    def first_question(self):
        return self.root.question if self.root.kind == "question" else None

    def leaves(self):
        result = []

        def visit(node, path):
            if node.kind == "leaf":
                record = OrderedDict(
                    [
                        ("leaf_id", "leaf-{0}".format(len(result) + 1)),
                        ("path", list(path)),
                        ("decision", node.decision),
                        ("unresolved", node.unresolved),
                        ("scenario_count", node.scenario_count),
                        ("scenario_ids", list(node.scenario_ids)),
                        ("outcomes", node.outcome_counts),
                        ("cost", _number(node.cost_so_far)),
                        ("worst_cost", _number(node.worst_cost)),
                        ("score_range", node.score_range),
                    ]
                )
                if node.missing is not None:
                    record["missing"] = node.missing
                result.append(record)
                return
            for label, child in node.answers.items():
                step = OrderedDict(
                    [
                        ("question_id", node.question.id),
                        ("answer", label),
                        ("cost", _number(node.question.cost)),
                    ]
                )
                visit(child, path + [step])

        visit(self.root, [])
        return result

    def as_dict(self, include_scenarios=True):
        leaves = self.leaves()
        planner = self._planner
        threshold = planner.threshold
        result = OrderedDict(
            [
                ("schema", "cvss-inquiry-plan/v1"),
                (
                    "objective",
                    OrderedDict(
                        [
                            (
                                "criterion",
                                "lexicographic(min worst unresolved mass, "
                                "min worst inquiry cost)",
                            ),
                            ("average_based", False),
                            ("budget_scope", "root-to-leaf path"),
                        ]
                    ),
                ),
                (
                    "threshold",
                    OrderedDict(
                        [
                            ("value", _audit_value(threshold)),
                            ("score", _audit_value(planner.score_kind)),
                            (
                                "labels",
                                OrderedDict(
                                    [
                                        ("at_or_above", planner.outcome_labels[0]),
                                        ("below", planner.outcome_labels[1]),
                                    ]
                                ),
                            ),
                        ]
                    ),
                ),
                ("budget", _number(planner.budget) if planner.budget is not None else None),
                ("scenario_count", len(planner.scenarios)),
                ("question_count", len(planner.questions)),
                ("complete", self.complete),
                ("worst_case_cost", _number(self.worst_case_cost)),
                ("worst_unresolved_mass", _number(self.worst_unresolved_mass)),
                ("leaf_count", len(leaves)),
                ("unresolved_leaf_count", sum(1 for item in leaves if item["unresolved"])),
                (
                    "first_question",
                    self.first_question.as_dict() if self.first_question is not None else None,
                ),
                ("leaves", leaves),
                ("tree", self.root.as_dict(include_scenarios)),
                (
                    "unresolved_disagreements",
                    [item for item in leaves if item["unresolved"]],
                ),
                (
                    "audit",
                    OrderedDict(
                        [
                            ("questions", [question.as_dict() for question in planner.questions]),
                            (
                                "scenarios",
                                (
                                    [scenario.as_dict() for scenario in planner.scenarios]
                                    if include_scenarios
                                    else None
                                ),
                            ),
                        ]
                    ),
                ),
            ]
        )
        return result

    def to_json(self, indent=2, include_scenarios=True):
        return json.dumps(
            self.as_dict(include_scenarios=include_scenarios),
            indent=indent,
            ensure_ascii=False,
        )

    def format_lines(self):
        return self.root.format_lines()

    def __str__(self):
        return "\n".join(self.format_lines())


class _Candidate(object):
    def __init__(
        self, question, children, unresolved_mass, worst_cost, child_question_count, child_depth
    ):
        self.question = question
        self.children = children
        self.unresolved_mass = unresolved_mass
        self.worst_cost = worst_cost
        self.question_count = 1 + child_question_count
        self.depth = 1 + child_depth

    def key(self):
        # The final fields only make ties deterministic; they do not change the
        # worst-branch objective.
        return (
            self.unresolved_mass,
            self.worst_cost,
            self.question_count,
            self.depth,
            self.question.id,
        )


class _Solution(object):
    def __init__(self, node, question_count, depth):
        self.node = node
        self._question_count = question_count
        self._depth = depth

    def get(self, key, default=None):
        if key == "question_count":
            return self._question_count
        if key == "depth":
            return self._depth
        return default


class InquiryPlanner(object):
    """
    Exhaustive minimax planner over the remaining scenario set.

    The state space is exponential in the number of scenarios because the
    planner considers every reachable subset.  It is intended for the small,
    explicitly enumerated sets used in review triage and in exhaustive
    optimality checks.
    """

    def __init__(
        self,
        scenarios,
        questions,
        threshold,
        budget=None,
        score="base",
        outcome_labels=(OUTCOME_HOLD, OUTCOME_NORMAL),
        classifier=None,
        weights=None,
    ):
        if threshold is None and classifier is None:
            raise InquiryError("threshold is required unless classifier is supplied")
        if len(outcome_labels) != 2 or outcome_labels[0] == outcome_labels[1]:
            raise InquiryError("outcome_labels must contain two distinct labels")

        self.threshold = threshold
        self.score_kind = score
        self.outcome_labels = tuple(outcome_labels)
        self.budget = _decimal(budget, "budget") if budget is not None else None
        self.classifier = classifier

        entries = _coerce_scenarios(scenarios)
        if not entries:
            raise InquiryError("at least one scenario is required")
        count = len(entries)
        scenario_list = []
        for index, (key, scenario_id, vector) in enumerate(entries):
            cvss = _parse_cvss(vector)
            numeric_score, severity = _resolve_score(cvss, score)
            outcome = _outcome_from_score(
                numeric_score,
                severity,
                threshold,
                self.outcome_labels,
                classifier,
            )
            weight = _weight_for_scenario(key, scenario_id, weights, index, count)
            scenario_list.append(
                Scenario(scenario_id, vector, cvss, numeric_score, outcome, weight)
            )

        self.scenarios = scenario_list
        self._scenario_order = [scenario.id for scenario in scenario_list]
        self._by_id = OrderedDict((scenario.id, scenario) for scenario in scenario_list)

        self.questions = []
        seen_questions = set()
        if questions is None:
            question_items = []
        elif isinstance(questions, (InquiryQuestion, Mapping)):
            question_items = [questions]
        else:
            question_items = questions
        for item in question_items:
            question = _coerce_question(item)
            if question.id in seen_questions:
                raise InquiryError('Duplicate question ID "{0}"'.format(question.id))
            seen_questions.add(question.id)
            self.questions.append(question.prepare(scenario_list))

        self._outcome_order = []
        for scenario in scenario_list:
            if scenario.outcome not in self._outcome_order:
                self._outcome_order.append(scenario.outcome)
        self._cache = {}

    def _scenarios(self, subset):
        wanted = frozenset(subset)
        return [scenario for scenario in self.scenarios if scenario.id in wanted]

    def _total_weight(self, subset):
        return sum((self._by_id[scenario_id].weight for scenario_id in subset), D("0"))

    def _leaf(self, subset, cost_so_far, remaining_budget, analyze_missing):
        scenarios = self._scenarios(subset)
        outcomes = {scenario.outcome for scenario in scenarios}
        pure = len(outcomes) == 1
        total_weight = self._total_weight(subset)
        unresolved_mass = D("0") if pure else total_weight
        node = DecisionNode(
            "leaf",
            scenarios,
            cost_so_far,
            cost_so_far,
            unresolved_mass,
            self._outcome_order,
        )
        if pure:
            node.decision = scenarios[0].outcome
            return _Solution(node, 0, 0)

        node.unresolved = True
        node.missing = self._missing_evidence(
            subset, cost_so_far, remaining_budget, analyze_missing
        )
        return _Solution(node, 0, 0)

    def _missing_evidence(self, subset, cost_so_far, remaining_budget, analyze_missing):
        scenarios = self._scenarios(subset)
        missing = OrderedDict()
        missing["reason"] = "no_applicable_question_separates_remaining_outcomes"
        missing["outcome_counts"] = _counts(scenarios, "outcome", self._outcome_order)
        missing["outcome_weights"] = _weight_counts(scenarios, self._outcome_order)
        missing["score_range"] = _score_range(scenarios)
        missing["remaining_budget"] = (
            _number(remaining_budget) if remaining_budget is not None else None
        )

        remaining_metrics = _remaining_metrics(scenarios)
        missing["remaining_metrics"] = remaining_metrics
        missing["missing_metrics"] = list(remaining_metrics)

        candidates = []
        for question in self.questions:
            if not question.applies_to(subset):
                continue
            groups = question.groups_for(subset, self._scenario_order)
            if len(groups) < 2:
                continue
            answer_groups = OrderedDict()
            for label, scenario_ids in groups.items():
                group_scenarios = [self._by_id[scenario_id] for scenario_id in scenario_ids]
                answer_groups[label] = OrderedDict(
                    [
                        ("scenario_count", len(scenario_ids)),
                        (
                            "outcomes",
                            _counts(group_scenarios, "outcome", self._outcome_order),
                        ),
                    ]
                )
            affordable = remaining_budget is None or question.cost <= remaining_budget
            shortfall = D("0")
            if remaining_budget is not None and question.cost > remaining_budget:
                shortfall = question.cost - remaining_budget
            candidates.append(
                OrderedDict(
                    [
                        ("question_id", question.id),
                        ("prompt", question.prompt),
                        ("cost", _number(question.cost)),
                        ("affordable", affordable),
                        ("shortfall", _number(shortfall)),
                        ("answers", answer_groups),
                    ]
                )
            )

        extra_budget = None
        reason = "no_applicable_question_separates_remaining_outcomes"
        if candidates:
            reason = "questions_cannot_resolve_all_outcomes"
        if analyze_missing:
            unlimited = self._solve(frozenset(subset), None, cost_so_far, analyze_missing=False)
            if unlimited.node.worst_unresolved_mass == D("0"):
                extra_budget = unlimited.node.worst_cost - cost_so_far
                if remaining_budget is not None and extra_budget > remaining_budget:
                    reason = "budget_exhausted"
                else:
                    reason = "budget_insufficient_after_answers"

        missing["reason"] = reason
        missing["candidate_questions"] = candidates
        missing["minimum_extra_budget"] = (
            _number(extra_budget) if extra_budget is not None else None
        )
        missing["missing_budget"] = (
            _number(max(D("0"), extra_budget - remaining_budget))
            if extra_budget is not None and remaining_budget is not None
            else None
        )
        examples = OrderedDict()
        for scenario in scenarios:
            examples.setdefault(scenario.outcome, [])
            if len(examples[scenario.outcome]) < 3:
                examples[scenario.outcome].append(
                    OrderedDict([("id", scenario.id), ("vector", scenario.vector)])
                )
        missing["examples"] = examples
        return missing

    def _solve(self, subset, remaining_budget, cost_so_far, analyze_missing=True):
        """
        Return the best subtree for a state.

        ``remaining_budget`` is a path-local budget.  The cache key includes
        ``cost_so_far`` for unlimited plans because the same subset can be
        reached by paths that spent different amounts.
        """
        key = (
            frozenset(subset),
            remaining_budget,
            cost_so_far if remaining_budget is None else None,
            analyze_missing,
        )
        if key in self._cache:
            return self._cache[key]

        scenarios = self._scenarios(subset)
        if len({scenario.outcome for scenario in scenarios}) <= 1:
            solution = self._leaf(subset, cost_so_far, remaining_budget, analyze_missing)
            self._cache[key] = solution
            return solution

        candidates = []
        for question in self.questions:
            if not question.applies_to(subset):
                continue
            if remaining_budget is not None and question.cost > remaining_budget:
                continue
            groups = question.groups_for(subset, self._scenario_order)
            if len(groups) < 2:
                continue

            next_budget = remaining_budget - question.cost if remaining_budget is not None else None
            child_solutions = OrderedDict()
            branch_unresolved = D("0")
            branch_worst_cost = D("0")
            child_question_count = 0
            child_depth = 0
            for label, scenario_ids in groups.items():
                child = self._solve(
                    frozenset(scenario_ids),
                    next_budget,
                    cost_so_far + question.cost,
                    analyze_missing,
                )
                child_solutions[label] = child.node
                if child._question_count > child_question_count:
                    child_question_count = child._question_count
                if child._depth > child_depth:
                    child_depth = child._depth
                if child.node.worst_unresolved_mass > branch_unresolved:
                    branch_unresolved = child.node.worst_unresolved_mass
                if child.node.worst_cost > branch_worst_cost:
                    branch_worst_cost = child.node.worst_cost
            candidates.append(
                _Candidate(
                    question,
                    child_solutions,
                    branch_unresolved,
                    branch_worst_cost,
                    child_question_count,
                    child_depth,
                )
            )

        if not candidates:
            solution = self._leaf(subset, cost_so_far, remaining_budget, analyze_missing)
            self._cache[key] = solution
            return solution

        candidates.sort(key=lambda candidate: candidate.key())
        best = candidates[0]
        node = DecisionNode(
            "question",
            scenarios,
            cost_so_far,
            best.worst_cost,
            best.unresolved_mass,
            self._outcome_order,
        )
        node.question = best.question
        node.answers = best.children
        node.alternatives = [
            OrderedDict(
                [
                    ("question_id", candidate.question.id),
                    ("worst_unresolved_mass", _number(candidate.unresolved_mass)),
                    ("worst_cost", _number(candidate.worst_cost)),
                    ("complete", candidate.unresolved_mass == D("0")),
                ]
            )
            for candidate in candidates
        ]
        solution = _Solution(node, best.question_count, best.depth)
        self._cache[key] = solution
        return solution

    def plan(self):
        subsets = frozenset(self._scenario_order)
        solution = self._solve(subsets, self.budget, D("0"), analyze_missing=True)
        return InquiryPlan(solution.node, self)


def plan_inquiries(
    scenarios,
    questions,
    threshold,
    budget=None,
    score="base",
    outcome_labels=(OUTCOME_HOLD, OUTCOME_NORMAL),
    classifier=None,
    weights=None,
):
    """
    Build a minimax inquiry decision tree for CVSS release triage.

    Args:
        scenarios: Mapping ``scenario_id -> full CVSS vector``, a sequence of
            vectors, or a sequence of ``(id, vector)`` pairs.  Use
            :func:`enumerate_scenarios` to expand remaining metric choices.
        questions: Sequence of :class:`InquiryQuestion` objects or dictionaries
            with ``id``, ``prompt``, ``cost`` and one of ``metric``/``answers``
            (partition) or ``split``.
        threshold: Numeric score threshold; a severity name (``"High"`` etc.);
            or ``None`` when ``classifier`` is used.  Scores at or above the
            threshold receive ``outcome_labels[0]`` (default ``"hold"``).
        budget: Optional maximum inquiry cost on any root-to-leaf path.
        score: ``"base"`` (default), ``"temporal"``, ``"environmental"``, an
            index into ``scores()``, or a callable receiving the CVSS object.
        outcome_labels: ``(at_or_above, below)`` labels, default
            ``("hold", "normal")``.
        classifier: Optional callable receiving the numeric score and returning
            an outcome label.  It overrides ``threshold``.
        weights: Optional scenario weights, used only to measure unresolved
            mass in the worst leaf.  They are not averaged across branches.

    Returns:
        InquiryPlan: Auditable tree, flat leaf list with worst costs, and
        serialization through ``as_dict()``/``to_json()``.
    """
    return InquiryPlanner(
        scenarios,
        questions,
        threshold,
        budget=budget,
        score=score,
        outcome_labels=outcome_labels,
        classifier=classifier,
        weights=weights,
    ).plan()


# Readable aliases for callers that prefer the domain wording.
build_decision_tree = plan_inquiries
