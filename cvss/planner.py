"""
In-memory remediation planning for CVSS4.

The planner deliberately treats :class:`cvss.cvss4.CVSS4` as the scoring kernel.  Every
candidate combination is materialised as a CVSS4 vector and scored by the normal parser and
lookup-table implementation; the planner never estimates a score by adding per-action deltas.
That is important because CVSS4 metrics are normalised through macro-vectors and can offset one
another.

The public API is intentionally small:

* :class:`CVSS4Action` describes one caller-supplied metric transformation, its cost, and the
  actions it cannot be combined with.
* :class:`CVSS4Planner` enumerates feasible subsets, scores them with the real kernel, and exposes
  the Pareto frontier for the objectives ``(residual score, cost)``.
* :class:`CVSS4Plan` is a dict-like result.  It contains the resulting vector, score, cost,
  objective vector, and a human-readable rationale.  ``plan.recompute_objectives()`` rebuilds the
  objective vector from the vector and cost.

The module performs no I/O and stores no state outside the planner instance.
"""

from __future__ import unicode_literals

import copy
from itertools import combinations
from numbers import Number

from .constants4 import (
    METRICS_ABBREVIATIONS,
    METRICS_MANDATORY,
    METRICS_VALUE_NAMES,
)
from .cvss4 import CVSS4
from .exceptions import CVSS4PlanningError

try:
    from collections.abc import Mapping
except ImportError:  # pragma: no cover - Python 2 compatibility
    from collections import Mapping

try:
    string_types = (basestring,)  # noqa: F821 - Python 2 compatibility
except NameError:  # pragma: no cover - Python 3
    string_types = (str,)


_NAME_KEYS = ("name", "id", "action", "key")
_CHANGE_KEYS = (
    "changes",
    "transformations",
    "metric_changes",
    "metrics",
    "transform",
    "transforms",
    "change",
    "mutation",
    "patch",
)
_COST_KEYS = ("cost", "effort", "price", "expense", "weight")
_CONFLICT_KEYS = (
    "conflicts",
    "conflicts_with",
    "incompatible_with",
    "excludes",
    "excluded_by",
    "incompatible",
    "mutex",
    "mutually_exclusive_with",
)
_DESCRIPTION_KEYS = ("description", "rationale", "note", "notes")
_ACTION_SPEC_KEYS = set(
    _NAME_KEYS
    + _CHANGE_KEYS
    + _COST_KEYS
    + _CONFLICT_KEYS
    + _DESCRIPTION_KEYS
    + ("enabled", "active", "label")
)

_EPSILON = 1e-9


def _round1(value):
    """Round for display without introducing binary floating-point surprises."""
    return float("{0:.1f}".format(float(value) + _EPSILON))


def _as_string(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return "{0}".format(value)


def _normalize_metric(metric):
    metric = _as_string(metric).strip()
    if metric in METRICS_VALUE_NAMES:
        return metric
    upper = metric.upper()
    if upper in METRICS_VALUE_NAMES:
        return upper
    raise CVSS4PlanningError('Unknown CVSS4 metric "{0}" in action transformation'.format(metric))


def _normalize_value(metric, value):
    value = _as_string(value).strip()
    allowed = METRICS_VALUE_NAMES[metric]
    if value in allowed:
        return value
    case_insensitive = [candidate for candidate in allowed if candidate.lower() == value.lower()]
    if len(case_insensitive) == 1:
        return case_insensitive[0]
    raise CVSS4PlanningError(
        'Invalid value "{0}" for CVSS4 metric "{1}"; expected one of {2}'.format(
            value, metric, ", ".join(allowed)
        )
    )


def _split_change_text(text):
    text = text.strip()
    if not text:
        return []
    fields = []
    for separator in ("/", ",", ";"):
        text = text.replace(separator, "|")
    for field in text.split("|"):
        field = field.strip()
        if not field:
            continue
        if ":" not in field:
            raise CVSS4PlanningError(
                'Malformed metric change "{0}"; expected METRIC:VALUE'.format(field)
            )
        metric, value = field.split(":", 1)
        fields.append((metric, value))
    return fields


def _normalize_change_mapping(changes, action_name=None):
    """
    Converts supported caller forms into ``{metric: value}``.

    Accepted forms are a mapping, an iterable of two- or three-item iterables, a string such as
    ``"VC:L/VI:L"``, or a callable.  A three-item iterable is interpreted as
    ``(metric, old_value, new_value)`` so callers can keep an audit trail in their action data.
    """
    prefix = 'Action "{0}": '.format(action_name) if action_name is not None else ""
    if changes is None:
        return {}
    if isinstance(changes, string_types):
        items = _split_change_text(changes)
    elif isinstance(changes, Mapping):
        items = list(changes.items())
    else:
        items = []
        try:
            iterator = iter(changes)
        except TypeError:
            raise CVSS4PlanningError(prefix + "metric changes must be a mapping or iterable")
        for item in iterator:
            if isinstance(item, string_types):
                items.extend(_split_change_text(item))
                continue
            try:
                item = list(item)
            except TypeError:
                raise CVSS4PlanningError(
                    prefix + "each metric change must be METRIC:VALUE or a sequence"
                )
            if len(item) == 2:
                items.append((item[0], item[1]))
            elif len(item) == 3:
                items.append((item[0], item[2]))
            else:
                raise CVSS4PlanningError(
                    prefix + "each metric change must contain two or three items"
                )

    normalized = {}
    for metric, value in items:
        metric = _normalize_metric(metric)
        if isinstance(value, Mapping):
            value = value.get("to", value.get("new", value.get("value")))
        elif isinstance(value, (list, tuple)) and len(value) == 2:
            value = value[1]
        normalized[metric] = _normalize_value(metric, value)
    return normalized


def _normalize_refs(refs):
    if refs is None:
        return []
    if isinstance(refs, string_types):
        return [refs]
    if isinstance(refs, Mapping):
        return list(refs.keys())
    return [ref for ref in refs]


def _pop_first(spec, keys, default=None):
    for key in keys:
        if key in spec:
            return spec.pop(key)
    return default


def _pop_merged_changes(spec):
    changes = {}
    transform = None
    for key in _CHANGE_KEYS:
        if key not in spec:
            continue
        value = spec.pop(key)
        if value is None:
            continue
        if callable(value):
            if transform is not None:
                raise CVSS4PlanningError("Only one callable metric transformation is allowed")
            transform = value
            continue
        changes.update(_normalize_change_mapping(value))
    return changes, transform


class _Record(dict):
    """A dict whose keys are also available as attributes."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self[name] = value

    def __delattr__(self, name):
        try:
            del self[name]
        except KeyError:
            raise AttributeError(name)


class _ObjectiveVector(tuple):
    """A (score, cost) tuple that also compares cleanly with lists and mappings."""

    def __new__(cls, score, cost=None):
        if cost is None and isinstance(score, (list, tuple)) and len(score) == 2:
            score, cost = score
        return tuple.__new__(cls, (score, cost))

    @property
    def score(self):
        return self[0]

    @property
    def cost(self):
        return self[1]

    def __eq__(self, other):
        if isinstance(other, Mapping):
            other_score = other.get("score", other.get("risk"))
            return other_score == self[0] and other.get("cost") == self[1]
        if isinstance(other, (list, tuple)) and len(other) == 2:
            return tuple(self) == tuple(other)
        return tuple.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = tuple.__hash__


class _PlanSequence(list):
    """A list that can also be called, for compatibility with attribute/method styles."""

    def __call__(self):
        return list(self)


class CVSS4Action(_Record):
    """
    One caller-supplied remediation action.

    Args:
        name: Identifier for the action.  ``id`` is accepted as a keyword alias.
        changes: Metric transformation.  A mapping (``{"VC": "L"}``), an iterable of pairs/
            triples, or a string such as ``"VC:L/VI:L"``.  ``transformations``, ``metrics`` and
            ``metric_changes`` are accepted aliases.  A callable may be supplied through the
            ``transform`` alias; it receives a copy of the explicit metric dict and returns a
            mapping of changes (or mutates and returns ``None``).
        cost: Non-negative cost/effort of the action.
        conflicts: Action names or ids that cannot be selected with this action.  ``excludes``,
            ``mutex`` and ``conflicts_with`` are accepted aliases.

    Additional fields such as ``description`` are retained and copied into plan rationales.
    """

    def __init__(self, name=None, changes=None, cost=0.0, conflicts=None, **kwargs):
        if isinstance(name, Mapping):
            spec = dict(name)
            if kwargs:
                spec.update(kwargs)
            name = None
        else:
            spec = dict(kwargs)

        if name is not None:
            spec.setdefault("name", name)
        if changes is not None:
            spec.setdefault("changes", changes)
        if cost is not None and cost != 0.0:
            spec.setdefault("cost", cost)
        if conflicts is not None:
            spec.setdefault("conflicts", conflicts)

        action_id = spec.pop("id", None)
        action_name = spec.pop("name", None)
        if action_name is None:
            action_name = spec.pop("action", None)
        if action_name is None:
            action_name = spec.pop("key", None)
        if action_id is None:
            action_id = action_name
        if action_name is None:
            action_name = action_id
        if action_name is None:
            raise CVSS4PlanningError("Every CVSS4 action needs a name or id")
        action_name = _as_string(action_name)
        action_id = _as_string(action_id)

        normalized_changes, transform = _pop_merged_changes(spec)
        normalized_cost = _pop_first(spec, _COST_KEYS, 0.0)
        if isinstance(normalized_cost, bool) or not isinstance(normalized_cost, Number):
            raise CVSS4PlanningError(
                'Action "{0}": cost must be a non-negative number'.format(action_name)
            )
        normalized_cost = float(normalized_cost)
        if normalized_cost < 0:
            raise CVSS4PlanningError(
                'Action "{0}": cost must be a non-negative number'.format(action_name)
            )

        conflict_values = []
        for key in _CONFLICT_KEYS:
            if key in spec:
                conflict_values.extend(_normalize_refs(spec.pop(key)))
        enabled = bool(_pop_first(spec, ("enabled", "active"), True))
        description = _pop_first(spec, _DESCRIPTION_KEYS, None)
        label = spec.pop("label", None)

        super(CVSS4Action, self).__init__()
        self["id"] = action_id
        self["name"] = action_name
        self["label"] = _as_string(label) if label is not None else action_name
        self["changes"] = normalized_changes
        self["cost"] = normalized_cost
        self["conflicts"] = [
            ref if isinstance(ref, int) and not isinstance(ref, bool) else _as_string(ref)
            for ref in conflict_values
        ]
        self["enabled"] = enabled
        self["description"] = description
        self["transform"] = transform
        if spec:
            self["extra"] = copy.deepcopy(spec)

    def as_dict(self):
        data = dict(self)
        data["changes"] = dict(self["changes"])
        data["conflicts"] = list(self["conflicts"])
        data["transform"] = None if self["transform"] is None else repr(self["transform"])
        return data


class CVSS4Plan(_Record):
    """
    A scored, feasible remediation combination.

    The objective vector is ``(score, cost)`` and both components are minimised.  It can always
    be rebuilt with :meth:`recompute_objectives`, which invokes the same CVSS4 kernel on
    ``plan["vector"]``.
    """

    def recompute_objectives(self):
        score = CVSS4(self["vector"]).base_score
        return (score, self["cost"])

    def recompute_objective_vector(self):
        return self.recompute_objectives()

    def recompute(self):
        return self.recompute_objectives()

    def score_from_kernel(self):
        return CVSS4(self["vector"]).base_score

    def recomputed_score(self):
        return self.score_from_kernel()

    def objectives_match(self):
        score, cost = self.recompute_objectives()
        return abs(score - self["score"]) < _EPSILON and abs(cost - self["cost"]) < _EPSILON

    def as_dict(self):
        data = copy.deepcopy(dict(self))
        data["objective_vector"] = tuple(self["objective_vector"])
        data["objectives"] = dict(self["objectives"])
        return data


class CVSS4Planner(object):
    """
    Enumerate and score CVSS4 remediation combinations in memory.

    Args:
        base_vector: A CVSS4 vector or an existing :class:`CVSS4` instance.
        actions: Iterable of :class:`CVSS4Action` objects or action mappings.  A mapping of
            ``{id: changes}`` is also accepted.
        max_actions: Maximum number of actions per maintenance window.  ``budget`` is accepted as
            an alias when it is an integer.
        fixed_metrics: Metrics outside the caller's control.  Either an iterable of metric names
            or a mapping of metric name to its required effective value.  ``locked`` and
            ``immutable_metrics`` are aliases.
        release_threshold: Score at or below which a plan is release-eligible.
        exclusions: Extra mutually-exclusive pairs/groups.  Action-level ``conflicts`` are also
            honoured.
        mutable_metrics: Optional allow-list; metrics not listed are treated as fixed.
        include_empty: Include the do-nothing plan in enumeration (default false).
        cost_budget: Optional maximum total cost for a feasible plan.

    The planner caches all feasible plans after construction.  No mutation of the supplied
    actions affects the cached result.
    """

    def __init__(
        self,
        base_vector,
        actions=None,
        max_actions=2,
        fixed_metrics=None,
        release_threshold=None,
        exclusions=None,
        mutable_metrics=None,
        include_empty=False,
        cost_budget=None,
        min_actions=1,
        **kwargs
    ):
        if "threshold" in kwargs:
            if release_threshold is not None:
                raise TypeError("Specify either release_threshold or threshold, not both")
            release_threshold = kwargs.pop("threshold")
        if "risk_limit" in kwargs:
            if release_threshold is not None:
                raise TypeError("Specify only one release threshold")
            release_threshold = kwargs.pop("risk_limit")
        if "release_gate" in kwargs:
            if release_threshold is not None:
                raise TypeError("Specify only one release threshold")
            release_threshold = kwargs.pop("release_gate")
        if "release_line" in kwargs:
            if release_threshold is not None:
                raise TypeError("Specify only one release threshold")
            release_threshold = kwargs.pop("release_line")

        for alias in (
            "fixed",
            "frozen_metrics",
            "locked",
            "locked_metrics",
            "immutable_metrics",
            "immutable",
        ):
            if alias in kwargs:
                if fixed_metrics is not None:
                    raise TypeError("Specify only one fixed-metric argument")
                fixed_metrics = kwargs.pop(alias)

        if "mutable" in kwargs:
            if mutable_metrics is not None:
                raise TypeError("Specify only one mutable-metric argument")
            mutable_metrics = kwargs.pop("mutable")

        for alias in (
            "conflicts",
            "mutex",
            "mutually_exclusive",
            "excluded_actions",
            "exclusion_pairs",
        ):
            if alias in kwargs:
                if exclusions is not None:
                    raise TypeError("Specify only one exclusion argument")
                exclusions = kwargs.pop(alias)

        for alias in ("window", "max_actions_per_window", "max_changes", "action_limit"):
            if alias in kwargs:
                if max_actions != 2:
                    raise TypeError("Specify only one action limit")
                max_actions = kwargs.pop(alias)

        if "exact_actions" in kwargs or "window_size" in kwargs:
            exact = kwargs.pop("exact_actions", kwargs.pop("window_size", None))
            if min_actions != 1 or max_actions != 2:
                raise TypeError("Specify only one action-count constraint")
            min_actions = max_actions = exact
        elif "min_actions" in kwargs:
            if min_actions != 1:
                raise TypeError("Specify only one minimum action count")
            min_actions = kwargs.pop("min_actions")

        if "budget" in kwargs:
            budget = kwargs.pop("budget")
            if isinstance(budget, bool):
                raise TypeError("budget must be an action count or a number")
            if isinstance(budget, int) and max_actions == 2:
                max_actions = budget
            elif cost_budget is None:
                cost_budget = budget
            else:
                raise TypeError("Specify only one cost budget")

        for alias in ("max_cost", "cost_limit"):
            if alias in kwargs:
                if cost_budget is not None:
                    raise TypeError("Specify only one cost budget")
                cost_budget = kwargs.pop(alias)

        if kwargs:
            raise TypeError(
                "Unexpected CVSS4Planner argument(s): {0}".format(", ".join(sorted(kwargs.keys())))
            )

        if isinstance(base_vector, CVSS4):
            self.base_vector = base_vector.clean_vector()
        elif isinstance(base_vector, string_types):
            self.base_vector = _as_string(base_vector)
        else:
            raise CVSS4PlanningError("base_vector must be a CVSS4 vector string or CVSS4 instance")

        self.base = CVSS4(self.base_vector)
        self.base_vector = self.base.clean_vector()
        self.base = CVSS4(self.base_vector)
        self.base_score = self.base.base_score
        self.base_metrics = dict(self.base.original_metrics)

        if isinstance(max_actions, bool) or not isinstance(max_actions, int):
            raise CVSS4PlanningError("max_actions must be a non-negative integer")
        if max_actions < 0:
            raise CVSS4PlanningError("max_actions must be a non-negative integer")
        if isinstance(min_actions, bool) or not isinstance(min_actions, int):
            raise CVSS4PlanningError("min_actions must be a non-negative integer")
        if min_actions < 0:
            raise CVSS4PlanningError("min_actions must be a non-negative integer")
        if min_actions > max_actions:
            raise CVSS4PlanningError("min_actions cannot exceed max_actions")
        if release_threshold is not None:
            try:
                release_threshold = float(release_threshold)
            except (TypeError, ValueError):
                raise CVSS4PlanningError("release_threshold must be a number between 0 and 10")
            if release_threshold < 0 or release_threshold > 10:
                raise CVSS4PlanningError("release_threshold must be a number between 0 and 10")
        if cost_budget is not None:
            if isinstance(cost_budget, bool) or not isinstance(cost_budget, Number):
                raise CVSS4PlanningError("cost_budget must be a non-negative number")
            cost_budget = float(cost_budget)
            if cost_budget < 0:
                raise CVSS4PlanningError("cost_budget must be a non-negative number")

        self.max_actions = max_actions
        self.min_actions = min_actions
        self.release_threshold = release_threshold
        self.cost_budget = cost_budget
        self.include_empty = bool(include_empty)

        self.actions = self._coerce_actions(actions)
        self._action_by_id = {}
        self._action_by_name = {}
        self._action_index = {}
        for index, action in enumerate(self.actions):
            if action["id"] in self._action_by_id:
                raise CVSS4PlanningError('Duplicate action id "{0}"'.format(action["id"]))
            if action["name"] in self._action_by_name:
                raise CVSS4PlanningError('Duplicate action name "{0}"'.format(action["name"]))
            self._action_by_id[action["id"]] = action
            self._action_by_name[action["name"]] = action
            self._action_index[action["id"]] = index
            if action["name"] != action["id"]:
                self._action_index[action["name"]] = index

        self.fixed_metrics = self._normalize_fixed_metrics(fixed_metrics)
        self.mutable_metrics = self._normalize_mutable_metrics(mutable_metrics)
        self.conflicts = self._normalize_conflicts(exclusions)

        self.rejected_actions = []
        self._action_rejections = {}
        for action in self.actions:
            reason = self._static_action_rejection(action)
            if reason is not None:
                self._action_rejections[action["id"]] = reason
                self.rejected_actions.append(
                    _Record({"id": action["id"], "name": action["name"], "reason": reason})
                )

        self.infeasible_combinations = []
        self._all_plans = []
        self._plans_by_indices = {}
        self._single_action_plans = []
        self._prepare()

    @staticmethod
    def _looks_like_action_spec(value):
        return isinstance(value, Mapping) and bool(_ACTION_SPEC_KEYS.intersection(value.keys()))

    def _coerce_actions(self, actions):
        if actions is None:
            return []
        if isinstance(actions, CVSS4Action):
            source = [actions]
        elif self._looks_like_action_spec(actions):
            source = [actions]
        elif isinstance(actions, Mapping):
            source = []
            for key, value in actions.items():
                if isinstance(value, CVSS4Action):
                    if value["id"] == value["name"]:
                        value = CVSS4Action(value)
                        value["id"] = _as_string(key)
                        value["name"] = _as_string(key)
                    source.append(value)
                elif self._looks_like_action_spec(value):
                    spec = dict(value)
                    spec.setdefault("name", key)
                    source.append(spec)
                else:
                    source.append({"name": key, "changes": value})
        else:
            source = list(actions)

        coerced = []
        for index, action in enumerate(source):
            if isinstance(action, CVSS4Action):
                coerced.append(action)
                continue
            if isinstance(action, Mapping):
                coerced.append(CVSS4Action(action))
                continue
            raise CVSS4PlanningError(
                "Action at position {0} must be CVSS4Action or a mapping".format(index)
            )
        return coerced

    def _normalize_fixed_metrics(self, fixed_metrics):
        fixed = {}
        if fixed_metrics is None:
            return fixed
        if isinstance(fixed_metrics, string_types):
            fixed_metrics = [fixed_metrics]
        if isinstance(fixed_metrics, Mapping):
            for metric, value in fixed_metrics.items():
                metric = _normalize_metric(metric)
                value = _normalize_value(metric, value)
                actual = self.base.m(metric)
                if actual != value:
                    raise CVSS4PlanningError(
                        'Fixed metric "{0}" is {1} in the base vector, not {2}'.format(
                            metric, actual, value
                        )
                    )
                fixed[metric] = value
            return fixed
        for metric in fixed_metrics:
            metric = _normalize_metric(metric)
            fixed[metric] = self.base.m(metric)
        return fixed

    def _normalize_mutable_metrics(self, mutable_metrics):
        if mutable_metrics is None:
            return None
        if isinstance(mutable_metrics, string_types):
            mutable_metrics = [mutable_metrics]
        return set(_normalize_metric(metric) for metric in mutable_metrics)

    def _normalize_conflicts(self, exclusions):
        pairs = set()

        def add_group(group):
            refs = list(group)
            for left, right in combinations(refs, 2):
                left_index = self._resolve_action_ref(left)
                right_index = self._resolve_action_ref(right)
                if left_index == right_index:
                    continue
                pairs.add((min(left_index, right_index), max(left_index, right_index)))

        for action in self.actions:
            refs = list(action["conflicts"])
            if "*" in refs:
                action_index = self._action_index[action["id"]]
                for other_index in range(len(self.actions)):
                    if other_index != action_index:
                        pairs.add((min(action_index, other_index), max(action_index, other_index)))
                refs = [ref for ref in refs if ref != "*"]
            for ref in refs:
                add_group([action["id"], ref])

        if exclusions is None:
            return pairs
        if isinstance(exclusions, Mapping):
            for key, refs in exclusions.items():
                for ref in _normalize_refs(refs):
                    add_group([key, ref])
            return pairs
        if isinstance(exclusions, string_types):
            exclusions = [part for part in exclusions.replace(",", " ").split() if part]
        exclusions = list(exclusions)
        if exclusions and all(isinstance(item, string_types) for item in exclusions):
            add_group(exclusions)
            return pairs
        for item in exclusions:
            if isinstance(item, string_types):
                refs = [part for part in item.replace(",", " ").split() if part]
            else:
                refs = list(item)
            if len(refs) >= 2:
                add_group(refs)
        return pairs

    def _resolve_action_ref(self, ref):
        if isinstance(ref, CVSS4Action):
            ref = ref["id"]
        elif isinstance(ref, Mapping):
            ref = ref.get("id", ref.get("name"))
        if isinstance(ref, int) and not isinstance(ref, bool):
            if 0 <= ref < len(self.actions):
                return ref
            raise CVSS4PlanningError("Action index {0} is out of range".format(ref))
        ref = _as_string(ref)
        try:
            return self._action_index[ref]
        except KeyError:
            raise CVSS4PlanningError('Unknown action referenced by exclusion: "{0}"'.format(ref))

    def _is_locked(self, metric):
        if self.mutable_metrics is not None and metric not in self.mutable_metrics:
            return True
        if not self.fixed_metrics:
            return False
        if metric in self.fixed_metrics:
            return True
        if metric.startswith("M") and metric[1:] in self.fixed_metrics:
            return True
        if "M" + metric in self.fixed_metrics:
            return True
        return False

    def _static_action_rejection(self, action):
        if not action["enabled"]:
            return "action is disabled"
        for metric in action["changes"]:
            if self._is_locked(metric):
                return 'action changes caller-fixed metric "{0}"'.format(metric)
        if (
            action["cost"] > 0
            and self.cost_budget is not None
            and action["cost"] > self.cost_budget
        ):
            return "action cost exceeds the total cost budget"
        return None

    def _resolve_action_changes(self, action, working):
        if action["transform"] is None:
            return dict(action["changes"])
        candidate = copy.copy(working)
        result = action["transform"](candidate)
        if result is None:
            result = candidate
        if not isinstance(result, Mapping):
            raise CVSS4PlanningError(
                'Action "{0}" transform must return a metric mapping'.format(action["name"])
            )
        return _normalize_change_mapping(result, action["name"])

    def _build_vector(self, working):
        fields = []
        for metric in METRICS_ABBREVIATIONS:
            if metric not in working:
                continue
            value = working[metric]
            if value == "X":
                continue
            fields.append("{0}:{1}".format(metric, value))
        for metric in METRICS_MANDATORY:
            if working.get(metric) in (None, "X"):
                raise CVSS4PlanningError(
                    'Combination removes mandatory metric "{0}"'.format(metric)
                )
        return "CVSS:4.0/" + "/".join(fields)

    def _evaluate_indices(self, indices):
        working = copy.copy(self.base_metrics)
        assigned_by = {}
        applied_changes = []

        for index in indices:
            action = self.actions[index]
            changes = self._resolve_action_changes(action, working)
            for metric, value in changes.items():
                if self._is_locked(metric):
                    raise CVSS4PlanningError(
                        'action "{0}" changes caller-fixed metric "{1}"'.format(
                            action["id"], metric
                        )
                    )
                if metric in assigned_by and working.get(metric) != value:
                    other = self.actions[assigned_by[metric]]["id"]
                    raise CVSS4PlanningError(
                        'actions "{0}" and "{1}" assign different values to metric "{2}"'.format(
                            other, action["id"], metric
                        )
                    )
                assigned_by[metric] = index
                working[metric] = value
            applied_changes.append((action, changes))

        vector = self._build_vector(working)
        scored = CVSS4(vector)
        for metric, expected in self.fixed_metrics.items():
            if scored.m(metric) != expected:
                raise CVSS4PlanningError(
                    'combination changes caller-fixed effective metric "{0}"'.format(metric)
                )
        return vector, scored, working, applied_changes

    def _plan_from_evaluation(self, indices, vector, scored, working, applied_changes):
        actions = [self.actions[index] for index in indices]
        action_ids = [action["id"] for action in actions]
        action_names = [action["name"] for action in actions]
        cost = float(sum(action["cost"] for action in actions))
        score = scored.base_score
        score_delta = _round1(self.base_score - score)

        if len(indices) == 1:
            single_delta_sum = score_delta
        else:
            single_delta_sum = 0.0
            for index in indices:
                single_plan = self._single_action_by_index(index)
                if single_plan is not None:
                    single_delta_sum += single_plan["score_delta"]
            single_delta_sum = _round1(single_delta_sum)
        interaction = _round1(score_delta - single_delta_sum)

        changed_metrics = {}
        for metric in METRICS_ABBREVIATIONS:
            if metric in working and self.base_metrics.get(metric) != working[metric]:
                changed_metrics[metric] = working[metric]
        for metric in working:
            if metric not in changed_metrics and metric not in self.base_metrics:
                changed_metrics[metric] = working[metric]

        meets_threshold = None
        risk_gap = None
        if self.release_threshold is not None:
            meets_threshold = score <= self.release_threshold + _EPSILON
            risk_gap = _round1(score - self.release_threshold)

        reasons = []
        for action, changes in applied_changes:
            rendered = ", ".join(
                "{0} {1}->{2}".format(metric, self.base_metrics.get(metric, "X"), value)
                for metric, value in changes.items()
            )
            reasons.append(
                "{0}: {1} (cost {2:.1f})".format(
                    action["id"], rendered or "no metric change", action["cost"]
                )
            )
        movement = "score {0:.1f} -> {1:.1f} (drop {2:.1f})".format(
            self.base_score, score, score_delta
        )
        if len(actions) > 1:
            movement += (
                "; single-action drops sum to {0:.1f}, combined interaction {1:+.1f}".format(
                    single_delta_sum, interaction
                )
            )
        if self.release_threshold is None:
            threshold_text = "no release threshold supplied"
        elif meets_threshold:
            threshold_text = "meets release threshold {0:.1f}".format(self.release_threshold)
        else:
            threshold_text = "misses release threshold {0:.1f} by {1:.1f}".format(
                self.release_threshold, max(0.0, risk_gap)
            )

        rationale = "{0}; total cost {1:.1f}; {2}.".format(movement, cost, threshold_text)
        if len(actions) > 1 and abs(interaction) >= 0.05:
            reasons.append(
                "Non-additive interaction {0:+.1f}; the combination was scored as a whole "
                "rather than ranked by individual drops.".format(interaction)
            )

        plan = CVSS4Plan()
        plan["id"] = "+".join(action_ids) if action_ids else "baseline"
        plan["actions"] = action_ids
        plan["action_ids"] = action_ids
        plan["action_names"] = action_names
        plan["names"] = action_names
        plan["action_count"] = len(actions)
        plan["changes"] = changed_metrics
        plan["changed_metrics"] = list(changed_metrics.keys())
        plan["action_changes"] = [
            _Record(
                {
                    "id": action["id"],
                    "name": action["name"],
                    "changes": dict(changes),
                    "cost": action["cost"],
                }
            )
            for action, changes in applied_changes
        ]
        plan["vector"] = vector
        plan["vector_string"] = vector
        plan["base_vector"] = self.base_vector
        plan["base_score"] = self.base_score
        plan["score_before"] = self.base_score
        plan["score"] = score
        plan["score_after"] = score
        plan["residual_score"] = score
        plan["risk"] = score
        plan["residual_risk"] = score
        plan["severity"] = scored.severity
        plan["score_delta"] = score_delta
        plan["risk_reduction"] = score_delta
        plan["single_action_delta_sum"] = single_delta_sum
        plan["interaction"] = interaction
        plan["cost"] = cost
        plan["total_cost"] = cost
        plan["objective_vector"] = _ObjectiveVector(score, cost)
        plan["objective_values"] = _ObjectiveVector(score, cost)
        plan["target_vector"] = _ObjectiveVector(score, cost)
        plan["cost_total"] = cost
        plan["selected_actions"] = list(action_ids)
        plan["metrics"] = dict(working)
        plan["objectives"] = _Record({"score": score, "cost": cost})
        plan["objective"] = _Record({"score": score, "cost": cost})
        plan["release_threshold"] = self.release_threshold
        plan["meets_threshold"] = meets_threshold
        plan["threshold_met"] = meets_threshold
        plan["meets_release"] = meets_threshold
        plan["compliant"] = meets_threshold
        plan["below_release_line"] = meets_threshold
        plan["risk_gap"] = risk_gap
        plan["within_cost_budget"] = (
            None if self.cost_budget is None else cost <= self.cost_budget + _EPSILON
        )
        plan["feasible"] = True
        plan["pareto_optimal"] = False
        plan["non_dominated"] = False
        plan["dominated_by"] = []
        plan["rationale"] = rationale
        plan["reason"] = rationale
        plan["why"] = rationale
        plan["reasons"] = reasons
        return plan

    def _single_action_by_index(self, index):
        for plan in self._single_action_plans:
            if plan["action_ids"] == [self.actions[index]["id"]]:
                return plan
        return None

    def _candidate_indices(self):
        indices = range(len(self.actions))
        if self.include_empty:
            yield ()
        lower = max(1, self.min_actions)
        for size in range(lower, min(self.max_actions, len(self.actions)) + 1):
            for combination in combinations(indices, size):
                yield tuple(combination)

    def _conflict_reason(self, indices):
        for left, right in combinations(indices, 2):
            pair = (min(left, right), max(left, right))
            if pair in self.conflicts:
                return 'actions "{0}" and "{1}" are mutually exclusive'.format(
                    self.actions[left]["id"], self.actions[right]["id"]
                )
        return None

    def _prepare(self):
        for indices in self._candidate_indices():
            action_ids = [self.actions[index]["id"] for index in indices]
            if any(index in self._action_rejections for index in indices):
                continue
            reason = self._conflict_reason(indices)
            if reason is not None:
                self.infeasible_combinations.append(
                    _Record({"actions": action_ids, "reason": reason})
                )
                continue
            try:
                vector, scored, working, applied_changes = self._evaluate_indices(indices)
            except CVSS4PlanningError as exc:
                self.infeasible_combinations.append(
                    _Record({"actions": action_ids, "reason": str(exc)})
                )
                continue
            if self.cost_budget is not None:
                total_cost = sum(self.actions[index]["cost"] for index in indices)
                if total_cost > self.cost_budget + _EPSILON:
                    self.infeasible_combinations.append(
                        _Record(
                            {
                                "actions": action_ids,
                                "reason": "total cost {0:.1f} exceeds budget {1:.1f}".format(
                                    total_cost, self.cost_budget
                                ),
                            }
                        )
                    )
                    continue
            plan = self._plan_from_evaluation(indices, vector, scored, working, applied_changes)
            self._plans_by_indices[indices] = plan
            self._all_plans.append(plan)
            if len(indices) == 1:
                self._single_action_plans.append(plan)

        self._mark_pareto()

        self.all_plans = _PlanSequence(self._all_plans)
        self.plans = self.all_plans
        self.feasible_plans = self.all_plans
        self.candidates = self.all_plans
        self.pareto_front = _PlanSequence(
            plan for plan in self._all_plans if plan["pareto_optimal"]
        )
        self.pareto_plans = self.pareto_front
        self.non_dominated_plans = self.pareto_front
        self.front = self.pareto_front
        self.dominated_plans = _PlanSequence(
            plan for plan in self._all_plans if not plan["pareto_optimal"]
        )
        self.compliant_plans = _PlanSequence(
            plan for plan in self._all_plans if plan["compliant"] is True
        )
        self.compliant_front = _PlanSequence(
            plan for plan in self.pareto_front if plan["compliant"] is True
        )
        self.compliant_pareto_front = self.compliant_front
        self.single_action_plans = _PlanSequence(self._single_action_plans)

    @staticmethod
    def _dominates(left, right):
        left_score, left_cost = left["objective_vector"]
        right_score, right_cost = right["objective_vector"]
        no_worse = left_score <= right_score + _EPSILON and left_cost <= right_cost + _EPSILON
        strictly_better = left_score < right_score - _EPSILON or left_cost < right_cost - _EPSILON
        return no_worse and strictly_better

    def _mark_pareto(self):
        for plan in self._all_plans:
            dominators = [
                other["id"]
                for other in self._all_plans
                if other is not plan and self._dominates(other, plan)
            ]
            plan["dominated_by"] = dominators
            plan["pareto_optimal"] = not dominators
            plan["non_dominated"] = not dominators
            if dominators:
                plan["pareto_reason"] = "dominated by {0}".format(", ".join(dominators))
            else:
                plan["pareto_reason"] = (
                    "no feasible plan has both a lower residual score and a lower cost"
                )
            plan["rationale"] = "{0}; {1}.".format(
                plan["rationale"].rstrip("."), plan["pareto_reason"]
            )
            plan["reason"] = plan["rationale"]
            plan["why"] = plan["rationale"]
            plan["reasons"].append("Pareto check: {0}.".format(plan["pareto_reason"]))

        self._all_plans.sort(
            key=lambda plan: (
                plan["score"],
                plan["cost"],
                plan["action_count"],
                plan["id"],
            )
        )

    def evaluate(self, action_refs):
        """
        Scores an explicit action subset and returns its plan, bypassing Pareto filtering.

        The same combination is reused from the cached enumeration when possible.
        """
        indices = tuple(sorted(set(self._resolve_action_ref(ref) for ref in action_refs)))
        if indices in self._plans_by_indices:
            return self._plans_by_indices[indices]
        if any(index in self._action_rejections for index in indices):
            rejected = [
                self._action_rejections[index]
                for index in indices
                if index in self._action_rejections
            ]
            raise CVSS4PlanningError("; ".join(rejected))
        reason = self._conflict_reason(indices)
        if reason is not None:
            raise CVSS4PlanningError(reason)
        vector, scored, working, applied_changes = self._evaluate_indices(indices)
        return self._plan_from_evaluation(indices, vector, scored, working, applied_changes)

    def best(self, prefer="score"):
        """
        Returns the preferred plan.

        If a release threshold is configured and any plan meets it, the choice is restricted to
        compliant plans.  ``prefer="score"`` (default) minimises residual score then cost;
        ``prefer="cost"`` minimises cost then residual score.
        """
        candidates = list(self._all_plans)
        if self.release_threshold is not None and self.compliant_plans:
            candidates = list(self.compliant_plans)
        if not candidates:
            return None
        if prefer == "cost":
            return min(
                candidates,
                key=lambda plan: (
                    plan["cost"],
                    plan["score"],
                    plan["action_count"],
                    plan["id"],
                ),
            )
        if prefer != "score":
            raise ValueError('prefer must be "score" or "cost"')
        return min(
            candidates,
            key=lambda plan: (
                plan["score"],
                plan["cost"],
                plan["action_count"],
                plan["id"],
            ),
        )

    def best_by_cost(self):
        return self.best(prefer="cost")

    def best_plan(self):
        return self.best()

    def cheapest_compliant(self):
        if not self.compliant_plans:
            return None
        return min(
            self.compliant_plans,
            key=lambda plan: (
                plan["cost"],
                plan["score"],
                plan["action_count"],
                plan["id"],
            ),
        )

    def plan(self, compliant_only=False):
        """Returns the Pareto frontier as a list."""
        if compliant_only:
            return [plan for plan in self.pareto_front if plan.get("compliant") is True]
        return list(self.pareto_front)

    def solve(self, compliant_only=False):
        return self.plan(compliant_only=compliant_only)

    def run(self, compliant_only=False):
        return self.plan(compliant_only=compliant_only)

    def pareto(self, compliant_only=False):
        return self.plan(compliant_only=compliant_only)

    def non_dominated(self, compliant_only=False):
        return self.plan(compliant_only=compliant_only)

    def frontier(self, compliant_only=False):
        return self.plan(compliant_only=compliant_only)

    def analyze(self):
        """
        Returns a serialisable report with candidates, frontier, dominated plans, and rejects.
        """
        return {
            "base_vector": self.base_vector,
            "base_score": self.base_score,
            "release_threshold": self.release_threshold,
            "max_actions": self.max_actions,
            "min_actions": self.min_actions,
            "cost_budget": self.cost_budget,
            "fixed_metrics": dict(self.fixed_metrics),
            "actions": [action.as_dict() for action in self.actions],
            "rejected_actions": [dict(item) for item in self.rejected_actions],
            "infeasible_combinations": [dict(item) for item in self.infeasible_combinations],
            "plans": [plan.as_dict() for plan in self.all_plans],
            "pareto_front": [plan.as_dict() for plan in self.pareto_front],
            "dominated": [plan.as_dict() for plan in self.dominated_plans],
            "compliant": [plan.as_dict() for plan in self.compliant_plans],
            "best": None if self.best() is None else self.best().as_dict(),
        }

    def summary(self):
        return self.analyze()

    def report(self):
        return self.analyze()

    def to_dict(self):
        return self.analyze()

    @property
    def result(self):
        return self.analyze()

    def __iter__(self):
        return iter(self.pareto_front)

    def __len__(self):
        return len(self.pareto_front)

    def __getitem__(self, index):
        return self.pareto_front[index]

    def __repr__(self):
        return "CVSS4Planner(base_score={0}, actions={1}, plans={2}, frontier={3})".format(
            self.base_score,
            len(self.actions),
            len(self.all_plans),
            len(self.pareto_front),
        )


def plan_cvss4_remediations(base_vector, actions, **kwargs):
    """
    Convenience wrapper around :class:`CVSS4Planner`.

    Returns the non-dominated plans.  Use ``analyze=True`` to get the full report instead.
    """
    analyze = kwargs.pop("analyze", False)
    planner = CVSS4Planner(base_vector, actions, **kwargs)
    if analyze:
        return planner.analyze()
    return planner.plan()


plan_remediations = plan_cvss4_remediations
plan_actions = plan_cvss4_remediations
plan_cvss4 = plan_cvss4_remediations
plan_cvss4_actions = plan_cvss4_remediations
plan = plan_cvss4_remediations

# Friendly aliases for callers that do not include the version in the class name.
Action = CVSS4Action
Plan = CVSS4Plan
Planner = CVSS4Planner
CVSS4Planning = CVSS4Planner
RemediationAction = CVSS4Action
RemediationPlan = CVSS4Plan
RemediationPlanner = CVSS4Planner

__all__ = [
    "Action",
    "CVSS4Action",
    "CVSS4Plan",
    "CVSS4Planner",
    "Plan",
    "Planner",
    "CVSS4Planning",
    "RemediationAction",
    "RemediationPlan",
    "RemediationPlanner",
    "plan",
    "plan_actions",
    "plan_cvss4",
    "plan_cvss4_actions",
    "plan_cvss4_remediations",
    "plan_remediations",
]
