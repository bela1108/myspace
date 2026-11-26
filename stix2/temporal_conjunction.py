"""Local temporal conjunction queries for STIX 2 indicators.

This module deliberately keeps the temporal contract explicit:

* observation uncertainty is represented as a :class:`TimeWindow`;
* STIX ``valid_from`` is inclusive and ``valid_until`` is exclusive;
* indicator text is selected with real :class:`~stix2.datastore.Filter`
  objects ANDed by a local :class:`~stix2.datastore.MemoryStore`; and
* a possible common time is distinguished from a guarantee over every time
  that remains legal for the supplied observations.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Union

from stix2.base import _STIXBase
from stix2.datastore.filters import Filter
from stix2.datastore.memory import MemoryStore
from stix2.parsing import parse
from stix2.utils import parse_into_datetime


UTC = timezone.utc


class ConjunctionStatus(str, Enum):
    """Verdict codes for the temporal conjunction contract."""

    ALL_LEGAL_TIMES_SUPPORT = "all_legal_times_support"
    SOME_CREDIBLE_COMMON_POINT = "some_credible_common_point"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NO_COMMON_POINT = "no_common_point"


# Friendly aliases for callers that prefer the wording in the request.
ALL_LEGAL_TIMES_SUPPORTED = ConjunctionStatus.ALL_LEGAL_TIMES_SUPPORT
CREDIBLE_COMMON_POINT = ConjunctionStatus.SOME_CREDIBLE_COMMON_POINT
SOME_COMMON_GROUND = ConjunctionStatus.SOME_CREDIBLE_COMMON_POINT
INSUFFICIENT_EVIDENCE = ConjunctionStatus.INSUFFICIENT_EVIDENCE
NO_COMMON_POINT = ConjunctionStatus.NO_COMMON_POINT


class TimePrecision(str, Enum):
    EXACT = "exact"
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"
    INTERVAL = "interval"
    UNKNOWN = "unknown"


class ConjunctionContractError(ValueError):
    """Raised when filters or object selection violate the query contract."""


DateTimeLike = Union[datetime, date, str, None]
EvidenceLike = Union["ObservationEvidence", Mapping[str, Any], _STIXBase, None]

_WEEK_RE = re.compile(r"^(?P<year>\d{4})-W(?P<week>\d{1,2})(?:-(?P<day>[1-7]))?$")


def utc_datetime(value: DateTimeLike) -> Optional[datetime]:
    """Coerce a STIX timestamp, date, or ISO string to aware UTC datetime."""
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day)
    elif isinstance(value, str):
        text = value.strip()
        week_match = _WEEK_RE.match(text)
        if week_match:
            iso_date = date.fromisocalendar(
                int(week_match.group("year")),
                int(week_match.group("week")),
                1,
            )
            parsed = datetime(iso_date.year, iso_date.month, iso_date.day)
        else:
            # stix2's parser accepts STIX timestamps and preserves their
            # precision metadata; only its datetime value is needed here.
            parsed = parse_into_datetime(text)
    else:
        raise TypeError("Unsupported datetime value: %r" % (value,))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def isoformat(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    text = value.astimezone(UTC).isoformat()
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


@dataclasses.dataclass(frozen=True)
class TimeWindow:
    """A temporal interval with explicit endpoint inclusion.

    STIX validity windows use ``[start, end)``. Observed-data bounds are
    normally closed because both ``first_observed`` and ``last_observed`` are
    actual observed extrema.
    """

    start: Optional[datetime] = None
    end: Optional[datetime] = None
    start_inclusive: bool = True
    end_inclusive: bool = False
    precision: str = TimePrecision.INTERVAL.value

    def __post_init__(self) -> None:
        start = utc_datetime(self.start)
        end = utc_datetime(self.end)
        if start is not self.start:
            object.__setattr__(self, "start", start)
        if end is not self.end:
            object.__setattr__(self, "end", end)

        if start is not None and end is not None:
            if start > end:
                raise ValueError("TimeWindow start must not be after end")
            if start == end and not (self.start_inclusive and self.end_inclusive):
                raise ValueError("A zero-length TimeWindow must include both endpoints")

    @property
    def lower(self) -> Optional[datetime]:
        return self.start

    @property
    def upper(self) -> Optional[datetime]:
        return self.end

    @property
    def is_unbounded(self) -> bool:
        return self.start is None and self.end is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": isoformat(self.start),
            "end": isoformat(self.end),
            "lower": isoformat(self.start),
            "upper": isoformat(self.end),
            "start_inclusive": self.start_inclusive,
            "end_inclusive": self.end_inclusive,
            "precision": self.precision,
        }


def exact_point(value: DateTimeLike, ref: Optional[str] = None) -> TimeWindow:
    """Create a closed point interval for an exactly known timestamp."""
    point = utc_datetime(value)
    if point is None:
        raise ValueError("An exact point requires a timestamp")
    return TimeWindow(point, point, True, True, TimePrecision.EXACT.value)


def minute_window(value: DateTimeLike) -> TimeWindow:
    """Return the complete UTC minute containing ``value``."""
    point = utc_datetime(value)
    if point is None:
        raise ValueError("A minute window requires a timestamp")
    start = point.replace(second=0, microsecond=0)
    return TimeWindow(
        start,
        start + timedelta(minutes=1),
        True,
        False,
        TimePrecision.MINUTE.value,
    )


def week_window(value: DateTimeLike) -> TimeWindow:
    """Return the ISO week (Monday 00:00 through next Monday 00:00, UTC)."""
    if isinstance(value, str):
        match = _WEEK_RE.match(value.strip())
        if match:
            monday = date.fromisocalendar(
                int(match.group("year")),
                int(match.group("week")),
                1,
            )
            start = datetime(monday.year, monday.month, monday.day, tzinfo=UTC)
            return TimeWindow(
                start,
                start + timedelta(days=7),
                True,
                False,
                TimePrecision.WEEK.value,
            )

    point = utc_datetime(value)
    if point is None:
        raise ValueError("A week window requires a week, date, or timestamp")
    monday_date = (point - timedelta(days=point.weekday())).date()
    start = datetime(
        monday_date.year,
        monday_date.month,
        monday_date.day,
        tzinfo=UTC,
    )
    return TimeWindow(
        start,
        start + timedelta(days=7),
        True,
        False,
        TimePrecision.WEEK.value,
    )


def precision_window(value: DateTimeLike, precision: str) -> TimeWindow:
    """Expand a coarse timestamp into all legal times for its precision."""
    normalized = precision.lower().replace("_", "-")
    aliases = {
        "exact": TimePrecision.EXACT.value,
        "second": TimePrecision.SECOND.value,
        "seconds": TimePrecision.SECOND.value,
        "minute": TimePrecision.MINUTE.value,
        "minutes": TimePrecision.MINUTE.value,
        "1-minute": TimePrecision.MINUTE.value,
        "hour": TimePrecision.HOUR.value,
        "hours": TimePrecision.HOUR.value,
        "day": TimePrecision.DAY.value,
        "date": TimePrecision.DAY.value,
        "week": TimePrecision.WEEK.value,
        "iso-week": TimePrecision.WEEK.value,
    }
    kind = aliases.get(normalized)
    if kind is None:
        raise ValueError("Unsupported time precision: %r" % precision)

    if kind == TimePrecision.EXACT.value or kind == TimePrecision.SECOND.value:
        point = utc_datetime(value)
        if kind == TimePrecision.SECOND.value and point is not None:
            point = point.replace(microsecond=0)
        return exact_point(point)
    if kind == TimePrecision.MINUTE.value:
        return minute_window(value)
    if kind == TimePrecision.WEEK.value:
        return week_window(value)

    point = utc_datetime(value)
    if point is None:
        raise ValueError("Precision %r requires a timestamp" % precision)
    if kind == TimePrecision.HOUR.value:
        start = point.replace(minute=0, second=0, microsecond=0)
        delta = timedelta(hours=1)
    else:
        start = point.replace(hour=0, minute=0, second=0, microsecond=0)
        delta = timedelta(days=1)
    return TimeWindow(start, start + delta, True, False, kind)


def intersect_windows(
    left: Optional[TimeWindow],
    right: Optional[TimeWindow],
) -> Optional[TimeWindow]:
    """Return the common interval, or ``None`` when no point is legal."""
    if left is None or right is None:
        return None

    if left.start is None:
        start, start_inclusive = right.start, right.start_inclusive
    elif right.start is None:
        start, start_inclusive = left.start, left.start_inclusive
    elif left.start > right.start:
        start, start_inclusive = left.start, left.start_inclusive
    elif right.start > left.start:
        start, start_inclusive = right.start, right.start_inclusive
    else:
        start = left.start
        start_inclusive = left.start_inclusive and right.start_inclusive

    if left.end is None:
        end, end_inclusive = right.end, right.end_inclusive
    elif right.end is None:
        end, end_inclusive = left.end, left.end_inclusive
    elif left.end < right.end:
        end, end_inclusive = left.end, left.end_inclusive
    elif right.end < left.end:
        end, end_inclusive = right.end, right.end_inclusive
    else:
        end = left.end
        end_inclusive = left.end_inclusive and right.end_inclusive

    if start is not None and end is not None:
        if start > end:
            return None
        if start == end and not (start_inclusive and end_inclusive):
            return None

    precision = (
        left.precision
        if left.precision != TimePrecision.UNKNOWN.value
        else right.precision
    )
    return TimeWindow(start, end, start_inclusive, end_inclusive, precision)


def contains_window(outer: Optional[TimeWindow], inner: Optional[TimeWindow]) -> bool:
    """Return whether every legal point of ``inner`` is in ``outer``."""
    if outer is None or inner is None:
        return False

    if inner.start is not None:
        if outer.start is None:
            pass
        elif inner.start < outer.start:
            return False
        elif inner.start == outer.start:
            if not outer.start_inclusive and inner.start_inclusive:
                return False

    if inner.end is not None:
        if outer.end is None:
            pass
        elif inner.end > outer.end:
            return False
        elif inner.end == outer.end:
            if not outer.end_inclusive and inner.end_inclusive:
                return False
    elif outer.end is not None:
        # An unbounded-above inner interval cannot fit a bounded outer one.
        return False

    if inner.start is None and outer.start is not None:
        return False

    return True


@dataclasses.dataclass(frozen=True)
class ObservationEvidence:
    """Provenance and temporal uncertainty for one original observation."""

    observation_ref: Optional[str] = None
    window: Optional[TimeWindow] = None
    precision: str = TimePrecision.UNKNOWN.value
    indicator_ref: Optional[str] = None
    original_time: Optional[str] = None
    needs_time: bool = False
    note: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_ref": self.observation_ref,
            "indicator_ref": self.indicator_ref,
            "precision": self.precision,
            "original_time": self.original_time,
            "window": self.window.to_dict() if self.window else None,
            "needs_time": self.needs_time,
            "note": self.note,
        }


def _mapping_get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    if hasattr(obj, "get"):
        try:
            return obj.get(key, default)
        except (KeyError, TypeError):
            return getattr(obj, key, default)
    return getattr(obj, key, default)


def evidence_from_stix(obj: Any, *, indicator_ref: Optional[str] = None) -> ObservationEvidence:
    """Extract evidence from an observed-data or sighting STIX object."""
    object_type = _mapping_get(obj, "type")
    ref = _mapping_get(obj, "id")
    precision = _mapping_get(obj, "x_time_precision") or TimePrecision.INTERVAL.value

    if object_type == "observed-data":
        first = _mapping_get(obj, "first_observed")
        last = _mapping_get(obj, "last_observed")
        if precision in (None, TimePrecision.INTERVAL.value, TimePrecision.UNKNOWN.value):
            window = TimeWindow(first, last, True, True, TimePrecision.INTERVAL.value)
            original = "%s/%s" % (isoformat(utc_datetime(first)), isoformat(utc_datetime(last)))
        else:
            window = precision_window(first or last, precision)
            original = isoformat(utc_datetime(first or last))
    elif object_type == "sighting":
        first = _mapping_get(obj, "first_seen")
        last = _mapping_get(obj, "last_seen")
        observed_refs = _mapping_get(obj, "observed_data_refs") or []
        if observed_refs:
            ref = observed_refs[0]
        if precision in (None, TimePrecision.INTERVAL.value, TimePrecision.UNKNOWN.value):
            window = TimeWindow(first, last, True, True, TimePrecision.INTERVAL.value)
        else:
            window = precision_window(first or last, precision)
        original = "%s/%s" % (isoformat(utc_datetime(first)), isoformat(utc_datetime(last)))
        indicator_ref = indicator_ref or _mapping_get(obj, "sighting_of_ref")
    else:
        time_value = _mapping_get(obj, "time") or _mapping_get(obj, "timestamp")
        window_value = _mapping_get(obj, "window")
        if isinstance(window_value, TimeWindow):
            window = window_value
        elif isinstance(window_value, Mapping):
            window = TimeWindow(**window_value)
        elif time_value is not None and precision not in (
            None,
            TimePrecision.UNKNOWN.value,
        ):
            window = precision_window(time_value, precision)
        else:
            window = None
        original = isoformat(utc_datetime(time_value)) if time_value else None
        ref = _mapping_get(obj, "observation_ref") or _mapping_get(obj, "ref") or ref
        indicator_ref = indicator_ref or _mapping_get(obj, "indicator_ref")

    return ObservationEvidence(
        observation_ref=ref,
        indicator_ref=indicator_ref,
        window=window,
        precision=precision or TimePrecision.INTERVAL.value,
        original_time=original,
        needs_time=window is None,
    )


def coerce_evidence(
    value: EvidenceLike,
    *,
    indicator_ref: Optional[str] = None,
) -> Optional[ObservationEvidence]:
    if value is None:
        return None
    if isinstance(value, ObservationEvidence):
        if indicator_ref and value.indicator_ref is None:
            return dataclasses.replace(value, indicator_ref=indicator_ref)
        return value
    if isinstance(value, (_STIXBase, Mapping)):
        evidence = evidence_from_stix(value, indicator_ref=indicator_ref)
        if indicator_ref and evidence.indicator_ref is None:
            evidence = dataclasses.replace(evidence, indicator_ref=indicator_ref)
        return evidence
    raise TypeError("Unsupported observation evidence: %r" % (value,))


def evidence_map(
    observations: Union[
        Mapping[str, EvidenceLike],
        Sequence[EvidenceLike],
        None,
    ],
) -> dict[str, ObservationEvidence]:
    """Normalize mapping/list evidence into ``{indicator_ref: evidence}``."""
    result: dict[str, ObservationEvidence] = {}
    if observations is None:
        return result

    if isinstance(observations, Mapping):
        for indicator_ref, value in observations.items():
            evidence = coerce_evidence(value, indicator_ref=indicator_ref)
            if evidence is not None:
                result[indicator_ref] = evidence
        return result

    for value in observations:
        evidence = coerce_evidence(value)
        if evidence is None:
            continue
        if not evidence.indicator_ref:
            raise ConjunctionContractError(
                "List observation evidence must include indicator_ref: %r" % (evidence,),
            )
        result[evidence.indicator_ref] = evidence
    return result


def indicator_window(indicator: Any) -> TimeWindow:
    """Return ``[valid_from, valid_until)`` for a STIX indicator."""
    valid_from = _mapping_get(indicator, "valid_from")
    valid_until = _mapping_get(indicator, "valid_until")
    return TimeWindow(
        utc_datetime(valid_from),
        utc_datetime(valid_until),
        True,
        False,
        TimePrecision.INTERVAL.value,
    )


def build_indicator_filters(
    pattern: Optional[str] = None,
    *,
    spec_version: Optional[str] = None,
    extra_filters: Optional[Sequence[Filter]] = None,
) -> tuple[Filter, ...]:
    """Build the explicit AND filter contract used by local queries."""
    filters: list[Filter] = [Filter("type", "=", "indicator")]
    if pattern is not None:
        if not isinstance(pattern, str) or not pattern.strip():
            raise ConjunctionContractError("pattern must be a non-empty STIX pattern string")
        filters.append(Filter("pattern", "=", pattern))
    if spec_version is not None:
        filters.append(Filter("spec_version", "=", spec_version))
    for item in extra_filters or ():
        if not isinstance(item, Filter):
            raise TypeError("extra_filters must contain stix2.Filter instances")
        filters.append(item)
    return tuple(filters)


def build_local_store(
    objects: Sequence[Any],
    *,
    spec_version: Optional[str] = None,
) -> MemoryStore:
    """Parse objects under one explicit STIX version and put them in MemoryStore."""
    store = MemoryStore()
    for obj in objects:
        if spec_version is not None:
            if isinstance(obj, _STIXBase):
                payload = obj.serialize()
            else:
                payload = obj
            obj = parse(payload, version=spec_version)
        store.add(obj, version=spec_version)
    return store


def select_object_versions(objects: Sequence[Any], policy: str = "all") -> list[Any]:
    """Select all versions or the latest ``modified`` object per STIX ID."""
    if policy == "all":
        return list(objects)
    if policy != "latest":
        raise ConjunctionContractError("version_policy must be 'all' or 'latest'")

    latest: dict[str, Any] = {}
    for obj in objects:
        object_id = _mapping_get(obj, "id")
        current = latest.get(object_id)
        if current is None:
            latest[object_id] = obj
            continue
        current_modified = utc_datetime(_mapping_get(current, "modified"))
        new_modified = utc_datetime(_mapping_get(obj, "modified"))
        if new_modified is not None and (
            current_modified is None or new_modified >= current_modified
        ):
            latest[object_id] = obj
    return list(latest.values())


@dataclasses.dataclass
class IndicatorTemporalAssessment:
    indicator_id: str
    pattern: Optional[str]
    spec_version: Optional[str]
    modified: Optional[datetime]
    validity_window: TimeWindow
    observation: Optional[ObservationEvidence]
    individual_window: Optional[TimeWindow]
    truncated_window: Optional[TimeWindow]
    needs_time: bool
    reasons: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "pattern": self.pattern,
            "spec_version": self.spec_version,
            "modified": isoformat(self.modified),
            "validity_window": self.validity_window.to_dict(),
            "observation": self.observation.to_dict() if self.observation else None,
            "individual_window": self.individual_window.to_dict() if self.individual_window else None,
            "truncated_window": self.truncated_window.to_dict() if self.truncated_window else None,
            "truncated_bounds": _bounds(self.truncated_window),
            "needs_time": self.needs_time,
            "reasons": list(self.reasons),
        }


@dataclasses.dataclass
class ConjunctionResult:
    status: ConjunctionStatus
    pattern: Optional[str]
    spec_version: Optional[str]
    matched_count: int
    filter_contract: list[tuple[str, str, Any]]
    indicators: list[IndicatorTemporalAssessment]
    version_policy: str = "all"
    common_validity_window: Optional[TimeWindow] = None
    common_observation_window: Optional[TimeWindow] = None
    common_window: Optional[TimeWindow] = None
    credible_common_point: bool = False
    all_legal_times_support: bool = False
    observations_needing_time: list[str] = dataclasses.field(default_factory=list)
    refinement_requests: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    truncated_boundaries: dict[str, Optional[dict[str, Any]]] = dataclasses.field(default_factory=dict)
    reasons: list[str] = dataclasses.field(default_factory=list)

    @property
    def insufficient_evidence(self) -> bool:
        return self.status == ConjunctionStatus.INSUFFICIENT_EVIDENCE

    @property
    def has_credible_common_point(self) -> bool:
        return self.credible_common_point

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "status_zh": STATUS_ZH[self.status],
            "pattern": self.pattern,
            "spec_version": self.spec_version,
            "matched_count": self.matched_count,
            "version_policy": self.version_policy,
            "filter_contract": [
                {"property": prop, "op": op, "value": value}
                for prop, op, value in self.filter_contract
            ],
            "credible_common_point": self.credible_common_point,
            "has_credible_common_point": self.has_credible_common_point,
            "all_legal_times_support": self.all_legal_times_support,
            "insufficient_evidence": self.insufficient_evidence,
            "common_validity_window": _window_dict(self.common_validity_window),
            "common_observation_window": _window_dict(self.common_observation_window),
            "common_window": _window_dict(self.common_window),
            "common_boundaries": _bounds(self.common_window),
            "truncated_boundaries": self.truncated_boundaries,
            "observations_needing_time": list(self.observations_needing_time),
            "refinement_requests": list(self.refinement_requests),
            "reasons": list(self.reasons),
            "indicators": [item.to_dict() for item in self.indicators],
        }

    def to_json(self, pretty: bool = True) -> str:
        import json

        if pretty:
            return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=False)
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


STATUS_ZH = {
    ConjunctionStatus.ALL_LEGAL_TIMES_SUPPORT: "所有合法时间都支持",
    ConjunctionStatus.SOME_CREDIBLE_COMMON_POINT: "存在某个可信共同点",
    ConjunctionStatus.INSUFFICIENT_EVIDENCE: "证据不足",
    ConjunctionStatus.NO_COMMON_POINT: "不存在可信共同点",
}


def _window_dict(window: Optional[TimeWindow]) -> Optional[dict[str, Any]]:
    return window.to_dict() if window else None


def _bounds(window: Optional[TimeWindow]) -> Optional[dict[str, Optional[str]]]:
    if window is None:
        return None
    return {
        "start": isoformat(window.start),
        "end": isoformat(window.end),
        "lower": isoformat(window.start),
        "upper": isoformat(window.end),
        "start_inclusive": window.start_inclusive,
        "end_inclusive": window.end_inclusive,
    }


def _filter_contract_data(filters: Sequence[Filter]) -> list[tuple[str, str, Any]]:
    return [(item.property, item.op, item.value) for item in filters]


def assess_indicator(
    indicator: Any,
    evidence: Optional[ObservationEvidence],
    *,
    required_window: Optional[TimeWindow] = None,
) -> IndicatorTemporalAssessment:
    indicator_id = _mapping_get(indicator, "id")
    validity = indicator_window(indicator)
    obs_window = evidence.window if evidence is not None else None
    reasons: list[str] = []
    needs_time = False

    if evidence is None or obs_window is None:
        needs_time = True
        reasons.append("missing_observation_time")
        individual = None
        truncated = None
    else:
        individual = intersect_windows(validity, obs_window)
        if individual is None:
            reasons.append("observation_outside_its_indicator_window")
        elif not contains_window(validity, obs_window):
            needs_time = True
            reasons.append("observation_window_crosses_its_validity_boundary")

        target = required_window or validity
        truncated = intersect_windows(target, obs_window)
        if truncated is None and individual is not None and required_window is not None:
            reasons.append("observation_outside_common_validity_window")
        elif truncated is not None and required_window is not None and not contains_window(required_window, obs_window):
            # The per-individual boundary reason is already present when the
            # own validity is crossed; add the conjunction-specific reason.
            if not contains_window(validity, obs_window):
                reasons.append("observation_window_not_wholly_in_common_validity")
            else:
                needs_time = True
                reasons.append("observation_window_crosses_common_validity_boundary")

    if evidence is not None and evidence.needs_time and obs_window is None:
        needs_time = True

    spec_version = _mapping_get(indicator, "spec_version")
    modified = utc_datetime(_mapping_get(indicator, "modified"))
    pattern = _mapping_get(indicator, "pattern")

    return IndicatorTemporalAssessment(
        indicator_id=indicator_id,
        pattern=pattern,
        spec_version=spec_version,
        modified=modified,
        validity_window=validity,
        observation=evidence,
        individual_window=individual,
        truncated_window=truncated,
        needs_time=needs_time,
        reasons=reasons,
    )


def evaluate_pair(
    left: Any,
    right: Any,
    *,
    observations: Union[Mapping[str, EvidenceLike], Sequence[EvidenceLike], None] = None,
    left_observation: EvidenceLike = None,
    right_observation: EvidenceLike = None,
    pattern: Optional[str] = None,
    spec_version: Optional[str] = None,
    stix_version: Optional[str] = None,
    filters: Optional[Sequence[Filter]] = None,
    version_policy: str = "all",
) -> ConjunctionResult:
    """Evaluate temporal conjunction for exactly two STIX indicators."""
    spec_version = spec_version or stix_version
    if isinstance(left, Sequence) and not isinstance(left, (_STIXBase, Mapping, str)) and right is None:
        pair = list(left)
        if len(pair) != 2:
            raise ConjunctionContractError("evaluate_pair sequence must contain exactly two indicators")
        left, right = pair

    evidence_by_id = evidence_map(observations)
    left_id = _mapping_get(left, "id")
    right_id = _mapping_get(right, "id")
    if left_observation is not None:
        evidence_by_id[left_id] = coerce_evidence(left_observation, indicator_ref=left_id)
    if right_observation is not None:
        evidence_by_id[right_id] = coerce_evidence(right_observation, indicator_ref=right_id)

    if pattern is None:
        left_pattern = _mapping_get(left, "pattern")
        right_pattern = _mapping_get(right, "pattern")
        if left_pattern != right_pattern:
            raise ConjunctionContractError("The two indicators do not have the same pattern text")
        pattern = left_pattern
    elif _mapping_get(left, "pattern") != pattern or _mapping_get(right, "pattern") != pattern:
        raise ConjunctionContractError("Both indicators must match the requested pattern filter")

    common_validity = intersect_windows(indicator_window(left), indicator_window(right))
    left_assessment = assess_indicator(
        left,
        evidence_by_id.get(left_id),
        required_window=common_validity,
    )
    right_assessment = assess_indicator(
        right,
        evidence_by_id.get(right_id),
        required_window=common_validity,
    )
    assessments = [left_assessment, right_assessment]

    filter_contract = list(filters or build_indicator_filters(pattern, spec_version=spec_version))
    common_observation = None
    evidence_windows = [
        item.observation.window if item.observation is not None else None
        for item in assessments
    ]
    if all(window is not None for window in evidence_windows):
        common_observation = intersect_windows(evidence_windows[0], evidence_windows[1])

    common_window = None
    if common_validity is not None:
        common_window = common_validity
        for window in evidence_windows:
            common_window = intersect_windows(common_window, window)

    missing_evidence = any(
        item.observation is None or item.observation.window is None
        for item in assessments
    )
    credible = common_window is not None
    all_legal = False
    reasons: list[str] = []

    needing_refs: list[str] = []
    refinement: list[dict[str, Any]] = []
    truncated: dict[str, Optional[dict[str, Any]]] = {}
    for assessment in assessments:
        truncated[assessment.indicator_id] = _bounds(assessment.truncated_window)
        if assessment.needs_time:
            obs_ref = None
            if assessment.observation is not None:
                obs_ref = assessment.observation.observation_ref
            needing_refs.append(obs_ref or assessment.indicator_id)
            refinement.append({
                "indicator_id": assessment.indicator_id,
                "observation_ref": obs_ref,
                "precision": assessment.observation.precision if assessment.observation else TimePrecision.UNKNOWN.value,
                "reasons": assessment.reasons,
            })

    if missing_evidence:
        status = ConjunctionStatus.INSUFFICIENT_EVIDENCE
        reasons.append("at_least_one_observation_has_no_known_time_window")
    elif not credible:
        status = ConjunctionStatus.NO_COMMON_POINT
        reasons.append("known_validity_and_observation_windows_have_empty_intersection")
    else:
        # Strong local contract: every time still legal for either original
        # observation must fall in the common validity window.
        all_legal = all(
            item.observation is not None
            and item.observation.window is not None
            and contains_window(common_validity, item.observation.window)
            for item in assessments
        )
        if all_legal:
            status = ConjunctionStatus.ALL_LEGAL_TIMES_SUPPORT
        else:
            status = ConjunctionStatus.SOME_CREDIBLE_COMMON_POINT
            reasons.append("common_point_exists_but_some_legal_observation_times_are_outside_common_validity")

    selected_spec_version = spec_version
    if selected_spec_version is None:
        versions = {item.spec_version for item in assessments if item.spec_version}
        selected_spec_version = next(iter(versions)) if len(versions) == 1 else ("mixed" if versions else None)

    return ConjunctionResult(
        status=status,
        pattern=pattern,
        spec_version=selected_spec_version,
        matched_count=2,
        version_policy=version_policy,
        filter_contract=_filter_contract_data(filter_contract),
        indicators=assessments,
        common_validity_window=common_validity,
        common_observation_window=common_observation,
        common_window=common_window,
        credible_common_point=credible and not missing_evidence,
        all_legal_times_support=all_legal,
        observations_needing_time=needing_refs,
        refinement_requests=refinement,
        truncated_boundaries=truncated,
        reasons=reasons,
    )


def local_conjunctive_query(
    pattern: Union[str, Sequence[Any], MemoryStore, None] = None,
    objects: Optional[Sequence[Any]] = None,
    *,
    observations: Union[Mapping[str, EvidenceLike], Sequence[EvidenceLike], None] = None,
    spec_version: Optional[str] = None,
    stix_version: Optional[str] = None,
    version: Optional[str] = None,
    extra_filters: Optional[Sequence[Filter]] = None,
    include_revoked: bool = False,
    version_policy: str = "all",
    store: Optional[MemoryStore] = None,
    indicator_ids: Optional[Sequence[str]] = None,
    filter_spec_version: bool = False,
) -> ConjunctionResult:
    """Run an explicit AND-filter local query, then evaluate two matches.

    Calling conventions::

        local_conjunctive_query(pattern, indicators, observations=...)
        local_conjunctive_query(objects=indicators, pattern=pattern, ...)
        local_conjunctive_query(pattern, store=memory_store, ...)
    """
    spec_version = spec_version or stix_version or version

    if objects is None and store is None and pattern is not None and not isinstance(pattern, str):
        maybe_objects = pattern
        pattern = None
        if isinstance(maybe_objects, MemoryStore):
            store = maybe_objects
        else:
            objects = maybe_objects

    if store is None:
        if objects is None:
            raise ConjunctionContractError("Provide objects or a local MemoryStore")
        store = build_local_store(objects, spec_version=spec_version)

    filters = build_indicator_filters(
        pattern,
        spec_version=spec_version if filter_spec_version else None,
        extra_filters=extra_filters,
    )
    matches = list(store.query(list(filters)))

    if not include_revoked:
        matches = [item for item in matches if _mapping_get(item, "revoked", False) is not True]

    matches = select_object_versions(matches, version_policy)
    if indicator_ids is not None:
        wanted = list(indicator_ids)
        by_id = {_mapping_get(item, "id"): item for item in matches}
        missing = [item_id for item_id in wanted if item_id not in by_id]
        if missing:
            raise ConjunctionContractError("Indicator IDs did not match query: %r" % missing)
        matches = [by_id[item_id] for item_id in wanted]

    if pattern is None and matches:
        patterns = {_mapping_get(item, "pattern") for item in matches}
        if len(patterns) == 1:
            pattern = next(iter(patterns))

    if len(matches) != 2:
        raise ConjunctionContractError(
            "Conjunction query requires exactly two indicators after filters; got %d" % len(matches),
        )

    return evaluate_pair(
        matches[0],
        matches[1],
        observations=observations,
        pattern=pattern,
        spec_version=spec_version,
        filters=filters,
        version_policy=version_policy,
    )


# Concise alias for callers describing the operation as a conjunctive query.
conjunctive_query = local_conjunctive_query
query_conjunction = local_conjunctive_query
conjunction_query = local_conjunctive_query
temporal_conjunction_query = local_conjunctive_query
