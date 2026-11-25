"""
Replayable remediation calendars for `pip-audit` results.

A remediation calendar turns a saved, fictional maintenance schedule into a
deterministic report.  It deliberately has no clock of its own: every result is
derived from the saved inputs and a caller-supplied reference date, so the same
inputs always produce the same report.

The report keeps three moments separate:

* ``first_seen``: when the alert was first observed for a version group.
* ``actionable_at``: the first moment a fix exists *and* a maintenance window is
  open for it.
* ``due_at``: the end of the business-day deadline that starts at
  ``actionable_at``.

Maintenance calendars are versioned.  When replaying a date, only the calendar
version in effect at that date is used.  A calendar that arrives later therefore
never rewrites earlier decisions: it only changes windows and holidays from its
effective moment onwards.
"""

from __future__ import annotations

import enum
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import tomli
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

import pip_audit._service as service

_SCHEMA_VERSION = 1
_MAX_SEARCH_DAYS = 366 * 20
_MAX_REPLAY_STEPS = 10_000
_DEFAULT_SLA_BUSINESS_DAYS = 5

_WEEKDAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_WEEKDAYS = {
    "mon": 0,
    "monday": 0,
    "tue": 1,
    "tues": 1,
    "tuesday": 1,
    "wed": 2,
    "weds": 2,
    "wednesday": 2,
    "thu": 3,
    "thur": 3,
    "thurs": 3,
    "thursday": 3,
    "fri": 4,
    "friday": 4,
    "sat": 5,
    "saturday": 5,
    "sun": 6,
    "sunday": 6,
}


class RemediationCalendarError(ValueError):
    """Raised when a saved remediation calendar cannot be parsed or replayed."""


@enum.unique
class RemediationStatus(str, enum.Enum):
    """The state of one version group / alert pair at a reference date."""

    WaitingPatch = "waiting_patch"
    WaitingWindow = "waiting_window"
    Actionable = "actionable"
    Overdue = "overdue"


def _as_datetime(value: object, tz: ZoneInfo, field_name: str) -> datetime:
    """Parse an ISO 8601 value into an aware datetime."""
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, date):
        result = datetime.combine(value, time.min)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise RemediationCalendarError(f"{field_name}: expected a non-empty timestamp")
        try:
            result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RemediationCalendarError(
                f"{field_name}: invalid ISO 8601 timestamp {value!r}"
            ) from exc
    else:
        raise RemediationCalendarError(f"{field_name}: expected an ISO 8601 timestamp")

    if result.tzinfo is None:
        result = result.replace(tzinfo=tz)
    return result


def _as_date(value: object, tz: ZoneInfo, field_name: str) -> date:
    """Parse a date or timestamp into a local calendar date."""
    if isinstance(value, datetime):
        return _as_datetime(value, tz, field_name).astimezone(tz).date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            return _as_datetime(value, tz, field_name).astimezone(tz).date()
    raise RemediationCalendarError(f"{field_name}: expected a date")


def _as_int(
    value: object,
    field_name: str,
    *,
    default: int | None = None,
    minimum: int | None = None,
) -> int:
    """Parse an integer, rejecting booleans and applying an optional minimum."""
    if value is None:
        if default is None:
            raise RemediationCalendarError(f"{field_name}: a value is required")
        parsed = default
    elif isinstance(value, bool) or not isinstance(value, int):
        raise RemediationCalendarError(f"{field_name}: expected an integer")
    else:
        parsed = value

    if minimum is not None and parsed < minimum:
        raise RemediationCalendarError(f"{field_name}: must be at least {minimum}")
    return parsed


def _as_str(value: object, field_name: str) -> str:
    """Parse a required non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise RemediationCalendarError(f"{field_name}: expected a non-empty string")
    return value.strip()


def _as_mapping(value: object, field_name: str) -> Mapping[str, Any]:
    """Parse a JSON/TOML object."""
    if not isinstance(value, Mapping):
        raise RemediationCalendarError(f"{field_name}: expected an object")
    return value


def _as_list(value: object, field_name: str) -> list[Any]:
    """Parse a JSON/TOML array."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise RemediationCalendarError(f"{field_name}: expected an array")
    return list(value)


def _zone(name: str) -> ZoneInfo:
    """Resolve an IANA timezone name."""
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise RemediationCalendarError(f"unknown timezone {name!r}") from exc


def _start_of_day(day: date, tz: ZoneInfo) -> datetime:
    """Return the first instant of ``day`` in ``tz``."""
    return datetime.combine(day, time.min, tzinfo=tz)


def _end_of_day(day: date, tz: ZoneInfo) -> datetime:
    """Return the last whole second of ``day`` in ``tz``."""
    return datetime.combine(day, time(23, 59, 59), tzinfo=tz)


def _iso(value: datetime) -> str:
    """Format an aware datetime deterministically."""
    return value.isoformat(timespec="seconds")


def _parse_weekday(value: object, field_name: str) -> int:
    """Parse a weekday name or a Monday-based integer."""
    if isinstance(value, bool):
        raise RemediationCalendarError(f"{field_name}: invalid weekday")
    if isinstance(value, int):
        if 0 <= value <= 6:
            return value
        raise RemediationCalendarError(f"{field_name}: weekday integers must be in 0..6")
    if isinstance(value, str):
        parsed = _WEEKDAYS.get(value.strip().lower())
        if parsed is not None:
            return parsed
    raise RemediationCalendarError(f"{field_name}: unknown weekday {value!r}")


def _parse_minute(value: object, field_name: str) -> int:
    """Parse a time of day into minutes since midnight."""
    if isinstance(value, bool):
        raise RemediationCalendarError(f"{field_name}: invalid time")
    if isinstance(value, int):
        minute = value
    elif isinstance(value, str):
        text = value.strip()
        if text == "24:00":
            return 24 * 60
        try:
            parsed = time.fromisoformat(text)
        except ValueError as exc:
            raise RemediationCalendarError(f"{field_name}: invalid time {value!r}") from exc
        minute = parsed.hour * 60 + parsed.minute
    else:
        raise RemediationCalendarError(f"{field_name}: expected a time")

    if not 0 <= minute <= 24 * 60:
        raise RemediationCalendarError(f"{field_name}: time must be within one day")
    return minute


def _format_minute(minute: int) -> str:
    """Format minutes since midnight as ``HH:MM``."""
    if minute == 24 * 60:
        return "24:00"
    return f"{minute // 60:02d}:{minute % 60:02d}"


def _minute_datetime(day: date, minute: int, tz: ZoneInfo) -> datetime:
    """Return the instant at ``minute`` minutes into ``day``."""
    extra_days, remainder = divmod(minute, 24 * 60)
    local_day = day + timedelta(days=extra_days)
    return datetime.combine(local_day, time(remainder // 60, remainder % 60), tzinfo=tz)


@dataclass(frozen=True)
class MaintenanceWindow:
    """A recurring weekly window in which changes may be applied."""

    weekdays: frozenset[int]
    start_minute: int
    end_minute: int

    def start_at(self, day: date, tz: ZoneInfo) -> datetime:
        """Return this window's start on ``day``."""
        return _minute_datetime(day, self.start_minute, tz)

    def end_at(self, day: date, tz: ZoneInfo) -> datetime:
        """Return this window's end on ``day``."""
        return _minute_datetime(day, self.end_minute, tz)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation of this window."""
        return {
            "weekdays": [_WEEKDAY_NAMES[day] for day in sorted(self.weekdays)],
            "start": _format_minute(self.start_minute),
            "end": _format_minute(self.end_minute),
        }


def _parse_window(value: object, field_name: str) -> MaintenanceWindow:
    """Parse one maintenance-window entry."""
    raw = _as_mapping(value, field_name)
    weekdays_raw = raw.get("weekdays", raw.get("weekday", raw.get("days", raw.get("day"))))
    if weekdays_raw is None:
        raise RemediationCalendarError(f"{field_name}: weekdays are required")
    if isinstance(weekdays_raw, (str, int)) and not isinstance(weekdays_raw, bool):
        weekdays_seq = [weekdays_raw]
    else:
        weekdays_seq = _as_list(weekdays_raw, f"{field_name}.weekdays")
    if not weekdays_seq:
        raise RemediationCalendarError(f"{field_name}: at least one weekday is required")

    weekdays = frozenset(
        _parse_weekday(day, f"{field_name}.weekdays[{index}]")
        for index, day in enumerate(weekdays_seq)
    )
    start_raw = raw.get("start", raw.get("opens", raw.get("from")))
    end_raw = raw.get("end", raw.get("closes", raw.get("to")))
    if start_raw is None or end_raw is None:
        raise RemediationCalendarError(f"{field_name}: start and end are required")
    start_minute = _parse_minute(start_raw, f"{field_name}.start")
    end_minute = _parse_minute(end_raw, f"{field_name}.end")
    if end_minute <= start_minute:
        raise RemediationCalendarError(f"{field_name}: end must be after start")
    return MaintenanceWindow(weekdays, start_minute, end_minute)


@dataclass(frozen=True)
class CalendarVersion:
    """One immutable version of a maintenance calendar."""

    effective_at: datetime
    timezone: ZoneInfo
    windows: tuple[MaintenanceWindow, ...]
    holidays: frozenset[date]

    def windows_on(self, day: date) -> tuple[MaintenanceWindow, ...]:
        """Return the windows that recur on ``day``, ignoring holidays."""
        if day in self.holidays:
            return ()
        return tuple(
            sorted(
                (window for window in self.windows if day.weekday() in window.weekdays),
                key=lambda window: window.start_minute,
            )
        )

    def is_business_day(self, day: date) -> bool:
        """Return whether ``day`` is a weekday that is not a holiday."""
        return day.weekday() < 5 and day not in self.holidays

    def next_window_start(self, after: datetime) -> datetime | None:
        """Return the first window instant at or after ``after``."""
        local = after.astimezone(self.timezone)
        start_day = local.date()
        for offset in range(_MAX_SEARCH_DAYS):
            day = start_day + timedelta(days=offset)
            for window in self.windows_on(day):
                start = window.start_at(day, self.timezone)
                end = window.end_at(day, self.timezone)
                if end < local:
                    continue
                if start <= local <= end:
                    return local
                if start > local:
                    return start
        return None

    def window_span_at(self, moment: datetime) -> tuple[datetime, datetime] | None:
        """Return the window containing or following ``moment``."""
        local = moment.astimezone(self.timezone)
        start_day = local.date()
        for offset in range(_MAX_SEARCH_DAYS):
            day = start_day + timedelta(days=offset)
            for window in self.windows_on(day):
                start = window.start_at(day, self.timezone)
                end = window.end_at(day, self.timezone)
                if end < local:
                    continue
                return start, end
        return None

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation of this calendar version."""
        return {
            "effective_at": _iso(self.effective_at),
            "timezone": str(self.timezone),
            "windows": [window.to_dict() for window in self.windows],
            "holidays": [day.isoformat() for day in sorted(self.holidays)],
        }


@dataclass(frozen=True)
class AlertObservation:
    """One alert as observed by a version group."""

    id: str
    first_seen: datetime
    sla_business_days: int


@dataclass(frozen=True)
class VersionGroup:
    """A maintenance line plus the package versions it owns."""

    id: str
    line: str
    package: str
    versions: tuple[str, ...]
    alerts: tuple[AlertObservation, ...]


@dataclass(frozen=True)
class PatchAvailability:
    """The first moment a fixed version is available for a group/alert pair."""

    group_id: str
    alert_id: str
    available_at: datetime
    fixed_version: str | None


def _validate_version_selector(value: str, field_name: str) -> str:
    """Validate an exact version or a PEP 440 specifier."""
    text = value.strip()
    if not text:
        raise RemediationCalendarError(f"{field_name}: expected a version or specifier")
    if text[0] in "<>=!~":
        try:
            SpecifierSet(text)
        except InvalidSpecifier as exc:
            raise RemediationCalendarError(
                f"{field_name}: invalid version specifier {value!r}"
            ) from exc
    else:
        try:
            Version(text)
        except InvalidVersion as exc:
            raise RemediationCalendarError(f"{field_name}: invalid version {value!r}") from exc
    return text


def _parse_alerts(
    raw: Mapping[str, Any],
    field_name: str,
    timezone_: ZoneInfo,
    default_sla: int,
) -> tuple[AlertObservation, ...]:
    """Parse the alerts attached to one version group."""
    group_sla = _as_int(
        raw.get("sla_business_days"),
        f"{field_name}.sla_business_days",
        default=default_sla,
        minimum=0,
    )

    alerts_raw = raw.get("alerts")
    if alerts_raw is None:
        alert_id = raw.get("alert", raw.get("alert_id"))
        first_seen = raw.get("first_seen", raw.get("observed_at"))
        if alert_id is None and first_seen is None:
            return ()
        if alert_id is None or first_seen is None:
            raise RemediationCalendarError(
                f"{field_name}: alert shorthand requires both alert and first_seen"
            )
        return (
            AlertObservation(
                _as_str(alert_id, f"{field_name}.alert"),
                _as_datetime(first_seen, timezone_, f"{field_name}.first_seen"),
                group_sla,
            ),
        )

    alerts: list[AlertObservation] = []
    seen: set[str] = set()
    for index, item in enumerate(_as_list(alerts_raw, f"{field_name}.alerts")):
        alert_field = f"{field_name}.alerts[{index}]"
        if isinstance(item, str):
            alert_id = _as_str(item, alert_field)
            first_seen_raw = raw.get("first_seen", raw.get("observed_at"))
            if first_seen_raw is None:
                raise RemediationCalendarError(
                    f"{alert_field}: shorthand alerts require first_seen on the group"
                )
            sla = group_sla
        else:
            alert_raw = _as_mapping(item, alert_field)
            alert_id = _as_str(
                alert_raw.get("id", alert_raw.get("alert", alert_raw.get("alert_id"))),
                f"{alert_field}.id",
            )
            first_seen_raw = alert_raw.get(
                "first_seen", alert_raw.get("observed_at", raw.get("first_seen"))
            )
            sla = _as_int(
                alert_raw.get("sla_business_days"),
                f"{alert_field}.sla_business_days",
                default=group_sla,
                minimum=0,
            )
        if alert_id in seen:
            raise RemediationCalendarError(f"{field_name}: duplicate alert {alert_id!r}")
        seen.add(alert_id)
        alerts.append(
            AlertObservation(
                alert_id,
                _as_datetime(first_seen_raw, timezone_, f"{alert_field}.first_seen"),
                sla,
            )
        )
    return tuple(alerts)


def _parse_group(
    value: object,
    field_name: str,
    timezone_: ZoneInfo,
    default_sla: int,
) -> VersionGroup:
    """Parse one version group."""
    raw = _as_mapping(value, field_name)
    package = _as_str(raw.get("package", raw.get("name")), f"{field_name}.package")
    group_id = _as_str(
        raw.get("id", raw.get("group", package)),
        f"{field_name}.id",
    )
    line = _as_str(
        raw.get("line", raw.get("maintenance_line", group_id)),
        f"{field_name}.line",
    )

    versions_raw = raw.get("versions", raw.get("version"))
    if versions_raw is None and "version_specifier" in raw:
        versions_raw = [raw["version_specifier"]]
    if versions_raw is None:
        versions: tuple[str, ...] = ()
    elif isinstance(versions_raw, (str, int, float)) and not isinstance(versions_raw, bool):
        versions = (_validate_version_selector(str(versions_raw), f"{field_name}.version"),)
    else:
        versions = tuple(
            _validate_version_selector(
                _as_str(item, f"{field_name}.versions[{index}]"),
                f"{field_name}.versions[{index}]",
            )
            for index, item in enumerate(_as_list(versions_raw, f"{field_name}.versions"))
        )

    return VersionGroup(
        id=group_id,
        line=line,
        package=package,
        versions=versions,
        alerts=_parse_alerts(raw, field_name, timezone_, default_sla),
    )


def _patch_owner_matches(raw: Mapping[str, Any], group: VersionGroup) -> bool:
    """Return whether a patch entry applies to ``group``."""
    owner = raw.get("group", raw.get("owner"))
    if owner is not None and owner != "*" and owner != group.id:
        return False
    line = raw.get("line", raw.get("maintenance_line"))
    if line is not None and line != "*" and line != group.line:
        return False
    package = raw.get("package")
    if package is not None and package != "*":
        if canonicalize_name(_as_str(package, "package")) != canonicalize_name(group.package):
            return False
    return True


def _parse_patches(
    value: object,
    groups: tuple[VersionGroup, ...],
    timezone_: ZoneInfo,
    field_name: str,
) -> tuple[PatchAvailability, ...]:
    """Parse patch availability and expand per-group entries."""
    patches: dict[tuple[str, str], PatchAvailability] = {}
    for index, item in enumerate(_as_list(value, field_name)):
        patch_field = f"{field_name}[{index}]"
        raw = _as_mapping(item, patch_field)
        if not any(key in raw for key in ("group", "owner", "line", "maintenance_line", "package")):
            raise RemediationCalendarError(
                f"{patch_field}: specify group, line, or package so the patch can be matched"
            )
        available_at = _as_datetime(
            raw.get("available_at", raw.get("available")),
            timezone_,
            f"{patch_field}.available_at",
        )
        fixed_version_raw = raw.get("fixed_version", raw.get("version"))
        fixed_version = (
            None
            if fixed_version_raw is None
            else _as_str(fixed_version_raw, f"{patch_field}.fixed_version")
        )
        alert_raw = raw.get("alert", raw.get("alert_id", raw.get("vuln")))
        alert_id = (
            None
            if alert_raw is None or alert_raw in ("*", "all", "any")
            else _as_str(alert_raw, f"{patch_field}.alert")
        )

        matched = [group for group in groups if _patch_owner_matches(raw, group)]
        if not matched:
            raise RemediationCalendarError(f"{patch_field}: patch does not match any version group")

        for group in matched:
            if alert_id is None:
                target_alerts = [alert.id for alert in group.alerts]
            else:
                target_alerts = [alert.id for alert in group.alerts if alert.id == alert_id]
                if not target_alerts:
                    raise RemediationCalendarError(
                        f"{patch_field}: group {group.id!r} has no alert {alert_id!r}"
                    )
            for target_alert in target_alerts:
                patch = PatchAvailability(group.id, target_alert, available_at, fixed_version)
                key = (group.id, target_alert)
                existing = patches.get(key)
                if existing is None or (patch.available_at, patch.fixed_version or "") < (
                    existing.available_at,
                    existing.fixed_version or "",
                ):
                    patches[key] = patch
    return tuple(patches[key] for key in sorted(patches))


def _parse_calendar_version(
    value: object,
    field_name: str,
    default_timezone: ZoneInfo,
) -> CalendarVersion:
    """Parse one calendar version."""
    raw = _as_mapping(value, field_name)
    timezone_name = raw.get("timezone")
    timezone_ = (
        default_timezone
        if timezone_name is None
        else _zone(_as_str(timezone_name, f"{field_name}.timezone"))
    )
    effective_at = _as_datetime(
        raw.get("effective_at", raw.get("effective")),
        timezone_,
        f"{field_name}.effective_at",
    )
    windows = tuple(
        _parse_window(window, f"{field_name}.windows[{index}]")
        for index, window in enumerate(_as_list(raw.get("windows"), f"{field_name}.windows"))
    )
    if not windows:
        raise RemediationCalendarError(f"{field_name}: at least one maintenance window is required")
    windows = tuple(sorted(windows, key=lambda window: window.start_minute))

    holidays_raw = raw.get("holidays", raw.get("blackouts", ()))
    holidays = frozenset(
        _as_date(day, timezone_, f"{field_name}.holidays[{index}]")
        for index, day in enumerate(_as_list(holidays_raw, f"{field_name}.holidays"))
    )
    return CalendarVersion(effective_at, timezone_, windows, holidays)


@dataclass(frozen=True)
class RemediationCalendar:
    """A complete, replayable remediation calendar."""

    timezone: ZoneInfo
    versions: tuple[CalendarVersion, ...]
    groups: tuple[VersionGroup, ...]
    patches: tuple[PatchAvailability, ...]
    default_sla_business_days: int
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RemediationCalendar:
        """Build a calendar from an already-parsed JSON/TOML object."""
        if not isinstance(data, Mapping):
            raise RemediationCalendarError("remediation calendar must be an object")
        raw = dict(data)
        schema_version = _as_int(
            raw.get("schema_version"),
            "schema_version",
            default=_SCHEMA_VERSION,
            minimum=1,
        )
        if schema_version != _SCHEMA_VERSION:
            raise RemediationCalendarError(
                f"schema_version: unsupported version {schema_version}; expected {_SCHEMA_VERSION}"
            )

        timezone_name = raw.get("timezone", "UTC")
        timezone_ = _zone(_as_str(timezone_name, "timezone"))
        default_sla = _as_int(
            raw.get("default_sla_business_days"),
            "default_sla_business_days",
            default=_DEFAULT_SLA_BUSINESS_DAYS,
            minimum=0,
        )

        versions_raw = raw.get(
            "maintenance_calendars", raw.get("calendar_versions", raw.get("calendars"))
        )
        if versions_raw is None:
            raise RemediationCalendarError(
                "maintenance_calendars: at least one version is required"
            )
        versions = tuple(
            _parse_calendar_version(item, f"maintenance_calendars[{index}]", timezone_)
            for index, item in enumerate(_as_list(versions_raw, "maintenance_calendars"))
        )
        if not versions:
            raise RemediationCalendarError(
                "maintenance_calendars: at least one version is required"
            )
        effective_moments = [version.effective_at for version in versions]
        if len(set(effective_moments)) != len(effective_moments):
            raise RemediationCalendarError(
                "maintenance_calendars: effective_at values must be unique"
            )
        versions = tuple(sorted(versions, key=lambda version: version.effective_at))

        groups_raw = raw.get("version_groups", raw.get("groups"))
        if groups_raw is None:
            raise RemediationCalendarError("version_groups: at least one group is required")
        groups = tuple(
            _parse_group(item, f"version_groups[{index}]", timezone_, default_sla)
            for index, item in enumerate(_as_list(groups_raw, "version_groups"))
        )
        if not groups:
            raise RemediationCalendarError("version_groups: at least one group is required")
        group_ids = [group.id for group in groups]
        if len(set(group_ids)) != len(group_ids):
            raise RemediationCalendarError("version_groups: ids must be unique")

        patches_raw = raw.get("patches", raw.get("patch_availability"))
        patches = (
            () if patches_raw is None else _parse_patches(patches_raw, groups, timezone_, "patches")
        )

        return cls(
            timezone=timezone_,
            versions=versions,
            groups=groups,
            patches=patches,
            default_sla_business_days=default_sla,
            raw=raw,
        )

    @classmethod
    def load(cls, path: Path | str) -> RemediationCalendar:
        """Load a calendar from a JSON or TOML file."""
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RemediationCalendarError(
                f"cannot read remediation calendar {path}: {exc}"
            ) from exc
        try:
            if path.suffix.lower() == ".toml":
                parsed = tomli.loads(text)
            else:
                parsed = json.loads(text)
        except (json.JSONDecodeError, tomli.TOMLDecodeError) as exc:
            raise RemediationCalendarError(
                f"cannot parse remediation calendar {path}: {exc}"
            ) from exc
        return cls.from_dict(parsed)

    def at(self, moment: datetime) -> CalendarVersion:
        """Return the calendar version in effect at ``moment``."""
        aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=self.timezone)
        for version in reversed(self.versions):
            if version.effective_at <= aware:
                return version
        # The earliest saved calendar is the baseline for moments before its
        # stated effective date.
        return self.versions[0]

    def as_of(self, moment: datetime) -> RemediationCalendar:
        """Return a view containing only calendar versions in effect at ``moment``."""
        cutoff = moment if moment.tzinfo is not None else moment.replace(tzinfo=self.timezone)
        effective = tuple(version for version in self.versions if version.effective_at <= cutoff)
        if not effective:
            effective = (self.versions[0],)
        return RemediationCalendar(
            timezone=self.timezone,
            versions=effective,
            groups=self.groups,
            patches=self.patches,
            default_sla_business_days=self.default_sla_business_days,
            raw=self.raw,
        )

    def _next_effective(self, after: datetime, limit: datetime) -> datetime | None:
        """Return the next effective moment in ``(after, limit]``."""
        candidates = [
            version.effective_at
            for version in self.versions
            if after < version.effective_at <= limit
        ]
        return min(candidates) if candidates else None

    def next_window_start(self, after: datetime) -> datetime | None:
        """Return the first actionable window instant, replaying calendar versions."""
        cursor = after if after.tzinfo is not None else after.replace(tzinfo=self.timezone)
        for _ in range(_MAX_REPLAY_STEPS):
            candidate = self.at(cursor).next_window_start(cursor)
            if candidate is None:
                return None
            newer = self._next_effective(cursor, candidate)
            if newer is None:
                return candidate
            cursor = newer
        raise RemediationCalendarError(
            "too many calendar versions while finding a maintenance window"
        )

    def window_span(self, moment: datetime) -> tuple[datetime, datetime] | None:
        """Return the maintenance window containing or following ``moment``."""
        cursor = moment if moment.tzinfo is not None else moment.replace(tzinfo=self.timezone)
        for _ in range(_MAX_REPLAY_STEPS):
            span = self.at(cursor).window_span_at(cursor)
            if span is None:
                return None
            newer = self._next_effective(cursor, span[0])
            if newer is None:
                return span
            cursor = newer
        raise RemediationCalendarError(
            "too many calendar versions while finding a maintenance window"
        )

    def add_business_days(self, start: date, count: int) -> date:
        """Add ``count`` business days, skipping weekends and holidays."""
        if count < 0:
            raise RemediationCalendarError("business-day count cannot be negative")
        if count == 0:
            return start
        current = start
        added = 0
        for _ in range(_MAX_SEARCH_DAYS):
            current += timedelta(days=1)
            if self.at(_start_of_day(current, self.timezone)).is_business_day(current):
                added += 1
                if added == count:
                    return current
        raise RemediationCalendarError(
            f"no {count} business days found after {start.isoformat()} within the search horizon"
        )

    def business_days_between(self, start: date, end: date) -> int:
        """Return the signed number of business days from ``start`` to ``end``."""
        if start == end:
            return 0
        direction = 1 if end > start else -1
        current = start
        total = 0
        for _ in range(_MAX_SEARCH_DAYS):
            current += timedelta(days=direction)
            if self.at(_start_of_day(current, self.timezone)).is_business_day(current):
                total += direction
            if current == end:
                return total
        raise RemediationCalendarError(
            f"cannot count business days between {start.isoformat()} and {end.isoformat()}"
        )

    def patch_for(self, group_id: str, alert_id: str) -> PatchAvailability | None:
        """Return the earliest patch recorded for a group/alert pair."""
        candidates = [patch for patch in self.patches if patch.group_id == group_id]
        matching = [patch for patch in candidates if patch.alert_id == alert_id]
        if not matching:
            return None
        return min(
            matching,
            key=lambda patch: (patch.available_at, patch.fixed_version or ""),
        )


def _matches_group_version(group: VersionGroup, installed: str) -> bool:
    """Return whether an installed version belongs to a group."""
    if not group.versions:
        return True
    try:
        parsed = Version(installed)
    except InvalidVersion:
        return False
    for selector in group.versions:
        if selector[0] in "<>=!~":
            if parsed in SpecifierSet(selector):
                return True
        elif Version(selector) == parsed:
            return True
    return False


def _audit_index(
    audit_result: dict[service.Dependency, list[service.VulnerabilityResult]] | None,
) -> dict[str, list[tuple[str, frozenset[str]]]] | None:
    """Index audit results by canonical package name."""
    if audit_result is None:
        return None
    index: dict[str, list[tuple[str, frozenset[str]]]] = {}
    for dependency, vulnerabilities in audit_result.items():
        if dependency.is_skipped():
            continue
        resolved = cast(service.ResolvedDependency, dependency)
        ids: set[str] = set()
        for vulnerability in vulnerabilities:
            ids.add(vulnerability.id)
            ids.update(vulnerability.aliases)
        index.setdefault(resolved.canonical_name, []).append(
            (str(resolved.version), frozenset(ids))
        )
    return index


@dataclass(frozen=True)
class RemediationEntry:
    """The replayed schedule for one version group / alert pair."""

    group_id: str
    line: str
    package: str
    versions: tuple[str, ...]
    alert_id: str
    first_seen: datetime
    patch_available_at: datetime | None
    fixed_version: str | None
    actionable_at: datetime | None
    due_at: datetime | None
    due_date: date | None
    status: RemediationStatus
    sla_business_days: int
    business_days_remaining: int | None
    next_window: tuple[datetime, datetime] | None
    calendar_effective_at: datetime
    audit_checked: bool
    observed: bool
    alert_observed: bool
    observed_versions: tuple[str, ...]
    projected: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation of this entry."""
        next_window = None
        if self.next_window is not None:
            next_window = {
                "start": _iso(self.next_window[0]),
                "end": _iso(self.next_window[1]),
            }
        return {
            "group": self.group_id,
            "line": self.line,
            "package": self.package,
            "versions": list(self.versions),
            "alert": self.alert_id,
            "first_seen": _iso(self.first_seen),
            "patch_available_at": (
                None if self.patch_available_at is None else _iso(self.patch_available_at)
            ),
            "fixed_version": self.fixed_version,
            "actionable_at": None if self.actionable_at is None else _iso(self.actionable_at),
            "projected": self.projected,
            "due_date": None if self.due_date is None else self.due_date.isoformat(),
            "due_at": None if self.due_at is None else _iso(self.due_at),
            "status": self.status.value,
            "sla_business_days": self.sla_business_days,
            "business_days_remaining": self.business_days_remaining,
            "next_maintenance_window": next_window,
            "calendar_in_effect": _iso(self.calendar_effective_at),
            "audit": {
                "checked": self.audit_checked,
                "observed": self.observed,
                "alert_observed": self.alert_observed,
                "observed_versions": list(self.observed_versions),
            },
            "reason": self.reason,
        }


def _entry_for(
    calendar: RemediationCalendar,
    group: VersionGroup,
    alert: AlertObservation,
    as_of: datetime,
    index: dict[str, list[tuple[str, frozenset[str]]]] | None,
) -> RemediationEntry:
    """Replay one group/alert pair as of ``as_of``."""
    visible = calendar.as_of(as_of)
    patch = visible.patch_for(group.id, alert.id)
    actionable_at: datetime | None = None
    due_at: datetime | None = None
    due_date: date | None = None
    if patch is not None:
        ready_at = max(alert.first_seen, patch.available_at)
        actionable_at = visible.next_window_start(ready_at)
        if actionable_at is not None:
            due_date = visible.add_business_days(
                actionable_at.astimezone(visible.timezone).date(),
                alert.sla_business_days,
            )
            due_at = _end_of_day(due_date, visible.timezone)

    if patch is None:
        status = RemediationStatus.WaitingPatch
        reason = "no patch is recorded for this version group"
    elif patch.available_at > as_of:
        status = RemediationStatus.WaitingPatch
        reason = "patch is not available yet"
    elif actionable_at is None:
        status = RemediationStatus.WaitingWindow
        reason = "no maintenance window was found within the search horizon"
    elif actionable_at > as_of:
        status = RemediationStatus.WaitingWindow
        reason = "waiting for the next maintenance window"
    elif due_at is not None and as_of > due_at:
        status = RemediationStatus.Overdue
        reason = f"past the {alert.sla_business_days}-business-day deadline"
    else:
        status = RemediationStatus.Actionable
        reason = f"within the {alert.sla_business_days}-business-day deadline"

    installed = [] if index is None else index.get(canonicalize_name(group.package), [])
    observed_versions = tuple(
        sorted({version for version, _ in installed if _matches_group_version(group, version)})
    )
    observed = bool(observed_versions)
    alert_observed = any(
        alert.id in ids for version, ids in installed if _matches_group_version(group, version)
    )
    remaining = (
        None
        if due_date is None
        else visible.business_days_between(as_of.astimezone(visible.timezone).date(), due_date)
    )
    projected = bool(
        (patch is not None and patch.available_at > as_of)
        or (actionable_at is not None and actionable_at > as_of)
    )
    return RemediationEntry(
        group_id=group.id,
        line=group.line,
        package=group.package,
        versions=group.versions,
        alert_id=alert.id,
        first_seen=alert.first_seen,
        patch_available_at=None if patch is None else patch.available_at,
        fixed_version=None if patch is None else patch.fixed_version,
        actionable_at=actionable_at,
        due_at=due_at,
        due_date=due_date,
        status=status,
        sla_business_days=alert.sla_business_days,
        business_days_remaining=remaining,
        next_window=visible.window_span(as_of),
        calendar_effective_at=visible.at(as_of).effective_at,
        audit_checked=index is not None,
        observed=observed,
        alert_observed=alert_observed,
        observed_versions=observed_versions,
        projected=projected,
        reason=reason,
    )


def _summarize(entries: Sequence[RemediationEntry]) -> dict[str, Any]:
    """Build stable status counts and group lists."""
    counts = {status.value: 0 for status in RemediationStatus}
    groups: dict[str, set[str]] = {status.value: set() for status in RemediationStatus}
    for entry in entries:
        counts[entry.status.value] += 1
        groups[entry.status.value].add(entry.group_id)
    return {
        "entries": len(entries),
        "counts": counts,
        "overdue_groups": sorted(groups["overdue"]),
        "waiting_patch_groups": sorted(groups["waiting_patch"]),
        "waiting_window_groups": sorted(groups["waiting_window"]),
        "actionable_groups": sorted(groups["actionable"]),
        "observed": sum(1 for entry in entries if entry.observed),
        "not_observed": sum(1 for entry in entries if entry.audit_checked and not entry.observed),
        "audit_checked": any(entry.audit_checked for entry in entries),
    }


@dataclass(frozen=True)
class WeeklyRow:
    """One ISO week in a weekly remediation report."""

    week: str
    start: date
    end: date
    evaluated_at: datetime
    entries: tuple[RemediationEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation of this week."""
        return {
            "week": self.week,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "evaluated_at": _iso(self.evaluated_at),
            "summary": _summarize(self.entries),
            "groups": [
                {
                    "group": entry.group_id,
                    "line": entry.line,
                    "alert": entry.alert_id,
                    "status": entry.status.value,
                    "patch_available_at": (
                        None if entry.patch_available_at is None else _iso(entry.patch_available_at)
                    ),
                    "actionable_at": (
                        None if entry.actionable_at is None else _iso(entry.actionable_at)
                    ),
                    "due_at": None if entry.due_at is None else _iso(entry.due_at),
                }
                for entry in self.entries
            ],
        }


def _weekly_rows(
    calendar: RemediationCalendar,
    as_of: datetime,
    index: dict[str, list[tuple[str, frozenset[str]]]] | None,
) -> tuple[WeeklyRow, ...]:
    """Recompute statuses for every ISO week up to ``as_of``."""
    first_seen_moments = [alert.first_seen for group in calendar.groups for alert in group.alerts]
    if not first_seen_moments:
        return ()
    first_date = min(first_seen_moments).astimezone(calendar.timezone).date()
    last_date = as_of.astimezone(calendar.timezone).date()
    if first_date > last_date:
        return ()

    week_start = first_date - timedelta(days=first_date.weekday())
    rows: list[WeeklyRow] = []
    while week_start <= last_date:
        week_end = week_start + timedelta(days=6)
        evaluated_at = min(_end_of_day(week_end, calendar.timezone), as_of)
        entries = tuple(
            _entry_for(calendar, group, alert, evaluated_at, index)
            for group in calendar.groups
            for alert in group.alerts
            if alert.first_seen <= evaluated_at
        )
        iso = week_start.isocalendar()
        rows.append(
            WeeklyRow(
                week=f"{iso.year}-W{iso.week:02d}",
                start=week_start,
                end=week_end,
                evaluated_at=evaluated_at,
                entries=entries,
            )
        )
        week_start += timedelta(days=7)
    return tuple(rows)


@dataclass(frozen=True)
class RemediationReport:
    """A replayed remediation report."""

    mode: str
    as_of: datetime
    digest: str
    calendar: RemediationCalendar
    entries: tuple[RemediationEntry, ...]
    weeks: tuple[WeeklyRow, ...] | None = None

    @property
    def summary(self) -> dict[str, Any]:
        """Return the report summary."""
        return _summarize(self.entries)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON representation of this report."""
        document: dict[str, Any] = {
            "schema_version": _SCHEMA_VERSION,
            "mode": self.mode,
            "as_of": _iso(self.as_of),
            "digest": self.digest,
            "timezone": str(self.calendar.timezone),
            "calendar_versions": [version.to_dict() for version in self.calendar.versions],
            "summary": self.summary,
            "entries": [entry.to_dict() for entry in self.entries],
        }
        if self.weeks is not None:
            document["weeks"] = [row.to_dict() for row in self.weeks]
        return {"remediation_calendar": document}


def _digest(calendar: RemediationCalendar, as_of: datetime, mode: str) -> str:
    """Return a stable digest of the effective inputs and reference date."""
    effective = [v for v in calendar.versions if v.effective_at <= as_of]
    if not effective:
        effective = [calendar.versions[0]]
    raw = {
        key: value
        for key, value in calendar.raw.items()
        if key not in {"maintenance_calendars", "calendar_versions", "calendars"}
    }
    payload = {
        "mode": mode,
        "as_of": _iso(as_of),
        "inputs": raw,
        "effective_calendar_versions": [v.to_dict() for v in effective],
    }
    blob = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def parse_reference(
    value: str | None,
    calendar: RemediationCalendar,
    *,
    now: datetime | None = None,
) -> datetime:
    """Parse a CLI reference value, defaulting to the current instant."""
    if value is None:
        current = now if now is not None else datetime.now(timezone.utc)
        return current if current.tzinfo is not None else current.replace(tzinfo=timezone.utc)
    return _as_datetime(value, calendar.timezone, "as-of")


def build_report(
    calendar: RemediationCalendar,
    as_of: datetime | date | str,
    audit_result: dict[service.Dependency, list[service.VulnerabilityResult]] | None = None,
    *,
    weekly: bool = False,
) -> RemediationReport:
    """Replay a calendar as of ``as_of`` and optionally build weekly snapshots."""
    if isinstance(as_of, str):
        reference = _as_datetime(as_of, calendar.timezone, "as_of")
    elif isinstance(as_of, date) and not isinstance(as_of, datetime):
        reference = datetime.combine(as_of, time.min, tzinfo=calendar.timezone)
    else:
        reference = as_of if as_of.tzinfo is not None else as_of.replace(tzinfo=calendar.timezone)
    index = _audit_index(audit_result)
    entries = tuple(
        _entry_for(calendar, group, alert, reference, index)
        for group in calendar.groups
        for alert in group.alerts
        if alert.first_seen <= reference
    )
    mode = "weekly" if weekly else "calendar"
    weeks = _weekly_rows(calendar, reference, index) if weekly else None
    return RemediationReport(
        mode=mode,
        as_of=reference,
        digest=_digest(calendar, reference, mode),
        calendar=calendar.as_of(reference),
        entries=entries,
        weeks=weeks,
    )


def render_json(report: RemediationReport) -> str:
    """Render a report as indented JSON."""
    return json.dumps(report.to_dict(), indent=2)


def render_markdown(report: RemediationReport) -> str:
    """Render a report as Markdown."""
    document = report.to_dict()["remediation_calendar"]
    lines = [
        "## Remediation calendar",
        "",
        f"Replay reference: `{document['as_of']}`",
        "",
        f"Input digest: `{document['digest']}`",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status, count in document["summary"]["counts"].items():
        lines.append(f"| {status} | {count} |")

    lines += [
        "",
        "| Group | Line | Alert | First seen | Patch available | Actionable at | Due at | Status |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in document["entries"]:
        lines.append(
            "| {group} | {line} | {alert} | {first_seen} | {patch} | {actionable} | "
            "{due} | {status} |".format(
                group=entry["group"],
                line=entry["line"],
                alert=entry["alert"],
                first_seen=entry["first_seen"],
                patch=entry["patch_available_at"] or "waiting",
                actionable=entry["actionable_at"] or "waiting",
                due=entry["due_at"] or "waiting",
                status=entry["status"],
            )
        )

    if "weeks" in document:
        lines += [
            "",
            "### Weekly report",
            "",
            "| Week | Evaluated at | Group | Status | Due at |",
            "| --- | --- | --- | --- | --- |",
        ]
        for week in document["weeks"]:
            for group in week["groups"]:
                lines.append(
                    f"| {week['week']} | {week['evaluated_at']} | {group['group']} | "
                    f"{group['status']} | {group['due_at'] or 'waiting'} |"
                )
    return "\n".join(lines)
