"""
Provider availability and cache-freshness status models.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _datetime_to_json(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _datetime_from_json(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class SourceAvailability(str, enum.Enum):
    """
    Whether a vulnerability source answered a query.
    """

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"

    def __str__(self) -> str:
        return self.value


# Convenience alias for callers that prefer "source status" terminology.
SourceState = SourceAvailability


class CacheFreshness(str, enum.Enum):
    """
    The cache state observed for a source query.
    """

    FRESH = "fresh"
    STALE = "stale"
    MISS = "miss"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


# Convenience alias for callers that prefer "cache state" terminology.
CacheState = CacheFreshness


@dataclass(frozen=True)
class CacheStatus:
    """
    Cache freshness information for one vulnerability source.
    """

    source: str
    freshness: CacheFreshness = CacheFreshness.UNKNOWN
    checked_at: datetime = field(default_factory=_utc_now)
    cached_at: datetime | None = None
    age_seconds: float | None = None
    ttl_seconds: int | None = None
    from_cache: bool | None = None
    detail: str | None = None

    @classmethod
    def unknown(cls, source: str, detail: str | None = None) -> CacheStatus:
        """
        Create an unknown cache status for `source`.
        """
        return cls(source=source, freshness=CacheFreshness.UNKNOWN, detail=detail)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheStatus:
        """
        Restore a cache status from a JSON-compatible dictionary.
        """
        return cls(
            source=str(data["source"]),
            freshness=CacheFreshness(data.get("freshness", CacheFreshness.UNKNOWN.value)),
            checked_at=_datetime_from_json(data.get("checked_at")) or _utc_now(),
            cached_at=_datetime_from_json(data.get("cached_at")),
            age_seconds=data.get("age_seconds"),
            ttl_seconds=data.get("ttl_seconds"),
            from_cache=data.get("from_cache"),
            detail=data.get("detail"),
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize this status to a JSON-compatible dictionary.
        """
        return {
            "source": self.source,
            "freshness": self.freshness.value,
            "checked_at": _datetime_to_json(self.checked_at),
            "cached_at": _datetime_to_json(self.cached_at),
            "age_seconds": self.age_seconds,
            "ttl_seconds": self.ttl_seconds,
            "from_cache": self.from_cache,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class SourceSnapshot:
    """
    A provenance snapshot for one vulnerability source.
    """

    name: str
    availability: SourceAvailability
    checked_at: datetime = field(default_factory=_utc_now)
    snapshot_id: str | None = None
    input_digest: str | None = None
    url: str | None = None
    error: str | None = None
    cache: CacheStatus | None = None
    first_observed_at: datetime | None = None
    last_successful_at: datetime | None = None
    last_known_good: SourceSnapshot | None = None

    @property
    def available(self) -> bool:
        """
        Return whether the source was available during this check.
        """
        return self.availability is SourceAvailability.AVAILABLE

    # Descriptive aliases used by some result-model consumers.
    @property
    def status(self) -> SourceAvailability:
        """
        Alias for `availability`.
        """
        return self.availability

    @property
    def cache_freshness(self) -> CacheFreshness | None:
        """
        Return the cache freshness, when cache information is available.
        """
        return self.cache.freshness if self.cache is not None else None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceSnapshot:
        """
        Restore a source snapshot from a JSON-compatible dictionary.
        """
        last_known_good = data.get("last_known_good")
        cache = data.get("cache")
        return cls(
            name=str(data["name"]),
            availability=SourceAvailability(
                data.get("availability", SourceAvailability.UNAVAILABLE.value)
            ),
            checked_at=_datetime_from_json(data.get("checked_at")) or _utc_now(),
            snapshot_id=data.get("snapshot_id"),
            input_digest=data.get("input_digest"),
            url=data.get("url"),
            error=data.get("error"),
            cache=CacheStatus.from_dict(cache) if isinstance(cache, dict) else None,
            first_observed_at=_datetime_from_json(data.get("first_observed_at")),
            last_successful_at=_datetime_from_json(data.get("last_successful_at")),
            last_known_good=cls.from_dict(last_known_good)
            if isinstance(last_known_good, dict)
            else None,
        )

    def to_dict(self, *, include_last_known_good: bool = True) -> dict[str, Any]:
        """
        Serialize this snapshot to a JSON-compatible dictionary.
        """
        result: dict[str, Any] = {
            "name": self.name,
            "availability": self.availability.value,
            "available": self.available,
            "status": self.availability.value,
            "checked_at": _datetime_to_json(self.checked_at),
            "snapshot_id": self.snapshot_id,
            "input_digest": self.input_digest,
            "url": self.url,
            "error": self.error,
            "cache": self.cache.to_dict() if self.cache is not None else None,
            "cache_freshness": self.cache.freshness.value if self.cache is not None else None,
            "first_observed_at": _datetime_to_json(self.first_observed_at),
            "last_successful_at": _datetime_to_json(self.last_successful_at),
        }
        if include_last_known_good and self.last_known_good is not None:
            result["last_known_good"] = self.last_known_good.to_dict(include_last_known_good=False)
        else:
            result["last_known_good"] = None
        return result


# Common naming alias.
SourceStatus = SourceSnapshot
