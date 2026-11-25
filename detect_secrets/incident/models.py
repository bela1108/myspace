"""Data models for offline credential-incident recomputation.

All classes here are plain data; the replay engine is the single place that
evolves them.  Timestamps are fixed-width ISO-8601 strings and are compared
lexicographically, which keeps the tool free of timezone bookkeeping.
"""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from detect_secrets.incident.enums import EventType
from detect_secrets.incident.enums import ReviewState


def parse_iso8601(value: Any) -> str:
    if not isinstance(value, str) or len(value) < 10:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}")
    return value


@dataclass(frozen=True)
class Finding:
    """A pre-existing detect-secrets finding with a caller-assigned stable id."""

    finding_id: str
    secret_type: str
    hashed_secret: str
    initial_path: str
    line_number: int = 0

    @property
    def natural_key(self) -> str:
        return f"{self.secret_type}:{self.hashed_secret}"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            finding_id=data["finding_id"],
            secret_type=data["type"],
            hashed_secret=data["hashed_secret"],
            initial_path=data["filename"],
            line_number=int(data.get("line_number", 0)),
        )


@dataclass(frozen=True)
class OwnershipRule:
    """Path-prefix ownership valid during a half-open time interval.

    ``effective_to`` of ``None`` means the rule is still in force.
    """

    record_id: str
    path_prefix: str
    team: str
    effective_from: str
    effective_to: Optional[str] = None
    source: str = ""

    def covers_path(self, path: str) -> bool:
        if self.path_prefix in ("", "/"):
            return True
        prefix = self.path_prefix.rstrip("/")
        return path == prefix or path.startswith(prefix + "/")

    def in_force_at(self, timestamp: str) -> bool:
        if timestamp < self.effective_from:
            return False
        return self.effective_to is None or timestamp < self.effective_to

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OwnershipRule":
        effective_to = data.get("effective_to")
        return cls(
            record_id=data["record_id"],
            path_prefix=data["path_prefix"],
            team=data["team"],
            effective_from=parse_iso8601(data["effective_from"]),
            effective_to=parse_iso8601(effective_to) if effective_to else None,
            source=data.get("source", ""),
        )


@dataclass(frozen=True)
class Exemption:
    """A time-limited exemption bound to one finding id and one path."""

    exemption_id: str
    finding_id: str
    path: str
    granted_at: str
    expires_at: str
    justification: str = ""
    revoked_at: Optional[str] = None

    def is_revoked_at(self, timestamp: str) -> bool:
        return self.revoked_at is not None and timestamp >= self.revoked_at

    def is_expired_at(self, timestamp: str) -> bool:
        return timestamp >= self.expires_at

    def active_at(self, timestamp: str) -> bool:
        return not self.is_revoked_at(timestamp) and not self.is_expired_at(timestamp)

    def covers(self, finding_id: str, path: str, timestamp: str) -> bool:
        """Exemptions stay glued to the path they were registered against.

        A move or fork creates an occurrence at another path that this
        exemption can never cover, so one stale exemption cannot silence two
        sibling occurrences.
        """
        return (
            self.finding_id == finding_id
            and self.path == path
            and self.active_at(timestamp)
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Exemption":
        revoked_at = data.get("revoked_at")
        return cls(
            exemption_id=data["exemption_id"],
            finding_id=data["finding_id"],
            path=data["path"],
            granted_at=parse_iso8601(data["granted_at"]),
            expires_at=parse_iso8601(data["expires_at"]),
            justification=data.get("justification", ""),
            revoked_at=parse_iso8601(revoked_at) if revoked_at else None,
        )



@dataclass(frozen=True)
class Event:
    """An immutable fact in the incident timeline."""

    event_id: str
    event_type: EventType
    timestamp: str
    finding_id: Optional[str] = None
    from_path: Optional[str] = None
    to_path: Optional[str] = None
    team: Optional[str] = None
    exemption_id: Optional[str] = None
    detail: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        return cls(
            event_id=data["event_id"],
            event_type=EventType(data["event_type"]),
            timestamp=parse_iso8601(data["timestamp"]),
            finding_id=data.get("finding_id"),
            from_path=data.get("from_path"),
            to_path=data.get("to_path"),
            team=data.get("team"),
            exemption_id=data.get("exemption_id"),
            detail=data.get("detail", ""),
        )


@dataclass
class Occurrence:
    """Runtime state for one finding at one path.

    A forked finding has several independent occurrences; each carries its
    own owner, exemption and review state.
    """

    finding_id: str
    path: str
    line_number: int
    born_at: str
    team: Optional[str] = None
    ownership_record_id: Optional[str] = None
    review_deadline: Optional[str] = None
    state: ReviewState = ReviewState.OPEN
    active_exemption_id: Optional[str] = None
    last_event_id: Optional[str] = None
    forked_from: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "path": self.path,
            "line_number": self.line_number,
            "born_at": self.born_at,
            "team": self.team,
            "ownership_record_id": self.ownership_record_id,
            "review_deadline": self.review_deadline,
            "state": self.state.value,
            "active_exemption_id": self.active_exemption_id,
            "last_event_id": self.last_event_id,
            "forked_from": self.forked_from,
        }


@dataclass(frozen=True)
class AuditEntry:
    """One append-only, fully traceable decision made during replay."""

    sequence: int
    event_id: str
    timestamp: str
    action: str
    decision: str
    reason: str
    finding_id: Optional[str] = None
    path: Optional[str] = None
    team: Optional[str] = None
    ownership_record_id: Optional[str] = None
    exemption_id: Optional[str] = None
    review_deadline: Optional[str] = None
    state_before: Optional[str] = None
    state_after: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "finding_id": self.finding_id,
            "path": self.path,
            "team": self.team,
            "ownership_record_id": self.ownership_record_id,
            "exemption_id": self.exemption_id,
            "review_deadline": self.review_deadline,
            "state_before": self.state_before,
            "state_after": self.state_after,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Case:
    """All inputs required for one offline recomputation."""

    findings: List[Finding]
    ownership_rules: List[OwnershipRule]
    exemptions: List[Exemption]
    events: List[Event]
    review_sla_days: int = 30

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Case":
        return cls(
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            ownership_rules=[
                OwnershipRule.from_dict(item) for item in data.get("ownership", [])
            ],
            exemptions=[
                Exemption.from_dict(item) for item in data.get("exemptions", [])
            ],
            events=[Event.from_dict(item) for item in data.get("events", [])],
            review_sla_days=int(data.get("review_sla_days", 30)),
        )
