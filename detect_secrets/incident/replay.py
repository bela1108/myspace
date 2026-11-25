"""Deterministic, side-effect free replay of credential disposition events.

Given a fixed :class:`~detect_secrets.incident.models.Case` the engine
recomputes every finding occurrence from scratch and appends one immutable
:class:`~detect_secrets.incident.models.AuditEntry` per decision.

Load-bearing guarantees:

* Past decisions remain queryable through :class:`AuditLog` even after the
  owner, path or exemption changes.
* A finding that forks to two paths becomes two independent occurrences; an
  exemption bound to one occurrence can never close the sibling.
"""
from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional

from detect_secrets.incident.enums import Decision
from detect_secrets.incident.enums import EventType
from detect_secrets.incident.enums import OwnerSource
from detect_secrets.incident.enums import ReviewState
from detect_secrets.incident.exceptions import DuplicateEventError
from detect_secrets.incident.exceptions import EventOrderError
from detect_secrets.incident.exceptions import InvalidEventError
from detect_secrets.incident.exceptions import UnknownFindingError
from detect_secrets.incident.exemptions import ExemptionRegistry
from detect_secrets.incident.models import AuditEntry
from detect_secrets.incident.models import Case
from detect_secrets.incident.models import Event
from detect_secrets.incident.models import Exemption
from detect_secrets.incident.models import Finding
from detect_secrets.incident.models import Occurrence
from detect_secrets.incident.models import OwnershipRule
from detect_secrets.incident.ownership import OwnershipBook


def _add_days(timestamp: str, days: int) -> str:
    return (
        datetime.fromisoformat(timestamp) + timedelta(days=days)
    ).isoformat()


class AuditLog:
    """Append-only history of every disposition decision."""

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []

    def record(self, **kwargs: Any) -> AuditEntry:
        entry = AuditEntry(sequence=len(self._entries), **kwargs)
        self._entries.append(entry)
        return entry

    def entries(self) -> List[AuditEntry]:
        return list(self._entries)

    def for_finding(self, finding_id: str) -> List[AuditEntry]:
        return [entry for entry in self._entries if entry.finding_id == finding_id]

    def decisions(self) -> List[str]:
        return [entry.decision for entry in self._entries]

    def to_dicts(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self._entries]


class ReplayEngine:
    """Replays an ordered event log over a fixed set of inputs."""

    def __init__(
        self,
        findings: Iterable[Finding],
        ownership_rules: Iterable[OwnershipRule],
        exemptions: Iterable[Exemption],
        review_sla_days: int = 30,
    ) -> None:
        self._findings: Dict[str, Finding] = {
            finding.finding_id: finding for finding in findings
        }
        self._ownership = OwnershipBook(ownership_rules)
        self._exemptions = ExemptionRegistry(exemptions)
        self._sla_days = review_sla_days
        self._occurrences: Dict[str, Dict[str, Occurrence]] = {}
        self._audit = AuditLog()
        self._seen_events: set[str] = set()
        self._last_timestamp: Optional[str] = None

    @property
    def audit_log(self) -> AuditLog:
        return self._audit

    @property
    def findings(self) -> Dict[str, Finding]:
        return dict(self._findings)

    @property
    def occurrences(self) -> Dict[str, Dict[str, Occurrence]]:
        return self._occurrences

    @property
    def event_count(self) -> int:
        return len(self._seen_events)

    @property
    def last_event_at(self) -> Optional[str]:
        return self._last_timestamp

    def run(self, events: Iterable[Event]) -> Dict[str, Dict[str, Occurrence]]:
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            self._dispatch(event)
        self._refresh_review_states()
        return self._occurrences

    def _refresh_review_states(self) -> None:
        at = self._last_timestamp
        if at is None:
            return
        for paths in self._occurrences.values():
            for occurrence in paths.values():
                if occurrence.state == ReviewState.SUPPRESSED:
                    continue
                if self._exemptions.active_for(
                    occurrence.finding_id, occurrence.path, at,
                ):
                    occurrence.state = ReviewState.EXEMPT
                elif occurrence.review_deadline is not None and at >= occurrence.review_deadline:
                    occurrence.state = ReviewState.OVERDUE
                else:
                    occurrence.state = ReviewState.PENDING


    def _dispatch(self, event: Event) -> None:
        if event.event_id in self._seen_events:
            raise DuplicateEventError(event.event_id)
        self._seen_events.add(event.event_id)
        if (
            self._last_timestamp is not None
            and event.timestamp < self._last_timestamp
        ):
            raise EventOrderError(
                f"event {event.event_id} at {event.timestamp} precedes prior"
                f" event at {self._last_timestamp}",
            )
        self._last_timestamp = event.timestamp

        handlers = {
            EventType.FINDING_INTRODUCED: self._on_introduced,
            EventType.CODE_MOVED: self._on_code_moved,
            EventType.FINDING_FORKED: self._on_forked,
            EventType.OWNERSHIP_CHANGED: self._on_ownership_changed,
            EventType.EXEMPTION_GRANTED: self._on_exemption_granted,
            EventType.EXEMPTION_REVOKED: self._on_exemption_revoked,
            EventType.SUPPRESS: self._on_suppress,
        }
        handler = handlers.get(event.event_type)
        if handler is None:
            raise InvalidEventError(f"unsupported event type: {event.event_type}")
        handler(event)

    def _require_finding(self, event: Event) -> Finding:
        finding = self._findings.get(event.finding_id or "")
        if finding is None:
            raise UnknownFindingError(
                f"event {event.event_id} references unknown finding "
                f"{event.finding_id!r}",
            )
        return finding

    def _require_occurrence(self, event: Event, path: str) -> Occurrence:
        state = self._occurrences.get(event.finding_id or "")
        if state is None or path not in state:
            raise UnknownFindingError(
                f"event {event.event_id}: finding {event.finding_id} has no "
                f"occurrence at {path}",
            )
        return state[path]

    def _record(self, event: Event, **kwargs: Any) -> AuditEntry:
        return self._audit.record(
            event_id=event.event_id,
            timestamp=event.timestamp,
            **kwargs,
        )

    def _on_introduced(self, event: Event) -> None:
        finding = self._require_finding(event)
        path = event.to_path or finding.initial_path
        resolution = self._ownership.resolve(path, event.timestamp)
        deadline = _add_days(event.timestamp, self._sla_days)
        occurrence = Occurrence(
            finding_id=finding.finding_id,
            path=path,
            line_number=finding.line_number,
            born_at=event.timestamp,
            team=resolution.team,
            ownership_record_id=resolution.record_id,
            review_deadline=deadline,
            last_event_id=event.event_id,
        )
        self._occurrences.setdefault(finding.finding_id, {})[path] = occurrence
        self._record(
            event,
            action=event.event_type.value,
            decision=Decision.REGISTERED.value,
            reason="detect-secrets finding first registered",
            finding_id=finding.finding_id,
            path=path,
            team=resolution.team,
            ownership_record_id=resolution.record_id,
            review_deadline=deadline,
            state_after=ReviewState.OPEN.value,
            evidence={"ownership_source": resolution.source},
        )

    def _move_ownership(
        self,
        new_path: str,
        at: str,
        source: Occurrence,
    ):
        try:
            return self._ownership.resolve(new_path, at)
        except LookupError:
            return self._ownership.resolve(
                new_path,
                at,
                fallback_team=source.team,
                fallback_record_id=source.ownership_record_id,
            )

    def _on_code_moved(self, event: Event) -> None:
        finding = self._require_finding(event)
        old_path = event.from_path
        new_path = event.to_path
        if not old_path or not new_path:
            raise InvalidEventError(
                f"event {event.event_id} needs from_path and to_path",
            )
        source = self._require_occurrence(event, old_path)
        resolution = self._move_ownership(new_path, event.timestamp, source)
        moved = Occurrence(
            finding_id=finding.finding_id,
            path=new_path,
            line_number=source.line_number,
            born_at=source.born_at,
            team=resolution.team,
            ownership_record_id=resolution.record_id,
            review_deadline=source.review_deadline,
            state=source.state,
            active_exemption_id=None,
            last_event_id=event.event_id,
        )
        del self._occurrences[finding.finding_id][old_path]
        self._occurrences[finding.finding_id][new_path] = moved
        self._record(
            event,
            action=event.event_type.value,
            decision=Decision.MOVED.value,
            reason=(
                f"code moved {old_path} -> {new_path}; exemptions do not "
                "travel with the code"
            ),
            finding_id=finding.finding_id,
            path=new_path,
            team=resolution.team,
            ownership_record_id=resolution.record_id,
            review_deadline=moved.review_deadline,
            state_before=source.state.value,
            state_after=moved.state.value,
            evidence={
                "ownership_source": resolution.source,
                "previous_path": old_path,
            },
        )


    def _on_forked(self, event: Event) -> None:
        finding = self._require_finding(event)
        source_path = event.from_path
        new_path = event.to_path
        if not source_path or not new_path:
            raise InvalidEventError(
                f"event {event.event_id} needs from_path and to_path",
            )
        source = self._require_occurrence(event, source_path)
        if new_path in self._occurrences[finding.finding_id]:
            raise InvalidEventError(
                f"event {event.event_id}: occurrence already exists at {new_path}",
            )
        resolution = self._move_ownership(new_path, event.timestamp, source)
        forked = Occurrence(
            finding_id=finding.finding_id,
            path=new_path,
            line_number=source.line_number,
            born_at=event.timestamp,
            team=resolution.team,
            ownership_record_id=resolution.record_id,
            review_deadline=source.review_deadline,
            active_exemption_id=None,
            last_event_id=event.event_id,
            forked_from=source_path,
        )
        self._occurrences[finding.finding_id][new_path] = forked
        self._record(
            event,
            action=event.event_type.value,
            decision=Decision.FORKED.value,
            reason=(
                f"finding duplicated from {source_path} to {new_path}; the two "
                "occurrences are independent and cannot share an exemption"
            ),
            finding_id=finding.finding_id,
            path=new_path,
            team=resolution.team,
            ownership_record_id=resolution.record_id,
            review_deadline=forked.review_deadline,
            state_after=ReviewState.OPEN.value,
            evidence={
                "ownership_source": resolution.source,
                "forked_from": source_path,
            },
        )

    def _on_ownership_changed(self, event: Event) -> None:
        finding = self._require_finding(event)
        path = event.from_path or event.to_path
        occurrence = self._require_occurrence(event, path)
        previous_team = occurrence.team
        if event.team:
            team = event.team
            record_id = event.event_id
            source = OwnerSource.EVENT.value
        else:
            resolution = self._ownership.resolve(path, event.timestamp)
            team = resolution.team
            record_id = resolution.record_id
            source = resolution.source
        occurrence.team = team
        occurrence.ownership_record_id = record_id
        occurrence.last_event_id = event.event_id
        self._record(
            event,
            action=event.event_type.value,
            decision=Decision.OWNER_ASSIGNED.value,
            reason=(
                f"responsibility transferred {previous_team} -> {team}; "
                "review deadline unchanged"
            ),
            finding_id=finding.finding_id,
            path=path,
            team=team,
            ownership_record_id=record_id,
            review_deadline=occurrence.review_deadline,
            state_before=occurrence.state.value,
            state_after=occurrence.state.value,
            evidence={"ownership_source": source, "previous_team": previous_team},
        )

    def _on_exemption_granted(self, event: Event) -> None:
        finding = self._require_finding(event)
        if not event.exemption_id:
            raise InvalidEventError(
                f"event {event.event_id} requires an exemption_id",
            )
        exemption = self._exemptions.get(event.exemption_id)
        if exemption.finding_id != finding.finding_id:
            raise InvalidEventError(
                f"exemption {event.exemption_id} is bound to "
                f"{exemption.finding_id}, not {finding.finding_id}",
            )
        occurrence = self._require_occurrence(event, exemption.path)
        occurrence.active_exemption_id = exemption.exemption_id
        if (
            occurrence.review_deadline is None
            or exemption.expires_at > occurrence.review_deadline
        ):
            occurrence.review_deadline = exemption.expires_at
        occurrence.last_event_id = event.event_id
        self._record(
            event,
            action=event.event_type.value,
            decision=Decision.EXEMPTION_APPLIED.value,
            reason=(
                f"time-limited exemption {exemption.exemption_id} attached; "
                f"expires {exemption.expires_at}"
            ),
            finding_id=finding.finding_id,
            path=exemption.path,
            team=occurrence.team,
            ownership_record_id=occurrence.ownership_record_id,
            exemption_id=exemption.exemption_id,
            review_deadline=occurrence.review_deadline,
            state_after=ReviewState.EXEMPT.value,
            evidence={"expires_at": exemption.expires_at},
        )

    def _on_exemption_revoked(self, event: Event) -> None:
        finding = self._require_finding(event)
        if not event.exemption_id:
            raise InvalidEventError(
                f"event {event.event_id} requires an exemption_id",
            )
        exemption = self._exemptions.get(event.exemption_id)
        occurrence = self._require_occurrence(event, exemption.path)
        was_active = occurrence.active_exemption_id == exemption.exemption_id
        before = occurrence.state.value
        if was_active:
            occurrence.active_exemption_id = None
        if occurrence.state == ReviewState.SUPPRESSED:
            occurrence.state = ReviewState.OPEN
        occurrence.last_event_id = event.event_id
        self._record(
            event,
            action=event.event_type.value,
            decision=Decision.EXEMPTION_REVOKED.value,
            reason=(
                f"exemption {exemption.exemption_id} withdrawn before expiry"
                if was_active
                else f"revocation recorded for inactive {exemption.exemption_id}"
            ),
            finding_id=finding.finding_id,
            path=exemption.path,
            team=occurrence.team,
            ownership_record_id=occurrence.ownership_record_id,
            exemption_id=exemption.exemption_id,
            review_deadline=occurrence.review_deadline,
            state_before=before,
            state_after=occurrence.state.value,
        )

    def _on_suppress(self, event: Event) -> None:
        finding = self._require_finding(event)
        path = event.to_path or event.from_path
        if not path:
            raise InvalidEventError(f"event {event.event_id} requires a path")
        occurrence = self._require_occurrence(event, path)
        before = occurrence.state.value
        coverage = self._exemptions.evaluate(
            finding.finding_id,
            path,
            event.timestamp,
            event.exemption_id,
        )
        if coverage.allowed and coverage.exemption_id is not None:
            exemption = self._exemptions.get(coverage.exemption_id)
            occurrence.state = ReviewState.SUPPRESSED
            occurrence.active_exemption_id = coverage.exemption_id
            if (
                occurrence.review_deadline is None
                or exemption.expires_at > occurrence.review_deadline
            ):
                occurrence.review_deadline = exemption.expires_at
            occurrence.last_event_id = event.event_id
            self._record(
                event,
                action=event.event_type.value,
                decision=Decision.SUPPRESSED.value,
                reason=coverage.reason,
                finding_id=finding.finding_id,
                path=path,
                team=occurrence.team,
                ownership_record_id=occurrence.ownership_record_id,
                exemption_id=coverage.exemption_id,
                review_deadline=occurrence.review_deadline,
                state_before=before,
                state_after=ReviewState.SUPPRESSED.value,
                evidence={"exemption_status": coverage.status.value},
            )
            return

        self._record(
            event,
            action=event.event_type.value,
            decision=Decision.SUPPRESSION_REJECTED.value,
            reason=coverage.reason,
            finding_id=finding.finding_id,
            path=path,
            team=occurrence.team,
            ownership_record_id=occurrence.ownership_record_id,
            exemption_id=coverage.exemption_id,
            review_deadline=occurrence.review_deadline,
            state_before=before,
            state_after=before,
            evidence={"exemption_status": coverage.status.value},
        )


def replay_case(
    data: Mapping[str, Any],
    as_of: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse a combined case document and return the full report dict."""
    from detect_secrets.incident.report import build_report

    case = Case.from_dict(data)
    engine = ReplayEngine(
        case.findings,
        case.ownership_rules,
        case.exemptions,
        review_sla_days=case.review_sla_days,
    )
    engine.run(case.events)
    return build_report(engine, as_of=as_of)
