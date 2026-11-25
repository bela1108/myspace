from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Iterable
from uuid import UUID

from sigma.collection import SigmaCollection
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule


class RuleAuditStatus(Enum):
    MATCHED = "matched"
    NO_HITS = "no_hits"
    NOT_SCANNED = "not_scanned"


class ObservationAuditStatus(Enum):
    UNIQUE = "unique"
    DUPLICATE = "duplicate"
    UNKNOWN_RULE = "unknown_rule"
    UNSCANNED_RULE = "unscanned_rule"


@dataclass(frozen=True)
class RuleStaticIdentity:
    rule_id: UUID | None
    name: str | None
    title: str
    logsource: SigmaLogSource
    source: str | None
    references: tuple[str, ...]

    @property
    def key(self) -> str:
        if self.rule_id is not None:
            return f"id:{self.rule_id}"
        if self.name is not None:
            return f"name:{self.name}"
        return f"title:{self.title}"


@dataclass(frozen=True)
class AuditObservation:
    observation_id: str
    rule_identifier: UUID | str
    event_id: str
    groups: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    source: str | None = None

    @classmethod
    def from_grouped(
        cls,
        observation_id: str,
        rule_identifier: UUID | str,
        event_id: str,
        groups: dict[str, str] | None = None,
        source: str | None = None,
    ) -> "AuditObservation":
        return cls(
            observation_id=observation_id,
            rule_identifier=rule_identifier,
            event_id=event_id,
            groups=frozenset((groups or {}).items()),
            source=source,
        )


@dataclass(frozen=True)
class ScanCoverage:
    logsources: frozenset[SigmaLogSource]

    def covers(self, logsource: SigmaLogSource) -> bool:
        return any(logsource in covered_logsource for covered_logsource in self.logsources)

    @classmethod
    def from_logsources(cls, logsources: Iterable[SigmaLogSource]) -> "ScanCoverage":
        return cls(frozenset(logsources))


@dataclass(frozen=True)
class RuleAuditResult:
    rule: RuleStaticIdentity
    status: RuleAuditStatus
    scanned: bool
    unique_observations: tuple[AuditObservation, ...]
    duplicate_observations: tuple[AuditObservation, ...]

    @property
    def unique_count(self) -> int:
        return len(self.unique_observations)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicate_observations)

    @property
    def evidence_count(self) -> int:
        return self.unique_count + self.duplicate_count


@dataclass(frozen=True)
class AuditGroupSummary:
    dimension: str
    value: str
    unique_count: int
    duplicate_count: int
    matched_rule_count: int
    no_hits_rule_count: int
    not_scanned_rule_count: int
    rule_keys: tuple[str, ...]


@dataclass(frozen=True)
class AuditReport:
    rule_results: tuple[RuleAuditResult, ...]
    unassigned_observations: tuple[AuditObservation, ...]
    confirmed_denominator: int
    matched_rule_count: int
    no_hits_rule_count: int
    not_scanned_rule_count: int
    unique_observation_count: int
    duplicate_observation_count: int

    def group_summaries(self, dimension: str) -> tuple[AuditGroupSummary, ...]:
        return summarize_by_group(self, dimension)


def _static_identity(rule: SigmaRule) -> RuleStaticIdentity:
    source = str(rule.source) if rule.source is not None else None
    return RuleStaticIdentity(
        rule_id=rule.id,
        name=rule.name,
        title=rule.title,
        logsource=rule.logsource,
        source=source,
        references=tuple(rule.references),
    )


def _rule_lookup(collection: SigmaCollection) -> dict[str, tuple[SigmaRule, RuleStaticIdentity]]:
    lookup: dict[str, tuple[SigmaRule, RuleStaticIdentity]] = {}
    for rule in collection.rules:
        if not isinstance(rule, SigmaRule):
            continue
        identity = _static_identity(rule)
        if identity.rule_id is not None:
            lookup[f"id:{identity.rule_id}"] = (rule, identity)
        if identity.name is not None:
            lookup[f"name:{identity.name}"] = (rule, identity)
        lookup[f"title:{identity.title}"] = (rule, identity)
    return lookup


def _observation_rule_key(observation: AuditObservation) -> str:
    identifier = observation.rule_identifier
    if isinstance(identifier, UUID):
        return f"id:{identifier}"
    try:
        return f"id:{UUID(str(identifier))}"
    except ValueError:
        return f"name:{identifier}"


def audit_observations(
    collection: SigmaCollection,
    observations: Iterable[AuditObservation],
    coverage: ScanCoverage,
) -> AuditReport:
    lookup = _rule_lookup(collection)
    grouped: dict[str, list[AuditObservation]] = {}
    unassigned: list[AuditObservation] = []

    for observation in observations:
        rule_key = _observation_rule_key(observation)
        if rule_key in lookup:
            grouped.setdefault(rule_key, []).append(observation)
        else:
            unassigned.append(observation)

    rule_results: list[RuleAuditResult] = []
    for rule, identity in lookup.values():
        scanned = coverage.covers(rule.logsource)
        rule_observations = grouped.get(identity.key, [])
        if not scanned:
            status = RuleAuditStatus.NOT_SCANNED
            unique = tuple(rule_observations)
            duplicates: tuple[AuditObservation, ...] = ()
        else:
            unique_items: list[AuditObservation] = []
            duplicate_items: list[AuditObservation] = []
            seen_events: set[str] = set()
            for observation in sorted(rule_observations, key=lambda item: item.observation_id):
                if observation.event_id in seen_events:
                    duplicate_items.append(observation)
                else:
                    seen_events.add(observation.event_id)
                    unique_items.append(observation)
            unique = tuple(unique_items)
            duplicates = tuple(duplicate_items)
            status = RuleAuditStatus.MATCHED if unique_items else RuleAuditStatus.NO_HITS

        rule_results.append(
            RuleAuditResult(
                rule=identity,
                status=status,
                scanned=scanned,
                unique_observations=unique,
                duplicate_observations=duplicates,
            )
        )

    scanned_results = [result for result in rule_results if result.scanned]
    return AuditReport(
        rule_results=tuple(rule_results),
        unassigned_observations=tuple(unassigned),
        confirmed_denominator=len(scanned_results),
        matched_rule_count=sum(
            result.status is RuleAuditStatus.MATCHED for result in scanned_results
        ),
        no_hits_rule_count=sum(
            result.status is RuleAuditStatus.NO_HITS for result in scanned_results
        ),
        not_scanned_rule_count=sum(result.status is RuleAuditStatus.NOT_SCANNED for result in rule_results),
        unique_observation_count=sum(result.unique_count for result in scanned_results),
        duplicate_observation_count=sum(result.duplicate_count for result in scanned_results),
    )


def summarize_by_group(report: AuditReport, dimension: str) -> tuple[AuditGroupSummary, ...]:
    grouped: dict[str, list[RuleAuditResult]] = {}
    for result in report.rule_results:
        values = {value for name, value in result.rule.groups}
        for value in values:
            grouped.setdefault(value, []).append(result)

    summaries = [
        AuditGroupSummary(
            dimension=dimension,
            value=value,
            unique_count=sum(item.unique_count for item in items),
            duplicate_count=sum(item.duplicate_count for item in items),
            matched_rule_count=sum(item.status is RuleAuditStatus.MATCHED for item in items),
            no_hits_rule_count=sum(item.status is RuleAuditStatus.NO_HITS for item in items),
            not_scanned_rule_count=sum(
                item.status is RuleAuditStatus.NOT_SCANNED for item in items
            ),
            rule_keys=tuple(sorted(item.rule.key for item in items)),
        )
        for value, items in grouped.items()
    ]
    return tuple(sorted(summaries, key=lambda item: (item.dimension, item.value)))
