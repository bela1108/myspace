from __future__ import annotations

from dataclasses import dataclass, field

from sigma.collection import SigmaCollection
from sigma.exceptions import SampleSourceError
from sigma.governance.enums import SamplePurpose
from sigma.governance.gate import PurposeGate
from sigma.governance.models import MatchResultRecord, SampleKey, SampleRecord
from sigma.matching import Event, EventLogSource, SigmaMatcher


def _build_event(sample: SampleRecord) -> Event:
    return Event(
        timestamp=sample.timestamp,
        logsource=EventLogSource(
            category=sample.logsource_category,
            product=sample.logsource_product,
            service=sample.logsource_service,
        ),
        data=dict(sample.data),
        raw=sample.raw,
    )


@dataclass(frozen=True)
class CoverageEntry:
    """One rule/sample line admitted to the formal coverage report."""

    rule_name: str
    sample_key: SampleKey
    matched: bool


@dataclass(frozen=True)
class RejectedEntry:
    """A rule/sample line kept out of the formal report, with the reason."""

    rule_name: str
    sample_key: SampleKey
    reason: str


@dataclass
class RuleCoverageReport:
    """Formal coverage evidence for one rule.

    Only entries that pass the :class:`PurposeGate` for the requested purpose
    appear in :attr:`entries`. Rejected evidence is retained separately for
    auditability but is never part of the formal listing.
    """

    rule_name: str
    purpose: SamplePurpose
    entries: list[CoverageEntry] = field(default_factory=list)
    rejected: list[RejectedEntry] = field(default_factory=list)

    def sample_keys(self) -> list[SampleKey]:
        return [entry.sample_key for entry in self.entries]


@dataclass
class OfflineRunResult:
    """Outcome of two independent offline runs over identical rule input."""

    report: RuleCoverageReport
    first_run_label: str
    second_run_label: str
    consistent: bool
    discrepancies: list[SampleKey] = field(default_factory=list)


def _run_once(
    label: str,
    collection: SigmaCollection,
    samples: list[SampleRecord],
    rule_name: str,
) -> dict[SampleKey, MatchResultRecord]:
    """Run one isolated matcher pass and return keyed match records."""
    results: dict[SampleKey, MatchResultRecord] = {}
    with SigmaMatcher(collection) as matcher:
        for sample in samples:
            event = _build_event(sample)
            matches = matcher.match(event)
            matched = any(match.rule.name == rule_name for match in matches)
            results[sample.key] = MatchResultRecord(
                rule_name=rule_name,
                sample_key=sample.key,
                sample_purpose=sample.purpose,
                matched=matched,
                run_label=label,
            )
    return results


def _ensure_distinct_keys(samples: list[SampleRecord]) -> None:
    """Reject input that would silently fold distinct records onto one key."""
    seen: set[SampleKey] = set()
    for sample in samples:
        if sample.key in seen:
            raise SampleSourceError(
                f"Duplicate sample key for source '{sample.key.source_name}' "
                f"and sample id '{sample.sample_id}'; sources must stay independent."
            )
        seen.add(sample.key)


def _rule_name(collection: SigmaCollection) -> str:
    names = [rule.name for rule in collection.rules if getattr(rule, "name", None)]
    if not names:
        raise ValueError("Rule collection must contain at least one named rule.")
    unique = set(names)
    if len(unique) != 1:
        raise ValueError("Offline coverage run expects a single rule per collection.")
    return names[0]


def run_offline_coverage(
    rule_input: str,
    gate: PurposeGate,
    samples: list[SampleRecord],
    purpose: SamplePurpose = SamplePurpose.FORMAL,
    *,
    first_run_label: str = "run-1",
    second_run_label: str = "run-2",
) -> OfflineRunResult:
    """Run the same rule input twice, independently, then build a gated report.

    Each run parses the YAML into its own :class:`SigmaCollection` and matcher,
    so shared state cannot fold samples together. The formal report lists only
    samples whose source is approved for every evidence kind under ``purpose``
    and that carry a registered dual-person confirmation.
    """
    _ensure_distinct_keys(samples)
    first_collection = SigmaCollection.from_yaml(rule_input)
    second_collection = SigmaCollection.from_yaml(rule_input)
    rule_name = _rule_name(first_collection)

    first_results = _run_once(first_run_label, first_collection, samples, rule_name)
    second_results = _run_once(second_run_label, second_collection, samples, rule_name)

    discrepancies = [
        key for key in first_results if first_results[key].matched != second_results[key].matched
    ]
    consistent = not discrepancies

    report = RuleCoverageReport(rule_name=rule_name, purpose=purpose)
    for sample in samples:
        key = sample.key
        record = first_results[key]
        if sample.purpose != purpose:
            reason = f"sample purpose {sample.purpose} does not match report purpose {purpose}"
        else:
            reason = gate.rejection_reason(key, record)
        if reason is None:
            gate.register_match_result(record)
            report.entries.append(
                CoverageEntry(rule_name=rule_name, sample_key=key, matched=record.matched)
            )
        else:
            report.rejected.append(
                RejectedEntry(rule_name=rule_name, sample_key=key, reason=reason)
            )

    return OfflineRunResult(
        report=report,
        first_run_label=first_run_label,
        second_run_label=second_run_label,
        consistent=consistent,
        discrepancies=discrepancies,
    )
