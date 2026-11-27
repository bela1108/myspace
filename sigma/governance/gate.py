from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from sigma.exceptions import SampleSourceError, SigmaGovernanceError
from sigma.governance.enums import EvidenceKind, SamplePurpose
from sigma.governance.models import (
    DualPersonConfirmation,
    MatchResultRecord,
    SampleKey,
    SampleRecord,
    SampleSource,
)


def _source_name(source: SampleSource | str) -> str:
    if isinstance(source, SampleSource):
        return source.name
    if isinstance(source, str) and source.strip():
        return source
    raise SampleSourceError("Source must be a SampleSource or a non-empty string.")


@dataclass
class PurposeGate:
    """Enforces purpose-based access to governed evidence.

    Grants are maintained independently for each :class:`EvidenceKind`, source
    and :class:`SamplePurpose`. A grant for sample provenance never implies a
    grant for match results or dual-person confirmation, and a training grant
    never satisfies a formal-purpose request.

    Registered samples, match results and confirmations are keyed by the
    composite :class:`SampleKey`, so identical sample ids from different
    sources (e.g. a training package and a rule-release package) stay separate.
    """

    _grants: dict[EvidenceKind, dict[str, set[SamplePurpose]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(set)),
        repr=False,
    )
    _samples: dict[SampleKey, SampleRecord] = field(default_factory=dict, repr=False)
    _match_results: dict[SampleKey, MatchResultRecord] = field(default_factory=dict, repr=False)
    _confirmations: dict[SampleKey, DualPersonConfirmation] = field(
        default_factory=dict, repr=False
    )

    def grant(
        self,
        evidence_kind: EvidenceKind,
        source: SampleSource | str,
        purpose: SamplePurpose,
    ) -> None:
        """Approve one purpose for one source and one evidence kind."""
        self._grants[evidence_kind][_source_name(source)].add(purpose)

    def revoke(
        self,
        evidence_kind: EvidenceKind,
        source: SampleSource | str,
        purpose: SamplePurpose,
    ) -> None:
        """Remove a previously granted purpose. Missing grants are ignored."""
        self._grants[evidence_kind][_source_name(source)].discard(purpose)

    def is_allowed(
        self,
        evidence_kind: EvidenceKind,
        source: SampleSource | str,
        purpose: SamplePurpose,
    ) -> bool:
        """Return whether the source may serve the evidence kind for the purpose."""
        return purpose in self._grants[evidence_kind][_source_name(source)]

    def allowed_purposes(
        self, evidence_kind: EvidenceKind, source: SampleSource | str
    ) -> frozenset[SamplePurpose]:
        """Return the purposes currently approved for a source and evidence kind."""
        return frozenset(self._grants[evidence_kind][_source_name(source)])

    def require_allowed(
        self,
        evidence_kind: EvidenceKind,
        source: SampleSource | str,
        purpose: SamplePurpose,
    ) -> None:
        """Raise :class:`SigmaGovernanceError` unless the usage is approved."""
        source_name = _source_name(source)
        if not self.is_allowed(evidence_kind, source_name, purpose):
            raise SigmaGovernanceError(
                f"Source '{source_name}' is not approved for evidence kind "
                f"{evidence_kind} under purpose {purpose}."
            )

    def register_sample(self, sample: SampleRecord) -> None:
        """Register a sample after checking its provenance grant.

        Re-registering the same composite key replaces the previous record;
        equal sample ids from other sources remain independent entries.
        """
        self.require_allowed(EvidenceKind.SAMPLE_SOURCE, sample.source, sample.purpose)
        self._samples[sample.key] = sample

    def register_match_result(self, record: MatchResultRecord) -> None:
        """Register a rule match result after checking the match-result grant."""
        self.require_allowed(
            EvidenceKind.MATCH_RESULT, record.sample_key.source, record.sample_purpose
        )
        self._match_results[record.sample_key] = record

    def register_confirmation(
        self, sample_key: SampleKey, confirmation: DualPersonConfirmation
    ) -> None:
        """Register a dual-person confirmation after checking its specific grant."""
        self.require_allowed(
            EvidenceKind.DUAL_CONFIRMATION, sample_key.source, self._purpose_of(sample_key)
        )
        self._confirmations[sample_key] = confirmation

    def get_sample(self, sample_key: SampleKey) -> SampleRecord | None:
        return self._samples.get(sample_key)

    def get_match_result(self, sample_key: SampleKey) -> MatchResultRecord | None:
        return self._match_results.get(sample_key)

    def get_confirmation(self, sample_key: SampleKey) -> DualPersonConfirmation | None:
        return self._confirmations.get(sample_key)

    def _purpose_of(self, sample_key: SampleKey) -> SamplePurpose:
        sample = self._samples.get(sample_key)
        if sample is None:
            raise SampleSourceError(
                f"No registered sample for source '{sample_key.source_name}' "
                f"and sample id '{sample_key.sample_id}'."
            )
        return sample.purpose

    def is_formal_reportable(
        self,
        sample_key: SampleKey,
        match_record: MatchResultRecord | None = None,
    ) -> bool:
        """Whether a sample may appear in a formal coverage report.

        All three evidence kinds must be approved for the sample's source and
        its declared purpose, the rule must have matched, and a dual-person
        confirmation must be on record. When ``match_record`` is omitted the
        previously registered match result for the key is evaluated.
        """
        sample = self._samples.get(sample_key)
        if sample is None or sample_key not in self._confirmations:
            return False
        if match_record is None:
            match_record = self._match_results.get(sample_key)
        if match_record is None or not match_record.matched:
            return False
        return all(
            self.is_allowed(kind, sample_key.source, sample.purpose) for kind in EvidenceKind
        )

    def reportable_keys(
        self, match_records: dict[SampleKey, MatchResultRecord] | None = None
    ) -> list[SampleKey]:
        """Composite keys of every sample eligible for the formal report."""
        match_records = match_records or {}
        return [
            key for key in self._samples if self.is_formal_reportable(key, match_records.get(key))
        ]

    def rejection_reason(
        self,
        sample_key: SampleKey,
        match_record: MatchResultRecord | None = None,
    ) -> str | None:
        """Human-readable reason why a sample is excluded from the formal report."""
        sample = self._samples.get(sample_key)
        if sample is None:
            return "sample is not registered"
        missing_kinds = [
            str(kind)
            for kind in EvidenceKind
            if not self.is_allowed(kind, sample_key.source, sample.purpose)
        ]
        if missing_kinds:
            return "missing purpose approval for evidence kinds: " + ", ".join(missing_kinds)
        if match_record is None:
            match_record = self._match_results.get(sample_key)
        if match_record is None:
            return "no match result registered"
        if not match_record.matched:
            return "rule did not match the sample"
        if sample_key not in self._confirmations:
            return "missing dual-person confirmation"
        return None
