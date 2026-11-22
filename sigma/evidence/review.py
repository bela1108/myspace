from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from sigma.evidence.facts import EvidenceFact, FactExtractor
from sigma.evidence.policy import Audience
from sigma.evidence.provenance import FieldProvenance

STATUS_CONFIRMED = "confirmed"
STATUS_PENDING = "pending"
STATUS_WITHHELD = "withheld"
STATUS_NOT_PUBLISHED = "not_published"


@dataclass(frozen=True)
class EvidenceFinding:
    """Audit result for a single fact."""

    fact: EvidenceFact
    status: str
    sources: frozenset[str]
    required_sources: frozenset[str]
    missing_sources: frozenset[str]
    restricted_sources: frozenset[str]
    public_statement: str | None
    reason: str | None = None

    @property
    def fact_id(self) -> str:
        return self.fact.id

    @property
    def statement(self) -> str:
        return self.fact.statement

    @property
    def kind(self) -> str:
        return self.fact.kind

    @property
    def publishable(self) -> bool:
        return self.status == STATUS_CONFIRMED and self.public_statement is not None

    @property
    def actionable_sources(self) -> frozenset[str]:
        """Sources that still have to be supplied or authorized before publication."""
        return frozenset(self.missing_sources | self.restricted_sources)

    def as_dict(self, *, public: bool = False) -> dict[str, Any]:
        if public:
            result: dict[str, Any] = {
                "statement": self.public_statement,
                "sources": sorted(self.required_sources),
            }
            if self.fact.event_index is not None:
                result["event_index"] = self.fact.event_index
            return result
        return {
            "fact_id": self.fact_id,
            "kind": self.fact.kind,
            "statement": self.statement,
            "status": self.status,
            "direct_sources": sorted(self.fact.sources),
            "sources": sorted(self.sources),
            "required_sources": sorted(self.required_sources),
            "missing_sources": sorted(self.missing_sources),
            "restricted_sources": sorted(self.restricted_sources),
            "public_statement": self.public_statement,
            "publishable": self.publishable,
            "reason": self.reason,
            "event_index": self.fact.event_index,
        }


@dataclass(frozen=True)
class PendingEvidence:
    """Evidence that is required before a withheld statement can be released."""

    fact_id: str
    statement: str
    missing_sources: frozenset[str]
    restricted_sources: frozenset[str]
    reason: str

    @property
    def fields(self) -> frozenset[str]:
        return frozenset(self.missing_sources | self.restricted_sources)

    def as_dict(self, *, public: bool = False) -> dict[str, Any]:
        if public:
            # Do not disclose restricted field names in an external-facing view.
            return {"statement": self.statement, "reason": self.reason}
        return {
            "fact_id": self.fact_id,
            "statement": self.statement,
            "missing_sources": sorted(self.missing_sources),
            "restricted_sources": sorted(self.restricted_sources),
            "fields": sorted(self.fields),
            "reason": self.reason,
        }


@dataclass
class EvidenceReport:
    """Result of reviewing a match for one audience."""

    audience: Audience
    findings: list[EvidenceFinding]
    suspended: bool = False
    suspension_reason: str | None = None

    @property
    def published(self) -> list[EvidenceFinding]:
        return [finding for finding in self.findings if finding.publishable]

    @property
    def public_statements(self) -> list[str]:
        return [
            finding.public_statement
            for finding in self.published
            if finding.public_statement is not None
        ]

    @property
    def pending(self) -> list[PendingEvidence]:
        pending: list[PendingEvidence] = []
        for finding in self.findings:
            if finding.status == STATUS_PENDING:
                reason = "Required telemetry is not present in the matched event(s)."
            elif finding.status == STATUS_WITHHELD:
                reason = "The conclusion depends on fields that are not public for this audience."
            else:
                continue
            pending.append(
                PendingEvidence(
                    fact_id=finding.fact_id,
                    statement=finding.statement,
                    missing_sources=finding.missing_sources,
                    restricted_sources=finding.restricted_sources,
                    reason=finding.reason or reason,
                )
            )
        return pending

    @property
    def withheld(self) -> list[EvidenceFinding]:
        return [
            finding
            for finding in self.findings
            if finding.status in (STATUS_WITHHELD, STATUS_PENDING, STATUS_NOT_PUBLISHED)
        ]

    @property
    def internal_report(self) -> dict[str, Any]:
        """Alias for :meth:`as_internal_dict`."""
        return self.as_internal_dict()

    @property
    def external_report(self) -> dict[str, Any]:
        """Alias for :meth:`as_public_dict`."""
        return self.as_public_dict()

    def as_internal_dict(self) -> dict[str, Any]:
        """Full audit view, including field names and evidence waiting to be supplied."""
        return {
            "audience": self.audience.name,
            "view": "internal",
            "suspended": self.suspended,
            "suspension_reason": self.suspension_reason,
            "findings": [finding.as_dict() for finding in self.findings],
            "pending": [item.as_dict() for item in self.pending],
        }

    def as_public_dict(self) -> dict[str, Any]:
        """External view: only independently confirmable conclusions."""
        return {
            "audience": self.audience.name,
            "view": "public",
            "suspended": self.suspended,
            "conclusions": [finding.as_dict(public=True) for finding in self.published],
        }

    def as_dict(self, view: str = "internal") -> dict[str, Any]:
        if view not in {"internal", "public"}:
            raise ValueError("view must be 'internal' or 'public'")
        return self.as_internal_dict() if view == "internal" else self.as_public_dict()

    def to_text(self, view: str = "internal") -> str:
        if view == "public":
            lines = [f"Audience: {self.audience.name}"]
            if self.suspended:
                lines.append("Publication status: partially suspended")
            else:
                lines.append("Publication status: released")
            if not self.published:
                lines.append("(no independently confirmable conclusions)")
            for finding in self.published:
                lines.append(f"- {finding.public_statement}")
            return "\n".join(lines)

        lines = [f"Audience: {self.audience.name}", f"Suspended: {self.suspended}"]
        if self.suspension_reason:
            lines.append(f"Suspension reason: {self.suspension_reason}")
        for finding in self.findings:
            lines.append(f"- [{finding.status}] {finding.statement}")
            if finding.missing_sources:
                lines.append("  pending telemetry: " + ", ".join(sorted(finding.missing_sources)))
            if finding.restricted_sources:
                lines.append(
                    "  restricted sources: " + ", ".join(sorted(finding.restricted_sources))
                )
            if finding.public_statement and finding.status == STATUS_CONFIRMED:
                lines.append(f"  publishable as: {finding.public_statement}")
        return "\n".join(lines)


class EvidenceReviewer:
    """
    Offline evidence review between conversion and match output.

    The reviewer takes a successful :class:`~sigma.matching.SigmaMatch`, resolves every
    field named by a fact through :class:`FieldProvenance`, and applies an
    :class:`Audience` policy.  It never executes the converted query and does not mutate
    the rule or the match.
    """

    def __init__(
        self,
        provenance: FieldProvenance | None = None,
        *,
        suspend_on_insufficient: bool = True,
        fact_extractor: FactExtractor | None = None,
    ) -> None:
        self.provenance = provenance.copy() if provenance is not None else FieldProvenance()
        self.suspend_on_insufficient = suspend_on_insufficient
        self.fact_extractor = fact_extractor or FactExtractor()

    def review(
        self,
        match: Any,
        audience: Audience,
        *,
        claims: Iterable[EvidenceFact] | None = None,
        facts: Iterable[EvidenceFact] | None = None,
        conversion: Any = None,
        field_mappings: Mapping[str | None, Iterable[str | None]] | None = None,
        provenance: FieldProvenance | None = None,
        aliases: Mapping[str, Iterable[str]] | None = None,
        derived_fields: Mapping[str, Iterable[str]] | None = None,
        include_detection_facts: bool = False,
    ) -> EvidenceReport:
        """
        Review one match for one audience.

        Args:
            match: A successful match produced by :class:`~sigma.matching.SigmaMatcher`.
            audience: Field and fact projection policy for this report.
            claims: Caller-supplied semantic facts.  When omitted, facts are extracted
                from the matched rule condition.
            facts: Alias for ``claims``.
            conversion: Optional conversion side input.  A ``Backend``, processing
                pipeline, ``FieldMappingTracking``, field-mapping dict, or
                :class:`ConversionRecord` are accepted.
            provenance: Additional provenance to merge for this review only.
            aliases: Additional alias definitions (alias -> source fields).
            derived_fields: Additional derived fields (field -> all source fields).
            include_detection_facts: Emit extracted detection facts in addition to
                caller-supplied claims.
        """
        if claims is not None and facts is not None:
            raise TypeError("pass either claims or facts, not both")
        supplied = claims if claims is not None else facts

        effective_provenance = self._build_provenance(
            match=match,
            conversion=conversion,
            field_mappings=field_mappings,
            provenance=provenance,
            aliases=aliases,
            derived_fields=derived_fields,
        )

        if supplied is None:
            review_facts = list(self.fact_extractor.extract(match))
        else:
            review_facts = list(supplied)
            if include_detection_facts:
                review_facts = list(self.fact_extractor.extract(match)) + review_facts
        review_facts = self._deduplicate(review_facts)

        findings = [
            self._review_fact(fact, match, audience, effective_provenance) for fact in review_facts
        ]
        suspended, reason = self._suspension(findings, audience)
        return EvidenceReport(
            audience=audience,
            findings=findings,
            suspended=suspended,
            suspension_reason=reason,
        )

    def review_match(self, match: Any, audience: Audience, **kwargs: Any) -> EvidenceReport:
        """Alias for :meth:`review`."""
        return self.review(match, audience, **kwargs)

    def review_all(
        self,
        match: Any,
        audiences: Iterable[Audience],
        **kwargs: Any,
    ) -> dict[str, EvidenceReport]:
        """Review the same match for several audiences and return reports by name."""
        return {audience.name: self.review(match, audience, **kwargs) for audience in audiences}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_provenance(
        self,
        *,
        match: Any,
        conversion: Any,
        field_mappings: Any,
        provenance: FieldProvenance | None,
        aliases: Mapping[str, Iterable[str]] | None,
        derived_fields: Mapping[str, Iterable[str]] | None,
    ) -> FieldProvenance:
        effective = self.provenance.copy()
        effective.merge(self._provenance_from_conversion(conversion))
        effective.merge(self._provenance_from_conversion(field_mappings))
        effective.merge(provenance)

        rule = getattr(match, "rule", None)
        if rule is not None:
            effective.merge(
                FieldProvenance.from_correlation_aliases(getattr(rule, "aliases", None))
            )

        for alias, sources in (aliases or {}).items():
            effective.add_alias(alias, sources)
        for field_name, sources in (derived_fields or {}).items():
            effective.add_derived(field_name, sources)
        return effective

    def _provenance_from_conversion(self, conversion: Any) -> FieldProvenance:
        if conversion is None:
            return FieldProvenance()
        if isinstance(conversion, FieldProvenance):
            return conversion
        if isinstance(conversion, Mapping):
            return FieldProvenance.from_field_mappings(conversion)
        if isinstance(conversion, (list, tuple, set)):
            merged = FieldProvenance()
            for item in conversion:
                merged.merge(self._provenance_from_conversion(item))
            return merged

        provenance = getattr(conversion, "field_provenance", None)
        if isinstance(provenance, FieldProvenance):
            return provenance

        pipeline = getattr(conversion, "last_processing_pipeline", None)
        if pipeline is not None:
            return FieldProvenance.from_processing_pipeline(pipeline)

        # ProcessingPipeline has a field_mappings attribute but no last_processing_pipeline.
        if hasattr(conversion, "field_mappings"):
            return FieldProvenance.from_processing_pipeline(conversion)
        return FieldProvenance()

    def _review_fact(
        self,
        fact: EvidenceFact,
        match: Any,
        audience: Audience,
        provenance: FieldProvenance,
    ) -> EvidenceFinding:
        event_data = [event.data for event in getattr(match, "events", [])]
        if fact.event_index is not None:
            if 0 <= fact.event_index < len(event_data):
                data: Any = [event_data[fact.event_index]]
            else:
                data = []
        else:
            data = event_data

        sources: set[str] = set()
        required: set[str] = set()
        missing: set[str] = set()
        for source in sorted(fact.sources):
            resolution = provenance.resolve(source, data)
            sources.update(resolution.sources)
            required.update(resolution.required)
            if source not in fact.absent_sources and not resolution.sources <= fact.absent_sources:
                missing.update(resolution.missing)

        if not fact.observed:
            # The caller marked the statement as unsupported by the available evidence.
            required.update(fact.sources)
            missing.update(fact.sources)
        elif not fact.requires_presence:
            # Absence itself is the evidence, e.g. a negated condition.
            missing.clear()

        restricted = {source for source in required if not audience.field_allowed(source)}
        projected = audience.project(fact)
        if isinstance(projected, str):
            public_statement = projected
        elif projected is True:
            public_statement = fact.public_statement or fact.statement
        else:
            public_statement = None

        if missing:
            status = STATUS_PENDING
            reason = "Required telemetry is missing: " + ", ".join(sorted(missing))
        elif restricted:
            status = STATUS_WITHHELD
            reason = "Restricted sources: " + ", ".join(sorted(restricted))
        elif public_statement is None:
            status = STATUS_NOT_PUBLISHED
            reason = "The audience policy does not permit this fact to be projected."
        else:
            status = STATUS_CONFIRMED
            reason = None

        return EvidenceFinding(
            fact=fact,
            status=status,
            sources=frozenset(sources),
            required_sources=frozenset(required),
            missing_sources=frozenset(missing),
            restricted_sources=frozenset(restricted),
            public_statement=public_statement,
            reason=reason,
        )

    def _suspension(
        self, findings: list[EvidenceFinding], audience: Audience
    ) -> tuple[bool, str | None]:
        if not self.suspend_on_insufficient:
            return False, None

        blocking = [
            finding
            for finding in findings
            if finding.fact.required and finding.status in {STATUS_PENDING, STATUS_WITHHELD}
        ]
        if not blocking:
            return False, None

        missing = sorted({source for finding in blocking for source in finding.missing_sources})
        restricted = sorted(
            {source for finding in blocking for source in finding.restricted_sources}
        )
        reason_parts: list[str] = []
        if missing:
            reason_parts.append("missing telemetry: " + ", ".join(missing))
        if restricted:
            reason_parts.append("restricted sources: " + ", ".join(restricted))
        return True, "; ".join(reason_parts)

    @staticmethod
    def _deduplicate(facts: list[EvidenceFact]) -> list[EvidenceFact]:
        seen: set[str] = set()
        result: list[EvidenceFact] = []
        for fact in facts:
            if fact.id in seen:
                continue
            seen.add(fact.id)
            result.append(fact)
        return result


def review_match(
    match: Any,
    audience: Audience,
    *,
    provenance: FieldProvenance | None = None,
    **kwargs: Any,
) -> EvidenceReport:
    """Convenience wrapper around :class:`EvidenceReviewer`."""
    return EvidenceReviewer(provenance=provenance).review(match, audience, **kwargs)


# Clear aliases for integrations that use different terminology.
OfflineEvidenceReview = EvidenceReviewer
EvidenceReview = EvidenceReviewer
