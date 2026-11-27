from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sigma.exceptions import SampleSourceError
from sigma.governance.enums import EvidenceKind, SamplePurpose


@dataclass(frozen=True)
class SampleSource:
    """Provenance descriptor identifying where a sample originated.

    The source is independent of the sample identifier. Two records sharing the
    same ``sample_id`` but coming from different sources must never be folded
    together; see :class:`SampleKey`.
    """

    name: str
    description: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise SampleSourceError("Sample source name must be a non-empty string.")


@dataclass(frozen=True)
class SampleKey:
    """Composite identity of a sample: provenance plus the source-local identifier.

    Equality and hashing always include the source, so identical sample ids
    from a training package and a rule-release evidence package remain distinct.
    Shared event fields or the same sample id can therefore never collapse
    records of different origin.
    """

    source: SampleSource
    sample_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.sample_id, str) or not self.sample_id.strip():
            raise SampleSourceError("Sample id must be a non-empty string.")

    @classmethod
    def of(cls, source: SampleSource | str, sample_id: str) -> SampleKey:
        """Build a key from a :class:`SampleSource` or a plain source name."""
        if isinstance(source, str):
            source = SampleSource(source)
        return cls(source=source, sample_id=sample_id)

    @property
    def source_name(self) -> str:
        return self.source.name


@dataclass(frozen=True)
class DualPersonConfirmation:
    """Four-eyes confirmation recorded for one sample.

    The two reviewers must be distinct natural persons; a person cannot
    confirm their own submission.
    """

    submitter: str
    reviewer: str
    confirmed_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    note: str | None = None

    def __post_init__(self) -> None:
        for label, value in (("submitter", self.submitter), ("reviewer", self.reviewer)):
            if not isinstance(value, str) or not value.strip():
                raise SampleSourceError(f"Dual-person {label} must be a non-empty string.")
        if self.submitter == self.reviewer:
            raise SampleSourceError(
                "Dual-person confirmation requires two distinct persons; "
                "submitter and reviewer must not be identical."
            )


@dataclass
class SampleRecord:
    """A governed event sample with provenance and an intended purpose.

    The purpose states how the sample may be used; the :class:`PurposeGate`
    decides, per evidence kind, whether that usage is actually approved for the
    sample's source.
    """

    sample_id: str
    source: SampleSource
    purpose: SamplePurpose
    data: dict[str, Any]
    logsource_category: str | None = None
    logsource_product: str | None = None
    logsource_service: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    raw: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.sample_id, str) or not self.sample_id.strip():
            raise SampleSourceError("Sample id must be a non-empty string.")
        if not isinstance(self.source, SampleSource):
            raise SampleSourceError("Sample record requires an explicit SampleSource.")
        if not isinstance(self.purpose, SamplePurpose):
            raise SampleSourceError("Sample record requires an explicit SamplePurpose.")

    @property
    def key(self) -> SampleKey:
        """Composite (source, sample_id) identity."""
        return SampleKey(source=self.source, sample_id=self.sample_id)


@dataclass(frozen=True)
class MatchResultRecord:
    """The result of evaluating one governed sample against a rule.

    The record preserves the full composite sample key and the sample's own
    declared purpose. It never dedupes on the sample id alone.
    """

    rule_name: str
    sample_key: SampleKey
    sample_purpose: SamplePurpose
    matched: bool
    run_label: str | None = None
    evidence_kind: EvidenceKind = field(default=EvidenceKind.MATCH_RESULT)
