"""
Domain models for the side-channel "receipt evidence" reconciliation.

The security group's audit sheet only carries a package name and version,
while procurement ships concrete distribution files (wheels/sdists) and the
same version can be published for several platforms. Reconciliation therefore
has to be performed against the *distribution file* (its filename and digest)
rather than against the name/version coordinate alone.

Every piece of evidence remembers which source provided it ("who provided
each step") so that a disagreement between two handoffs can be traced back to
the exact stage at which it occurred.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum

from packaging.utils import canonicalize_name


class ReceiptError(Exception):
    """Base class for every error raised by the receipt reconciliation API."""


class ReceiptSourceError(ReceiptError):
    """Raised when an evidence document cannot be loaded or parsed."""


class HandoffStage(str, Enum):
    """
    The ordered handoffs a distribution file passes through.

    The ordering matters: when two consecutive handoffs disagree, the later
    stage is the one at which the conflict is first observable.
    """

    LOCAL_PLAN = "local_plan"
    WAREHOUSE = "warehouse"
    TRANSIT = "transit"

    @property
    def order(self) -> int:
        return [
            HandoffStage.LOCAL_PLAN,
            HandoffStage.WAREHOUSE,
            HandoffStage.TRANSIT,
        ].index(self)


class ReconciliationStatus(str, Enum):
    """
    The outcome of matching a single distribution file across the handoffs.
    """

    MATCHED = "matched"
    PENDING = "pending"
    CONFLICT = "conflict"


def normalize_digest(digest: str | None) -> str | None:
    """
    Normalize a digest string for comparison.

    Accepts both bare hex digests and ``alg:hex`` forms and compares them
    case-insensitively. Returns ``None`` when no digest is present.
    """

    if digest is None:
        return None
    normalized = digest.strip().lower()
    if not normalized:
        return None
    if ":" in normalized:
        _algorithm, _, hexdigest = normalized.partition(":")
        return hexdigest
    return normalized


def normalize_filename(filename: str | None) -> str | None:
    """Normalize a distribution filename for comparison."""

    if filename is None:
        return None
    normalized = filename.strip()
    return normalized or None


@dataclass(frozen=True)
class ArtifactIdentity:
    """
    The file-level identity of a distribution artifact.

    ``filename`` is the distribution file (wheel/sdist) as shipped; ``digest``
    is its content digest. Either may be missing for legacy reports, in which
    case the identity is considered incomplete and the row can only be opened
    as "pending verification".
    """

    filename: str | None
    digest: str | None

    @classmethod
    def create(cls, filename: str | None, digest: str | None) -> ArtifactIdentity:
        return cls(
            filename=normalize_filename(filename),
            digest=normalize_digest(digest),
        )

    @property
    def is_complete(self) -> bool:
        """Whether this identity is concrete enough to reconcile on."""

        return self.filename is not None and self.digest is not None

    @property
    def missing_materials(self) -> tuple[str, ...]:
        """The identity materials that this artifact is lacking."""

        missing: list[str] = []
        if self.filename is None:
            missing.append("filename")
        if self.digest is None:
            missing.append("digest")
        return tuple(missing)


@dataclass(frozen=True)
class PackageCoordinate:
    """
    The name/version coordinate carried by the original audit sheet.

    This deliberately does *not* identify an artifact: one coordinate can map
    to several platform-specific distribution files.
    """

    name: str
    version: str

    @property
    def canonical_name(self) -> str:
        return canonicalize_name(self.name)

    @property
    def key(self) -> tuple[str, str]:
        return self.canonical_name, self.version


@dataclass(frozen=True)
class EvidenceRecord:
    """
    A single piece of evidence about a distribution file.

    ``provided_by`` records who supplied this step, while ``source_document``
    records which document carried it. Together they answer "who provided this
    handoff" independently for every stage.
    """

    stage: HandoffStage
    coordinate: PackageCoordinate
    identity: ArtifactIdentity
    provided_by: str
    source_document: str

    @property
    def name(self) -> str:
        return self.coordinate.name

    @property
    def version(self) -> str:
        return self.coordinate.version

    @property
    def filename(self) -> str | None:
        return self.identity.filename

    @property
    def digest(self) -> str | None:
        return self.identity.digest

    @property
    def has_identity(self) -> bool:
        """Whether this record carries a concrete distribution-file identity."""

        return self.identity.is_complete

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage.value,
            "provided_by": self.provided_by,
            "source_document": self.source_document,
            "name": self.coordinate.name,
            "version": self.coordinate.version,
            "filename": self.identity.filename,
            "digest": self.identity.digest,
        }


@dataclass(frozen=True)
class StageConflict:
    """
    A disagreement between two consecutive handoffs for the same file.

    ``stage`` is the handoff at which the divergence first becomes observable
    and ``introduced_at`` is the stage judged responsible for it. Both are
    retained so a report can point at the precise handoff in the chain.
    """

    stage: HandoffStage
    expected_digest: str | None
    observed_digest: str | None
    expected_source: str
    observed_source: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage.value,
            "introduced_at": self.stage.value,
            "expected_digest": self.expected_digest,
            "observed_digest": self.observed_digest,
            "expected_source": self.expected_source,
            "observed_source": self.observed_source,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class MissingMaterial:
    """A piece of evidence (a handoff or an identity material) that is absent."""

    stage: HandoffStage
    material: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage.value,
            "material": self.material,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ReconciliationRow:
    """
    The reconciliation outcome for one concrete distribution file.

    Two local files sharing a name/version produce two independent rows: each
    has its own status, its own provenance chain and its own missing
    materials. Rows built from legacy records without an artifact identity use
    a placeholder filename so they can still be opened and inspected.
    """

    coordinate: PackageCoordinate
    filename: str | None
    status: ReconciliationStatus
    evidence: tuple[EvidenceRecord, ...]
    conflicts: tuple[StageConflict, ...] = field(default_factory=tuple)
    missing_materials: tuple[MissingMaterial, ...] = field(default_factory=tuple)

    @property
    def name(self) -> str:
        return self.coordinate.name

    @property
    def version(self) -> str:
        return self.coordinate.version

    @property
    def digest(self) -> str | None:
        """The digest identifying this row, taken from the local plan when known."""

        for record in self.evidence:
            if record.stage is HandoffStage.LOCAL_PLAN:
                return record.digest
        return self.evidence[0].digest if self.evidence else None

    @property
    def identity_known(self) -> bool:
        """Whether the row is anchored to a concrete distribution file."""

        return self.filename is not None

    @property
    def providers(self) -> dict[HandoffStage, str]:
        """A stage -> provider mapping for quickly inspecting provenance."""

        return {record.stage: record.provided_by for record in self.evidence}

    @property
    def is_pending(self) -> bool:
        """Whether this row still needs human confirmation."""

        return self.status is not ReconciliationStatus.MATCHED

    @property
    def row_key(self) -> tuple[str, str, str]:
        """The grouping key guaranteeing one row per local distribution file."""

        filename = self.filename or "<no-distribution-file>"
        return self.coordinate.canonical_name, self.coordinate.version, filename

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.coordinate.name,
            "version": self.coordinate.version,
            "filename": self.filename,
            "digest": self.digest,
            "status": self.status.value,
            "identity_known": self.identity_known,
            "providers": {stage.value: provider for stage, provider in self.providers.items()},
            "evidence": [record.to_dict() for record in self.evidence],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "missing_materials": [missing.to_dict() for missing in self.missing_materials],
        }


@dataclass(frozen=True)
class ReconciliationReport:
    """The full result of reconciling the three evidence sources."""

    rows: tuple[ReconciliationRow, ...]
    sources: tuple[EvidenceRecord, ...] = field(default_factory=tuple)

    def __iter__(self) -> Iterator[ReconciliationRow]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    @property
    def pending_rows(self) -> tuple[ReconciliationRow, ...]:
        """All rows that are not fully matched, one per distribution file."""

        return tuple(row for row in self.rows if row.is_pending)

    def to_dict(self) -> dict[str, object]:
        return {
            "rows": [row.to_dict() for row in self.rows],
            "pending_filenames": [row.filename for row in self.pending_rows],
        }
