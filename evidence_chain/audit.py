"""Audit supplemental read-only metadata against the external archive chain.

Terminology (compliance domain -> implementation):

- external archive chain (外置封存链): the original release manifest plus
  the recognized module generations it vouches for, kept outside the
  binaries themselves.
- generation identifier (代际标识): the Module.Mvid of a normal sample,
  consumed with dnfile (see evidence_chain.generation).
- supplement (在同一已认定代际上补齐说明): a submission whose observed
  Mvid equals the recognized generation of its component.
- replacement (跨代替换): a submission whose observed Mvid differs from
  the recognized generation.
- missing witness (仍缺关联见证): a submission whose referenced external
  file is absent from its recorded location, or whose component has no
  recognized generation in the chain to attach to.

The evidence catalog (证物目录) continues the original release manifest
order: release items keep their original sequence, accepted supplements
are appended with continuing sequence numbers in submission order.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from evidence_chain.generation import (
    GenerationUnreadable,
    normalize_mvid,
    read_module_identity,
)

PathLike = Union[str, Path]


class Classification(str, enum.Enum):
    """Per-submission verdict along the external archive chain."""

    SUPPLEMENT = "supplement"
    """Same recognized generation: documentation supplemented in place."""

    REPLACEMENT = "replacement"
    """Cross-generation replacement: observed Mvid breaks the generation."""

    MISSING_WITNESS = "missing_witness"
    """Still missing an associated witness (file absent or no chain link)."""

    INDETERMINATE = "indeterminate"
    """Not a normal sample: no generation identifier could be consumed."""

    DUPLICATE = "duplicate"
    """Same-name sibling already accepted for this generation chain."""


# ---------------------------------------------------------------------------
# inputs: original release manifest and supplemental records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReleaseItem:
    """One entry of the original release manifest (an old record)."""

    seq: int
    component: str
    location: str
    recognized_mvid: str
    note: Optional[str] = None


@dataclass(frozen=True)
class ReleaseManifest:
    """The original release order that the evidence catalog continues."""

    release: str
    items: List[ReleaseItem]

    @property
    def recognized_generations(self) -> Dict[str, str]:
        """component -> recognized generation (first occurrence wins)."""
        recognized: Dict[str, str] = {}
        for item in self.items:
            recognized.setdefault(item.component, item.recognized_mvid)
        return recognized


@dataclass(frozen=True)
class SupplementRecord:
    """One supplemental read-only metadata record from the vendor."""

    record_id: str
    component: str
    location: str
    note: Optional[str] = None


def load_manifest(path: PathLike) -> ReleaseManifest:
    """Load the original release manifest (JSON), read-only."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        items_raw = raw["items"]
        release = str(raw.get("release", ""))
    except (AttributeError, KeyError) as exc:
        raise ValueError(f"{path}: malformed release manifest") from exc
    items: List[ReleaseItem] = []
    for i, entry in enumerate(items_raw):
        try:
            mvid = normalize_mvid(entry["mvid"])
            if mvid is None:
                raise ValueError("unparseable mvid")
            items.append(
                ReleaseItem(
                    seq=int(entry["seq"]),
                    component=str(entry["component"]),
                    location=str(entry["location"]),
                    recognized_mvid=mvid,
                    note=entry.get("note"),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"{path}: malformed manifest item #{i}: {exc}"
            ) from exc
    return ReleaseManifest(release=release, items=items)


def load_records(path: PathLike) -> List[SupplementRecord]:
    """Load the supplemental read-only metadata records (JSON)."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        submissions = raw["submissions"]
    except (AttributeError, KeyError) as exc:
        raise ValueError(f"{path}: malformed supplemental records") from exc
    records: List[SupplementRecord] = []
    for i, entry in enumerate(submissions):
        try:
            records.append(
                SupplementRecord(
                    record_id=str(entry["record_id"]),
                    component=str(entry["component"]),
                    location=str(entry["location"]),
                    note=entry.get("note"),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"{path}: malformed submission #{i}: {exc}"
            ) from exc
    return records


# ---------------------------------------------------------------------------
# audit results
# ---------------------------------------------------------------------------


@dataclass
class ManifestAuditEntry:
    """Audit of one old record: does its external file still correspond?"""

    seq: int
    component: str
    location: str
    recognized_mvid: str
    location_status: str
    generation_status: Optional[str]
    observed_mvid: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "component": self.component,
            "location": self.location,
            "recognized_mvid": self.recognized_mvid,
            "location_status": self.location_status,
            "generation_status": self.generation_status,
            "observed_mvid": self.observed_mvid,
            "note": self.note,
        }


@dataclass
class SubmissionVerdict:
    """Classification of one supplemental record along the chain."""

    record_id: str
    component: str
    location: str
    classification: Classification
    accepted: bool
    reason: Optional[str]
    recognized_mvid: Optional[str]
    observed_mvid: Optional[str] = None
    module_name: Optional[str] = None
    name_mismatch: bool = False
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "component": self.component,
            "location": self.location,
            "classification": self.classification.value,
            "accepted": self.accepted,
            "reason": self.reason,
            "recognized_mvid": self.recognized_mvid,
            "observed_mvid": self.observed_mvid,
            "module_name": self.module_name,
            "name_mismatch": self.name_mismatch,
            "note": self.note,
        }


@dataclass
class CatalogEntry:
    """One evidence-catalog entry, sequenced to continue the release order."""

    seq: int
    component: str
    location: str
    mvid: str
    origin: str
    source_record: Optional[str] = None
    location_status: Optional[str] = None
    generation_status: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "component": self.component,
            "location": self.location,
            "mvid": self.mvid,
            "origin": self.origin,
            "source_record": self.source_record,
            "location_status": self.location_status,
            "generation_status": self.generation_status,
            "note": self.note,
        }


@dataclass
class AuditReport:
    release: str
    archive_root: str
    manifest_audit: List[ManifestAuditEntry] = field(default_factory=list)
    submissions: List[SubmissionVerdict] = field(default_factory=list)
    catalog: List[CatalogEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "release": self.release,
            "archive_root": self.archive_root,
            "manifest_audit": [e.to_dict() for e in self.manifest_audit],
            "submissions": [v.to_dict() for v in self.submissions],
            "catalog": [e.to_dict() for e in self.catalog],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# the audit itself
# ---------------------------------------------------------------------------


def _resolve(archive_root: Path, location: str) -> Path:
    candidate = Path(location)
    if not candidate.is_absolute():
        candidate = archive_root / candidate
    return candidate


def _audit_manifest(
    manifest: ReleaseManifest, archive_root: Path
) -> List[ManifestAuditEntry]:
    """Check whether files referenced by old records still correspond."""
    entries: List[ManifestAuditEntry] = []
    for item in manifest.items:
        path = _resolve(archive_root, item.location)
        if not path.is_file():
            entries.append(
                ManifestAuditEntry(
                    seq=item.seq,
                    component=item.component,
                    location=item.location,
                    recognized_mvid=item.recognized_mvid,
                    location_status="missing",
                    generation_status=None,
                    note=item.note,
                )
            )
            continue
        try:
            identity = read_module_identity(path)
        except GenerationUnreadable:
            entries.append(
                ManifestAuditEntry(
                    seq=item.seq,
                    component=item.component,
                    location=item.location,
                    recognized_mvid=item.recognized_mvid,
                    location_status="intact",
                    generation_status="unreadable",
                    note=item.note,
                )
            )
            continue
        status = (
            "confirmed"
            if identity.mvid == item.recognized_mvid
            else "diverged"
        )
        entries.append(
            ManifestAuditEntry(
                seq=item.seq,
                component=item.component,
                location=item.location,
                recognized_mvid=item.recognized_mvid,
                location_status="intact",
                generation_status=status,
                observed_mvid=identity.mvid,
                note=item.note,
            )
        )
    return entries


def _classify_record(
    record: SupplementRecord,
    recognized: Dict[str, str],
    archive_root: Path,
) -> SubmissionVerdict:
    recognized_mvid = recognized.get(record.component)
    verdict = SubmissionVerdict(
        record_id=record.record_id,
        component=record.component,
        location=record.location,
        classification=Classification.MISSING_WITNESS,
        accepted=False,
        reason=None,
        recognized_mvid=recognized_mvid,
        note=record.note,
    )
    if recognized_mvid is None:
        verdict.reason = "no-recognized-generation"
        return verdict

    path = _resolve(archive_root, record.location)
    if not path.is_file():
        verdict.reason = "artifact-absent"
        return verdict

    try:
        identity = read_module_identity(path)
    except GenerationUnreadable:
        verdict.classification = Classification.INDETERMINATE
        verdict.reason = "unreadable-sample"
        return verdict

    verdict.observed_mvid = identity.mvid
    verdict.module_name = identity.name
    verdict.name_mismatch = (
        identity.name is not None and identity.name != record.component
    )
    if identity.mvid == recognized_mvid:
        verdict.classification = Classification.SUPPLEMENT
        verdict.reason = "generation-continues"
    else:
        verdict.classification = Classification.REPLACEMENT
        verdict.reason = "cross-generation"
    return verdict


def _apply_acceptance(verdicts: List[SubmissionVerdict]) -> None:
    """Accept at most one generation-continuing record per component name.

    When two new components share a name and each carries its own record,
    only the record that confirms generation continuity is accepted; a
    later same-generation record for the same name is a duplicate.
    """
    accepted_by_component: Dict[str, str] = {}
    for verdict in verdicts:
        if verdict.classification is not Classification.SUPPLEMENT:
            continue
        holder = accepted_by_component.get(verdict.component)
        if holder is None:
            verdict.accepted = True
            accepted_by_component[verdict.component] = verdict.record_id
        else:
            verdict.classification = Classification.DUPLICATE
            verdict.reason = f"superseded-by-{holder}"


def _build_catalog(
    manifest: ReleaseManifest,
    manifest_audit: List[ManifestAuditEntry],
    verdicts: List[SubmissionVerdict],
    records: Sequence[SupplementRecord],
) -> List[CatalogEntry]:
    """Evidence catalog continuing the original release order."""
    catalog: List[CatalogEntry] = []
    audit_by_seq = {entry.seq: entry for entry in manifest_audit}
    for item in manifest.items:
        audited = audit_by_seq.get(item.seq)
        catalog.append(
            CatalogEntry(
                seq=item.seq,
                component=item.component,
                location=item.location,
                mvid=item.recognized_mvid,
                origin="release",
                source_record=None,
                location_status=audited.location_status if audited else None,
                generation_status=(
                    audited.generation_status if audited else None
                ),
                note=item.note,
            )
        )
    next_seq = max((item.seq for item in manifest.items), default=0) + 1
    notes = {record.record_id: record.note for record in records}
    for verdict in verdicts:
        if not verdict.accepted:
            continue
        catalog.append(
            CatalogEntry(
                seq=next_seq,
                component=verdict.component,
                location=verdict.location,
                mvid=verdict.observed_mvid or "",
                origin="supplement",
                source_record=verdict.record_id,
                location_status="intact",
                generation_status="confirmed",
                note=notes.get(verdict.record_id),
            )
        )
        next_seq += 1
    return catalog


def audit(
    manifest: ReleaseManifest,
    records: Sequence[SupplementRecord],
    archive_root: PathLike = ".",
) -> AuditReport:
    """Run the read-only evidence-chain audit.

    1. Audit old records: does each referenced external file still sit at
       its original location, and does its generation still match?
    2. Classify every supplemental record along the external archive
       chain (supplement / replacement / missing witness).
    3. Build the evidence catalog continuing the original release order.
    """
    root = Path(archive_root)
    report = AuditReport(release=manifest.release, archive_root=str(root))
    report.manifest_audit = _audit_manifest(manifest, root)
    recognized = manifest.recognized_generations
    verdicts = [
        _classify_record(record, recognized, root) for record in records
    ]
    _apply_acceptance(verdicts)
    report.submissions = verdicts
    report.catalog = _build_catalog(
        manifest, report.manifest_audit, verdicts, records
    )
    return report
