# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Offline rework verification.

This module supports the verifier of a supply chain in which an intermediate
product had to be reworked *after* the downstream steps had already sampled
("spot-checked") the original product.

It works entirely on already signed, in-toto link metadata and never reaches
out to a network.  For every artifact and every recorded inspection it decides
which evidence is still valid after the rework and which responsibility has to
be re-established.  The decision is based on three independent factors:

1. *material identity* -- is an artifact unchanged, replaced by an unrelated
   material, or replaced in place by a new revision of the same material;
2. *rework completion time* -- was an inspection performed before or after the
   rework was finished; and
3. *inspection authorization* -- does the inspection explicitly permit its
   verdict to be carried over for the given replacement type.

Replacing an unrelated material never invalidates an inspection of a
different, still-identical artifact, whereas replacing the exact artifact that
was inspected always requires a fresh inspection item.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping

from in_toto.exceptions import InvalidMetadata
from in_toto.models.link import Link


class ArtifactChange(Enum):
    """How a single artifact changed between the original and reworked link."""

    UNCHANGED = "unchanged"
    REMOVED = "removed"
    ADDED = "added"
    REPLACED = "replaced"


class ReplacementType(Enum):
    """Authorization category for an artifact whose material identity changed.

    The categories mirror the two ways in which a material identity can
    change: the replacement is unrelated to the original material, or it is a
    new revision of the very same material (the inspected artifact itself).
    """

    UNRELATED = "unrelated"
    INSPECTED = "inspected"


class InspectionStatus(Enum):
    """Verdict for an inspection item after offline rework verification."""

    CARRIED_OVER = "carried-over"
    REOPENED = "reopened"
    CURRENT = "current"


def _as_hash_dict(artifacts, source):
    """Normalize a link, its products or a raw artifact hash dict."""
    if isinstance(artifacts, Link):
        return dict(artifacts.products)
    if not isinstance(artifacts, Mapping):
        raise InvalidMetadata(
            f"{source} must be a Link or a mapping of artifact hashes"
        )
    return dict(artifacts)


def _hash_equal(left, right):
    """Compare two hash dicts on every algorithm they both report."""
    algorithms = set(left).intersection(right)
    if not algorithms:
        return False
    return all(left[algorithm] == right[algorithm] for algorithm in algorithms)


def classify_artifacts(original_artifacts, reworked_artifacts):
    """Classify every artifact by how the rework changed its material identity.

    Arguments:
      original_artifacts: A `Link` or artifact hash dict describing the
          product before the rework.  When a `Link` is passed its products are
          used.
      reworked_artifacts: A `Link` or artifact hash dict describing the
          product after the rework.

    Returns:
      A dict mapping artifact path to an `ArtifactChange`.
    """
    original = _as_hash_dict(original_artifacts, "original artifacts")
    reworked = _as_hash_dict(reworked_artifacts, "reworked artifacts")

    changes = {}
    for name in original:
        if name not in reworked:
            changes[name] = ArtifactChange.REMOVED
        elif _hash_equal(original[name], reworked[name]):
            changes[name] = ArtifactChange.UNCHANGED
        else:
            changes[name] = ArtifactChange.REPLACED

    for name in reworked:
        if name not in original:
            changes[name] = ArtifactChange.ADDED

    return changes


@dataclass(frozen=True)
class InspectionRecord:
    """A spot-check (inspection) that was performed on an artifact set.

    Attributes:
      name: A unique identifier of the inspection item.
      artifacts: The artifact paths covered by the inspection.
      performed_at: When the inspection was performed.  Must be timezone
          aware so it can be compared against the rework completion time.
      authorized_replacements: Replacement types whose verdict the
          inspection is explicitly authorized to carry over.
    """

    name: str
    artifacts: frozenset[str]
    performed_at: datetime
    authorized_replacements: frozenset[ReplacementType] = frozenset()

    @classmethod
    def from_dict(cls, data):
        """Create an `InspectionRecord` from a plain dictionary."""
        try:
            name = data["name"]
            artifacts = data["artifacts"]
            performed_at = data["performed_at"]
        except KeyError as error:
            raise InvalidMetadata(
                f"inspection record is missing field {error.args[0]!r}"
            ) from error

        authorized = frozenset(
            _as_replacement_type(value) for value in data.get("authorized", ())
        )
        return cls(
            name=name,
            artifacts=frozenset(artifacts),
            performed_at=_check_datetime(performed_at, f"inspection {name!r}"),
            authorized_replacements=authorized,
        )


@dataclass(frozen=True)
class ArtifactReport:
    """Reusability verdict for a single artifact."""

    path: str
    change: ArtifactChange
    reusable: bool
    replacement_type: ReplacementType | None = None
    reason: str = ""


@dataclass(frozen=True)
class InspectionVerdict:
    """Reusability verdict for a single inspection item."""

    name: str
    status: InspectionStatus
    affected_artifacts: frozenset[str]
    reason: str = ""


@dataclass
class ReworkVerificationReport:
    """Complete result of an offline rework verification.

    Attributes:
      artifact_reports: Per-artifact reusability verdicts, keyed by path.
      carried_over_artifacts: Artifacts whose original evidence stays valid.
      replaced_artifacts: Artifacts that received a new material identity.
      reopened_inspections: Inspections whose responsibility was reactivated
          by a replacement and which must be issued again.
      new_inspection_items: Artifact paths that require a fresh spot-check.
      inspection_verdicts: Per-inspection verdicts.
    """

    artifact_reports: dict[str, ArtifactReport] = field(default_factory=dict)
    inspection_verdicts: dict[str, InspectionVerdict] = field(
        default_factory=dict
    )

    @property
    def carried_over_artifacts(self):
        return {
            report.path
            for report in self.artifact_reports.values()
            if report.reusable
        }

    @property
    def replaced_artifacts(self):
        return {
            report.path
            for report in self.artifact_reports.values()
            if report.change == ArtifactChange.REPLACED
        }

    @property
    def new_inspection_items(self):
        return {
            artifact
            for verdict in self.inspection_verdicts.values()
            if verdict.status == InspectionStatus.REOPENED
            for artifact in verdict.affected_artifacts
        }

    @property
    def reopened_inspections(self):
        return {
            verdict.name
            for verdict in self.inspection_verdicts.values()
            if verdict.status == InspectionStatus.REOPENED
        }


def _check_datetime(value, label):
    if not isinstance(value, datetime):
        raise InvalidMetadata(f"{label} timestamp must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise InvalidMetadata(f"{label} timestamp must be timezone aware")
    return value


def _as_replacement_type(value):
    if isinstance(value, ReplacementType):
        return value
    try:
        return ReplacementType(value)
    except ValueError as error:
        raise InvalidMetadata(
            f"unknown replacement type {value!r}"
        ) from error


def _coerce_inspections(inspections):
    records = []
    for inspection in inspections:
        if isinstance(inspection, InspectionRecord):
            records.append(inspection)
        elif isinstance(inspection, Mapping):
            records.append(InspectionRecord.from_dict(inspection))
        else:
            raise InvalidMetadata(
                "inspections must be InspectionRecord objects or dicts"
            )
    return records


def _build_artifact_reports(changes):
    reports = {}
    for path, change in changes.items():
        if change == ArtifactChange.UNCHANGED:
            reports[path] = ArtifactReport(
                path=path,
                change=change,
                reusable=True,
                reason="material identity unchanged",
            )
        elif change == ArtifactChange.REMOVED:
            reports[path] = ArtifactReport(
                path=path,
                change=change,
                reusable=False,
                reason="artifact removed during rework",
            )
        elif change == ArtifactChange.ADDED:
            reports[path] = ArtifactReport(
                path=path,
                change=change,
                reusable=False,
                replacement_type=ReplacementType.UNRELATED,
                reason="new material without prior evidence",
            )
        else:
            reports[path] = ArtifactReport(
                path=path,
                change=change,
                reusable=False,
                replacement_type=ReplacementType.INSPECTED,
                reason="replaced material requires fresh evidence",
            )
    return reports


def _verify_inspection(inspection, changes, rework_completed_at):
    covered = frozenset(inspection.artifacts)

    # An inspection performed after the rework reflects the current product.
    if inspection.performed_at >= rework_completed_at:
        return InspectionVerdict(
            name=inspection.name,
            status=InspectionStatus.CURRENT,
            affected_artifacts=covered,
            reason="inspection performed after rework completion",
        )

    affected = set()
    for artifact in covered:
        change = changes.get(artifact, ArtifactChange.ADDED)
        if change == ArtifactChange.UNCHANGED:
            continue
        if change == ArtifactChange.REPLACED:
            # The exact spot-checked artifact received a new material identity.
            # This always reactivates the responsibility: no authorization can
            # substitute fresh evidence for a different material.
            affected.add(artifact)
            continue

        # Additions/removals are unrelated material changes.  The inspection may
        # explicitly authorize carrying its verdict over such changes; otherwise
        # the affected coverage reopens as well.
        if ReplacementType.UNRELATED not in inspection.authorized_replacements:
            affected.add(artifact)

    if not affected:
        return InspectionVerdict(
            name=inspection.name,
            status=InspectionStatus.CARRIED_OVER,
            affected_artifacts=frozenset(),
            reason="covered artifacts unchanged or authorized for carryover",
        )

    return InspectionVerdict(
        name=inspection.name,
        status=InspectionStatus.REOPENED,
        affected_artifacts=frozenset(affected),
        reason="replacement invalidates the prior inspection verdict",
    )


def verify_rework(
    original_artifacts,
    reworked_artifacts,
    rework_completed_at,
    inspections,
):
    """Verify which evidence survives an offline rework.

    Arguments:
      original_artifacts: A `Link` (its products are used) or an artifact hash
          dict describing the product that was originally spot-checked.
      reworked_artifacts: A `Link` or artifact hash dict describing the
          reworked product.
      rework_completed_at: Timezone-aware `datetime` at which the rework was
          finished.
      inspections: Iterable of `InspectionRecord` objects or equivalent plain
          dicts describing the already performed spot-checks.

    Raises:
      InvalidMetadata: If an argument has an unexpected shape or a timestamp
          is not timezone aware.

    Returns:
      A `ReworkVerificationReport` stating which artifacts and inspections
      carry over and which responsibilities are reactivated by the rework.
    """
    rework_completed_at = _check_datetime(
        rework_completed_at, "rework completion"
    )
    changes = classify_artifacts(original_artifacts, reworked_artifacts)
    records = _coerce_inspections(inspections)

    report = ReworkVerificationReport(
        artifact_reports=_build_artifact_reports(changes)
    )
    for record in records:
        verdict = _verify_inspection(record, changes, rework_completed_at)
        report.inspection_verdicts[record.name] = verdict

    return report
