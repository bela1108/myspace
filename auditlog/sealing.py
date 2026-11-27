"""Sealed audit-log segments and integrity verification.

Audit log rows are intentionally left untouched by sealing. A segment stores an
ordered manifest of the rows and a digest for each row. Segments also form a
chain: every segment digest includes the digest of the preceding segment.

This makes it possible to:

* hand out a reviewable summary of an existing range of log entries;
* continue the history in later segments without rewriting earlier ones;
* verify a sealed copy independently of the database it came from;
* report the first deleted or modified entry when an export is verified.

Only rows that are visible to the sealing database connection are included in a
segment. In particular, a write that is pending in another transaction (and
therefore not committed) is not visible to the sealing connection.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time as time_module
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import DEFAULT_DB_ALIAS, IntegrityError, OperationalError, transaction
from django.db.models import Max
from django.utils import timezone
from django.utils.dateparse import parse_datetime

SEGMENT_FORMAT = "django-auditlog-segments"
SEGMENT_FORMAT_VERSION = 1
DEFAULT_ALGORITHM = "sha256"


class AuditLogIntegrityError(Exception):
    """Raised when a sealed segment no longer matches its log entries."""

    def __init__(self, mismatches):
        self.mismatches = list(mismatches)
        self.first_mismatch = self.mismatches[0] if self.mismatches else None
        super().__init__(str(self.first_mismatch or "audit log integrity failure"))


@dataclass(frozen=True)
class IntegrityMismatch:
    """A single, deterministically ordered integrity failure."""

    sequence: int
    kind: str
    message: str
    entry_id: Any = None
    ordinal: int | None = None
    expected: Any = None
    actual: Any = None

    def to_dict(self):
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "message": self.message,
            "entry_id": self.entry_id,
            "ordinal": self.ordinal,
            "expected": self.expected,
            "actual": self.actual,
        }

    def __str__(self):
        location = f"segment {self.sequence}"
        if self.entry_id is not None:
            location += f", entry {self.entry_id}"
        if self.ordinal is not None:
            location += f", position {self.ordinal}"
        return f"{location}: {self.message}"


def get_segment_model():
    from auditlog.models import LogEntrySegment

    return LogEntrySegment


def get_logentry_model():
    from auditlog import get_logentry_model as _get_logentry_model

    return _get_logentry_model()


def _json_default(value):
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _canonical_json(value) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def normalize_value(value):
    """Convert a model value to a stable, JSON-compatible representation."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, dict):
        return {str(key): normalize_value(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_value(item) for item in value]
    return value


def entry_snapshot(entry):
    """Return all persisted field values of a log entry in stable form."""
    return {
        field.attname: normalize_value(getattr(entry, field.attname))
        for field in entry._meta.concrete_fields
    }


def snapshot_digest(snapshot, algorithm=DEFAULT_ALGORITHM) -> str:
    return hashlib.new(algorithm, _canonical_json(snapshot).encode("utf-8")).hexdigest()


def entry_digest(entry, algorithm=DEFAULT_ALGORITHM) -> str:
    return snapshot_digest(entry_snapshot(entry), algorithm=algorithm)


def manifest_item(entry, ordinal: int, algorithm=DEFAULT_ALGORITHM):
    snapshot = entry_snapshot(entry)
    item = {
        "ordinal": ordinal,
        "id": normalize_value(entry.pk),
        "digest": snapshot_digest(snapshot, algorithm=algorithm),
    }
    if "timestamp" in snapshot:
        item["timestamp"] = snapshot["timestamp"]
    return item


def compute_segment_digest(
    sequence: int,
    previous_digest: str,
    manifest,
    algorithm=DEFAULT_ALGORITHM,
) -> str:
    payload = {
        "algorithm": algorithm,
        "manifest": manifest,
        "previous_digest": previous_digest,
        "sequence": sequence,
    }
    return hashlib.new(algorithm, _canonical_json(payload).encode("utf-8")).hexdigest()


def _model_pk(entry):
    return normalize_value(entry.pk)


def _pk_key(pk):
    return str(normalize_value(pk))


def latest_segment(using=DEFAULT_DB_ALIAS):
    Segment = get_segment_model()
    return Segment.objects.using(using).order_by("-sequence").first()


def _select_unsealed_entries(using=DEFAULT_DB_ALIAS, start_after=None, limit=None):
    LogEntry = get_logentry_model()

    latest = latest_segment(using=using)
    if start_after is None and latest is not None:
        start_after = latest.last_entry_id

    queryset = LogEntry.objects.using(using).order_by("id")
    if start_after is not None:
        queryset = queryset.filter(id__gt=start_after)
    if limit is not None and limit > 0:
        queryset = queryset[:limit]

    entries = list(queryset)
    return latest, entries, start_after


def _sealed_entry_ids(using=DEFAULT_DB_ALIAS):
    Segment = get_segment_model()
    sealed = []
    for manifest in Segment.objects.using(using).values_list("manifest", flat=True):
        for item in manifest or []:
            if isinstance(item, dict) and item.get("id") is not None:
                sealed.append(item["id"])
    return sealed


def unsealed_entries(using=DEFAULT_DB_ALIAS, *, limit=None):
    """Return queryable log entries that are not in any sealed manifest.

    Entries before the start of sealing, or entries deliberately left below a
    segment boundary, are not modified or hidden. They remain available through
    the normal LogEntry.objects manager as well as this helper.
    """
    LogEntry = get_logentry_model()
    queryset = LogEntry.objects.using(using).order_by("id")
    sealed_ids = _sealed_entry_ids(using=using)
    if sealed_ids:
        queryset = queryset.exclude(pk__in=sealed_ids)
    if limit is not None and limit > 0:
        queryset = queryset[:limit]
    return queryset


def plan_segment(
    using=DEFAULT_DB_ALIAS,
    *,
    start_after=None,
    limit=None,
    algorithm=DEFAULT_ALGORITHM,
):
    """Build the next segment without writing it.

    This is useful for a dry-run summary that can be reviewed before sealing.
    """
    latest, entries, effective_start = _select_unsealed_entries(
        using=using, start_after=start_after, limit=limit
    )

    if not entries:
        return None

    sequence = (latest.sequence if latest is not None else 0) + 1
    previous_digest = latest.digest if latest is not None else ""
    manifest = [
        manifest_item(entry, ordinal, algorithm=algorithm)
        for ordinal, entry in enumerate(entries)
    ]

    return {
        "sequence": sequence,
        "previous_digest": previous_digest,
        "digest": compute_segment_digest(
            sequence, previous_digest, manifest, algorithm=algorithm
        ),
        "entry_count": len(manifest),
        "first_entry_id": manifest[0]["id"],
        "last_entry_id": manifest[-1]["id"],
        "sealed_at": timezone.now().isoformat(),
        "algorithm": algorithm,
        "manifest": manifest,
        "start_after": effective_start,
        "entries": entries,
    }


def _read_segment_plan(using, start_after, limit, algorithm):
    Segment = get_segment_model()
    LogEntry = get_logentry_model()

    with transaction.atomic(using=using):
        latest = Segment.objects.using(using).order_by("-sequence").first()
        effective_start = start_after
        if effective_start is None and latest is not None:
            effective_start = latest.last_entry_id

        queryset = LogEntry.objects.using(using).order_by("id")
        if effective_start is not None:
            queryset = queryset.filter(id__gt=effective_start)

        max_id = queryset.aggregate(max_id=Max("id"))["max_id"]
        if max_id is None:
            return None

        queryset = queryset.filter(id__lte=max_id)
        if limit is not None and limit > 0:
            queryset = queryset[:limit]

        entries = list(queryset)
        if not entries:
            return None

    sequence = (latest.sequence if latest is not None else 0) + 1
    previous_digest = latest.digest if latest is not None else ""
    manifest = [
        manifest_item(entry, ordinal, algorithm=algorithm)
        for ordinal, entry in enumerate(entries)
    ]
    digest = compute_segment_digest(
        sequence, previous_digest, manifest, algorithm=algorithm
    )

    return {
        "sequence": sequence,
        "previous_digest": previous_digest,
        "digest": digest,
        "entry_count": len(manifest),
        "first_entry_id": manifest[0]["id"],
        "last_entry_id": manifest[-1]["id"],
        "manifest": manifest,
        "algorithm": algorithm,
    }


def seal_segment(
    using=DEFAULT_DB_ALIAS,
    *,
    start_after=None,
    limit=None,
    algorithm=DEFAULT_ALGORITHM,
):
    """Seal the next committed range of log entries.

    The committed range is read first and the segment is written afterwards.
    That boundary is what excludes rows that are still uncommitted when the
    read happens. The write is retried if SQLite reports that another
    connection is holding its write lock; the already captured boundary is
    reused so a write that commits while we wait is not pulled into the
    segment.
    """
    Segment = get_segment_model()
    deadline = time_module.monotonic() + 60

    while True:
        plan = _read_segment_plan(using, start_after, limit, algorithm)
        if plan is None:
            return None

        try:
            with transaction.atomic(using=using):
                return Segment.objects.using(using).create(
                    sequence=plan["sequence"],
                    previous_digest=plan["previous_digest"],
                    digest=plan["digest"],
                    manifest=plan["manifest"],
                    entry_count=plan["entry_count"],
                    first_entry_id=plan["first_entry_id"],
                    last_entry_id=plan["last_entry_id"],
                    sealed_at=timezone.now(),
                    algorithm=plan["algorithm"],
                    source_alias=using,
                )
        except IntegrityError as exc:
            # A concurrent seal took the sequence. Re-read the chain head and
            # recompute the next segment instead of overwriting it.
            message = str(exc).lower()
            if (
                ("unique" not in message and "duplicate" not in message)
                or time_module.monotonic() >= deadline
            ):
                raise
            time_module.sleep(0.02)
        except OperationalError as exc:
            # SQLite reports the write lock as either "database is locked" or
            # "database table is locked". Keep the captured boundary and retry
            # the write after the other transaction releases it.
            message = str(exc).lower()
            if (
                "locked" in message or "busy" in message
            ) and time_module.monotonic() < deadline:
                time_module.sleep(0.05)
                continue
            raise


def _manifest_issues(segment, entry_by_key):
    """Check a segment manifest against a mapping of log entries."""
    issues = []
    manifest = segment.manifest if isinstance(segment.manifest, list) else None

    if manifest is None:
        return (
            [
                IntegrityMismatch(
                    sequence=segment.sequence,
                    kind="manifest",
                    message="manifest is not a list",
                    expected=list,
                    actual=type(segment.manifest).__name__,
                )
            ],
            [],
        )

    ids = []
    previous_id = None
    for ordinal, item in enumerate(manifest):
        if not isinstance(item, dict):
            issues.append(
                IntegrityMismatch(
                    sequence=segment.sequence,
                    kind="manifest",
                    message="manifest item is not an object",
                    entry_id=None,
                    ordinal=ordinal,
                    actual=type(item).__name__,
                )
            )
            continue

        if item.get("ordinal") != ordinal:
            issues.append(
                IntegrityMismatch(
                    sequence=segment.sequence,
                    kind="manifest",
                    message="manifest position is not stable",
                    entry_id=item.get("id"),
                    ordinal=ordinal,
                    expected=ordinal,
                    actual=item.get("ordinal"),
                )
            )

        entry_id = item.get("id")
        ids.append(entry_id)

        if previous_id is not None:
            try:
                ordered = entry_id > previous_id
            except TypeError:
                ordered = str(entry_id) > str(previous_id)
            if not ordered:
                issues.append(
                    IntegrityMismatch(
                        sequence=segment.sequence,
                        kind="manifest",
                        message="manifest is not in stable ascending order",
                        entry_id=entry_id,
                        ordinal=ordinal,
                        expected=f"> {previous_id}",
                        actual=entry_id,
                    )
                )
        previous_id = entry_id

        entry = entry_by_key.get(_pk_key(entry_id))
        if entry is None:
            issues.append(
                IntegrityMismatch(
                    sequence=segment.sequence,
                    kind="missing_entry",
                    message="sealed log entry is missing",
                    entry_id=entry_id,
                    ordinal=ordinal,
                )
            )
            continue

        actual_digest = entry_digest(entry, algorithm=segment.algorithm)
        expected_digest = item.get("digest")
        if actual_digest != expected_digest:
            issues.append(
                IntegrityMismatch(
                    sequence=segment.sequence,
                    kind="entry_digest",
                    message="sealed log entry has changed",
                    entry_id=entry_id,
                    ordinal=ordinal,
                    expected=expected_digest,
                    actual=actual_digest,
                )
            )

    expected_first = (
        manifest[0].get("id") if manifest and isinstance(manifest[0], dict) else None
    )
    expected_last = (
        manifest[-1].get("id") if manifest and isinstance(manifest[-1], dict) else None
    )

    if len(manifest) != segment.entry_count:
        issues.append(
            IntegrityMismatch(
                sequence=segment.sequence,
                kind="manifest",
                message="manifest entry count does not match the segment count",
                expected=segment.entry_count,
                actual=len(manifest),
            )
        )
    if expected_first != segment.first_entry_id:
        issues.append(
            IntegrityMismatch(
                sequence=segment.sequence,
                kind="manifest",
                message="first entry id does not match the manifest",
                entry_id=expected_first,
                expected=segment.first_entry_id,
                actual=expected_first,
            )
        )
    if expected_last != segment.last_entry_id:
        issues.append(
            IntegrityMismatch(
                sequence=segment.sequence,
                kind="manifest",
                message="last entry id does not match the manifest",
                entry_id=expected_last,
                expected=segment.last_entry_id,
                actual=expected_last,
            )
        )

    return issues, ids


def _segment_object_issues(
    segment, actual_digest, expected_sequence, expected_previous
):
    issues = []
    if segment.sequence != expected_sequence:
        issues.append(
            IntegrityMismatch(
                sequence=segment.sequence,
                kind="sequence",
                message="segment sequence is not continuous",
                expected=expected_sequence,
                actual=segment.sequence,
            )
        )
    if segment.previous_digest != expected_previous:
        issues.append(
            IntegrityMismatch(
                sequence=segment.sequence,
                kind="chain",
                message="segment does not continue the previous digest",
                expected=expected_previous,
                actual=segment.previous_digest,
            )
        )
    if segment.digest != actual_digest:
        issues.append(
            IntegrityMismatch(
                sequence=segment.sequence,
                kind="segment_digest",
                message="segment digest does not match its manifest chain",
                expected=segment.digest,
                actual=actual_digest,
            )
        )
    return issues


def verify_segments(
    using=DEFAULT_DB_ALIAS,
    *,
    fail_fast=False,
    segments=None,
):
    """Verify all sealed segments and their current log entries.

    The returned list is ordered by segment sequence and manifest position.
    With fail_fast=True, verification stops at the first mismatch.
    """
    Segment = get_segment_model()
    LogEntry = get_logentry_model()

    if segments is None:
        segments = list(Segment.objects.using(using).order_by("sequence"))
    else:
        segments = sorted(list(segments), key=lambda item: item.sequence)

    mismatches = []
    expected_sequence = 1
    expected_previous = ""

    for segment in segments:
        manifest = segment.manifest if isinstance(segment.manifest, list) else []
        ids = [
            item.get("id")
            for item in manifest
            if isinstance(item, dict) and item.get("id") is not None
        ]
        rows = LogEntry.objects.using(using).filter(pk__in=ids)
        entry_by_key = {_pk_key(row.pk): row for row in rows}

        issues, _ = _manifest_issues(segment, entry_by_key)

        actual_digest = compute_segment_digest(
            segment.sequence,
            segment.previous_digest,
            segment.manifest,
            algorithm=segment.algorithm,
        )
        issues.extend(
            _segment_object_issues(
                segment, actual_digest, expected_sequence, expected_previous
            )
        )

        mismatches.extend(issues)
        if fail_fast and mismatches:
            return mismatches

        expected_sequence = segment.sequence + 1
        expected_previous = segment.digest

    return mismatches


def find_first_mismatch(using=DEFAULT_DB_ALIAS, *, segments=None):
    """Return the first mismatch in stable segment order, or None."""
    mismatches = verify_segments(using=using, fail_fast=True, segments=segments)
    return mismatches[0] if mismatches else None


def segment_summaries(using=DEFAULT_DB_ALIAS, *, verify=True):
    """Return a reviewable summary of every sealed segment."""
    Segment = get_segment_model()
    segments = list(Segment.objects.using(using).order_by("sequence"))
    if verify:
        mismatch = find_first_mismatch(using=using, segments=segments)
        if mismatch is not None:
            raise AuditLogIntegrityError([mismatch])
    return [segment.summary() for segment in segments]

def export_segments(
    using=DEFAULT_DB_ALIAS,
    *,
    verify=True,
    segments=None,
):
    """Export sealed segments and their entries as a self-contained document.

    With verify=True (the default) the export is refused as soon as the first
    missing or modified entry is found. The returned document can be verified
    without access to the source database.
    """
    Segment = get_segment_model()
    LogEntry = get_logentry_model()

    if segments is None:
        segments = list(Segment.objects.using(using).order_by("sequence"))
    else:
        segments = sorted(list(segments), key=lambda item: item.sequence)

    if verify:
        mismatch = find_first_mismatch(using=using, segments=segments)
        if mismatch is not None:
            raise AuditLogIntegrityError([mismatch])

    entry_ids = []
    for segment in segments:
        for item in segment.manifest or []:
            if isinstance(item, dict) and item.get("id") is not None:
                entry_ids.append(item.get("id"))

    rows = list(
        LogEntry.objects.using(using).filter(pk__in=entry_ids).order_by("id")
    )
    entry_by_key = {_pk_key(row.pk): row for row in rows}

    exported_entries = []
    for segment in segments:
        for item in segment.manifest or []:
            if not isinstance(item, dict) or item.get("id") is None:
                continue
            row = entry_by_key.get(_pk_key(item["id"]))
            if row is None:
                continue
            exported_entries.append(
                {
                    "id": _model_pk(row),
                    "digest": entry_digest(row, algorithm=segment.algorithm),
                    "snapshot": entry_snapshot(row),
                }
            )

    return {
        "format": SEGMENT_FORMAT,
        "version": SEGMENT_FORMAT_VERSION,
        "algorithm": DEFAULT_ALGORITHM,
        "exported_at": timezone.now().isoformat(),
        "logentry_model": LogEntry._meta.label_lower,
        "source_alias": using,
        "segments": [segment.summary() for segment in segments],
        "entries": exported_entries,
    }


def write_export(document, path):
    path = Path(path)
    path.write_text(
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def read_export(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def export_to_file(path, using=DEFAULT_DB_ALIAS, *, verify=True):
    document = export_segments(using=using, verify=verify)
    return write_export(document, path)


def _format_issues(data):
    if not isinstance(data, dict):
        return [
            IntegrityMismatch(
                sequence=0,
                kind="format",
                message="audit-log segment export must be an object",
                actual=type(data).__name__,
            )
        ]
    if data.get("format") != SEGMENT_FORMAT:
        return [
            IntegrityMismatch(
                sequence=0,
                kind="format",
                message="not an audit-log segment export",
                expected=SEGMENT_FORMAT,
                actual=data.get("format"),
            )
        ]
    if data.get("version") != SEGMENT_FORMAT_VERSION:
        return [
            IntegrityMismatch(
                sequence=0,
                kind="format",
                message="unsupported export version",
                expected=SEGMENT_FORMAT_VERSION,
                actual=data.get("version"),
            )
        ]
    return []


def _export_entries_by_key(data):
    entries = {}
    for record in data.get("entries") or []:
        if not isinstance(record, dict) or record.get("id") is None:
            continue
        entries[_pk_key(record["id"])] = record
    return entries


def _export_manifest_issues(segment, entry_records, algorithm):
    issues = []
    manifest = segment.get("manifest")
    if not isinstance(manifest, list):
        return [
            IntegrityMismatch(
                sequence=segment.get("sequence", 0),
                kind="manifest",
                message="exported manifest is not a list",
            )
        ], []

    ids = []
    previous_id = None
    for ordinal, item in enumerate(manifest):
        if not isinstance(item, dict):
            issues.append(
                IntegrityMismatch(
                    sequence=segment.get("sequence", 0),
                    kind="manifest",
                    message="exported manifest item is not an object",
                    ordinal=ordinal,
                )
            )
            continue

        if item.get("ordinal") != ordinal:
            issues.append(
                IntegrityMismatch(
                    sequence=segment.get("sequence", 0),
                    kind="manifest",
                    message="exported manifest position is not stable",
                    entry_id=item.get("id"),
                    ordinal=ordinal,
                    expected=ordinal,
                    actual=item.get("ordinal"),
                )
            )

        entry_id = item.get("id")
        ids.append(entry_id)

        if previous_id is not None:
            try:
                ordered = entry_id > previous_id
            except TypeError:
                ordered = str(entry_id) > str(previous_id)
            if not ordered:
                issues.append(
                    IntegrityMismatch(
                        sequence=segment.get("sequence", 0),
                        kind="manifest",
                        message="exported manifest is not in stable ascending order",
                        entry_id=entry_id,
                        ordinal=ordinal,
                    )
                )
        previous_id = entry_id

        record = entry_records.get(_pk_key(entry_id))
        if record is None:
            issues.append(
                IntegrityMismatch(
                    sequence=segment.get("sequence", 0),
                    kind="missing_entry",
                    message="sealed entry is missing from the export",
                    entry_id=entry_id,
                    ordinal=ordinal,
                )
            )
            continue

        actual = snapshot_digest(record.get("snapshot") or {}, algorithm=algorithm)
        if actual != item.get("digest"):
            issues.append(
                IntegrityMismatch(
                    sequence=segment.get("sequence", 0),
                    kind="entry_digest",
                    message="sealed log entry has changed",
                    entry_id=entry_id,
                    ordinal=ordinal,
                    expected=item.get("digest"),
                    actual=actual,
                )
            )

    expected_first = (
        manifest[0].get("id") if manifest and isinstance(manifest[0], dict) else None
    )
    expected_last = (
        manifest[-1].get("id") if manifest and isinstance(manifest[-1], dict) else None
    )

    if len(manifest) != segment.get("entry_count"):
        issues.append(
            IntegrityMismatch(
                sequence=segment.get("sequence", 0),
                kind="manifest",
                message="exported entry count does not match the manifest",
                expected=segment.get("entry_count"),
                actual=len(manifest),
            )
        )
    if expected_first != segment.get("first_entry_id"):
        issues.append(
            IntegrityMismatch(
                sequence=segment.get("sequence", 0),
                kind="manifest",
                message="exported first entry id does not match the manifest",
                entry_id=expected_first,
                expected=segment.get("first_entry_id"),
                actual=expected_first,
            )
        )
    if expected_last != segment.get("last_entry_id"):
        issues.append(
            IntegrityMismatch(
                sequence=segment.get("sequence", 0),
                kind="manifest",
                message="exported last entry id does not match the manifest",
                entry_id=expected_last,
                expected=segment.get("last_entry_id"),
                actual=expected_last,
            )
        )

    return issues, ids


def verify_export(data, *, fail_fast=False):
    """Verify an exported segment document without consulting a database."""
    issues = _format_issues(data)
    if issues:
        return issues[:1] if fail_fast else issues

    algorithm = data.get("algorithm", DEFAULT_ALGORITHM)
    entry_records = _export_entries_by_key(data)
    mismatches = []

    # Check the entry payload itself first. This catches a snapshot that was
    # modified even when its stored digest was left unchanged.
    for record in data.get("entries") or []:
        if not isinstance(record, dict):
            mismatches.append(
                IntegrityMismatch(
                    sequence=0,
                    kind="entry_digest",
                    message="exported entry record is not an object",
                )
            )
            if fail_fast:
                return mismatches
            continue
        snapshot = record.get("snapshot")
        if not isinstance(snapshot, dict):
            mismatches.append(
                IntegrityMismatch(
                    sequence=0,
                    kind="entry_digest",
                    message="exported entry snapshot is missing",
                    entry_id=record.get("id"),
                )
            )
            if fail_fast:
                return mismatches
            continue
        actual = snapshot_digest(snapshot, algorithm=algorithm)
        if actual != record.get("digest"):
            mismatches.append(
                IntegrityMismatch(
                    sequence=0,
                    kind="entry_digest",
                    message="exported entry has changed",
                    entry_id=record.get("id"),
                    expected=record.get("digest"),
                    actual=actual,
                )
            )
            if fail_fast:
                return mismatches

    expected_sequence = 1
    expected_previous = ""
    segments = sorted(
        data.get("segments") or [], key=lambda item: item.get("sequence", 0)
    )

    for segment in segments:
        manifest = segment.get("manifest") or []
        issues, _ = _export_manifest_issues(segment, entry_records, algorithm)
        mismatches.extend(issues)
        if fail_fast and mismatches:
            return mismatches

        actual_digest = compute_segment_digest(
            segment.get("sequence"),
            segment.get("previous_digest", ""),
            manifest,
            algorithm=algorithm,
        )

        if segment.get("sequence") != expected_sequence:
            mismatches.append(
                IntegrityMismatch(
                    sequence=segment.get("sequence", 0),
                    kind="sequence",
                    message="exported segment sequence is not continuous",
                    expected=expected_sequence,
                    actual=segment.get("sequence"),
                )
            )
            if fail_fast:
                return mismatches
        if segment.get("previous_digest") != expected_previous:
            mismatches.append(
                IntegrityMismatch(
                    sequence=segment.get("sequence", 0),
                    kind="chain",
                    message="exported segment does not continue the previous digest",
                    expected=expected_previous,
                    actual=segment.get("previous_digest"),
                )
            )
            if fail_fast:
                return mismatches
        if segment.get("digest") != actual_digest:
            mismatches.append(
                IntegrityMismatch(
                    sequence=segment.get("sequence", 0),
                    kind="segment_digest",
                    message="exported segment digest does not match its manifest chain",
                    expected=segment.get("digest"),
                    actual=actual_digest,
                )
            )
            if fail_fast:
                return mismatches

        expected_sequence = segment.get("sequence", 0) + 1
        expected_previous = segment.get("digest", "")

    return mismatches


def verify_file(path, *, fail_fast=False):
    return verify_export(read_export(path), fail_fast=fail_fast)


def assert_export_integrity(data):
    mismatches = verify_export(data, fail_fast=True)
    if mismatches:
        raise AuditLogIntegrityError(mismatches)
    return data

def _coerce_snapshot_value(field, value):
    if value is None:
        return None
    target_field = field.target_field if field.is_relation else field
    try:
        return target_field.to_python(value)
    except (ValidationError, TypeError, ValueError):
        return value


def import_segments(data, using=DEFAULT_DB_ALIAS, *, replace=False):
    """Restore a verified export into another database.

    This is intended for moving an evidence ledger or for reading a sealed
    copy in an independent database. Existing rows are only overwritten when
    replace=True.
    """
    mismatches = verify_export(data, fail_fast=True)
    if mismatches:
        raise AuditLogIntegrityError(mismatches)

    LogEntry = get_logentry_model()
    Segment = get_segment_model()

    if data.get("logentry_model") and data["logentry_model"] != LogEntry._meta.label_lower:
        raise ValueError(
            "export was created for %s, but this project uses %s"
            % (data["logentry_model"], LogEntry._meta.label_lower)
        )

    field_by_attname = {field.attname: field for field in LogEntry._meta.concrete_fields}
    restored_entries = 0
    skipped_entries = 0
    restored_segments = 0
    skipped_segments = 0

    with transaction.atomic(using=using):
        if replace:
            Segment.objects.using(using).all().delete()

        export_records = data.get("entries") or []
        existing = {
            _pk_key(entry.pk): entry
            for entry in LogEntry.objects.using(using).filter(
                pk__in=[record["id"] for record in export_records]
            )
        }

        to_create = []
        for record in export_records:
            snapshot = record["snapshot"]
            key = _pk_key(record["id"])
            if key in existing:
                current = existing[key]
                if replace:
                    current.delete(using=using)
                else:
                    if entry_digest(current) != record["digest"]:
                        raise AuditLogIntegrityError(
                            [
                                IntegrityMismatch(
                                    sequence=0,
                                    kind="entry_digest",
                                    message="target database has a different entry",
                                    entry_id=record["id"],
                                    expected=record["digest"],
                                    actual=entry_digest(current),
                                )
                            ]
                        )
                    skipped_entries += 1
                    continue

            kwargs = {}
            for attname, value in snapshot.items():
                field = field_by_attname.get(attname)
                if field is not None:
                    kwargs[attname] = _coerce_snapshot_value(field, value)
            to_create.append(LogEntry(**kwargs))

        if to_create:
            LogEntry.objects.using(using).bulk_create(to_create)
            restored_entries = len(to_create)

        for summary in data.get("segments") or []:
            existing_segment = (
                Segment.objects.using(using).filter(sequence=summary["sequence"]).first()
            )
            if existing_segment is not None:
                if replace:
                    existing_segment.delete(using=using)
                elif existing_segment.digest == summary["digest"]:
                    skipped_segments += 1
                    continue
                else:
                    raise AuditLogIntegrityError(
                        [
                            IntegrityMismatch(
                                sequence=summary["sequence"],
                                kind="segment_digest",
                                message="target database has a different segment",
                                expected=summary["digest"],
                                actual=existing_segment.digest,
                            )
                        ]
                    )

            Segment.objects.using(using).create(
                sequence=summary["sequence"],
                previous_digest=summary.get("previous_digest", ""),
                digest=summary["digest"],
                manifest=summary.get("manifest") or [],
                entry_count=summary.get("entry_count", 0),
                first_entry_id=summary.get("first_entry_id"),
                last_entry_id=summary.get("last_entry_id"),
                sealed_at=parse_datetime(summary["sealed_at"]) or timezone.now(),
                algorithm=summary.get("algorithm", DEFAULT_ALGORITHM),
                source_alias=data.get("source_alias") or "",
            )
            restored_segments += 1

    return {
        "entries": restored_entries,
        "skipped_entries": skipped_entries,
        "segments": restored_segments,
        "skipped_segments": skipped_segments,
    }


# Short aliases for callers that prefer the operation name without the noun.
seal = seal_segment
verify = verify_segments
first_mismatch = find_first_mismatch
export = export_segments
restore = import_segments
