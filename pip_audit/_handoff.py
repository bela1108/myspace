"""Offline reconciliation for vulnerability handoff records.

The local handoff ledger stores source receipts/sign-offs, version impacts,
and every signed disposition fragment under an advisory.  Withdrawals may
cover an entire advisory, one remediation recommendation, or one release line.
The reconciler is read-only and accepts plain dictionaries, JSON text/paths,
or in-memory record batches.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

RecordLike = Mapping[str, Any]
BatchLike = str | Path | RecordLike | Sequence[Any] | None

ADVISORY_SCOPE = "advisory"
REMEDIATION_SCOPE = "remediation"
RELEASE_LINE_SCOPE = "release_line"
SCOPES = frozenset({ADVISORY_SCOPE, REMEDIATION_SCOPE, RELEASE_LINE_SCOPE})

_RECORD_TYPE_KEYS = ("record_type", "type", "kind", "event_type", "object")
_ID_KEYS = ("id", "record_id", "uuid", "identifier")
_EVIDENCE_ID_KEYS = ("evidence_id", "attestation_id", "receipt_id", "signoff_id", "id")
_SUBMISSION_KEYS = ("submission_id", "submit_id", "delivery_id", "message_id", "dedup_key")
_ADVISORY_KEYS = ("advisory_id", "advisory", "vulnerability_id", "vuln_id")
_REMEDIATION_KEYS = ("remediation_id", "fix_id", "recommendation_id", "advice_id", "patch_id")
_RELEASE_LINE_KEYS = ("release_line", "release_branch", "branch", "line", "series")
_INVALID_STATUSES = frozenset(
    {"invalid", "revoked", "expired", "rejected", "unverified", "failed", "superseded"}
)


class HandoffError(ValueError):
    """Raised when a handoff batch cannot be read."""


class DictAccessMixin(dict[str, Any]):
    """Dictionary and attribute compatibility for reports and items."""

    def __post_init__(self) -> None:
        """Populate the dictionary view after dataclass initialization."""
        dict.update(self, self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary view of this object."""
        return asdict(self)  # type: ignore[arg-type]

    def __getitem__(self, key: str) -> Any:
        to_dict = getattr(self, "to_dict", None)
        data = to_dict() if callable(to_dict) else asdict(self)  # type: ignore[arg-type]
        if key in data:
            return data[key]
        aliases = {
            "id": data.get("fragment_id") or data.get("withdrawal_id"),
            "item_id": data.get("fragment_id"),
            "evidence": data.get("preserved_by"),
            "preserving_evidence": data.get("preserved_by"),
            "evidence_refs": data.get("evidence_ids"),
        }
        if key in aliases:
            return aliases[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        """Return a mapping key or the default."""
        try:
            return self[key]
        except KeyError:
            return default


@dataclass(frozen=True)
class SourceSignoff:
    """A source receipt/sign-off covering one or more advisories."""

    evidence_id: str
    source_id: str | None
    advisory_ids: tuple[str, ...]
    signed_by: str | None = None
    signed_at: str | None = None
    valid: bool = True
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class VersionImpact:
    """Version/release-line impact evidence for an advisory."""

    evidence_id: str
    advisory_id: str | None
    package: str | None
    release_line: str | None = None
    affected_versions: str | None = None
    fixed_version: str | None = None
    remediation_id: str | None = None
    valid: bool = True
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class DispositionFragment(DictAccessMixin):
    """One signed disposition fragment under an advisory."""

    fragment_id: str
    advisory_id: str | None
    scope: str
    remediation_id: str | None = None
    release_line: str | None = None
    package: str | None = None
    conclusion: str | None = None
    signed_by: str | None = None
    evidence_ids: tuple[str, ...] = ()
    valid: bool = True
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class WithdrawalNotice:
    """A withdrawal scoped to an advisory, remediation, or release line."""

    withdrawal_id: str
    advisory_id: str | None
    scope: str
    remediation_id: str | None = None
    release_line: str | None = None
    target_evidence_id: str | None = None
    withdrawn_at: str | None = None
    valid: bool = True
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class ReopenItem(DictAccessMixin):
    """A signed fragment genuinely invalidated by a withdrawal."""

    fragment_id: str
    advisory_id: str | None
    scope: str
    reason: str
    withdrawal_ids: tuple[str, ...]
    remediation_id: str | None = None
    release_line: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        data = asdict(self)
        data["withdrawal_ids"] = list(self.withdrawal_ids)
        return data


@dataclass(frozen=True)
class PreservedItem(DictAccessMixin):
    """A signed fragment that remains supported by valid evidence."""

    fragment_id: str
    advisory_id: str | None
    scope: str
    preserved_by: str | None
    evidence_ids: tuple[str, ...]
    remediation_id: str | None = None
    release_line: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        data = asdict(self)
        data["evidence_ids"] = list(self.evidence_ids)
        return data


@dataclass(frozen=True)
class UnresolvedItem(DictAccessMixin):
    """An incomplete, ambiguous, unsupported, or conflicting record."""

    code: str
    message: str
    record_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class HandoffReport(DictAccessMixin):
    """Stable result of reconciling a handoff batch."""

    reopened: tuple[ReopenItem, ...]
    preserved: tuple[PreservedItem, ...]
    unresolved: tuple[UnresolvedItem, ...]
    duplicate_submissions: tuple[str, ...] = ()
    evidence_count: int = 0
    record_count: int = 0
    common_evidence_ids: tuple[str, ...] = ()

    @property
    def common_evidence(self) -> str | None:
        """Evidence shared by every preserved fragment, if any."""
        return self.common_evidence_ids[0] if self.common_evidence_ids else None

    @property
    def reopen_list(self) -> list[dict[str, Any]]:
        """Return reopen items as plain dictionaries."""
        return [item.to_dict() for item in self.reopened]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly report."""
        return {
            "reopened": self.reopen_list,
            "reopen_list": self.reopen_list,
            "preserved": [item.to_dict() for item in self.preserved],
            "preserved_fragments": [item.to_dict() for item in self.preserved],
            "unresolved": [item.to_dict() for item in self.unresolved],
            "needs_context": [item.to_dict() for item in self.unresolved],
            "duplicate_submissions": list(self.duplicate_submissions),
            "evidence_count": self.evidence_count,
            "record_count": self.record_count,
            "common_evidence": self.common_evidence,
            "common_evidence_ids": list(self.common_evidence_ids),
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Serialize the report to JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=True)

    def markdown(self) -> str:
        """Render a concise manager-facing reopen/evidence report."""
        lines = ["# Handoff reconciliation", "", "## Reopen list", ""]
        if not self.reopened:
            lines.append("- None")
        for item in self.reopened:
            target = item.remediation_id or item.release_line or item.scope
            lines.append(
                f"- {item.fragment_id} ({item.advisory_id or 'unknown advisory'}) "
                f"reopens {item.scope} {target}; withdrawals: "
                f"{', '.join(item.withdrawal_ids)}."
            )
        lines.extend(["", "## Preserved signed fragments", ""])
        if not self.preserved:
            lines.append("- None")
        for item in self.preserved:
            evidence = item.preserved_by or ", ".join(item.evidence_ids) or "no citable evidence"
            lines.append(f"- {item.fragment_id}: preserved by {evidence}.")
        if self.common_evidence:
            lines.append("")
            lines.append(f"Common evidence for all preserved fragments: {self.common_evidence}.")
        if self.unresolved:
            lines.extend(["", "## Needs context", ""])
            lines.extend([f"- {item.code}: {item.message}" for item in self.unresolved])
        return "\n".join(lines) + "\n"


class HandoffLedger:
    """Normalized in-memory store for local vulnerability handoff records."""

    def __init__(self) -> None:
        """Create an empty ledger."""
        self.source_signoffs: list[SourceSignoff] = []
        self.version_impacts: list[VersionImpact] = []
        self.fragments: list[DispositionFragment] = []
        self.withdrawals: list[WithdrawalNotice] = []
        self.unresolved: list[UnresolvedItem] = []
        self.duplicate_submissions: list[str] = []
        self.record_count = 0
        self._seen_submissions: set[str] = set()
        self._seen_hashes: set[str] = set()
        self._advisory_aliases: dict[str, str] = {}

    @classmethod
    def from_batch(cls, batch: BatchLike) -> HandoffLedger:
        """Read and ingest a mapping, sequence, JSON string, or JSON path."""
        return cls().ingest(batch)

    def ingest(self, batch: BatchLike) -> HandoffLedger:
        """Ingest any supported handoff batch representation."""
        data = _load_batch(batch)
        records = _extract_records(data)
        self._index_advisory_aliases(data, records)
        for record in records:
            self._ingest_record(record)
        return self

    def save_json(self, path: str | Path) -> Path:
        """Save normalized context as JSON and return the path."""
        target = Path(path)
        payload = {
            "source_signoffs": [asdict(item) for item in self.source_signoffs],
            "version_impacts": [asdict(item) for item in self.version_impacts],
            "dispositions": [asdict(item) for item in self.fragments],
            "withdrawals": [asdict(item) for item in self.withdrawals],
            "unresolved": [item.to_dict() for item in self.unresolved],
            "duplicate_submissions": self.duplicate_submissions,
        }
        target.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        return target

    def reconcile(self) -> HandoffReport:
        """Calculate reopened and preserved signed fragments."""
        return _reconcile_ledger(self)

    def _index_advisory_aliases(
        self, data: RecordLike | Sequence[Any], records: Sequence[RecordLike]
    ) -> None:
        candidates: list[Any] = list(records)
        if isinstance(data, Mapping):
            for key in ("advisories", "advisory_records"):
                value = data.get(key)
                if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                    candidates.extend(value)
        for item in candidates:
            if not isinstance(item, Mapping):
                continue
            advisory_id = _first_str(
                item, ("advisory_id", "canonical_id", "primary_id")
            ) or _first_str(item, _ID_KEYS)
            aliases = _as_str_list(item.get("aliases")) + _as_str_list(item.get("advisory_aliases"))
            if advisory_id:
                canonical = str(advisory_id)
                self._advisory_aliases[_advisory_key(canonical)] = canonical
                for alias in aliases:
                    self._advisory_aliases[_advisory_key(alias)] = canonical

    def _canonical_advisory(self, value: Any) -> str | None:
        advisory = (
            _first_str(value, _ADVISORY_KEYS) if isinstance(value, Mapping) else _string(value)
        )
        if advisory is None:
            return None
        return self._advisory_aliases.get(_advisory_key(advisory), advisory)

    def _ingest_record(self, record: RecordLike) -> None:
        self.record_count += 1
        submission = _submission_id(record)
        content_hash = _content_hash(record)

        if content_hash in self._seen_hashes:
            self.duplicate_submissions.append(submission or content_hash[:12])
            return

        if submission and submission in self._seen_submissions:
            self.unresolved.append(
                UnresolvedItem(
                    code="conflicting_duplicate_submission",
                    message=f"submission {submission} was reused with different content",
                    record_id=submission,
                )
            )
        if submission:
            self._seen_submissions.add(submission)
        self._seen_hashes.add(content_hash)

        record_type = (
            (_first_str(record, _RECORD_TYPE_KEYS) or "").strip().lower().replace("-", "_")
        )
        if not record_type:
            record_type = _infer_record_type(record) or ""
        if not record_type:
            self._unresolved("missing_record_type", "record has no record type", record)
            return

        if any(token in record_type for token in ("signoff", "receipt", "source_attestation")):
            self._ingest_signoff(record)
        elif "impact" in record_type or "version" in record_type:
            self._ingest_impact(record)
        elif any(token in record_type for token in ("withdraw", "revocation", "retract")):
            self._ingest_withdrawal(record)
        elif any(
            token in record_type for token in ("disposition", "fragment", "conclusion", "decision")
        ):
            self._ingest_fragment(record)
        else:
            self._unresolved(
                "unknown_record_type", f"unsupported record type {record_type!r}", record
            )

    def _ingest_signoff(self, record: RecordLike) -> None:
        evidence_id = _evidence_id(record)
        if not evidence_id:
            self._unresolved("missing_evidence_id", "source sign-off has no evidence id", record)
            return
        advisory_ids = tuple(
            self._canonical_advisory(item) or str(item)
            for item in _as_list(record.get("advisory_ids")) + _as_list(record.get("advisories"))
            if item is not None
        )
        single_advisory = self._canonical_advisory(record)
        if single_advisory and single_advisory not in advisory_ids:
            advisory_ids = (single_advisory, *advisory_ids)
        self.source_signoffs.append(
            SourceSignoff(
                evidence_id=evidence_id,
                source_id=_first_str(record, ("source_id", "source", "origin", "publisher")),
                advisory_ids=tuple(dict.fromkeys(advisory_ids)),
                signed_by=_first_str(record, ("signed_by", "signer", "approver")),
                signed_at=_first_str(record, ("signed_at", "timestamp", "created_at")),
                valid=_is_valid(record),
                raw=dict(record),
            )
        )

    def _ingest_impact(self, record: RecordLike) -> None:
        evidence_id = _evidence_id(record)
        if not evidence_id:
            self._unresolved("missing_evidence_id", "version impact has no evidence id", record)
            return
        advisory_id = self._canonical_advisory(record)
        package = _package_name(record)
        if not advisory_id and not package:
            self._unresolved(
                "missing_context", "version impact lacks advisory and package", record, evidence_id
            )
        line_entries = _as_list(record.get("release_lines")) + _as_list(record.get("lines"))
        if line_entries:
            for entry in line_entries:
                entry_map = entry if isinstance(entry, Mapping) else {"release_line": entry}
                merged = {**dict(record), **dict(entry_map)}
                self.version_impacts.append(
                    _impact_from_mapping(
                        evidence_id, self._canonical_advisory(merged) or advisory_id, merged
                    )
                )
        else:
            self.version_impacts.append(_impact_from_mapping(evidence_id, advisory_id, record))

    def _ingest_fragment(self, record: RecordLike) -> None:
        fragment_id = _first_str(
            record, ("fragment_id", "disposition_id", "item_id", "decision_id")
        ) or _evidence_id(record)
        if not fragment_id:
            self._unresolved("missing_fragment_id", "disposition fragment has no id", record)
            return
        scope = _normalize_scope(
            _first_str(record, ("scope", "withdrawal_scope", "fragment_type", "kind"))
        )
        remediation_id = _first_str(record, _REMEDIATION_KEYS)
        release_line = _normalize_line(_first_str(record, _RELEASE_LINE_KEYS))
        if scope is None:
            scope = (
                REMEDIATION_SCOPE
                if remediation_id
                else RELEASE_LINE_SCOPE
                if release_line
                else ADVISORY_SCOPE
            )
        if scope == REMEDIATION_SCOPE and not remediation_id:
            self._unresolved(
                "missing_remediation_context",
                "remediation fragment lacks remediation id",
                record,
                fragment_id,
            )
        if scope == RELEASE_LINE_SCOPE and not release_line:
            self._unresolved(
                "missing_release_line",
                "release-line fragment lacks release line",
                record,
                fragment_id,
            )
        evidence_ids = tuple(
            dict.fromkeys(
                _as_str_list(record.get("evidence_ids"))
                + _as_str_list(record.get("evidence_refs"))
                + _as_str_list(record.get("supports"))
            )
        )
        self.fragments.append(
            DispositionFragment(
                fragment_id=fragment_id,
                advisory_id=self._canonical_advisory(record),
                scope=scope,
                remediation_id=remediation_id,
                release_line=release_line,
                package=_package_name(record),
                conclusion=_first_str(record, ("conclusion", "status", "decision", "disposition")),
                signed_by=_first_str(record, ("signed_by", "signer", "approver")),
                evidence_ids=evidence_ids,
                valid=_is_valid(record),
                raw=dict(record),
            )
        )

    def _ingest_withdrawal(self, record: RecordLike) -> None:
        withdrawal_id = _first_str(
            record, ("withdrawal_id", "revocation_id", "retraction_id")
        ) or _evidence_id(record)
        if not withdrawal_id:
            self._unresolved("missing_withdrawal_id", "withdrawal has no id", record)
            return
        scope = _normalize_scope(
            _first_str(record, ("scope", "withdrawal_scope", "target_type", "kind"))
        )
        remediation_id = _first_str(record, _REMEDIATION_KEYS)
        release_line = _normalize_line(_first_str(record, _RELEASE_LINE_KEYS))
        target = record.get("target")
        target_map = target if isinstance(target, Mapping) else None
        if target_map:
            scope = scope or _normalize_scope(_first_str(target_map, ("type", "scope", "kind")))
            remediation_id = remediation_id or _first_str(target_map, _REMEDIATION_KEYS + ("id",))
            release_line = release_line or _normalize_line(
                _first_str(target_map, _RELEASE_LINE_KEYS + ("name",))
            )
        target_evidence = _first_str(
            record, ("target_evidence_id", "invalidates_evidence_id", "evidence_target")
        )
        target_fragment = _first_str(
            record, ("target_fragment_id", "fragment_id", "disposition_id")
        )
        if scope is None:
            scope = (
                REMEDIATION_SCOPE
                if remediation_id or target_evidence or target_fragment
                else RELEASE_LINE_SCOPE
                if release_line
                else ADVISORY_SCOPE
            )
        advisory_id = self._canonical_advisory(record)
        if advisory_id is None and target_map is not None:
            advisory_id = self._canonical_advisory(target_map)
        notice = WithdrawalNotice(
            withdrawal_id=withdrawal_id,
            advisory_id=advisory_id,
            scope=scope,
            remediation_id=remediation_id or target_fragment,
            release_line=release_line,
            target_evidence_id=target_evidence,
            withdrawn_at=_first_str(record, ("withdrawn_at", "timestamp", "created_at")),
            valid=_is_valid(record, notice=True),
            raw=dict(record),
        )
        problem = _withdrawal_context_problem(notice)
        if problem:
            self._unresolved(problem[0], problem[1], record, withdrawal_id)
        self.withdrawals.append(notice)

    def _unresolved(
        self,
        code: str,
        message: str,
        record: RecordLike,
        record_id: str | None = None,
    ) -> None:
        resolved_id = record_id or _first_str(
            record, _ID_KEYS + _EVIDENCE_ID_KEYS + _SUBMISSION_KEYS
        )
        submission = _submission_id(record)
        self.unresolved.append(
            UnresolvedItem(
                code=code,
                message=message,
                record_id=resolved_id,
                context={"submission_id": submission} if submission else {},
            )
        )


def _reconcile_ledger(ledger: HandoffLedger) -> HandoffReport:
    evidence_index = _index_evidence(ledger)
    reopened: list[ReopenItem] = []
    preserved: list[PreservedItem] = []
    unresolved = list(ledger.unresolved)

    for fragment in sorted(ledger.fragments, key=lambda item: item.fragment_id):
        applicable = [w for w in ledger.withdrawals if _withdrawal_applies(w, fragment, ledger)]
        invalid_applicable = [w for w in applicable if not w.valid]
        applicable = [w for w in applicable if w.valid]
        unresolved.extend(
            [
                UnresolvedItem(
                    code="invalid_withdrawal_ignored",
                    message=f"withdrawal {withdrawal.withdrawal_id} is not valid",
                    record_id=withdrawal.withdrawal_id,
                )
                for withdrawal in invalid_applicable
            ]
        )

        if applicable:
            reopened.append(
                ReopenItem(
                    fragment_id=fragment.fragment_id,
                    advisory_id=fragment.advisory_id,
                    scope=fragment.scope,
                    reason=_reopen_reason(applicable),
                    withdrawal_ids=tuple(sorted({w.withdrawal_id for w in applicable})),
                    remediation_id=fragment.remediation_id,
                    release_line=fragment.release_line,
                )
            )
            continue

        evidence = _supporting_evidence(fragment, ledger, evidence_index)
        primary = evidence[0] if evidence else None
        if primary is None:
            unresolved.append(
                UnresolvedItem(
                    code="missing_valid_evidence",
                    message=f"signed fragment {fragment.fragment_id} has no citable valid evidence",
                    record_id=fragment.fragment_id,
                    context={"advisory_id": fragment.advisory_id or ""},
                )
            )
        preserved.append(
            PreservedItem(
                fragment_id=fragment.fragment_id,
                advisory_id=fragment.advisory_id,
                scope=fragment.scope,
                preserved_by=primary,
                evidence_ids=tuple(evidence),
                remediation_id=fragment.remediation_id,
                release_line=fragment.release_line,
            )
        )

    common_evidence_ids = _common_evidence(preserved)
    return HandoffReport(
        reopened=tuple(reopened),
        preserved=tuple(preserved),
        unresolved=tuple(_dedupe_unresolved(unresolved)),
        duplicate_submissions=tuple(dict.fromkeys(ledger.duplicate_submissions)),
        evidence_count=len(ledger.source_signoffs) + len(ledger.version_impacts),
        record_count=ledger.record_count,
        common_evidence_ids=common_evidence_ids,
    )


def _common_evidence(preserved: Sequence[PreservedItem]) -> tuple[str, ...]:
    if not preserved:
        return ()
    shared = set(preserved[0].evidence_ids)
    for item in preserved[1:]:
        shared.intersection_update(item.evidence_ids)
    return tuple(evidence_id for evidence_id in preserved[0].evidence_ids if evidence_id in shared)


def reconcile_handoffs(batch: BatchLike = None, *records: Any, **kwargs: Any) -> HandoffReport:
    """Reconcile a batch or flexible in-memory handoff records."""
    payloads: list[Any] = []
    if batch is not None:
        payloads.append(batch)
    if records:
        payloads.extend(records)
    for key in ("records", "handoffs", "entries", "items", "data", "batch"):
        value = kwargs.pop(key, None)
        if value is not None:
            payloads.append(value)
    for key in (
        "signoffs",
        "source_signoffs",
        "source_receipts",
        "attestations",
        "impacts",
        "version_impacts",
        "fragments",
        "dispositions",
        "withdrawals",
        "revocations",
    ):
        value = kwargs.pop(key, None)
        if value is not None:
            payloads.append({key: value})

    ledger = HandoffLedger()
    for payload in payloads:
        if isinstance(payload, HandoffLedger):
            return payload.reconcile()
        ledger.ingest(payload)
    if kwargs:
        ledger.ingest(kwargs)
    return ledger.reconcile()


def build_reopen_list(
    batch: BatchLike = None, *records: Any, **kwargs: Any
) -> list[dict[str, Any]]:
    """Return only the stable reopen list for a handoff batch."""
    return reconcile_handoffs(batch, *records, **kwargs).reopen_list


def load_handoff_batch(source: BatchLike) -> HandoffLedger:
    """Load a batch into a normalized HandoffLedger."""
    return HandoffLedger.from_batch(source)


def save_handoff(batch: BatchLike, path: str | Path) -> Path:
    """Normalize and save a handoff batch to path."""
    return HandoffLedger.from_batch(batch).save_json(path)


class HandoffReconciler(HandoffLedger):
    """Compatibility name for code expecting a reconciler object."""

    def run(self) -> HandoffReport:
        """Alias for reconcile."""
        return self.reconcile()


AdvisoryHandoffStore = HandoffLedger
reconcile = reconcile_handoffs
reconcile_signoffs = reconcile_handoffs
reconcile_withdrawals = reconcile_handoffs
reconcile_advisory_handoffs = reconcile_handoffs
evaluate_withdrawals = reconcile_handoffs
process_handoff_records = reconcile_handoffs
reopen_list = build_reopen_list
get_reopen_list = build_reopen_list
build_reopen_plan = build_reopen_list
reopen_signed_conclusions = build_reopen_list
analyze_withdrawals = reconcile_handoffs
build_reopening_report = reconcile_handoffs
reconcile_advisories = reconcile_handoffs
review_withdrawals = reconcile_handoffs
load_records = load_handoff_batch


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline handoff report CLI."""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m pip_audit._handoff")
    parser.add_argument("batch", nargs="?", help="JSON handoff batch path or JSON text")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("-o", "--output", help="write report to this file")
    parser.add_argument("--save-ledger", help="also save normalized ledger JSON")
    args = parser.parse_args(argv)

    report = reconcile_handoffs(args.batch)
    if args.save_ledger:
        HandoffLedger.from_batch(args.batch).save_json(args.save_ledger)
    rendered = report.to_json() if args.format == "json" else report.markdown()
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    return 0


def _load_batch(batch: BatchLike) -> RecordLike | Sequence[Any]:
    if batch is None:
        return {"records": []}
    if isinstance(batch, Path):
        return json.loads(batch.read_text(encoding="utf-8"))
    if isinstance(batch, str):
        path = Path(batch)
        raw = path.read_text(encoding="utf-8") if path.exists() else batch
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HandoffError(f"invalid handoff JSON or unreadable path: {exc}") from exc
    if isinstance(batch, (Mapping, Sequence)):
        return batch
    raise HandoffError(f"unsupported handoff batch type: {type(batch).__name__}")


def _extract_records(data: RecordLike | Sequence[Any]) -> Sequence[RecordLike]:
    generic_keys = ("records", "events", "entries", "handoffs", "submissions", "items")
    section_types = (
        ("source_signoffs", "source_signoff"),
        ("source_receipts", "source_signoff"),
        ("signoffs", "source_signoff"),
        ("source_attestations", "source_signoff"),
        ("attestations", "source_signoff"),
        ("receipts", "source_signoff"),
        ("source_signoff", "source_signoff"),
        ("source_receipt", "source_signoff"),
        ("signoff", "source_signoff"),
        ("receipt", "source_signoff"),
        ("version_impacts", "version_impact"),
        ("version_impact_records", "version_impact"),
        ("impacts", "version_impact"),
        ("version_impact", "version_impact"),
        ("impact", "version_impact"),
        ("dispositions", "disposition"),
        ("disposition_fragments", "disposition"),
        ("signed_fragments", "disposition"),
        ("fragments", "disposition"),
        ("decisions", "disposition"),
        ("conclusions", "disposition"),
        ("disposition", "disposition"),
        ("fragment", "disposition"),
        ("withdrawals", "withdrawal"),
        ("withdrawal_records", "withdrawal"),
        ("withdrawal_notices", "withdrawal"),
        ("revocations", "withdrawal"),
        ("retractions", "withdrawal"),
        ("withdrawal", "withdrawal"),
        ("revocation", "withdrawal"),
        ("retraction", "withdrawal"),
    )
    if isinstance(data, Mapping):
        records: list[RecordLike] = []
        for key in generic_keys:
            value = data.get(key)
            candidates: list[Any] = []
            if isinstance(value, Mapping):
                looks_like_record = bool(
                    _first_str(value, _RECORD_TYPE_KEYS)
                    or _evidence_id(value)
                    or _submission_id(value)
                )
                candidates = [value] if looks_like_record else list(value.values())
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                candidates = list(value)
            records.extend(item for item in candidates if isinstance(item, Mapping))
        for key, record_type in section_types:
            value = data.get(key)
            for item in _as_list(value):
                if isinstance(item, Mapping):
                    merged = dict(item)
                    merged.setdefault("record_type", record_type)
                    records.append(merged)
        if records:
            return records
        if _first_str(data, _RECORD_TYPE_KEYS) or _evidence_id(data) or _submission_id(data):
            return [data]
        return []
    if isinstance(data, Sequence):
        return [item for item in data if isinstance(item, Mapping)]
    return []


def _infer_record_type(record: RecordLike) -> str | None:
    """Infer a record type for shorthand fixtures that omit record_type."""
    if _first_str(record, ("withdrawal_id", "revocation_id", "retraction_id")) or record.get(
        "withdrawn_at"
    ):
        return "withdrawal"
    if _first_str(record, ("fragment_id", "disposition_id", "decision_id")):
        return "disposition"
    if any(key in record for key in ("conclusion", "signed_conclusion", "disposition_status")):
        return "disposition"
    if any(key in record for key in ("affected_versions", "affected_range", "fixed_version")):
        return "version_impact"
    if any(key in record for key in ("advisory_ids", "source_id", "signature_status")):
        return "source_signoff"
    if any(key in record for key in ("package", "package_name", "distribution")) and any(
        key in record for key in ("release_line", "fixed_version", "affected", "affected_versions")
    ):
        return "version_impact"
    if "scope" in record and any(
        key in record for key in _REMEDIATION_KEYS + _RELEASE_LINE_KEYS + ("target",)
    ):
        # Signed fragments and withdrawal notices share these fields.  A
        # withdrawal timestamp/id was handled above; otherwise treat it as a
        # disposition because the ledger's primary object is a signed fragment.
        return "disposition"
    return None


def _impact_from_mapping(
    evidence_id: str,
    advisory_id: str | None,
    record: RecordLike,
) -> VersionImpact:
    return VersionImpact(
        evidence_id=evidence_id,
        advisory_id=advisory_id,
        package=_package_name(record),
        release_line=_normalize_line(_first_str(record, _RELEASE_LINE_KEYS)),
        affected_versions=_first_str(
            record, ("affected_versions", "affected_range", "affected", "version_range")
        ),
        fixed_version=_first_str(record, ("fixed_version", "fixed", "resolution_version")),
        remediation_id=_first_str(record, _REMEDIATION_KEYS),
        valid=_is_valid(record),
        raw=dict(record),
    )


def _index_evidence(ledger: HandoffLedger) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for signoff in ledger.source_signoffs:
        index[signoff.evidence_id] = {"kind": "source_signoff", "object": signoff}
    for impact in ledger.version_impacts:
        index[impact.evidence_id] = {"kind": "version_impact", "object": impact}
    for fragment in ledger.fragments:
        index.setdefault(fragment.fragment_id, {"kind": "disposition", "object": fragment})
    return index


def _supporting_evidence(
    fragment: DispositionFragment,
    ledger: HandoffLedger,
    index: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    candidates: list[tuple[int, str]] = []
    referenced = list(fragment.evidence_ids)
    seen_candidate_ids: set[str] = set()
    for evidence_id in dict.fromkeys(referenced):
        entry = index.get(evidence_id)
        if entry is None:
            continue
        obj = entry["object"]
        if not getattr(obj, "valid", True):
            continue
        if _evidence_targeted_by_withdrawal(evidence_id, fragment, ledger):
            continue
        if not _evidence_matches_fragment(obj, fragment):
            continue
        priority = {"disposition": 0, "version_impact": 1, "source_signoff": 2}.get(
            str(entry["kind"]), 3
        )
        candidates.append((priority, evidence_id))
        seen_candidate_ids.add(evidence_id)

    for impact in ledger.version_impacts:
        if impact.evidence_id in seen_candidate_ids or not impact.valid:
            continue
        if _evidence_targeted_by_withdrawal(impact.evidence_id, fragment, ledger):
            continue
        if _impact_matches_fragment(impact, fragment):
            candidates.append((1, impact.evidence_id))
            seen_candidate_ids.add(impact.evidence_id)

    for signoff in ledger.source_signoffs:
        if signoff.evidence_id in seen_candidate_ids or not signoff.valid:
            continue
        if _evidence_targeted_by_withdrawal(signoff.evidence_id, fragment, ledger):
            continue
        if fragment.advisory_id and fragment.advisory_id in signoff.advisory_ids:
            candidates.append((2, signoff.evidence_id))
            seen_candidate_ids.add(signoff.evidence_id)

    candidates.sort(key=lambda item: (item[0], item[1]))
    return list(dict.fromkeys(evidence_id for _, evidence_id in candidates))


def _evidence_matches_fragment(obj: Any, fragment: DispositionFragment) -> bool:
    if isinstance(obj, DispositionFragment):
        return obj.fragment_id == fragment.fragment_id and obj.valid
    if isinstance(obj, VersionImpact):
        return _impact_matches_fragment(obj, fragment)
    if isinstance(obj, SourceSignoff):
        return bool(fragment.advisory_id and fragment.advisory_id in obj.advisory_ids)
    return True


def _impact_matches_fragment(impact: VersionImpact, fragment: DispositionFragment) -> bool:
    if fragment.advisory_id and impact.advisory_id and fragment.advisory_id != impact.advisory_id:
        return False
    if fragment.package and impact.package:
        if _package_key(fragment.package) != _package_key(impact.package):
            return False
    if fragment.remediation_id and impact.remediation_id:
        return fragment.remediation_id == impact.remediation_id
    if fragment.release_line and impact.release_line:
        return _line_key(fragment.release_line) == _line_key(impact.release_line)
    return True


def _evidence_targeted_by_withdrawal(
    evidence_id: str,
    fragment: DispositionFragment,
    ledger: HandoffLedger,
) -> bool:
    return any(
        withdrawal.valid
        and withdrawal.target_evidence_id == evidence_id
        and _withdrawal_applies(withdrawal, fragment, ledger)
        for withdrawal in ledger.withdrawals
    )


def _withdrawal_applies(
    withdrawal: WithdrawalNotice,
    fragment: DispositionFragment,
    ledger: HandoffLedger | None = None,
) -> bool:
    if not _advisories_match(withdrawal.advisory_id, fragment.advisory_id):
        return False
    if withdrawal.scope == ADVISORY_SCOPE:
        return True
    if withdrawal.scope == REMEDIATION_SCOPE:
        if withdrawal.remediation_id:
            if withdrawal.remediation_id == fragment.remediation_id:
                return True
            if withdrawal.remediation_id == fragment.fragment_id:
                return True
        if withdrawal.target_evidence_id and withdrawal.target_evidence_id in fragment.evidence_ids:
            return True
        target_fragment = _first_str(
            withdrawal.raw, ("target_fragment_id", "fragment_id", "disposition_id")
        )
        return bool(target_fragment and target_fragment == fragment.fragment_id)
    if withdrawal.scope == RELEASE_LINE_SCOPE:
        if not withdrawal.release_line:
            return False
        target_line = _line_key(withdrawal.release_line)
        if fragment.release_line and _line_key(fragment.release_line) == target_line:
            return True
        if ledger is None:
            return False
        return any(
            impact.release_line
            and _line_key(impact.release_line) == target_line
            and _impact_matches_fragment(impact, fragment)
            for impact in ledger.version_impacts
        )
    return False


def _advisories_match(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return _advisory_key(left) == _advisory_key(right)


def _withdrawal_context_problem(notice: WithdrawalNotice) -> tuple[str, str] | None:
    if notice.scope not in SCOPES:
        return ("unknown_withdrawal_scope", f"unsupported withdrawal scope {notice.scope!r}")
    if notice.scope == ADVISORY_SCOPE and not notice.advisory_id:
        return ("missing_advisory_context", "advisory withdrawal lacks advisory id")
    if notice.scope == REMEDIATION_SCOPE and not (
        notice.remediation_id or notice.target_evidence_id
    ):
        return ("missing_remediation_context", "remediation withdrawal lacks remediation id")
    if notice.scope == RELEASE_LINE_SCOPE and not notice.release_line:
        return ("missing_release_line", "release-line withdrawal lacks release line")
    if notice.scope != ADVISORY_SCOPE and not notice.advisory_id:
        return ("missing_advisory_context", f"{notice.scope} withdrawal lacks advisory id")
    return None


def _reopen_reason(withdrawals: Sequence[WithdrawalNotice]) -> str:
    withdrawal = withdrawals[0]
    if withdrawal.scope == ADVISORY_SCOPE:
        return "advisory_withdrawn"
    if withdrawal.scope == REMEDIATION_SCOPE:
        return "remediation_withdrawn"
    if withdrawal.scope == RELEASE_LINE_SCOPE:
        return "release_line_withdrawn"
    return "withdrawal_applied"


def _dedupe_unresolved(items: Sequence[UnresolvedItem]) -> list[UnresolvedItem]:
    seen: set[tuple[str, str | None, str | None]] = set()
    result: list[UnresolvedItem] = []
    for item in items:
        key = (item.code, item.record_id, item.message)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return str(value)


def _first_str(value: Any, keys: Sequence[str]) -> str | None:
    if not isinstance(value, Mapping):
        return _string(value) if not keys else None
    for key in keys:
        if key in value:
            result = _string(value[key])
            if result is not None:
                return result
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, Mapping)):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    return [value]


def _as_str_list(value: Any) -> list[str]:
    results: list[str] = []
    for item in _as_list(value):
        if isinstance(item, str):
            results.extend(part.strip() for part in item.split(",") if part.strip())
        elif item is not None:
            text_value = str(item).strip()
            if text_value:
                results.append(text_value)
    return results


def _content_hash(record: RecordLike) -> str:
    encoded = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _submission_id(record: RecordLike) -> str | None:
    return _first_str(record, _SUBMISSION_KEYS)


def _evidence_id(record: RecordLike) -> str | None:
    return _first_str(record, _EVIDENCE_ID_KEYS)


def _advisory_key(value: str) -> str:
    return value.strip().upper()


def _package_name(record: RecordLike) -> str | None:
    return _first_str(record, ("package", "package_name", "name", "distribution", "dependency"))


def _package_key(value: str) -> str:
    return canonicalize_name(value)


def _normalize_line(value: str | None) -> str | None:
    if value is None:
        return None
    line = value.strip().lower().removeprefix("release-line:").removeprefix("branch:")
    line = line.removeprefix("v")
    return line.strip() or None


def _line_key(value: str) -> str:
    line = _normalize_line(value) or ""
    line = line.replace("*", "x")
    if line.endswith(".x"):
        line = line[:-2]
    return line


def _normalize_scope(value: str | None) -> str | None:
    if value is None:
        return None
    scope = value.strip().lower().replace("-", "_").replace(" ", "_")
    if scope in SCOPES:
        return scope
    if any(
        token in scope for token in ("whole", "full", "global", "all", "advisory", "vulnerability")
    ):
        return ADVISORY_SCOPE
    if any(token in scope for token in ("remed", "fix", "patch", "recommend", "advice")):
        return REMEDIATION_SCOPE
    if any(token in scope for token in ("line", "branch", "series", "train", "release")):
        return RELEASE_LINE_SCOPE
    return None


def _is_valid(record: RecordLike, *, notice: bool = False) -> bool:
    for key in ("valid", "is_valid", "effective"):
        value = record.get(key)
        if isinstance(value, bool):
            return value
    if record.get("invalid") is True:
        return False
    if record.get("revoked") is True or record.get("expired") is True:
        return False
    if record.get("signature_valid") is False or record.get("verified") is False:
        return False
    status = (
        _first_str(record, ("status", "state", "validation_status", "signature_status")) or ""
    ).lower()
    if status in _INVALID_STATUSES or status in {"cancelled", "canceled", "ineffective"}:
        return False
    if not notice:
        if status in {"withdrawn", "retracted"}:
            return False
        if record.get("withdrawn") is True or record.get("retracted") is True:
            return False
        if record.get("withdrawn_at") or record.get("retracted_at"):
            return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
