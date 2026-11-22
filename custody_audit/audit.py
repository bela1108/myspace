"""
Core offline custody reconciliation logic.

The reconciliation combines four caller-supplied inputs:

* the record ranges that are in scope for handover (per source EVTX file);
* the internal custodian roster, which states each custodian's permissions and
  period of responsibility;
* the external handover manifest, which must contain only non-sensitive
  metadata;
* handover receipts (shift-change and retroactive sign-off).

A record range counts as handed over only when an *effective* receipt covers
it: the signer is a rostered custodian, holds the permission matching the
handover mode (full review vs. summary only), the receipt was signed within
the signer's period of responsibility and before the archive cutoff, and the
same range appears on the external manifest.  A predecessor simply keeping a
copy never produces a handover by itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from custody_audit.evtx_records import RecordRange, parse_iso8601


class HandoverMode(str, Enum):
    """What a manifest entry promises to hand over."""

    FULL = "full"
    SUMMARY = "summary"


class CustodyState(str, Enum):
    """Final disposition of a single in-scope record."""

    REVIEWABLE = "reviewable"
    SUMMARY_ONLY = "summary_only"
    NOT_ACCEPTED = "not_accepted"


class Severity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


# Keys an external manifest entry is allowed to contain.  Raw event XML,
# user names, process data and other sensitive fields must never appear.
ALLOWED_MANIFEST_KEYS = frozenset(
    {
        "evtx_file",
        "first_record",
        "last_record",
        "mode",
        "record_count",
        "record_sha256",
        "file_sha256",
        "handover_due",
    }
)

SENSITIVE_KEY_TOKENS = (
    "xml",
    "event_data",
    "user",
    "userdata",
    "subject",
    "account",
    "logon",
    "process",
    "command",
    "binary",
    "payload",
    "raw",
    "computer",
)


@dataclass(frozen=True)
class Custodian:
    """A custodian as described by the internal responsibility roster."""

    custodian_id: str
    display_name: str
    permissions: frozenset
    responsibility_start: str
    responsibility_end: Optional[str]

    @classmethod
    def from_dict(cls, data: dict) -> "Custodian":
        end = data.get("responsibility_end")
        return cls(
            custodian_id=str(data["custodian_id"]),
            display_name=str(data["display_name"]),
            permissions=frozenset(data["permissions"]),
            responsibility_start=str(data["responsibility_start"]),
            responsibility_end=None if end is None else str(end),
        )

    def is_responsible_at(self, when) -> bool:
        start = parse_iso8601(self.responsibility_start)
        if when < start:
            return False
        if self.responsibility_end is None:
            return True
        return when <= parse_iso8601(self.responsibility_end)


@dataclass(frozen=True)
class ManifestEntry:
    evtx_file: str
    record_range: RecordRange
    mode: HandoverMode
    record_count: int
    record_sha256: tuple
    file_sha256: str

    @classmethod
    def from_dict(cls, data: dict) -> "ManifestEntry":
        mode = HandoverMode(str(data["mode"]).lower())
        last = data.get("last_record")
        return cls(
            evtx_file=str(data["evtx_file"]),
            record_range=RecordRange(
                first=int(data["first_record"]),
                last=None if last is None else int(last),
            ),
            mode=mode,
            record_count=int(data["record_count"]),
            record_sha256=tuple(data.get("record_sha256", ())),
            file_sha256=str(data["file_sha256"]),
        )


@dataclass(frozen=True)
class ExternalManifest:
    manifest_id: str
    evtx_files: tuple
    entries: tuple
    raw_entries: tuple

    @classmethod
    def from_dict(cls, data: dict) -> "ExternalManifest":
        raw_entries = tuple(data["entries"])
        entries = tuple(ManifestEntry.from_dict(entry) for entry in raw_entries)
        return cls(
            manifest_id=str(data["manifest_id"]),
            evtx_files=tuple(data["evtx_files"]),
            entries=entries,
            raw_entries=raw_entries,
        )

    def entries_for(self, evtx_file: str) -> tuple:
        return tuple(entry for entry in self.entries if entry.evtx_file == evtx_file)


@dataclass(frozen=True)
class HandoverReceipt:
    """
    A signed handover acknowledgement.

    ``receipt_type`` is ``shift_change`` for a normal guard-change handover or
    ``retroactive`` for a later supplementary sign-off.
    """

    receipt_id: str
    receipt_type: str
    evtx_file: str
    record_range: RecordRange
    mode: HandoverMode
    signer_id: str
    signed_at: str
    predecessor_id: Optional[str]

    @classmethod
    def from_dict(cls, data: dict) -> "HandoverReceipt":
        last = data.get("last_record")
        return cls(
            receipt_id=str(data["receipt_id"]),
            receipt_type=str(data["receipt_type"]),
            evtx_file=str(data["evtx_file"]),
            record_range=RecordRange(
                first=int(data["first_record"]),
                last=None if last is None else int(last),
            ),
            mode=HandoverMode(str(data["mode"]).lower()),
            signer_id=str(data["signer_id"]),
            signed_at=str(data["signed_at"]),
            predecessor_id=data.get("predecessor_id"),
        )


@dataclass(frozen=True)
class AuditConfig:
    archive_cutoff: str
    scope: dict

    @property
    def cutoff_dt(self):
        return parse_iso8601(self.archive_cutoff)

    def ranges_for(self, evtx_file: str) -> tuple:
        return tuple(RecordRange.from_dict(item) for item in self.scope.get(evtx_file, ()))


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    message: str
    reference: str


@dataclass(frozen=True)
class RecordDisposition:
    evtx_file: str
    record_num: int
    state: CustodyState
    effective_receipt_id: Optional[str]
    signer_id: Optional[str]
    manifest_modes: tuple
    reasons: tuple


@dataclass(frozen=True)
class FileReconciliation:
    evtx_file: str
    dispositions: tuple

    def _by_state(self, state: CustodyState) -> tuple:
        return tuple(d for d in self.dispositions if d.state == state)

    @property
    def reviewable(self) -> tuple:
        return self._by_state(CustodyState.REVIEWABLE)

    @property
    def summary_only(self) -> tuple:
        return self._by_state(CustodyState.SUMMARY_ONLY)

    @property
    def not_accepted(self) -> tuple:
        return self._by_state(CustodyState.NOT_ACCEPTED)


@dataclass(frozen=True)
class AuditResult:
    manifest: ExternalManifest
    file_results: tuple
    findings: tuple
    effective_receipts: dict
    rejected_receipts: tuple

    @property
    def has_blocking_errors(self) -> bool:
        return any(f.severity == Severity.ERROR for f in self.findings)


def _permission_for_mode(mode: HandoverMode) -> str:
    if mode == HandoverMode.FULL:
        return "evtx.full_review"
    return "evtx.summary"


def _evaluate_receipt(
    receipt: HandoverReceipt,
    custodians: dict,
    manifest: ExternalManifest,
    config: AuditConfig,
) -> tuple[bool, tuple[str, ...]]:
    """Return whether the receipt is effective plus rejection reasons."""
    reasons: list[str] = []
    signer = custodians.get(receipt.signer_id)
    if signer is None:
        reasons.append("签收人 %s 不在内部责任表中。" % receipt.signer_id)
        return False, tuple(reasons)

    signed_at = parse_iso8601(receipt.signed_at)
    if signed_at > config.cutoff_dt:
        reasons.append("回执 %s 签收时间 %s 晚于销档日期 %s。" % (receipt.receipt_id, receipt.signed_at, config.archive_cutoff))

    if not signer.is_responsible_at(signed_at):
        reasons.append("签收人 %s 在 %s 不处于责任期内。" % (receipt.signer_id, receipt.signed_at))

    required_permission = _permission_for_mode(receipt.mode)
    if required_permission not in signer.permissions:
        reasons.append("签收人 %s 缺少权限 %s，不能承接 %s 移交。" % (receipt.signer_id, required_permission, receipt.mode.value))

    matching = _matching_manifest_entry(receipt, manifest)
    if matching is None:
        reasons.append("回执 %s 的范围未出现在外部交接清单上，外部清单无法确认该交接范围。" % receipt.receipt_id)
    elif matching.mode != receipt.mode:
        reasons.append("回执 %s 模式 %s 与外部清单模式 %s 不一致。" % (receipt.receipt_id, receipt.mode.value, matching.mode.value))

    return len(reasons) == 0, tuple(reasons)


def _matching_manifest_entry(receipt: HandoverReceipt, manifest: ExternalManifest):
    for entry in manifest.entries_for(receipt.evtx_file):
        if entry.record_range.first == receipt.record_range.first and entry.record_range.last == receipt.record_range.last:
            return entry
    return None


def _manifest_entry_for_record(evtx_file: str, record_num: int, manifest: ExternalManifest):
    for entry in manifest.entries_for(evtx_file):
        if entry.record_range.contains(record_num):
            return entry
    return None


def _check_manifest_redaction(manifest: ExternalManifest) -> list:
    findings: list[Finding] = []
    for index, raw in enumerate(manifest.raw_entries):
        ref = "manifest.entries[%d]" % index
        extra = sorted(set(raw.keys()) - ALLOWED_MANIFEST_KEYS)
        if extra:
            findings.append(Finding(
                code="MANIFEST_SENSITIVE_KEY",
                severity=Severity.ERROR,
                message="外部清单含未授权字段 %r，外部交接材料禁止携带敏感原文。" % extra,
                reference=ref,
            ))
        for key in raw:
            lowered = key.lower()
            if any(token in lowered for token in SENSITIVE_KEY_TOKENS):
                findings.append(Finding(
                    code="MANIFEST_SENSITIVE_KEY",
                    severity=Severity.ERROR,
                    message="外部清单字段 %r 命中敏感字段命名，不得对外提供。" % key,
                    reference=ref,
                ))
    return findings


def _load_custodians(data: dict) -> dict:
    return {c.custodian_id: c for c in (Custodian.from_dict(item) for item in data["custodians"])}


def reconcile(
    config: AuditConfig,
    custodian_data: dict,
    manifest: ExternalManifest,
    receipts: list,
    record_index: dict,
) -> AuditResult:
    """
    Reconcile caller-supplied scope against manifest, roster and receipts.

    ``record_index`` maps an EVTX file name to the list of
    :class:`RecordSummary` objects parsed from that file.
    """
    custodians = _load_custodians(custodian_data)
    parsed_receipts = [HandoverReceipt.from_dict(item) for item in receipts]
    findings: list[Finding] = list(_check_manifest_redaction(manifest))

    effective: dict = {}
    rejected: list[Finding] = []
    for receipt in parsed_receipts:
        ok, reasons = _evaluate_receipt(receipt, custodians, manifest, config)
        if not ok:
            for reason in reasons:
                rejected.append(Finding(
                    code="RECEIPT_INVALID",
                    severity=Severity.ERROR,
                    message=reason,
                    reference="receipts.%s" % receipt.receipt_id,
                ))
            continue
        key = (receipt.evtx_file, receipt.record_range.first, receipt.record_range.last)
        previous = effective.get(key)
        if previous is None or parse_iso8601(receipt.signed_at) >= parse_iso8601(previous.signed_at):
            effective[key] = receipt

    findings.extend(rejected)
    file_results: list[FileReconciliation] = []
    covered_manifest_keys: set = set()
    for evtx_file, summaries in sorted(record_index.items()):
        scope_ranges = config.ranges_for(evtx_file)
        dispositions: list[RecordDisposition] = []
        for summary in summaries:
            if not any(rng.contains(summary.record_num) for rng in scope_ranges):
                continue
            entry = _manifest_entry_for_record(evtx_file, summary.record_num, manifest)
            manifest_modes = (entry.mode,) if entry is not None else ()
            if entry is not None:
                covered_manifest_keys.add((evtx_file, entry.record_range.first, entry.record_range.last))

            reasons: list[str] = []
            effective_receipt = None
            for rng in scope_ranges:
                if not rng.contains(summary.record_num):
                    continue
                effective_receipt = effective.get((evtx_file, rng.first, rng.last))
                if effective_receipt is not None:
                    break

            if entry is None:
                state = CustodyState.NOT_ACCEPTED
                reasons.append("记录不在外部交接清单范围内，无对外交接范围。")
            elif effective_receipt is None:
                state = CustodyState.NOT_ACCEPTED
                reasons.append("外部清单列出该范围，但内部责任表下无有效签收回执，副本持有不等于移交。")
            elif effective_receipt.mode == HandoverMode.SUMMARY:
                state = CustodyState.SUMMARY_ONLY
                reasons.append("保管人 %s 仅承接脱敏摘要，原始记录不再随外部清单复查。" % effective_receipt.signer_id)
            else:
                state = CustodyState.REVIEWABLE
                reasons.append("保管人 %s 已完整签收，可继续复查原文。" % effective_receipt.signer_id)

            if entry is not None and not summary.xml_ok:
                findings.append(Finding(
                    code="RECORD_UNREADABLE",
                    severity=Severity.WARNING,
                    message="记录 %d 无法完整渲染 XML，核对仅基于记录编号与原始哈希。" % summary.record_num,
                    reference="%s#%d" % (evtx_file, summary.record_num),
                ))

            dispositions.append(RecordDisposition(
                evtx_file=evtx_file,
                record_num=summary.record_num,
                state=state,
                effective_receipt_id=effective_receipt.receipt_id if effective_receipt else None,
                signer_id=effective_receipt.signer_id if effective_receipt else None,
                manifest_modes=manifest_modes,
                reasons=tuple(reasons),
            ))
        file_results.append(FileReconciliation(evtx_file=evtx_file, dispositions=tuple(dispositions)))
    for entry in manifest.entries:
        key = (entry.evtx_file, entry.record_range.first, entry.record_range.last)
        if key not in covered_manifest_keys:
            findings.append(Finding(
                code="MANIFEST_SCOPE_MISMATCH",
                severity=Severity.WARNING,
                message="外部清单范围 %s %s 在调用方记录范围或源证物中没有对应记录。" % (entry.evtx_file, entry.record_range.describe()),
                reference="manifest.%s" % entry.evtx_file,
            ))
        if key not in effective:
            findings.append(Finding(
                code="NO_EFFECTIVE_SIGNATURE",
                severity=Severity.ERROR,
                message="外部清单范围 %s %s 缺少有效签收回执，内部责任表无法确认实际签收人。" % (entry.evtx_file, entry.record_range.describe()),
                reference="manifest.%s" % entry.evtx_file,
            ))

    for evtx_file, scope in config.scope.items():
        summaries = record_index.get(evtx_file, ())
        present = {s.record_num for s in summaries}
        for item in scope:
            rng = RecordRange.from_dict(item)
            if not any(rng.contains(num) for num in present):
                findings.append(Finding(
                    code="SCOPE_RECORD_MISSING",
                    severity=Severity.WARNING,
                    message="调用方记录范围 %s 在源证物 %s 中没有任何记录。" % (rng.describe(), evtx_file),
                    reference="scope.%s" % evtx_file,
                ))

    return AuditResult(
        manifest=manifest,
        file_results=tuple(file_results),
        findings=tuple(findings),
        effective_receipts=effective,
        rejected_receipts=tuple(rejected),
    )
