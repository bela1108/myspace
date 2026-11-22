"""Offline custody reconciliation for EVTX evidence.

The module is deliberately independent of any service.  It reads an EVTX file,
the caller's record ranges, custodian permissions, receipts, an external
hand-off manifest, and an internal responsibility table, then reports which
record ranges are still reviewable, which only have a summary, and which have
not been accepted by the custodian.

The important distinction is that possession is not acceptance.  A previous
holder keeping a copy, or a transferor signing a hand-over, does not by itself
move custody.  A range is accepted only when the external manifest contains it
and the receiving custodian's signed receipt (or a supplemental signature)
covers it.
"""

from __future__ import annotations

import bisect
import csv
import datetime as _datetime
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from Evtx.Evtx import Evtx

__all__ = [
    "REVIEWABLE",
    "SUMMARY_ONLY",
    "NOT_ACCEPTED",
    "STATUS_LABELS_ZH",
    "REASON_LABELS_ZH",
    "RecordRange",
    "RecordInfo",
    "SourceEvidence",
    "ManifestEntry",
    "Permission",
    "PermissionDecision",
    "Receipt",
    "ResponsibilityRow",
    "SignerInfo",
    "ReceiptEvaluation",
    "GoverningReceipt",
    "ResponsibilityTable",
    "CustodyAudit",
    "CustodyAuditor",
    "CustodyReport",
    "reconcile_custody",
    "audit_custody",
    "check_custody",
    "verify_custody",
    "load_case",
    "load_json",
    "parse_time",
    "parse_ranges",
    "sanitize_external",
    "CustodyInputError",
    "format_time",
    "parse_deadline",
    "merge_ranges",
    "load_document",
    "FULL",
    "SUMMARY",
    "PENDING",
    "REVIEW",
    "main",
]

UTC = _datetime.timezone.utc

REVIEWABLE = "reviewable"
SUMMARY_ONLY = "summary_only"
NOT_ACCEPTED = "not_accepted"

STATUS_LABELS_ZH = {
    REVIEWABLE: "可继续复查",
    SUMMARY_ONLY: "只剩摘要",
    NOT_ACCEPTED: "尚未被承接",
}

REASON_LABELS_ZH = {
    "signed_scope_and_full_access": "外部清单、有效签收与完整查看权限均已核对",
    "custodian_has_summary_only": "保管人权限只允许摘要",
    "sensitive_fields_withheld": "敏感字段按外部清单规则保留在内部",
    "manifest_carries_summary_only": "外部清单只提供了摘要范围",
    "outside_external_manifest": "该范围未列入外部交接清单",
    "no_receipt": "没有对应回执",
    "no_signed_receipt": "只有未签署回执",
    "receipt_unsigned": "回执未签署",
    "receipt_revoked": "回执已撤销",
    "invalid_signed_at": "签收时间无法解析",
    "signed_after_deadline": "签收时间晚于销档期限",
    "missing_signer": "回执没有签收人",
    "transferor_signature_only": "只有移交方签名，承接方尚未签收",
    "missing_amended_receipt": "补签回执引用的原回执不存在",
    "amended_receipt_revoked": "补签所引用的原回执已撤销",
    "signer_not_in_responsibility_table": "内部责任表中没有该签收人",
    "signer_not_authorized_at_sign_time": "签收人当时不在授权时段",
    "signer_scope_mismatch": "签收人权限不覆盖该记录范围",
    "signer_revoked": "内部责任表显示签收人责任已撤销",
    "manifest_receipt_mismatch": "外部清单引用的回执与有效签收不一致",
    "manifest_receipt_not_effective": "外部清单引用的回执未形成有效承接",
    "permission_denied": "保管人没有该范围的查看权限",
    "no_matching_permission": "没有匹配的保管人权限",
    "record_missing": "源证物中缺少该批记录",
    "summary_remains_for_missing_records": "源记录缺失，外部清单仅保留摘要",
    "source_unreadable": "源证物无法读取",
    "source_unverified": "未提供源证物，范围未做字节核验",
    "prior_holder_possession_not_transfer": "上一位持有人仍持有副本不构成移交",
    "digest_mismatch": "外部清单摘要与源记录不一致",
    "record_after_signature": "记录晚于对应签收时间，尚未被承接",
}

_ACCESS_RANK = {"none": 0, "summary": 1, "full": 2}


class CustodyInputError(ValueError):
    """Raised when a custody input cannot be interpreted."""


def _norm_key(value: Any) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", str(value).lower())


def _lookup(mapping: Any, *names: str, default: Any = None) -> Any:
    if not isinstance(mapping, Mapping):
        return default
    normalized = {_norm_key(key): value for key, value in mapping.items()}
    for name in names:
        key = _norm_key(name)
        if key in normalized and normalized[key] not in (None, ""):
            return normalized[key]
    return default


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "是"}


def _basename(value: Any) -> str:
    text = str(value).replace("\\", "/")
    return text.rstrip("/").split("/")[-1]


def _coerce_int(value: Any) -> int:
    if isinstance(value, bool):
        raise CustodyInputError("boolean is not a record number")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise CustodyInputError("not an integer record number: {!r}".format(value)) from exc


def parse_time(value: Any, *, strict: bool = False) -> Optional[_datetime.datetime]:
    """Parse an ISO-8601 timestamp or epoch value into an aware UTC value."""

    if value in (None, ""):
        return None
    if isinstance(value, _datetime.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, _datetime.date):
        return _datetime.datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 1e12:
            seconds /= 1000.0
        return _datetime.datetime.fromtimestamp(seconds, UTC)

    text = str(value).strip()
    if not text:
        return None
    if text.isdigit() and len(text) >= 10:
        return _datetime.datetime.fromtimestamp(int(text), UTC)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    fractional = re.match(r"^(.*\.)(\d+)(.*)$", text)
    if fractional and len(fractional.group(2)) > 6:
        text = fractional.group(1) + fractional.group(2)[:6] + fractional.group(3)
    try:
        parsed = _datetime.datetime.fromisoformat(text)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d",
            "%Y/%m/%d",
        ):
            try:
                parsed = _datetime.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        if strict:
            raise CustodyInputError("invalid timestamp: {!r}".format(value))
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_deadline(value: Any) -> Optional[_datetime.datetime]:
    parsed = parse_time(value)
    if parsed is not None and isinstance(value, str) and re.fullmatch(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", value.strip()):
        parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed


def format_time(value: Optional[_datetime.datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, order=True)
class RecordRange:
    """An inclusive range of EVTX record numbers."""

    start: int
    end: int
    evidence_id: Optional[str] = None

    def __post_init__(self) -> None:
        start = _coerce_int(self.start)
        end = _coerce_int(self.end)
        if start > end:
            start, end = end, start
        evidence_id = self.evidence_id
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)
        object.__setattr__(self, "evidence_id", str(evidence_id) if evidence_id is not None else None)

    @property
    def length(self) -> int:
        return self.end - self.start + 1

    def contains_number(self, number: int) -> bool:
        return self.start <= number <= self.end

    def contains(self, other: Union[int, "RecordRange"]) -> bool:
        if isinstance(other, int):
            return self.contains_number(other)
        if self.evidence_id and other.evidence_id and self.evidence_id != other.evidence_id:
            return False
        return self.start <= other.start and other.end <= self.end

    def intersects(self, other: "RecordRange") -> bool:
        if self.evidence_id and other.evidence_id and self.evidence_id != other.evidence_id:
            return False
        return self.start <= other.end and other.start <= self.end

    def intersection(self, other: "RecordRange") -> Optional["RecordRange"]:
        if not self.intersects(other):
            return None
        evidence_id = self.evidence_id or other.evidence_id
        return RecordRange(max(self.start, other.start), min(self.end, other.end), evidence_id)

    def to_dict(self) -> Dict[str, Any]:
        return {"start": self.start, "end": self.end, "evidence_id": self.evidence_id}


def _range_regexes() -> Tuple[re.Pattern, ...]:
    return (
        re.compile(r"^\s*(\d+)\s*(?:-|–|—|~|\.\.)\s*(\d+)\s*$"),
        re.compile(r"^\s*(\d+)\s*$"),
    )


def _ranges_from_numbers(numbers: Iterable[int], evidence_id: Optional[str] = None) -> List[RecordRange]:
    values = sorted({_coerce_int(value) for value in numbers})
    if not values:
        return []
    result: List[RecordRange] = []
    start = values[0]
    previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        result.append(RecordRange(start, previous, evidence_id))
        start = previous = value
    result.append(RecordRange(start, previous, evidence_id))
    return result


def _scope_is_all(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"all", "*", "everything", "全部", "所有"}
    if isinstance(value, Mapping):
        if _as_bool(_lookup(value, "all", "everything", "all_scope", default=False)):
            return True
        scope = _lookup(value, "scope", "ranges", "records")
        return _scope_is_all(scope) if scope is not None else False
    if isinstance(value, (list, tuple)):
        return any(_scope_is_all(item) for item in value)
    return False


def parse_ranges(
    value: Any,
    evidence_id: Optional[str] = None,
    default_evidence: Optional[str] = None,
) -> List[RecordRange]:
    """Parse caller range notation into inclusive :class:`RecordRange` values."""

    if evidence_id is not None:
        evidence_id = str(evidence_id)
        if "/" in evidence_id or "\\" in evidence_id:
            evidence_id = _basename(evidence_id)
    if default_evidence is not None:
        default_evidence = str(default_evidence)
        if "/" in default_evidence or "\\" in default_evidence:
            default_evidence = _basename(default_evidence)
    if value is None:
        return []
    if isinstance(value, RecordRange):
        return [
            RecordRange(
                value.start,
                value.end,
                value.evidence_id or evidence_id or default_evidence,
            )
        ]
    if _scope_is_all(value):
        return []
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [RecordRange(value, value, evidence_id or default_evidence)]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if "," in text or ";" in text:
            result: List[RecordRange] = []
            for part in re.split(r"[,;]", text):
                result.extend(parse_ranges(part, evidence_id, default_evidence))
            return result
        for pattern in _range_regexes():
            match = pattern.match(text)
            if match:
                if match.lastindex == 1:
                    number = int(match.group(1))
                    return [RecordRange(number, number, evidence_id or default_evidence)]
                return [
                    RecordRange(
                        int(match.group(1)),
                        int(match.group(2)),
                        evidence_id or default_evidence,
                    )
                ]
        return []
    if isinstance(value, Mapping):
        resolved_evidence = _lookup(
            value,
            "evidence_id",
            "evidence",
            "log",
            "file",
            "attachment",
            default=evidence_id or default_evidence,
        )
        if resolved_evidence is not None:
            resolved_evidence = str(resolved_evidence)
            if "/" in resolved_evidence or "\\" in resolved_evidence:
                resolved_evidence = _basename(resolved_evidence)
        nested = _lookup(value, "ranges", "record_ranges", "records", "scope")
        if nested is not None and not isinstance(nested, (str, int)):
            return parse_ranges(nested, resolved_evidence, default_evidence)
        if isinstance(nested, str) and not _scope_is_all(nested):
            if "-" in nested or nested.strip().isdigit() or "," in nested or ";" in nested:
                return parse_ranges(nested, resolved_evidence, default_evidence)
        numbers = _lookup(value, "record_numbers", "record_nums", "numbers")
        if numbers is not None:
            return _ranges_from_numbers(_as_list(numbers), resolved_evidence)
        start = _lookup(
            value,
            "start",
            "record_start",
            "start_record",
            "from_record",
            "first",
            default=None,
        )
        end = _lookup(
            value,
            "end",
            "record_end",
            "end_record",
            "to_record",
            "last",
            default=None,
        )
        if start is None and end is None:
            range_value = _lookup(value, "range", "record_range")
            if range_value is not None:
                return parse_ranges(range_value, resolved_evidence, default_evidence)
            return []
        if start is None:
            start = end
        if end is None:
            end = start
        return [RecordRange(start, end, resolved_evidence)]
    if isinstance(value, (list, tuple)):
        items = list(value)
        if len(items) == 2 and all(isinstance(item, int) and not isinstance(item, bool) for item in items):
            return [RecordRange(items[0], items[1], evidence_id or default_evidence)]
        if items and all(isinstance(item, int) and not isinstance(item, bool) for item in items):
            return _ranges_from_numbers(items, evidence_id or default_evidence)
        result = []
        for item in items:
            result.extend(parse_ranges(item, evidence_id, default_evidence))
        return result
    return []


def merge_ranges(ranges: Iterable[RecordRange]) -> List[RecordRange]:
    grouped: Dict[Optional[str], List[RecordRange]] = {}
    for item in ranges:
        grouped.setdefault(item.evidence_id, []).append(item)
    result: List[RecordRange] = []
    for evidence_id, items in grouped.items():
        items = sorted(items, key=lambda item: (item.start, item.end))
        if not items:
            continue
        current = items[0]
        for item in items[1:]:
            if item.start <= current.end + 1:
                current = RecordRange(current.start, max(current.end, item.end), evidence_id)
            else:
                result.append(current)
                current = item
        result.append(current)
    return sorted(result, key=lambda item: (str(item.evidence_id or ""), item.start, item.end))


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class RecordInfo:
    record_num: int
    timestamp: Optional[_datetime.datetime]
    sha256: str
    size: int
    offset: int
    data: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_num": self.record_num,
            "timestamp": format_time(self.timestamp),
            "sha256": self.sha256,
            "size": self.size,
            "offset": self.offset,
        }


@dataclass
class SourceEvidence:
    evidence_id: str
    path: Optional[str] = None
    ranges: List[RecordRange] = field(default_factory=list)
    range_specs: List[Dict[str, Any]] = field(default_factory=list)
    records: Dict[int, RecordInfo] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    source_sha256: Optional[str] = None
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def record_numbers(self) -> List[int]:
        return sorted(self.records)

    def records_in(self, record_range: RecordRange) -> List[RecordInfo]:
        if not self.records:
            return []
        numbers = self.record_numbers
        left = bisect.bisect_left(numbers, record_range.start)
        right = bisect.bisect_right(numbers, record_range.end)
        return [self.records[number] for number in numbers[left:right]]

    def present_count(self, record_range: RecordRange) -> int:
        if not self.records:
            return 0
        numbers = self.record_numbers
        return bisect.bisect_right(numbers, record_range.end) - bisect.bisect_left(numbers, record_range.start)

    def digest_for(self, record_range: RecordRange) -> Optional[str]:
        records = self.records_in(record_range)
        if not records:
            return None
        digest = hashlib.sha256()
        for record in records:
            digest.update(record.data)
        return digest.hexdigest()

    def sensitivity_for(self, record_range: RecordRange) -> Optional[str]:
        for spec in self.range_specs:
            candidate = spec.get("range")
            if isinstance(candidate, RecordRange) and candidate.contains(record_range):
                return spec.get("sensitivity")
        return self.metadata.get("sensitivity")

    def summary_for(self, record_range: RecordRange) -> Optional[str]:
        for spec in self.range_specs:
            candidate = spec.get("range")
            if isinstance(candidate, RecordRange) and candidate.contains(record_range):
                return spec.get("summary")
        return self.metadata.get("summary")

    def summary_only_for(self, record_range: RecordRange) -> bool:
        for spec in self.range_specs:
            candidate = spec.get("range")
            if isinstance(candidate, RecordRange) and candidate.contains(record_range):
                return bool(spec.get("summary_only"))
        return bool(self.metadata.get("summary_only"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "path": self.metadata.get("input_path", self.path),
            "source_sha256": self.source_sha256,
            "source_verified": self.verified,
            "source_errors": list(self.errors),
            "records_loaded": len(self.records),
            "ranges": [item.to_dict() for item in self.ranges],
        }


def load_source_evidence(
    evidence_id: str,
    path: Optional[str],
    ranges: Optional[Sequence[RecordRange]] = None,
    range_specs: Optional[Sequence[Dict[str, Any]]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> SourceEvidence:
    """Load only the requested records from an EVTX file."""

    path = os.fsdecode(os.fspath(path)) if path is not None else None
    source = SourceEvidence(
        evidence_id=evidence_id,
        path=path,
        range_specs=list(range_specs or []),
        metadata=dict(metadata or {}),
    )
    requested = merge_ranges(ranges or [])
    source.ranges = requested
    if not path:
        return source
    if not os.path.exists(path):
        source.errors.append("source file does not exist: {}".format(path))
        return source
    try:
        source.source_sha256 = _file_sha256(path)
    except OSError as exc:
        source.errors.append("cannot read source file: {}".format(exc))
        return source

    try:
        with Evtx(path) as log:
            for record in log.records():
                try:
                    record_num = int(record.record_num())
                except Exception as exc:
                    source.errors.append("record number unreadable: {}".format(exc))
                    continue
                if requested and not any(item.contains_number(record_num) for item in requested):
                    continue
                try:
                    timestamp = record.timestamp()
                    if timestamp is not None and timestamp.year <= 1:
                        timestamp = None
                    else:
                        timestamp = parse_time(timestamp)
                except Exception:
                    timestamp = None
                try:
                    data = bytes(record.data())
                except Exception as exc:
                    source.errors.append("record {} data unreadable: {}".format(record_num, exc))
                    continue
                source.records[record_num] = RecordInfo(
                    record_num=record_num,
                    timestamp=timestamp,
                    sha256=hashlib.sha256(data).hexdigest(),
                    size=len(data),
                    offset=int(record.offset()),
                    data=data,
                )
    except Exception as exc:
        source.errors.append("source is not a readable EVTX file: {}".format(exc))
        return source

    if not requested:
        source.ranges = _ranges_from_numbers(source.record_numbers, evidence_id)
    source.verified = not source.errors
    return source


@dataclass
class ManifestEntry:
    evidence_id: Optional[str]
    record_range: Optional[RecordRange]
    receipt_id: Optional[str]
    digest: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)
    all_scope: bool = False
    summary_only: bool = False

    def covers(self, record_range: RecordRange) -> bool:
        if self.all_scope and (
            not self.evidence_id
            or not record_range.evidence_id
            or self.evidence_id == record_range.evidence_id
        ):
            return True
        if self.record_range is None:
            return False
        if self.evidence_id and record_range.evidence_id and self.evidence_id != record_range.evidence_id:
            return False
        return self.record_range.contains(record_range)

    def to_dict(self, *, safe: bool = False) -> Dict[str, Any]:
        if self.record_range is None:
            range_dict: Dict[str, Any] = {}
        else:
            range_dict = {
                "start": self.record_range.start,
                "end": self.record_range.end,
                "record_count": self.record_range.length,
            }
        result = {
            "evidence_id": self.evidence_id,
            **range_dict,
            "receipt_id": self.receipt_id,
            "sha256": self.digest,
            "all_scope": self.all_scope,
        }
        if not safe:
            result["raw_fields"] = sorted(str(key) for key in self.raw)
        return result


def _parse_manifest(value: Any, default_evidence: Optional[str] = None) -> List[ManifestEntry]:
    if value is None:
        return []
    if isinstance(value, str):
        return []
    if isinstance(value, Mapping):
        nested = _lookup(value, "entries", "items", "handover_list", "manifest")
        if nested is not None and nested is not value:
            return _parse_manifest(nested, default_evidence)
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return []

    result: List[ManifestEntry] = []
    for item in items:
        if isinstance(item, str):
            ranges = parse_ranges(item, default_evidence)
            for record_range in ranges:
                result.append(ManifestEntry(record_range.evidence_id, record_range, None, None))
            continue
        if not isinstance(item, Mapping):
            continue
        evidence_id = _lookup(
            item,
            "evidence_id",
            "evidence",
            "log",
            "file",
            "attachment",
            default=default_evidence,
        )
        if evidence_id is not None:
            evidence_id = str(evidence_id)
        if isinstance(evidence_id, str) and ("/" in evidence_id or "\\" in evidence_id):
            evidence_id = _basename(evidence_id)
        scope_all = _scope_is_all(item) or _scope_is_all(
            _lookup(item, "scope", "ranges", "record_ranges", "records")
        )
        summary_only = _is_summary_only(item)
        ranges = parse_ranges(
            _lookup(item, "ranges", "record_ranges", "records", "scope"),
            evidence_id,
            default_evidence,
        )
        if not ranges:
            ranges = parse_ranges(item, evidence_id, default_evidence)
        receipt_id = _lookup(
            item,
            "receipt_id",
            "receipt",
            "handover_id",
            "acceptance_id",
            "receipt_ref",
        )
        receipt_id = str(receipt_id) if receipt_id is not None else None
        digest = _lookup(item, "sha256", "digest", "hash", "record_sha256", "range_sha256")
        if digest is not None:
            digest = str(digest)
        if isinstance(digest, str) and digest.lower().startswith("sha256:"):
            digest = digest.split(":", 1)[1]
        if not ranges:
            result.append(
                ManifestEntry(evidence_id, None, receipt_id, digest, dict(item), scope_all, summary_only)
            )
            continue
        for record_range in ranges:
            result.append(
                ManifestEntry(
                    record_range.evidence_id or evidence_id,
                    record_range,
                    receipt_id,
                    digest,
                    dict(item),
                    scope_all,
                    summary_only,
                )
            )
    return result


@dataclass
class Permission:
    access: str
    evidence_id: Optional[str] = None
    record_range: Optional[RecordRange] = None
    sensitivity: Optional[str] = None
    principal_id: Optional[str] = None
    effect: str = "allow"
    valid_from: Optional[_datetime.datetime] = None
    valid_to: Optional[_datetime.datetime] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "access": self.access,
            "evidence_id": self.evidence_id,
            "sensitivity": self.sensitivity,
            "principal_id": self.principal_id,
            "effect": self.effect,
            "valid_from": format_time(self.valid_from),
            "valid_to": format_time(self.valid_to),
        }
        if self.record_range is not None:
            result.update(self.record_range.to_dict())
        return result


def _normalize_access(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {
        "full",
        "full_access",
        "raw",
        "review",
        "read",
        "reviewable",
        "continue_review",
        "完整",
        "复查",
        "可复查",
    }:
        return "full"
    if text in {
        "summary",
        "digest",
        "hash",
        "redacted",
        "page_summary",
        "summary_only",
        "digest_only",
        "metadata",
        "metadata_only",
        "abstract",
        "摘要",
        "仅摘要",
    }:
        return "summary"
    if text in {"none", "deny", "denied", "blocked", "no_access", "不可", "无权限"}:
        return "none"
    return "none"


def _is_summary_only(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if _as_bool(
        _lookup(
            value,
            "summary_only",
            "digest_only",
            "only_summary",
            "metadata_only",
            "redacted",
            default=False,
        )
    ):
        return True
    mode = str(
        _lookup(value, "availability", "retention", "available", "content", "retained", default="")
        or ""
    ).strip().lower()
    return mode in {"summary", "digest", "hash", "metadata", "redacted", "摘要", "仅摘要"}


def _parse_permissions(value: Any, default_evidence: Optional[str] = None) -> List[Permission]:
    if value is None:
        return []
    if isinstance(value, str):
        return [Permission(_normalize_access(value), default_evidence)]
    if isinstance(value, Mapping):
        nested = _lookup(value, "permissions", "grants", "rights", "access")
        if nested is not None and nested is not value and not isinstance(nested, str):
            return _parse_permissions(nested, default_evidence)
        permission_keys = {
            _norm_key(key)
            for key in ("access", "permission", "level", "mode", "view", "scope", "ranges", "record_ranges")
        }
        if _norm_key(next(iter(value), "")) not in permission_keys and value:
            if all(isinstance(item, Mapping) for item in value.values()):
                items = []
                for principal_id, row in value.items():
                    row = dict(row)
                    row.setdefault("principal_id", principal_id)
                    items.append(row)
            elif all(isinstance(item, str) for item in value.values()):
                items = [
                    {"evidence_id": evidence_id, "access": access}
                    for evidence_id, access in value.items()
                ]
            else:
                items = [value]
        else:
            items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return []

    result: List[Permission] = []
    for item in items:
        if isinstance(item, str):
            result.append(Permission(_normalize_access(item), default_evidence))
            continue
        if not isinstance(item, Mapping):
            continue
        access_value = _lookup(
            item,
            "access",
            "permission",
            "level",
            "mode",
            "view",
            default="none",
        )
        effect = str(_lookup(item, "effect", "decision", default="allow")).strip().lower()
        if effect in {"deny", "denied", "block", "blocked", "禁止"}:
            effect = "deny"
        else:
            effect = "allow"
        evidence_id = _lookup(
            item,
            "evidence_id",
            "evidence",
            "log",
            "file",
            "attachment",
            default=default_evidence,
        )
        if evidence_id is not None:
            evidence_id = str(evidence_id)
        if isinstance(evidence_id, str) and ("/" in evidence_id or "\\" in evidence_id):
            evidence_id = _basename(evidence_id)
        principal_id = _principal_from(
            _lookup(
                item,
                "principal_id",
                "custodian_id",
                "custodian",
                "principal",
                "user_id",
                "holder",
            )
        )
        sensitivity = _lookup(item, "sensitivity", "classification", "category")
        valid_from = parse_time(_lookup(item, "valid_from", "from", "starts_at", "effective_from"))
        valid_to = parse_time(_lookup(item, "valid_to", "to", "ends_at", "effective_to"))
        nested_ranges = _lookup(item, "ranges", "record_ranges", "records", "scope")
        ranges = parse_ranges(nested_ranges, evidence_id, default_evidence)
        if not ranges:
            ranges = parse_ranges(item, evidence_id, default_evidence)
        if not ranges:
            result.append(
                Permission(
                    _normalize_access(access_value),
                    evidence_id,
                    None,
                    sensitivity,
                    principal_id,
                    effect,
                    valid_from,
                    valid_to,
                    dict(item),
                )
            )
            continue
        for record_range in ranges:
            result.append(
                Permission(
                    _normalize_access(access_value),
                    record_range.evidence_id or evidence_id,
                    record_range,
                    sensitivity,
                    principal_id,
                    effect,
                    valid_from,
                    valid_to,
                    dict(item),
                )
            )
    return result


@dataclass
class PermissionDecision:
    access: str
    reason: str
    permission: Optional[Permission] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access": self.access,
            "reason": self.reason,
            "permission": self.permission.to_dict() if self.permission else None,
        }


def _permission_matches(
    permission: Permission,
    custodian_id: Optional[str],
    record_range: RecordRange,
    sensitivity: Optional[str],
    at_time: Optional[_datetime.datetime],
) -> bool:
    if permission.principal_id and custodian_id and permission.principal_id != custodian_id:
        return False
    if permission.evidence_id and record_range.evidence_id and permission.evidence_id != record_range.evidence_id:
        return False
    if permission.record_range is not None and not permission.record_range.contains(record_range):
        return False
    if permission.sensitivity and sensitivity and permission.sensitivity != sensitivity:
        return False
    if at_time is not None:
        if permission.valid_from is not None and at_time < permission.valid_from:
            return False
        if permission.valid_to is not None and at_time > permission.valid_to:
            return False
    return True


def resolve_permission(
    permissions: Sequence[Permission],
    custodian_id: Optional[str],
    record_range: RecordRange,
    sensitivity: Optional[str],
    at_time: Optional[_datetime.datetime],
) -> PermissionDecision:
    matches = [
        permission
        for permission in permissions
        if _permission_matches(permission, custodian_id, record_range, sensitivity, at_time)
    ]
    if not matches:
        return PermissionDecision("none", "no_matching_permission")
    denied = [permission for permission in matches if permission.effect == "deny"]
    if denied:
        return PermissionDecision("none", "permission_denied", denied[-1])
    best = max(matches, key=lambda permission: _ACCESS_RANK.get(permission.access, 0))
    if best.access == "none":
        return PermissionDecision("none", "permission_denied", best)
    return PermissionDecision(best.access, "matched_permission", best)


def _normalize_receipt_kind(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "shift" in text or "换岗" in text or "rotation" in text:
        return "shift_change"
    if "supp" in text or "补" in text or "amend" in text or "cure" in text:
        return "supplemental"
    if any(
        word in text
        for word in ("possession", "retain", "retained", "copy", "holding", "持有", "副本")
    ):
        return "possession"
    return "handover"


def _normalize_receipt_status(value: Any, signed_at: Optional[_datetime.datetime]) -> str:
    text = str(value or "").strip().lower()
    if text in {
        "revoked",
        "void",
        "cancelled",
        "canceled",
        "withdrawn",
        "expired",
        "inactive",
        "撤销",
        "作废",
    }:
        return "revoked"
    if text in {"draft", "pending", "unsigned", "unsealed", "未签", "待签"}:
        return "unsigned"
    if text in {"signed", "accepted", "sealed", "已签", "已接收"}:
        return "signed"
    if text:
        return text
    return "signed" if signed_at is not None else "unsigned"


def _principal_from(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, Mapping):
        result = _lookup(value, "id", "principal_id", "signer_id", "user_id", "employee_id", "name")
        return str(result) if result is not None else None
    return str(value)


def _name_from(value: Any) -> Optional[str]:
    if isinstance(value, Mapping):
        return _lookup(value, "actual_name", "name", "display_name", "signer_name", "person")
    return None


@dataclass
class Receipt:
    receipt_id: str
    kind: str
    signer_id: Optional[str] = None
    signed_at: Optional[_datetime.datetime] = None
    scope: List[RecordRange] = field(default_factory=list)
    scope_all: bool = False
    status: str = "unsigned"
    amends: List[str] = field(default_factory=list)
    supersedes: List[str] = field(default_factory=list)
    from_principal: Optional[str] = None
    to_principal: Optional[str] = None
    accepted_by: Optional[str] = None
    event_at: Optional[_datetime.datetime] = None
    declared_name: Optional[str] = None
    raw_signed_at: Any = None
    signatures: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def covers(self, record_range: RecordRange, receipts_by_id: Optional[Mapping[str, "Receipt"]] = None) -> bool:
        if self.scope_all:
            if not record_range.evidence_id:
                return True
            return any(item.evidence_id in (None, record_range.evidence_id) for item in self.scope) or not self.scope
        if any(item.contains(record_range) for item in self.scope):
            return True
        if not self.scope and self.amends and receipts_by_id:
            for base_id in self.amends:
                base = receipts_by_id.get(base_id)
                if base is not None and base.covers(record_range, receipts_by_id):
                    return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "kind": self.kind,
            "signer_id": self.signer_id,
            "signed_at": format_time(self.signed_at),
            "status": self.status,
            "scope": [item.to_dict() for item in self.scope],
            "scope_all": self.scope_all,
            "amends": list(self.amends),
            "supersedes": list(self.supersedes),
            "from_principal": self.from_principal,
            "to_principal": self.to_principal,
            "accepted_by": self.accepted_by,
            "event_at": format_time(self.event_at),
            "declared_name": self.declared_name,
        }


def _extract_signatures(item: Mapping[str, Any]) -> List[Dict[str, Any]]:
    signatures = _lookup(item, "signatures", "signers", "seals", "signature", "acceptance")
    result: List[Dict[str, Any]] = []
    for signature in _as_list(signatures):
        if isinstance(signature, Mapping):
            result.append(
                {
                    "role": str(_lookup(signature, "role", "party", "side", default="")).strip().lower(),
                    "signer_id": _principal_from(
                        _lookup(signature, "signer_id", "signer", "principal_id", "accepted_by", "by")
                    ),
                    "signed_at": parse_time(
                        _lookup(signature, "signed_at", "sign_time", "accepted_at", "time")
                    ),
                    "name": _name_from(
                        _lookup(signature, "signer", "name", "actual_name", "signed_by")
                    )
                    or _lookup(signature, "name", "actual_name", "signer_name"),
                }
            )
    return result


def _parse_receipts(
    value: Any,
    default_evidence: Optional[str] = None,
    fallback_signed_at: Optional[_datetime.datetime] = None,
) -> List[Receipt]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        if any(
            _norm_key(key) in {_norm_key(name) for name in ("receipt_id", "id", "ref", "kind", "type")}
            for key in value
        ):
            items: List[Any] = [value]
        else:
            nested = _lookup(value, "receipts", "items", "handovers", "chain")
            if nested is not None and nested is not value:
                return _parse_receipts(nested, default_evidence, fallback_signed_at)
            items = []
            for receipt_id, row in value.items():
                if isinstance(row, Mapping):
                    row = dict(row)
                    row.setdefault("receipt_id", receipt_id)
                    items.append(row)
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return []

    result: List[Receipt] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            continue
        receipt_id = _lookup(item, "receipt_id", "id", "ref", "acceptance_id", "handover_id")
        if receipt_id is None:
            receipt_id = "receipt-{}".format(index + 1)
        receipt_id = str(receipt_id)
        kind = _normalize_receipt_kind(_lookup(item, "kind", "type", "event", default="handover"))
        signatures = _extract_signatures(item)
        accepted_signature = next(
            (
                signature
                for signature in signatures
                if signature.get("role") in {"to", "recipient", "acceptor", "receiver", "custodian", "承接"}
            ),
            None,
        )
        transferor_signature = next(
            (
                signature
                for signature in signatures
                if signature.get("role") in {"from", "transferor", "sender", "giver", "移交"}
            ),
            None,
        )
        signer_value = _lookup(item, "signer_id", "signer", "signed_by", "accepted_by", "principal_id")
        signature_block = _lookup(item, "signature", "acceptance")
        if signer_value is None and isinstance(signature_block, Mapping):
            signer_value = _lookup(
                signature_block,
                "signer_id",
                "signer",
                "signed_by",
                "accepted_by",
                "principal_id",
            )
        declared_name = _name_from(signer_value) or _lookup(
            item, "signer_name", "signed_by_name", "actual_name"
        )
        if declared_name is None and isinstance(signature_block, Mapping):
            declared_name = _name_from(_lookup(signature_block, "signer", "name", "actual_name")) or _lookup(
                signature_block, "signer_name", "signed_by_name", "actual_name"
            )
        if isinstance(signer_value, Mapping):
            signer_id = _principal_from(signer_value)
        elif signer_value is not None:
            signer_id = str(signer_value)
        elif accepted_signature is not None:
            signer_id = accepted_signature.get("signer_id")
        else:
            signer_id = None
        signed_at = parse_time(
            _lookup(
                item,
                "signed_at",
                "sign_time",
                "signing_time",
                "signature_time",
                "accepted_at",
                "receipt_time",
            )
        )
        if signed_at is None and isinstance(signature_block, Mapping):
            signed_at = parse_time(
                _lookup(signature_block, "signed_at", "sign_time", "accepted_at", "time")
            )
        if signed_at is None and accepted_signature is not None:
            signed_at = accepted_signature.get("signed_at")
        explicit_status_value = _lookup(item, "status", "state")
        if signed_at is None and fallback_signed_at is not None:
            status_hint = _normalize_receipt_status(explicit_status_value, None)
            if explicit_status_value is None or status_hint not in {"unsigned", "revoked"}:
                signed_at = fallback_signed_at
        raw_signed_at = _lookup(
            item,
            "signed_at",
            "sign_time",
            "signing_time",
            "signature_time",
            "accepted_at",
            "receipt_time",
        )
        status = _normalize_receipt_status(_lookup(item, "status", "state"), signed_at)
        if signature_has_unsigned_transferor(signatures, transferor_signature) and accepted_signature is None:
            status = "unsigned"
        from_principal = _principal_from(
            _lookup(item, "from_principal", "from", "transferor", "sender", "previous_holder")
        )
        to_principal = _principal_from(
            _lookup(item, "to_principal", "to", "recipient", "receiver", "custodian", "new_holder")
        )
        accepted_by = _principal_from(_lookup(item, "accepted_by", "acceptor", "received_by"))
        if accepted_by is None and accepted_signature is not None:
            accepted_by = accepted_signature.get("signer_id")
        if accepted_by is not None:
            signer_id = accepted_by
            if accepted_signature is not None and accepted_signature.get("signed_at") is not None:
                signed_at = accepted_signature.get("signed_at")
                status = "signed" if status != "revoked" else status
            if accepted_signature is not None and accepted_signature.get("name"):
                declared_name = accepted_signature.get("name")
            if signed_at is None and fallback_signed_at is not None:
                signed_at = fallback_signed_at
                status = "signed" if status != "revoked" else status
        if signer_id is None and to_principal is not None:
            signer_id = to_principal
            if signed_at is None and fallback_signed_at is not None:
                signed_at = fallback_signed_at
            if signed_at is not None and status == "unsigned":
                status = "signed"
        scope_value = _lookup(item, "scope", "ranges", "record_ranges", "records", "covered_records")
        scope_all = _scope_is_all(item) or _scope_is_all(scope_value)
        scope = parse_ranges(scope_value, None, default_evidence)
        if not scope and not scope_all:
            scope = parse_ranges(item, None, default_evidence)
        amends = [
            str(value)
            for value in _as_list(_lookup(item, "amends", "amends_receipt", "corrects", "parent_receipt", "cures"))
            if value is not None
        ]
        supersedes = [
            str(value)
            for value in _as_list(_lookup(item, "supersedes", "replaces", "superseded_receipts"))
            if value is not None
        ]
        event_at = parse_time(
            _lookup(item, "event_at", "handover_at", "occurred_at", "effective_at", "transfer_at")
        )
        result.append(
            Receipt(
                receipt_id=receipt_id,
                kind=kind,
                signer_id=signer_id,
                signed_at=signed_at,
                scope=sum(([record_range] for record_range in scope), []),
                scope_all=scope_all,
                status=status,
                amends=amends,
                supersedes=supersedes,
                from_principal=from_principal,
                to_principal=to_principal,
                accepted_by=accepted_by,
                event_at=event_at,
                declared_name=declared_name,
                raw_signed_at=raw_signed_at,
                signatures=signatures,
                raw=dict(item),
            )
        )
    return result


def signature_has_unsigned_transferor(
    signatures: Sequence[Mapping[str, Any]],
    transferor_signature: Optional[Mapping[str, Any]],
) -> bool:
    if not signatures or transferor_signature is None:
        return False
    return transferor_signature.get("signed_at") is None and len(signatures) == 1


@dataclass
class ResponsibilityRow:
    receipt_id: Optional[str] = None
    principal_id: Optional[str] = None
    actual_name: Optional[str] = None
    role: Optional[str] = None
    authorized_from: Optional[_datetime.datetime] = None
    authorized_to: Optional[_datetime.datetime] = None
    scope: List[RecordRange] = field(default_factory=list)
    scope_all: bool = False
    status: str = "active"
    raw: Dict[str, Any] = field(default_factory=dict)

    def covers(self, record_range: RecordRange) -> bool:
        if self.scope_all or not self.scope:
            return True
        return any(item.contains(record_range) for item in self.scope)

    def active_at(self, at_time: Optional[_datetime.datetime]) -> bool:
        if self.status in {"revoked", "inactive", "expired", "撤销", "失效"}:
            return False
        if at_time is None:
            return True
        if self.authorized_from is not None and at_time < self.authorized_from:
            return False
        if self.authorized_to is not None and at_time > self.authorized_to:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "principal_id": self.principal_id,
            "actual_name": self.actual_name,
            "role": self.role,
            "authorized_from": format_time(self.authorized_from),
            "authorized_to": format_time(self.authorized_to),
            "scope": [item.to_dict() for item in self.scope],
            "scope_all": self.scope_all,
            "status": self.status,
        }


class ResponsibilityTable:
    def __init__(self, rows: Optional[Sequence[ResponsibilityRow]] = None, provided: bool = False):
        self.rows = list(rows or [])
        self.provided = provided

    def resolve(self, receipt: Receipt) -> Tuple[Optional[ResponsibilityRow], bool]:
        candidates = [
            row
            for row in self.rows
            if row.receipt_id and row.receipt_id == receipt.receipt_id
        ]
        if not candidates:
            principal_ids = {
                value
                for value in (receipt.signer_id, receipt.accepted_by, receipt.to_principal)
                if value
            }
            declared_names = {
                value
                for value in (
                    receipt.declared_name,
                    receipt.signer_id,
                    receipt.accepted_by,
                    receipt.to_principal,
                )
                if value
            }
            candidates = [
                row
                for row in self.rows
                if row.principal_id in principal_ids or row.actual_name in declared_names
            ]
        if not candidates:
            return None, False
        timed = [row for row in candidates if row.active_at(receipt.signed_at)]
        if timed:
            return timed[-1], True
        return candidates[-1], True


@dataclass
class SignerInfo:
    principal_id: Optional[str]
    actual_name: Optional[str]
    role: Optional[str]
    verified: bool
    declared_name: Optional[str] = None
    source: str = "receipt"
    reason: Optional[str] = None

    def to_dict(self, *, include_name: bool = True) -> Dict[str, Any]:
        result = {
            "principal_id": self.principal_id,
            "role": self.role,
            "verified": self.verified,
            "source": self.source,
            "reason": self.reason,
        }
        if include_name:
            result["actual_name"] = self.actual_name
            result["declared_name"] = self.declared_name
        return result


def _parse_responsibility(value: Any, default_evidence: Optional[str] = None) -> ResponsibilityTable:
    if value is None:
        return ResponsibilityTable([], provided=False)
    items: List[Any]
    if isinstance(value, Mapping):
        collected: List[Any] = []
        for key in ("signers", "receipt_signers", "responsibility", "rows", "assignments", "roles", "people"):
            candidate = _lookup(value, key)
            if candidate is not None and candidate is not value:
                collected.extend(_as_list(candidate))
        if collected:
            items = collected
        elif any(
            _norm_key(key)
            in {_norm_key(name) for name in ("receipt_id", "principal_id", "signer_id", "actual_name", "name")}
            for key in value
        ):
            items = [value]
        else:
            items = []
            for receipt_id, row in value.items():
                if isinstance(row, Mapping):
                    row = dict(row)
                    row.setdefault("receipt_id", receipt_id)
                    row.setdefault("principal_id", receipt_id)
                    items.append(row)
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return ResponsibilityTable([], provided=False)

    rows: List[ResponsibilityRow] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        receipt_id = _lookup(item, "receipt_id", "receipt", "acceptance_id", "handover_id")
        principal_id = _principal_from(
            _lookup(item, "principal_id", "signer_id", "user_id", "employee_id", "person", "id")
        )
        actual_name = _lookup(
            item,
            "actual_name",
            "actual_signer",
            "real_name",
            "name",
            "signer_name",
            "signed_by_name",
            "display_name",
            "person_name",
            "person",
        )
        if isinstance(actual_name, Mapping):
            actual_name = _name_from(actual_name)
        role = _lookup(item, "role", "title", "duty", "position")
        scope_value = _lookup(item, "scope", "ranges", "record_ranges", "records")
        scope_all = _scope_is_all(item) or _scope_is_all(scope_value)
        scope = parse_ranges(scope_value, None, default_evidence)
        if not scope and not scope_all:
            scope = parse_ranges(item, None, default_evidence)
        rows.append(
            ResponsibilityRow(
                receipt_id=str(receipt_id) if receipt_id is not None else None,
                principal_id=str(principal_id) if principal_id is not None else None,
                actual_name=str(actual_name) if actual_name is not None else None,
                role=str(role) if role is not None else None,
                authorized_from=parse_time(
                    _lookup(item, "authorized_from", "valid_from", "starts_at", "from", "effective_from")
                ),
                authorized_to=parse_time(
                    _lookup(item, "authorized_to", "valid_to", "ends_at", "to", "effective_to")
                ),
                scope=scope,
                scope_all=scope_all,
                status=str(_lookup(item, "status", "state", default="active")).strip().lower(),
                raw=dict(item),
            )
        )
    return ResponsibilityTable(rows, provided=bool(rows))


@dataclass
class ReceiptEvaluation:
    receipt: Receipt
    valid: bool
    reason: str
    signer: SignerInfo
    signed_at: Optional[_datetime.datetime]
    effective_at: Optional[_datetime.datetime]
    base_receipt_id: Optional[str] = None
    checks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt.receipt_id,
            "kind": self.receipt.kind,
            "valid": self.valid,
            "reason": self.reason,
            "signed_at": format_time(self.signed_at),
            "effective_at": format_time(self.effective_at),
            "base_receipt_id": self.base_receipt_id,
            "signer": self.signer.to_dict(),
            "checks": list(self.checks),
        }


def _evaluate_receipt(
    receipt: Receipt,
    receipts_by_id: Mapping[str, Receipt],
    responsibility: ResponsibilityTable,
    deadline: Optional[_datetime.datetime],
    require_responsibility: bool = False,
) -> ReceiptEvaluation:
    checks: List[str] = []
    row, table_found = responsibility.resolve(receipt)
    signer = SignerInfo(
        principal_id=receipt.signer_id,
        actual_name=receipt.declared_name,
        role=None,
        verified=False,
        declared_name=receipt.declared_name,
        source="receipt",
        reason=None,
    )
    if responsibility.provided:
        if row is None:
            signer.reason = "signer_not_in_responsibility_table"
        else:
            signer.principal_id = row.principal_id or signer.principal_id
            signer.actual_name = row.actual_name or signer.actual_name
            signer.role = row.role
            signer.source = "internal_responsibility"
            signer.verified = row.active_at(receipt.signed_at)
            if not signer.verified:
                if row.status in {"revoked", "inactive", "expired", "撤销", "失效"}:
                    signer.reason = "signer_revoked"
                else:
                    signer.reason = "signer_not_authorized_at_sign_time"

    def invalid(reason: str) -> ReceiptEvaluation:
        return ReceiptEvaluation(
            receipt=receipt,
            valid=False,
            reason=reason,
            signer=signer,
            signed_at=receipt.signed_at,
            effective_at=None,
            checks=checks,
        )

    if receipt.kind == "possession":
        checks.append("prior_holder_possession_not_transfer")
        return invalid("prior_holder_possession_not_transfer")
    if receipt.status in {
        "revoked",
        "void",
        "cancelled",
        "canceled",
        "withdrawn",
        "expired",
        "inactive",
    }:
        checks.append("receipt_revoked")
        return invalid("receipt_revoked")
    if receipt.status == "unsigned" or receipt.signed_at is None:
        checks.append("receipt_unsigned")
        if receipt.raw_signed_at not in (None, "") and receipt.signed_at is None:
            return invalid("invalid_signed_at")
        return invalid("receipt_unsigned")
    checks.append("signed_at_present")
    if deadline is not None and receipt.signed_at > deadline:
        checks.append("signed_after_deadline")
        return invalid("signed_after_deadline")
    if receipt.signer_id is None and receipt.accepted_by is None and receipt.to_principal is None:
        checks.append("missing_signer")
        return invalid("missing_signer")
    if (
        receipt.kind in {"handover", "shift_change"}
        and receipt.from_principal
        and receipt.to_principal
        and receipt.signer_id == receipt.from_principal
        and receipt.signer_id != receipt.to_principal
        and receipt.accepted_by is None
    ):
        checks.append("transferor_signature_only")
        return invalid("transferor_signature_only")
    if responsibility.provided:
        if row is None:
            checks.append("signer_not_in_responsibility_table")
            return invalid("signer_not_in_responsibility_table")
        if not signer.verified:
            reason = signer.reason or "signer_not_authorized_at_sign_time"
            checks.append(reason)
            return invalid(reason)
    elif require_responsibility:
        checks.append("signer_not_in_responsibility_table")
        return invalid("signer_not_in_responsibility_table")
    else:
        checks.append("internal_responsibility_table_not_supplied")

    effective_at = receipt.signed_at
    base_id: Optional[str] = None
    if receipt.kind == "supplemental":
        if not receipt.amends:
            checks.append("missing_amended_receipt")
            return invalid("missing_amended_receipt")
        base = receipts_by_id.get(receipt.amends[0])
        if base is None:
            checks.append("missing_amended_receipt")
            return invalid("missing_amended_receipt")
        if base.status in {
            "revoked",
            "void",
            "cancelled",
            "canceled",
            "withdrawn",
            "expired",
            "inactive",
        }:
            checks.append("amended_receipt_revoked")
            return invalid("amended_receipt_revoked")
        base_id = base.receipt_id
        effective_at = base.signed_at or base.event_at or receipt.signed_at
        checks.append("supplemental_amends:{}".format(base.receipt_id))

    checks.append("receipt_valid")
    return ReceiptEvaluation(
        receipt=receipt,
        valid=True,
        reason="receipt_valid",
        signer=signer,
        signed_at=receipt.signed_at,
        effective_at=effective_at,
        base_receipt_id=base_id,
        checks=checks,
    )


@dataclass
class GoverningReceipt:
    evaluation: ReceiptEvaluation
    chain: List[ReceiptEvaluation] = field(default_factory=list)

    @property
    def receipt(self) -> Receipt:
        return self.evaluation.receipt

    def contains_receipt(self, receipt_id: Optional[str]) -> bool:
        if not receipt_id:
            return True
        return any(item.receipt.receipt_id == receipt_id for item in self.chain)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt.receipt_id,
            "kind": self.receipt.kind,
            "signed_at": format_time(self.evaluation.signed_at),
            "effective_at": format_time(self.evaluation.effective_at),
            "base_receipt_id": self.evaluation.base_receipt_id,
            "signer": self.evaluation.signer.to_dict(),
            "chain": [item.to_dict() for item in self.chain],
        }


def _select_governing(
    record_range: RecordRange,
    receipts: Sequence[Receipt],
    receipts_by_id: Mapping[str, Receipt],
    evaluations: Mapping[str, ReceiptEvaluation],
    *,
    manifest_receipt_id: Optional[str] = None,
    authorize: Optional[Any] = None,
) -> Tuple[Optional[GoverningReceipt], str]:
    superseded = {
        receipt_id
        for receipt in receipts
        if evaluations.get(receipt.receipt_id) and evaluations[receipt.receipt_id].valid
        for receipt_id in receipt.supersedes
    }
    candidates: List[ReceiptEvaluation] = []
    for receipt in receipts:
        if receipt.receipt_id in superseded:
            continue
        evaluation = evaluations.get(receipt.receipt_id)
        if evaluation is None or not evaluation.valid:
            continue
        if not receipt.covers(record_range, receipts_by_id):
            continue
        if authorize is not None:
            allowed, _ = authorize(receipt, record_range)
            if not allowed:
                continue
        candidates.append(evaluation)

    precedence = {"handover": 1, "shift_change": 2, "supplemental": 3}
    candidates.sort(
        key=lambda item: (
            item.signed_at or _datetime.datetime.min.replace(tzinfo=UTC),
            precedence.get(item.receipt.kind, 0),
        )
    )
    if candidates:
        chosen = candidates[-1]
        chain = [chosen]
        current = chosen
        seen_chain = {chosen.receipt.receipt_id}
        while current.base_receipt_id:
            base_evaluation = evaluations.get(current.base_receipt_id)
            if base_evaluation is None or base_evaluation.receipt.receipt_id in seen_chain:
                break
            chain.insert(0, base_evaluation)
            seen_chain.add(base_evaluation.receipt.receipt_id)
            current = base_evaluation
        return GoverningReceipt(chosen, chain), "receipt_valid"

    relevant: List[ReceiptEvaluation] = []
    for receipt in receipts:
        evaluation = evaluations.get(receipt.receipt_id)
        if evaluation is None:
            continue
        if not receipt.covers(record_range, receipts_by_id):
            continue
        relevant.append(evaluation)
    if manifest_receipt_id:
        for evaluation in relevant:
            if evaluation.receipt.receipt_id == manifest_receipt_id:
                if authorize is not None:
                    allowed, reason = authorize(evaluation.receipt, record_range)
                    if not allowed:
                        return None, reason or evaluation.reason
                return None, evaluation.reason
    if relevant:
        relevant.sort(
            key=lambda item: item.signed_at or _datetime.datetime.min.replace(tzinfo=UTC)
        )
        authorization_reason: Optional[str] = None
        for evaluation in reversed(relevant):
            if authorize is not None:
                allowed, reason = authorize(evaluation.receipt, record_range)
                if allowed:
                    return None, evaluation.reason
                authorization_reason = authorization_reason or reason
            else:
                return None, evaluation.reason
        if authorization_reason:
            return None, authorization_reason
    return None, "no_receipt"


_SENSITIVE_KEYS = {
    "name",
    "actualname",
    "signername",
    "declaredname",
    "employeeid",
    "person",
    "subject",
    "suspect",
    "hostname",
    "host",
    "computer",
    "path",
    "fullpath",
    "user",
    "username",
    "account",
    "sid",
    "ip",
    "address",
    "email",
    "phone",
    "message",
    "summary",
    "summarytext",
    "description",
    "notes",
    "note",
    "eventxml",
    "xml",
    "raw",
    "content",
    "payload",
    "recorddata",
    "password",
    "secret",
    "token",
    "credential",
}

_SAFE_EXTERNAL_KEYS = {
    "caseid",
    "generatedat",
    "archivedeadline",
    "offline",
    "custodian",
    "custodianid",
    "custodianrole",
    "handoverscope",
    "scope",
    "scopecheck",
    "status",
    "statuszh",
    "reason",
    "reasoncode",
    "reasonzh",
    "counts",
    "reviewablerecords",
    "summaryonlyrecords",
    "notacceptedrecords",
    "reviewablesegments",
    "summaryonlysegments",
    "notacceptedsegments",
    "totalrecords",
    "totalrangerecords",
    "manifest",
    "allscope",
    "manifestentries",
    "matched",
    "manifestwithoutreceipt",
    "receiptwithoutmanifest",
    "scopematches",
    "actualsigner",
    "role",
    "receiptid",
    "verified",
    "sensitivefieldsomitted",
    "sourcedigests",
    "omittedsensitivefieldcount",
    "evidenceid",
    "filename",
    "start",
    "end",
    "recordstart",
    "recordend",
    "recordcount",
    "sha256",
    "digest",
    "digestverified",
    "manifestdigestverified",
    "signedat",
    "handoverid",
    "items",
    "entries",
}


def sanitize_external(value: Any, _counter: Optional[List[int]] = None) -> Any:
    """Return a copy containing only fields safe for an external manifest."""

    counter = _counter if _counter is not None else [0]
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            normalized = _norm_key(key)
            if normalized in _SENSITIVE_KEYS:
                counter[0] += 1
                continue
            if normalized not in _SAFE_EXTERNAL_KEYS:
                counter[0] += 1
                continue
            if normalized == "path" and isinstance(item, str):
                result[key] = _basename(item)
            else:
                result[key] = sanitize_external(item, counter)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize_external(item, counter) for item in value]
    return value


class CustodyReport(dict):
    """Dictionary report with convenience serializers and attribute access."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def to_dict(self) -> Dict[str, Any]:
        return dict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self, indent=indent, ensure_ascii=False, sort_keys=False)

    def external_dict(self) -> Dict[str, Any]:
        summary = self.get("summary") or {}
        signers = self.get("signer_verification") or {}
        primary = signers.get("actual_signer") or {}
        custodian = self.get("custodian") or {}
        external = {
            "case_id": self.get("case_id"),
            "generated_at": self.get("generated_at"),
            "offline": True,
            "status": self.get("status"),
            "status_zh": self.get("status_zh"),
            "archive_deadline": self.get("archive_deadline"),
            "custodian": {
                "role": custodian.get("role"),
            },
            "handover_scope": [],
            "counts": {
                "reviewable_records": summary.get("reviewable_records", 0),
                "summary_only_records": summary.get("summary_only_records", 0),
                "not_accepted_records": summary.get("not_accepted_records", 0),
                "reviewable_segments": summary.get("reviewable_segments", 0),
                "summary_only_segments": summary.get("summary_only_segments", 0),
                "not_accepted_segments": summary.get("not_accepted_segments", 0),
                "total_records": summary.get("total_records", 0),
                "total_range_records": summary.get("total_range_records", 0),
            },
            "scope_check": (self.get("handover_scope") or {}).get("scope_check", {}),
            "manifest": [
                {
                    "evidence_id": entry.get("evidence_id"),
                    "start": entry.get("start"),
                    "end": entry.get("end"),
                    "record_count": entry.get("record_count"),
                    "receipt_id": entry.get("receipt_id"),
                    "sha256": entry.get("sha256"),
                    "all_scope": entry.get("all_scope"),
                }
                for entry in (self.get("handover_scope") or {}).get("manifest_entries", [])
            ],
            "source_digests": [
                {
                    "evidence_id": evidence.get("evidence_id"),
                    "sha256": evidence.get("source_sha256"),
                }
                for evidence in self.get("evidence", []) or []
            ],
            "actual_signer": {
                "receipt_id": primary.get("receipt_id"),
                "role": primary.get("role"),
                "verified": primary.get("verified", False),
            },
            "sensitive_fields_omitted": True,
            "omitted_sensitive_field_count": len(self.get("redacted_fields", [])),
        }
        seen = set()
        for evidence in self.get("evidence", []):
            for segment in evidence.get("segments", []):
                key = (
                    evidence.get("evidence_id"),
                    segment.get("start"),
                    segment.get("end"),
                    segment.get("status"),
                    segment.get("receipt_id"),
                )
                if key in seen:
                    continue
                seen.add(key)
                external["handover_scope"].append(
                    {
                        "evidence_id": evidence.get("evidence_id"),
                        "start": segment.get("start"),
                        "end": segment.get("end"),
                        "record_count": segment.get("record_count"),
                        "status": segment.get("status"),
                        "status_zh": segment.get("status_zh"),
                        "reason_code": segment.get("reason"),
                        "receipt_id": segment.get("receipt_id"),
                        "signed_at": segment.get("signed_at"),
                        "sha256": segment.get("digest"),
                        "digest_verified": segment.get("digest_verified"),
                        "manifest_digest_verified": segment.get("manifest_digest_verified"),
                    }
                )
        external = sanitize_external(external)
        return external

    def external_json(self, indent: int = 2) -> str:
        return json.dumps(self.external_dict(), indent=indent, ensure_ascii=False)

    def render_text(self) -> str:
        lines: List[str] = []
        lines.append("离线保管核对 {}（内部报告）".format(self.get("case_id") or ""))
        if self.get("archive_deadline"):
            lines.append("销档期限: {}".format(self.get("archive_deadline")))
        custodian = self.get("custodian") or {}
        if custodian:
            lines.append(
                "长期保管人: {}{}".format(
                    custodian.get("id") or "-",
                    " ({})".format(custodian.get("role")) if custodian.get("role") else "",
                )
            )
        lines.append("")
        for status in (REVIEWABLE, SUMMARY_ONLY, NOT_ACCEPTED):
            label = STATUS_LABELS_ZH[status]
            summary = self.get("summary") or {}
            records = summary.get("{}_records".format(status), 0)
            segments = summary.get("{}_segments".format(status), 0)
            lines.append("[{}] {} 段 / {} 条记录".format(label, segments, records))
            for evidence in self.get("evidence", []) or []:
                for segment in evidence.get("segments", []):
                    if segment.get("status") != status:
                        continue
                    reason = segment.get("reason_zh") or segment.get("reason") or ""
                    signer = segment.get("signer") or {}
                    signer_text = ""
                    if signer.get("actual_name") or signer.get("principal_id"):
                        signer_text = " signer={}{}".format(
                            signer.get("actual_name") or signer.get("principal_id"),
                            " [{}]".format(signer.get("role")) if signer.get("role") else "",
                        )
                    receipt_text = (
                        " receipt={}".format(segment.get("receipt_id"))
                        if segment.get("receipt_id")
                        else ""
                    )
                    lines.append(
                        "  {} {}-{} ({} 条){}{} {}".format(
                            evidence.get("evidence_id"),
                            segment.get("start"),
                            segment.get("end"),
                            segment.get("record_count"),
                            receipt_text,
                            signer_text,
                            reason,
                        )
                    )
            lines.append("")

        scope = (self.get("handover_scope") or {}).get("scope_check", {})
        lines.append("交接范围核对")
        lines.append(
            "  外部清单 {} 条; 范围一致: {}; 清单无有效签收: {}; 有效签收未列清单: {}".format(
                scope.get("manifest_entries", 0),
                "是" if scope.get("scope_matches") else "否",
                scope.get("manifest_without_receipt", 0),
                scope.get("receipt_without_manifest", 0),
            )
        )
        for item in (self.get("handover_scope") or {}).get("manifest_without_receipt", []):
            lines.append(
                "  清单无有效签收: {} {}-{} ({})".format(
                    item.get("evidence_id"),
                    item.get("start"),
                    item.get("end"),
                    item.get("reason_zh") or item.get("reason"),
                )
            )
        for item in (self.get("handover_scope") or {}).get("receipt_without_manifest", []):
            lines.append(
                "  有效签收未列清单: {} {}-{} ({})".format(
                    item.get("evidence_id"),
                    item.get("start"),
                    item.get("end"),
                    item.get("receipt_id") or "-",
                )
            )

        signers = self.get("signer_verification") or {}
        lines.append("")
        lines.append("责任签署核对")
        for item in signers.get("signers", []):
            lines.append(
                "  {} -> {}{} {}".format(
                    item.get("receipt_id"),
                    item.get("actual_name") or item.get("principal_id") or "?",
                    " ({})".format(item.get("role")) if item.get("role") else "",
                    "已核实" if item.get("verified") else "未核实",
                )
            )
        if not signers.get("signers"):
            lines.append("  没有形成有效承接的签收记录")
        if signers.get("prior_holder_possession_ignored"):
            lines.append("  上一位人员仍持有同一份副本，按规则不计为移交发生")
        warnings = self.get("warnings", [])
        if warnings:
            lines.append("")
            lines.append("提示")
            for warning in warnings:
                lines.append("  - {}".format(warning))
        return "\n".join(lines)

    def render_external_text(self) -> str:
        external = self.external_dict()
        lines = [
            "外部交接范围清单（不含敏感字段）",
            "案件: {}".format(external.get("case_id") or ""),
            "销档期限: {}".format(external.get("archive_deadline") or ""),
            "保管角色: {}".format(external.get("custodian", {}).get("role") or ""),
            "",
        ]
        for item in external.get("handover_scope", []):
            lines.append(
                "{} {}-{} {} 条 {} {}".format(
                    item.get("evidence_id"),
                    item.get("start"),
                    item.get("end"),
                    item.get("record_count"),
                    item.get("status_zh"),
                    item.get("sha256") or "",
                ).rstrip()
            )
        lines.append("")
        lines.append("敏感字段已从外部清单移除: 是")
        return "\n".join(lines)


def _merge_segment(segments: List[Dict[str, Any]], segment: Dict[str, Any]) -> None:
    if segments:
        previous = segments[-1]
        keys = (
            "status",
            "reason",
            "receipt_id",
            "access",
            "signed_at",
            "manifest_receipt_id",
            "digest",
            "digest_verified",
            "manifest_digest_verified",
            "sensitivity",
            "summary_only",
        )
        if previous.get("evidence_id") == segment.get("evidence_id") and previous.get("end", -1) + 1 == segment.get(
            "start"
        ):
            if all(previous.get(key) == segment.get(key) for key in keys):
                previous["end"] = segment["end"]
                previous["record_count"] += segment["record_count"]
                previous["records_present"] += segment["records_present"]
                previous["records_missing"] += segment["records_missing"]
                if segment.get("digest") and previous.get("digest"):
                    previous["digest"] = segment["digest"]
                return
    segments.append(segment)


class CustodyAudit:
    """Run the offline reconciliation over one case description."""

    def __init__(
        self,
        case: Mapping[str, Any],
        *,
        base_dir: Optional[str] = None,
        evidence: Any = None,
        ranges: Any = None,
        permissions: Any = None,
        receipts: Any = None,
        external_manifest: Any = None,
        responsibility: Any = None,
        custodian: Any = None,
        deadline: Any = None,
        as_of: Any = None,
        use_record_timestamps: bool = False,
        require_manifest: bool = True,
        require_responsibility: bool = False,
    ):
        self.case = dict(case)
        for section_key in ("custody", "handover", "audit"):
            section = _lookup(self.case, section_key)
            if isinstance(section, Mapping):
                for key, value in section.items():
                    self.case.setdefault(key, value)
        self.base_dir = base_dir or self.case.get("_base_dir")
        self.deadline = parse_deadline(
            deadline
            if deadline is not None
            else _lookup(
                self.case,
                "archive_deadline",
                "destruction_date",
                "retention_deadline",
                "retention_date",
                "handover_deadline",
                "destroy_at",
                "deadline",
            )
        )
        self.as_of = parse_time(
            as_of
            if as_of is not None
            else _lookup(self.case, "as_of", "audit_time", "now", default=None)
        ) or self.deadline
        self.use_record_timestamps = _as_bool(
            _lookup(self.case, "use_record_timestamps", "record_time_cutoff", default=False)
            if not use_record_timestamps
            else use_record_timestamps
        )
        self.require_manifest = require_manifest
        self.require_responsibility = require_responsibility
        case_require_manifest = _lookup(self.case, "require_manifest", "require_external_manifest")
        if case_require_manifest is not None:
            self.require_manifest = _as_bool(case_require_manifest, require_manifest)
        case_require_responsibility = _lookup(
            self.case, "require_responsibility", "require_internal_responsibility"
        )
        if case_require_responsibility is not None:
            self.require_responsibility = _as_bool(
                case_require_responsibility, require_responsibility
            )
        self.warnings: List[str] = []
        self.redacted_fields: List[str] = []

        custodian_value = custodian if custodian is not None else _lookup(
            self.case, "custodian", "long_term_custodian", "archive_owner"
        )
        if isinstance(custodian_value, str):
            self.custodian = {"id": custodian_value}
        elif isinstance(custodian_value, Mapping):
            self.custodian = dict(custodian_value)
        else:
            self.custodian = {}
        self.custodian_id = (
            _lookup(self.custodian, "id", "principal_id", "custodian_id", "name")
            or self.case.get("custodian_id")
        )
        if not self.custodian_id:
            self.custodian_id = _lookup(self.custodian, "name")
        if self.custodian_id is not None:
            self.custodian_id = str(self.custodian_id)
        self.custodian_role = _lookup(
            self.custodian, "role", "name", "title", "organization", "department"
        )
        if not self.custodian_role:
            self.custodian_role = _lookup(
                self.case, "custodian_role", "archive_role", "long_term_custodian_role"
            )

        permission_value = permissions if permissions is not None else _lookup(
            self.custodian, "permissions", "permission", "grants", "rights", "access"
        )
        if permission_value is None or permission_value == [] or permission_value == {}:
            permission_value = _lookup(
                self.case,
                "permissions",
                "permission",
                "custodian_permissions",
                "custody_permissions",
                "grants",
                "access",
            )
        self.permissions = _parse_permissions(permission_value)

        receipt_value = receipts if receipts is not None else _lookup(
            self.case,
            "receipts",
            "handover_receipts",
            "acceptance_receipts",
            "handover",
            "acceptance",
        )
        fallback_signed_at = parse_time(
            _lookup(self.case, "signed_at", "signing_time", "acceptance_time")
        )
        receipt_value = _resolve_document(receipt_value, self.base_dir)
        self.receipts = _parse_receipts(receipt_value, None, fallback_signed_at)
        for receipt in self.receipts:
            if (
                receipt.signed_at is not None
                and not receipt.signer_id
                and not receipt.accepted_by
            ):
                receipt.signer_id = receipt.to_principal or self.custodian_id
        self.receipts_by_id = {receipt.receipt_id: receipt for receipt in self.receipts}

        manifest_value = external_manifest if external_manifest is not None else _lookup(
            self.case,
            "external_manifest",
            "handover_manifest",
            "external_list",
            "external",
            "manifest",
        )
        manifest_value = _resolve_document(manifest_value, self.base_dir)
        self.manifest_entries = _parse_manifest(manifest_value)
        if isinstance(manifest_value, Mapping) and _lookup(manifest_value, "entries", "items", "scope"):
            manifest_raw = manifest_value
        else:
            manifest_raw = {"entries": manifest_value if isinstance(manifest_value, list) else []}
        self.manifest_raw = manifest_raw
        for key in _all_keys(manifest_raw):
            if _norm_key(key) in _SENSITIVE_KEYS:
                self.redacted_fields.append(str(key))

        responsibility_value = responsibility if responsibility is not None else _lookup(
            self.case,
            "responsibility",
            "internal_responsibility",
            "responsibility_table",
            "receipt_signers",
            "roles",
            "signers",
            "people",
        )
        responsibility_value = _resolve_document(responsibility_value, self.base_dir)
        self.responsibility = _parse_responsibility(responsibility_value)
        if self.require_responsibility and not self.responsibility.provided:
            self.warnings.append("internal responsibility table is required but missing")

        self.prior_holder = _lookup(
            self.case, "previous_holder", "prior_holder", "predecessor", default={}
        )
        if not isinstance(self.prior_holder, Mapping):
            self.prior_holder = {"id": self.prior_holder}
        self.prior_holder_still_holds = _as_bool(
            _lookup(
                self.prior_holder,
                "still_holds_copy",
                "holds_copy",
                "copy_retained",
                "still_has_copy",
                default=False,
            )
        )
        top_level_prior_flag = _lookup(
            self.case,
            "prior_holder_still_holds_copy",
            "previous_holder_has_copy",
            "prior_holder_has_copy",
        )
        if top_level_prior_flag is not None:
            self.prior_holder_still_holds = _as_bool(top_level_prior_flag)
        if not _lookup(self.prior_holder, "id", "principal_id", "holder", "user_id"):
            prior_id = _lookup(self.case, "prior_holder_id", "previous_holder_id")
            if prior_id is not None:
                self.prior_holder = dict(self.prior_holder)
                self.prior_holder["id"] = str(prior_id)

        evidence_value = evidence if evidence is not None else _lookup(
            self.case, "evidence", "logs", "attachments", "evtx", "sources"
        )
        default_evidence_id = str(
            _lookup(self.case, "evidence_id", "source_id", default="evidence") or "evidence"
        )
        if evidence_value is None and ranges is not None:
            range_keys = {
                "start",
                "end",
                "range",
                "record_range",
                "records",
                "ranges",
                "record_ranges",
                "scope",
                "record_numbers",
            }
            if isinstance(ranges, Mapping) and ranges and not any(
                _norm_key(key) in {_norm_key(item) for item in range_keys} for key in ranges
            ):
                evidence_value = [
                    {"evidence_id": str(evidence_id), "ranges": value}
                    for evidence_id, value in ranges.items()
                ]
            else:
                parsed_override = parse_ranges(ranges)
                grouped: Dict[str, List[RecordRange]] = {}
                for record_range in parsed_override:
                    grouped.setdefault(record_range.evidence_id or default_evidence_id, []).append(record_range)
                if grouped:
                    evidence_value = [
                        {"evidence_id": evidence_id, "ranges": values}
                        for evidence_id, values in grouped.items()
                    ]
                else:
                    evidence_value = [{"evidence_id": default_evidence_id, "ranges": ranges}]
        self.evidence_specs = self._normalize_evidence_specs(evidence_value, ranges)
        self.sources: List[SourceEvidence] = []
        for spec in self.evidence_specs:
            path = spec.get("path")
            if path and not os.path.isabs(path):
                candidate = os.path.join(self.base_dir or os.getcwd(), path)
                if os.path.exists(candidate) or not os.path.exists(path):
                    path = candidate
            source = load_source_evidence(
                spec["evidence_id"],
                path,
                spec.get("ranges"),
                spec.get("range_specs"),
                spec.get("metadata"),
            )
            self.sources.append(source)

        self.source_by_id = {source.evidence_id: source for source in self.sources}
        self.aliases = self._build_aliases()
        self._normalize_manifest_evidence_ids()
        self.manifest_digest_status: Dict[int, bool] = {}
        for entry in self.manifest_entries:
            if entry.record_range is None or not entry.digest:
                continue
            source = self.source_by_id.get(entry.evidence_id)
            if source is None or not source.verified:
                continue
            actual = source.digest_for(entry.record_range)
            if actual is not None:
                self.manifest_digest_status[id(entry)] = entry.digest.lower() == actual.lower()
        self.warnings.extend(
            "{}: {}".format(source.evidence_id, error)
            for source in self.sources
            for error in source.errors
        )
        if self.prior_holder_still_holds:
            self.warnings.append(
                "previous holder still has a copy; possession is not treated as transfer"
            )
        if not self.manifest_entries and self.require_manifest:
            self.warnings.append("external handover manifest is missing or empty")
        if not self.responsibility.provided:
            self.warnings.append("internal responsibility table not supplied; signer names cannot be verified")
        if self.redacted_fields:
            self.warnings.append(
                "external manifest contained sensitive fields; they are omitted from external output"
            )

    def _normalize_evidence_specs(self, value: Any, override_ranges: Any) -> List[Dict[str, Any]]:
        if value is None:
            return []
        items: List[Any]
        if isinstance(value, Mapping):
            if _lookup(value, "path", "file", "evtx") is not None:
                items = [value]
            elif _lookup(value, "evidence_id", "id", "name") is not None:
                items = [value]
            else:
                items = []
                for evidence_id, spec in value.items():
                    if isinstance(spec, str):
                        items.append({"evidence_id": evidence_id, "path": spec})
                    elif isinstance(spec, Mapping):
                        row = dict(spec)
                        row.setdefault("evidence_id", evidence_id)
                        items.append(row)
                    elif isinstance(spec, (list, tuple)):
                        items.append({"evidence_id": evidence_id, "ranges": spec})
        elif isinstance(value, (list, tuple)):
            items = list(value)
        else:
            items = [value]

        result: List[Dict[str, Any]] = []
        for index, item in enumerate(items):
            if isinstance(item, str):
                spec = {"path": item}
            elif isinstance(item, Mapping):
                spec = dict(item)
            else:
                continue
            evidence_id = _lookup(spec, "evidence_id", "id", "name", "attachment_id")
            path = _lookup(spec, "path", "file", "evtx", "filename", "source")
            if evidence_id is None:
                evidence_id = _basename(path) if path else "evidence-{}".format(index + 1)
            evidence_id = str(evidence_id)
            if "/" in evidence_id or "\\" in evidence_id:
                evidence_id = _basename(evidence_id)
            ranges_value = _lookup(
                spec,
                "ranges",
                "record_ranges",
                "scope",
                "records",
                "record_range",
                "range",
                "record_numbers",
            )
            if ranges_value is None and override_ranges is not None and len(items) == 1:
                ranges_value = override_ranges
            ranges = parse_ranges(ranges_value, evidence_id)
            range_specs: List[Dict[str, Any]] = []
            if isinstance(ranges_value, (list, tuple)):
                for range_item in ranges_value:
                    if isinstance(range_item, Mapping):
                        parsed = parse_ranges(range_item, evidence_id)
                        for record_range in parsed:
                            range_specs.append(
                                {
                                    "range": record_range,
                                    "sensitivity": _lookup(
                                        range_item, "sensitivity", "classification", "category"
                                    ),
                                    "summary": _lookup(range_item, "summary", "abstract", "digest"),
                                    "summary_only": _is_summary_only(range_item),
                                }
                            )
            elif isinstance(ranges_value, Mapping) and not _scope_is_all(ranges_value):
                parsed = parse_ranges(ranges_value, evidence_id)
                for record_range in parsed:
                    range_specs.append(
                        {
                            "range": record_range,
                            "sensitivity": _lookup(
                                ranges_value, "sensitivity", "classification", "category"
                            ),
                            "summary": _lookup(ranges_value, "summary", "abstract", "digest"),
                            "summary_only": _is_summary_only(ranges_value),
                        }
                    )
            result.append(
                {
                    "evidence_id": evidence_id,
                    "path": path,
                    "ranges": ranges,
                    "range_specs": range_specs,
                    "metadata": {
                        "input_path": path,
                        "summary_only": _is_summary_only(spec),
                        **{
                            key: value
                            for key, value in spec.items()
                            if _norm_key(key)
                            not in {
                                _norm_key(item)
                                for item in ("ranges", "record_ranges", "scope", "records")
                            }
                        },
                    },
                }
            )
        return result

    def _build_aliases(self) -> Dict[str, str]:
        aliases: Dict[str, str] = {}
        for source in self.sources:
            aliases[source.evidence_id] = source.evidence_id
            if source.path:
                aliases[_basename(source.path)] = source.evidence_id
                aliases[os.path.splitext(_basename(source.path))[0]] = source.evidence_id
        return aliases

    def _canonical_evidence_id(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return self.aliases.get(value, value)

    def _fallback_evidence_id(self, value: Optional[str], raw: Mapping[str, Any]) -> Optional[str]:
        canonical = self._canonical_evidence_id(value)
        if canonical in self.source_by_id:
            return canonical
        for key in ("file", "path", "filename", "source", "attachment"):
            candidate = _lookup(raw, key)
            if isinstance(candidate, str):
                candidate_id = self._canonical_evidence_id(_basename(candidate))
                if candidate_id in self.source_by_id:
                    return candidate_id
        return canonical

    def _normalize_manifest_evidence_ids(self) -> None:
        for entry in self.manifest_entries:
            entry.evidence_id = self._fallback_evidence_id(entry.evidence_id, entry.raw)
            if entry.record_range is not None:
                entry.record_range = RecordRange(
                    entry.record_range.start,
                    entry.record_range.end,
                    self._fallback_evidence_id(entry.record_range.evidence_id, entry.raw)
                    or entry.evidence_id,
                )
        for permission in self.permissions:
            permission.evidence_id = self._fallback_evidence_id(
                permission.evidence_id, permission.raw
            )
            if permission.record_range is not None:
                permission.record_range = RecordRange(
                    permission.record_range.start,
                    permission.record_range.end,
                    self._fallback_evidence_id(permission.record_range.evidence_id, permission.raw)
                    or permission.evidence_id,
                )
        for receipt in self.receipts:
            receipt.scope = [
                RecordRange(
                    item.start,
                    item.end,
                    self._fallback_evidence_id(item.evidence_id, receipt.raw),
                )
                for item in receipt.scope
            ]
        for row in self.responsibility.rows:
            row.scope = [
                RecordRange(
                    item.start,
                    item.end,
                    self._fallback_evidence_id(item.evidence_id, row.raw),
                )
                for item in row.scope
            ]

    def _manifest_for(self, record_range: RecordRange) -> List[ManifestEntry]:
        return [entry for entry in self.manifest_entries if entry.covers(record_range)]

    def _manifest_receipt_for(self, record_range: RecordRange) -> Optional[str]:
        entries = self._manifest_for(record_range)
        for entry in entries:
            if entry.receipt_id:
                return entry.receipt_id
        return entries[0].receipt_id if entries else None

    def _receipt_authorized(
        self, receipt: Receipt, record_range: RecordRange
    ) -> Tuple[bool, Optional[str]]:
        prior_holder_id = _lookup(self.prior_holder, "id", "principal_id", "holder", "user_id")
        if (
            self.prior_holder_still_holds
            and prior_holder_id
            and receipt.signer_id == prior_holder_id
            and not receipt.to_principal
            and not receipt.accepted_by
        ):
            return False, "prior_holder_possession_not_transfer"
        if not self.responsibility.provided:
            return True, None
        row, _ = self.responsibility.resolve(receipt)
        if row is None:
            return False, "signer_not_in_responsibility_table"
        if not row.covers(record_range):
            return False, "signer_scope_mismatch"
        return True, None

    def _governing_authorized(
        self, governing: Optional[GoverningReceipt], record_range: RecordRange
    ) -> Tuple[bool, Optional[str]]:
        if governing is None:
            return True, None
        return self._receipt_authorized(governing.receipt, record_range)

    def _range_boundaries(self, source: SourceEvidence, record_range: RecordRange) -> List[int]:
        points = {record_range.start, record_range.end + 1}
        for entry in self.manifest_entries:
            if entry.record_range is None:
                continue
            if entry.evidence_id and entry.evidence_id != source.evidence_id:
                continue
            if entry.record_range.start > record_range.start:
                points.add(entry.record_range.start)
            if entry.record_range.end + 1 <= record_range.end:
                points.add(entry.record_range.end + 1)
        for receipt in self.receipts:
            for item in receipt.scope:
                if item.evidence_id and item.evidence_id != source.evidence_id:
                    continue
                if item.start > record_range.start:
                    points.add(item.start)
                if item.end + 1 <= record_range.end:
                    points.add(item.end + 1)
        for spec in source.range_specs:
            item = spec.get("range")
            if not isinstance(item, RecordRange):
                continue
            if item.evidence_id and item.evidence_id != source.evidence_id:
                continue
            if item.start > record_range.start:
                points.add(item.start)
            if item.end + 1 <= record_range.end:
                points.add(item.end + 1)
        for permission in self.permissions:
            if permission.record_range is None:
                continue
            if permission.evidence_id and permission.evidence_id != source.evidence_id:
                continue
            item = permission.record_range
            if item.start > record_range.start:
                points.add(item.start)
            if item.end + 1 <= record_range.end:
                points.add(item.end + 1)
        if source.records:
            numbers = source.record_numbers
            left = bisect.bisect_left(numbers, record_range.start)
            right = bisect.bisect_right(numbers, record_range.end)
            present = numbers[left:right]
            if present:
                run_start = present[0]
                previous = present[0]
                for number in present[1:]:
                    if number != previous + 1:
                        points.add(run_start)
                        points.add(previous + 1)
                        run_start = number
                    previous = number
                points.add(run_start)
                points.add(previous + 1)
        return sorted(point for point in points if record_range.start <= point <= record_range.end + 1)

    def _classify_segment(
        self,
        source: SourceEvidence,
        record_range: RecordRange,
        evaluations: Mapping[str, ReceiptEvaluation],
    ) -> Dict[str, Any]:
        sensitivity = source.sensitivity_for(record_range)
        permission = resolve_permission(
            self.permissions,
            self.custodian_id,
            record_range,
            sensitivity,
            self.as_of or self.deadline,
        )
        manifest_entries = self._manifest_for(record_range)
        present_count_now = (
            source.present_count(record_range) if source.verified else record_range.length
        )
        missing_digest_summary = (
            source.verified
            and present_count_now == 0
            and any(entry.digest or entry.summary_only for entry in manifest_entries)
        )
        summary_only = (
            source.summary_only_for(record_range)
            or any(entry.summary_only for entry in manifest_entries)
            or missing_digest_summary
        )
        manifest_receipt_id = None
        for entry in manifest_entries:
            if entry.receipt_id:
                manifest_receipt_id = entry.receipt_id
                break
        governing, receipt_reason = _select_governing(
            record_range,
            self.receipts,
            self.receipts_by_id,
            evaluations,
            manifest_receipt_id=manifest_receipt_id,
            authorize=self._receipt_authorized,
        )
        signer_authorized, signer_reason = self._governing_authorized(governing, record_range)

        status = NOT_ACCEPTED
        reason = "outside_external_manifest"
        if source.path and not source.verified:
            reason = "source_unreadable"
        elif source.verified and present_count_now == 0:
            if (
                governing is not None
                and missing_digest_summary
                and permission.access != "none"
            ):
                status = SUMMARY_ONLY
                reason = "summary_remains_for_missing_records"
            else:
                reason = "record_missing"
        elif governing is None:
            reason = receipt_reason
            if reason == "no_receipt" and self.prior_holder_still_holds:
                reason = "prior_holder_possession_not_transfer"
        elif self.require_manifest and not manifest_entries:
            reason = "outside_external_manifest"
        elif manifest_receipt_id and not governing.contains_receipt(manifest_receipt_id):
            if any(
                receipt.receipt_id == manifest_receipt_id for receipt in self.receipts
            ):
                reason = "manifest_receipt_not_effective"
            else:
                reason = "manifest_receipt_mismatch"
        elif not signer_authorized:
            reason = signer_reason
        elif permission.access == "none":
            reason = permission.reason
        elif permission.access == "summary" or summary_only:
            status = SUMMARY_ONLY
            reason = (
                "custodian_has_summary_only"
                if permission.access == "summary"
                else "manifest_carries_summary_only"
            )
        else:
            status = REVIEWABLE
            reason = "signed_scope_and_full_access"

        present = present_count_now
        missing = record_range.length - present if source.verified else 0
        digest = source.digest_for(record_range) if source.verified else None
        signer = governing.evaluation.signer.to_dict() if governing is not None else None
        result = {
            "evidence_id": source.evidence_id,
            "start": record_range.start,
            "end": record_range.end,
            "record_count": record_range.length if not source.verified else present,
            "records_present": present,
            "records_missing": missing,
            "status": status,
            "status_zh": STATUS_LABELS_ZH[status],
            "reason": reason,
            "reason_zh": REASON_LABELS_ZH.get(reason, reason),
            "access": permission.access,
            "sensitivity": sensitivity,
            "summary_only": summary_only or permission.access == "summary",
            "receipt_id": governing.receipt.receipt_id if governing is not None else None,
            "signed_at": format_time(governing.evaluation.signed_at) if governing is not None else None,
            "effective_at": format_time(governing.evaluation.effective_at) if governing is not None else None,
            "signer": signer,
            "manifest_receipt_id": manifest_receipt_id,
            "digest": digest,
            "digest_verified": None,
            "manifest_digest_verified": None,
        }
        if governing is not None and manifest_entries:
            direct_expected = next(
                (
                    entry.digest
                    for entry in manifest_entries
                    if entry.digest
                    and entry.record_range is not None
                    and entry.record_range.start == record_range.start
                    and entry.record_range.end == record_range.end
                ),
                None,
            )
            if direct_expected and digest:
                result["digest_verified"] = direct_expected.lower() == digest.lower()
            statuses = [
                self.manifest_digest_status[id(entry)]
                for entry in manifest_entries
                if id(entry) in self.manifest_digest_status
            ]
            if statuses:
                result["manifest_digest_verified"] = all(statuses)
            if result["digest_verified"] is False or result["manifest_digest_verified"] is False:
                self.warnings.append(
                    "{} {}-{} digest differs from external manifest".format(
                        source.evidence_id, record_range.start, record_range.end
                    )
                )
        return result

    def _reconcile_source(self, source: SourceEvidence) -> List[Dict[str, Any]]:
        evaluations = {
            receipt.receipt_id: _evaluate_receipt(
                receipt,
                self.receipts_by_id,
                self.responsibility,
                self.deadline,
                self.require_responsibility,
            )
            for receipt in self.receipts
        }
        segments: List[Dict[str, Any]] = []
        for source_range in merge_ranges(
            [RecordRange(item.start, item.end, source.evidence_id) for item in source.ranges]
        ):
            points = self._range_boundaries(source, source_range)
            for start, end_exclusive in zip(points, points[1:]):
                if end_exclusive <= start:
                    continue
                segment_range = RecordRange(start, end_exclusive - 1, source.evidence_id)
                segment = self._classify_segment(source, segment_range, evaluations)
                pieces = [segment]
                if self.use_record_timestamps:
                    pieces = self._split_by_record_time(segment, source)
                for piece in pieces:
                    _merge_segment(segments, piece)
        return segments

    def _split_by_record_time(
        self,
        segment: Dict[str, Any],
        source: SourceEvidence,
    ) -> List[Dict[str, Any]]:
        receipt = self.receipts_by_id.get(segment.get("receipt_id"))
        if receipt is None or receipt.signed_at is None:
            return [segment]
        if segment.get("records_missing"):
            return [segment]
        records = source.records_in(
            RecordRange(segment["start"], segment["end"], segment["evidence_id"])
        )
        if not records:
            return [segment]
        groups: List[Tuple[bool, List[RecordInfo]]] = []
        for record in records:
            is_late = record.timestamp is not None and record.timestamp > receipt.signed_at
            if groups and groups[-1][0] == is_late:
                groups[-1][1].append(record)
            else:
                groups.append((is_late, [record]))
        if len(groups) == 1 and not groups[0][0]:
            return [segment]
        pieces: List[Dict[str, Any]] = []
        for is_late, group in groups:
            piece = dict(segment)
            piece["start"] = group[0].record_num
            piece["end"] = group[-1].record_num
            piece["record_count"] = len(group)
            piece["records_present"] = len(group)
            piece["records_missing"] = 0
            piece["digest"] = source.digest_for(
                RecordRange(piece["start"], piece["end"], source.evidence_id)
            )
            piece["digest_verified"] = None
            if is_late:
                piece["status"] = NOT_ACCEPTED
                piece["status_zh"] = STATUS_LABELS_ZH[NOT_ACCEPTED]
                piece["reason"] = "record_after_signature"
                piece["reason_zh"] = REASON_LABELS_ZH["record_after_signature"]
            pieces.append(piece)
        return pieces

    def run(self) -> CustodyReport:
        evidence_reports: List[Dict[str, Any]] = []
        all_segments: List[Dict[str, Any]] = []
        for source in self.sources:
            segments = self._reconcile_source(source)
            all_segments.extend(segments)
            evidence_reports.append(
                {
                    **source.to_dict(),
                    "segments": segments,
                }
            )

        counts = {
            REVIEWABLE: {"records": 0, "segments": 0},
            SUMMARY_ONLY: {"records": 0, "segments": 0},
            NOT_ACCEPTED: {"records": 0, "segments": 0},
        }
        for segment in all_segments:
            status = segment["status"]
            counts[status]["records"] += segment["record_count"]
            counts[status]["segments"] += 1
        total_records = sum(item["records"] for item in counts.values())
        total_range_records = sum(
            segment.get("record_count", 0) + segment.get("records_missing", 0)
            for segment in all_segments
        )

        manifest_without_receipt: List[Dict[str, Any]] = []
        matched: List[Dict[str, Any]] = []
        evaluations = {
            receipt.receipt_id: _evaluate_receipt(
                receipt,
                self.receipts_by_id,
                self.responsibility,
                self.deadline,
                self.require_responsibility,
            )
            for receipt in self.receipts
        }
        for entry in self.manifest_entries:
            entry_ranges: List[Tuple[str, RecordRange]] = []
            if entry.record_range is not None:
                evidence_id = self._canonical_evidence_id(entry.evidence_id)
                entry_ranges.append(
                    (
                        evidence_id,
                        RecordRange(entry.record_range.start, entry.record_range.end, evidence_id),
                    )
                )
            elif entry.all_scope:
                for source in self.sources:
                    if entry.evidence_id and entry.evidence_id != source.evidence_id:
                        continue
                    for source_range in source.ranges:
                        entry_ranges.append(
                            (
                                source.evidence_id,
                                RecordRange(
                                    source_range.start,
                                    source_range.end,
                                    source.evidence_id,
                                ),
                            )
                        )
            for evidence_id, record_range in entry_ranges:
                governing, reason = _select_governing(
                    record_range,
                    self.receipts,
                    self.receipts_by_id,
                    evaluations,
                    manifest_receipt_id=entry.receipt_id,
                    authorize=self._receipt_authorized,
                )
                if governing is not None:
                    authorized, auth_reason = self._governing_authorized(governing, record_range)
                    if not authorized:
                        governing = None
                        reason = auth_reason or reason
                item = {
                    "evidence_id": evidence_id,
                    "start": record_range.start,
                    "end": record_range.end,
                    "receipt_id": entry.receipt_id,
                    "reason": reason,
                    "reason_zh": REASON_LABELS_ZH.get(reason, reason),
                }
                if governing is None:
                    manifest_without_receipt.append(item)
                else:
                    item["effective_receipt_id"] = governing.receipt.receipt_id
                    item["signer"] = governing.evaluation.signer.to_dict()
                    matched.append(item)

        receipt_without_manifest = [
            segment
            for segment in all_segments
            if segment.get("receipt_id") and not self._manifest_for(
                RecordRange(segment["start"], segment["end"], segment["evidence_id"])
            )
        ]
        scope_matches = not manifest_without_receipt and not receipt_without_manifest

        signer_reports: List[Dict[str, Any]] = []
        seen_receipts = set()
        accepted_counts: Dict[str, int] = {}
        for segment in all_segments:
            receipt_id = segment.get("receipt_id")
            if not receipt_id:
                continue
            if segment.get("status") in {REVIEWABLE, SUMMARY_ONLY}:
                accepted_counts[receipt_id] = accepted_counts.get(receipt_id, 0) + segment.get(
                    "record_count", 0
                )
            if receipt_id in seen_receipts:
                continue
            seen_receipts.add(receipt_id)
            signer = segment.get("signer")
            if signer:
                signer_reports.append(
                    {
                        "receipt_id": receipt_id,
                        "signed_at": segment.get("signed_at"),
                        **signer,
                    }
                )
        primary_signer = None
        if signer_reports:
            if accepted_counts:
                primary_id = max(
                    accepted_counts,
                    key=lambda receipt_id: (
                        accepted_counts[receipt_id],
                        next(
                            (
                                item.get("signed_at") or ""
                                for item in signer_reports
                                if item.get("receipt_id") == receipt_id
                            ),
                            "",
                        ),
                    ),
                )
            else:
                primary_id = signer_reports[-1]["receipt_id"]
            primary_signer = next(
                (item for item in signer_reports if item.get("receipt_id") == primary_id),
                signer_reports[-1],
            )
            primary_signer = dict(primary_signer)
            primary_signer.setdefault("verified", False)

        if not self.responsibility.provided:
            self.warnings.append("signer identity is based on receipt data only")

        report = CustodyReport(
            {
                "case_id": _lookup(self.case, "case_id", "id", "case", default=""),
                "generated_at": _lookup(
                    self.case,
                    "generated_at",
                    "report_time",
                    default=format_time(_datetime.datetime.now(UTC)),
                ),
                "offline": True,
                "archive_deadline": format_time(self.deadline),
                "custodian": {
                    "id": self.custodian_id,
                    "role": self.custodian_role,
                },
                "summary": {
                    "reviewable_records": counts[REVIEWABLE]["records"],
                    "summary_only_records": counts[SUMMARY_ONLY]["records"],
                    "not_accepted_records": counts[NOT_ACCEPTED]["records"],
                    "reviewable_segments": counts[REVIEWABLE]["segments"],
                    "summary_only_segments": counts[SUMMARY_ONLY]["segments"],
                    "not_accepted_segments": counts[NOT_ACCEPTED]["segments"],
                    "total_records": total_records,
                    "total_range_records": total_range_records,
                    "all_sources_verified": all(source.verified for source in self.sources),
                },
                "evidence": evidence_reports,
                "handover_scope": {
                    "manifest_entries": [entry.to_dict() for entry in self.manifest_entries],
                    "matched": matched,
                    "manifest_without_receipt": manifest_without_receipt,
                    "receipt_without_manifest": [
                        {
                            "evidence_id": segment["evidence_id"],
                            "start": segment["start"],
                            "end": segment["end"],
                            "receipt_id": segment["receipt_id"],
                        }
                        for segment in receipt_without_manifest
                    ],
                    "scope_matches": scope_matches,
                    "scope_check": {
                        "manifest_entries": len(self.manifest_entries),
                        "matched": len(matched),
                        "manifest_without_receipt": len(manifest_without_receipt),
                        "receipt_without_manifest": len(receipt_without_manifest),
                        "scope_matches": scope_matches,
                    },
                },
                "signer_verification": {
                    "actual_signer": primary_signer,
                    "signers": signer_reports,
                    "receipts": [evaluations[key].to_dict() for key in evaluations],
                    "internal_table_used": self.responsibility.provided,
                    "prior_holder_possession_ignored": self.prior_holder_still_holds,
                },
                "warnings": _unique(self.warnings),
                "redacted_fields": sorted(set(self.redacted_fields)),
            }
        )
        for segment in report["handover_scope"].get("receipt_without_manifest", []):
            if segment.get("receipt_id"):
                self.warnings.append(
                    "{} {}-{} has a receipt but is absent from the external manifest".format(
                        segment["evidence_id"], segment["start"], segment["end"]
                    )
                )
        if manifest_without_receipt:
            self.warnings.append("external manifest contains ranges without an effective receipt")
        report["warnings"] = _unique(self.warnings)
        overall = (
            NOT_ACCEPTED
            if not all_segments or counts[NOT_ACCEPTED]["segments"]
            else SUMMARY_ONLY
            if counts[SUMMARY_ONLY]["segments"]
            else REVIEWABLE
        )
        report["status"] = overall
        report["status_zh"] = STATUS_LABELS_ZH[overall]
        report["segments"] = all_segments
        report["reviewable"] = [item for item in all_segments if item["status"] == REVIEWABLE]
        report["summary_only"] = [item for item in all_segments if item["status"] == SUMMARY_ONLY]
        report["not_accepted"] = [item for item in all_segments if item["status"] == NOT_ACCEPTED]
        report["source_evidence"] = evidence_reports
        report["manifest_scope"] = report["handover_scope"]
        report["actual_signer"] = report["signer_verification"]["actual_signer"]
        report["external"] = report.external_dict()
        return report


def _all_keys(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _all_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _all_keys(item)


def _unique(values: Iterable[Any]) -> List[Any]:
    result = []
    seen = set()
    for value in values:
        key = repr(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_document(path: str) -> Any:
    """Load JSON, JSON-lines, CSV, or TSV custody metadata."""

    extension = os.path.splitext(path)[1].lower()
    if extension in {".csv", ".tsv"}:
        with open(path, "r", encoding="utf-8-sig", newline="") as handle:
            dialect = csv.excel_tab if extension == ".tsv" else csv.excel
            return [dict(row) for row in csv.DictReader(handle, dialect=dialect)]
    if extension == ".jsonl":
        with open(path, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
    return load_json(path)


def load_case(path: Any) -> Dict[str, Any]:
    path = os.fsdecode(os.fspath(path))
    data = load_json(path)
    if not isinstance(data, Mapping):
        raise CustodyInputError("case file must contain a JSON object")
    case = dict(data)
    case["_base_dir"] = os.path.dirname(os.path.abspath(path))
    for key in ("external_manifest", "responsibility", "receipts"):
        value = case.get(key)
        if isinstance(value, str):
            candidate = value
            if not os.path.isabs(candidate):
                candidate = os.path.join(case["_base_dir"], candidate)
            if os.path.exists(candidate):
                case[key] = load_document(candidate)
    return case


def _resolve_document(value: Any, base_dir: Optional[str], *keys: str) -> Any:
    if isinstance(value, (str, os.PathLike)):
        value = os.fsdecode(os.fspath(value))
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                return json.loads(stripped)
            except ValueError:
                pass
        extension = os.path.splitext(value)[1].lower()
        if extension in {".json", ".jsonl", ".csv", ".tsv", ""}:
            candidate = value
            if not os.path.isabs(candidate) and base_dir:
                candidate = os.path.join(base_dir, candidate)
            if os.path.exists(candidate):
                return load_document(candidate)
    return value


def reconcile_custody(
    case: Any = None,
    *,
    evidence: Any = None,
    ranges: Any = None,
    record_ranges: Any = None,
    permissions: Any = None,
    custodian_permissions: Any = None,
    custody_permissions: Any = None,
    receipts: Any = None,
    external_manifest: Any = None,
    handover_manifest: Any = None,
    responsibility: Any = None,
    responsibility_table: Any = None,
    custodian: Any = None,
    deadline: Any = None,
    archive_deadline: Any = None,
    handover_deadline: Any = None,
    destruction_date: Any = None,
    as_of: Any = None,
    audit_time: Any = None,
    signing_time: Any = None,
    signed_at: Any = None,
    use_record_timestamps: bool = False,
    temporal_cutoff: Any = None,
    require_manifest: bool = True,
    require_responsibility: bool = False,
    **kwargs: Any,
) -> CustodyReport:
    """Reconcile EVTX custody from caller-supplied metadata.

    ``case`` may be a path, a mapping, or ``None``.  Keyword names used by
    different callers are accepted for convenience; the canonical names are
    ``evidence``, ``ranges``, ``permissions``, ``receipts``,
    ``external_manifest`` and ``responsibility``.
    """

    base_dir = None
    if isinstance(case, (str, os.PathLike)):
        data = load_case(case)
        base_dir = data.get("_base_dir")
    elif isinstance(case, Mapping):
        data = dict(case)
        base_dir = data.get("_base_dir")
    elif case is None:
        data = {}
    elif isinstance(case, (list, tuple)):
        if case and all(
            isinstance(item, Mapping)
            and any(
                _norm_key(key) in {"path", "file", "evtx", "evidenceid", "id"}
                for key in item
            )
            for item in case
        ):
            evidence = case
        elif ranges is None:
            ranges = case
        data = {}
    else:
        data = dict(kwargs)

    if evidence is None:
        evidence = kwargs.get("sources") or kwargs.get("logs") or kwargs.get("attachments")
    if permissions is None:
        permissions = custodian_permissions if custodian_permissions is not None else custody_permissions
    if ranges is None:
        ranges = record_ranges
    if ranges is None and data:
        ranges = _lookup(data, "ranges", "record_ranges", "records", "scope")
    if external_manifest is None:
        external_manifest = handover_manifest
    if responsibility is None:
        responsibility = responsibility_table
    if deadline is None:
        deadline = archive_deadline or handover_deadline or destruction_date
    if as_of is None:
        as_of = audit_time
    if signing_time is None:
        signing_time = signed_at
    if temporal_cutoff is not None:
        use_record_timestamps = _as_bool(temporal_cutoff, use_record_timestamps)
    if data and external_manifest is None:
        external_manifest = _lookup(
            data,
            "external_manifest",
            "handover_manifest",
            "external_list",
            "external",
        )
        external_manifest = _resolve_document(external_manifest, base_dir)
    elif isinstance(external_manifest, (str, os.PathLike)):
        external_manifest = _resolve_document(external_manifest, base_dir)
    if data and responsibility is None:
        responsibility = _lookup(
            data,
            "responsibility",
            "internal_responsibility",
            "responsibility_table",
            "receipt_signers",
            "roles",
            "signers",
            "people",
        )
        responsibility = _resolve_document(responsibility, base_dir)
    elif isinstance(responsibility, (str, os.PathLike)):
        responsibility = _resolve_document(responsibility, base_dir)
    if data and receipts is None:
        receipts = _lookup(
            data,
            "receipts",
            "handover_receipts",
            "acceptance_receipts",
            "handover",
            "acceptance",
        )
        receipts = _resolve_document(receipts, base_dir)
    elif isinstance(receipts, (str, os.PathLike)):
        receipts = _resolve_document(receipts, base_dir)
    if signing_time is not None:
        data["signed_at"] = signing_time

    audit = CustodyAudit(
        data,
        base_dir=base_dir,
        evidence=evidence,
        ranges=ranges,
        permissions=permissions,
        receipts=receipts,
        external_manifest=external_manifest,
        responsibility=responsibility,
        custodian=custodian,
        deadline=deadline,
        as_of=as_of,
        use_record_timestamps=use_record_timestamps,
        require_manifest=require_manifest,
        require_responsibility=require_responsibility,
    )
    return audit.run()


CustodyAuditor = CustodyAudit
audit_custody = reconcile_custody
check_custody = reconcile_custody
verify_custody = reconcile_custody


FULL = "full"
SUMMARY = "summary"
PENDING = NOT_ACCEPTED
REVIEW = REVIEWABLE


def main(argv=None) -> int:
    """Run the custody reconciliation CLI from ``python -m Evtx.Custody``."""

    from evtx_scripts.evtx_custody_reconcile import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
