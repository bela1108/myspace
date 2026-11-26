"""Offline verification handover planning for encrypted Office evidence.

The planner combines three local inputs:

* the offline format evidence from :mod:`msoffcrypto.evidence`;
* a duty list saying which checks a format needs and who receives them;
* attachment availability windows and custodian windows.

It selects the cheapest allowed check that covers each duty, schedules the
operations against a caller-supplied virtual clock, and reports every location
that would need an extension.  No wall-clock read, password, decryption, or
macro execution is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from msoffcrypto.evidence import FormatEvidence, _canonical_json, inspect_file

PLAN_SCHEMA = "msoffcrypto.handover-plan/v1"
REQUEST_SCHEMA = "msoffcrypto.handover-request/v1"
RECEIPT_SCHEMA = "msoffcrypto.sealed-receipt/v1"

UTC = timezone.utc


class CheckKind(str, Enum):
    """Check types that can be requested by a local duty list."""

    SHELL = "shell"
    SEALED_RECEIPT = "sealed_receipt"
    PAYLOAD_DECRYPT = "payload_decrypt"


CHECK_ALIASES = {
    "shell": CheckKind.SHELL,
    "outer_shell": CheckKind.SHELL,
    "outer-wrapper": CheckKind.SHELL,
    "outer_wrapper": CheckKind.SHELL,
    "shell_only": CheckKind.SHELL,
    "sealed_receipt": CheckKind.SEALED_RECEIPT,
    "sealed-receipt": CheckKind.SEALED_RECEIPT,
    "sealed": CheckKind.SEALED_RECEIPT,
    "receipt": CheckKind.SEALED_RECEIPT,
    "payload_decrypt": CheckKind.PAYLOAD_DECRYPT,
    "payload": CheckKind.PAYLOAD_DECRYPT,
    "decrypt": CheckKind.PAYLOAD_DECRYPT,
}

# A sealed receipt is produced only after the outer wrapper has been read, so
# it also covers a shell duty.  Payload decryption is intentionally absent: the
# planner is an outer-wrapper-only workflow.
CHECK_COVERS: dict[CheckKind, frozenset[CheckKind]] = {
    CheckKind.SHELL: frozenset({CheckKind.SHELL}),
    CheckKind.SEALED_RECEIPT: frozenset({CheckKind.SHELL, CheckKind.SEALED_RECEIPT}),
}

SUPPORTED_CHECKS = frozenset(CHECK_COVERS)
OP_ORDER = {"inspect": 0, "seal": 1, "handover": 2}

FORMAT_ALIASES = {
    "docx": "ooxml",
    "xlsx": "ooxml",
    "pptx": "ooxml",
    "doc": "doc97",
    "xls": "xls97",
    "ppt": "ppt97",
}


def parse_datetime(value: Any) -> datetime:
    """Parse an ISO-8601 value and normalize it to UTC.

    A naive value is interpreted as UTC; no local timezone is consulted.
    """
    if isinstance(value, datetime):
        result = value
    else:
        text = str(value).strip()
        if text.endswith("Z") or text.endswith("z"):
            text = text[:-1] + "+00:00"
        result = datetime.fromisoformat(text)
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


def format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_duration(value: Any, default: int) -> int:
    """Parse seconds or a compact ``30s`` / ``5m`` / ``1h`` duration."""
    if value is None:
        return int(default)
    if isinstance(value, bool):
        raise ValueError("duration must not be a boolean")
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().lower()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*(ms|s|m|h|d)?", text)
    if not match:
        raise ValueError("invalid duration: {!r}".format(value))
    amount = float(match.group(1))
    unit = match.group(2) or "s"
    multiplier = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return max(0, int(amount * multiplier))


def _check_value(value: Any) -> CheckKind:
    if isinstance(value, CheckKind):
        return value
    text = str(value).strip().lower()
    if text not in CHECK_ALIASES:
        raise ValueError("unknown check kind: {!r}".format(value))
    return CHECK_ALIASES[text]


def _check_set(values: Iterable[Any] | None) -> frozenset[CheckKind]:
    if not values:
        return frozenset()
    if isinstance(values, (str, CheckKind)):
        return frozenset({_check_value(values)})
    return frozenset(_check_value(value) for value in values)


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime
    id: str | None = None

    def __post_init__(self) -> None:
        if self.end < self.start:
            raise ValueError("window end is before its start")

    @classmethod
    def from_value(cls, value: Any, default_id: str | None = None) -> "TimeWindow":
        if isinstance(value, Mapping):
            start = value.get("start") or value.get("from")
            end = value.get("end") or value.get("until")
            window_id = value.get("id", default_id)
        elif isinstance(value, (list, tuple)) and len(value) >= 2:
            start, end = value[0], value[1]
            window_id = default_id
        else:
            raise ValueError("window must be an object or a [start, end] pair")
        if start is None or end is None:
            raise ValueError("window needs both start and end")
        return cls(parse_datetime(start), parse_datetime(end), window_id)


@dataclass(frozen=True)
class DutyRule:
    id: str
    format: str
    required_checks: frozenset[CheckKind]
    custodian: str | None = None
    inspect_seconds: int = 300
    seal_seconds: int = 120
    handover_seconds: int = 300
    deliver: bool | None = None
    match: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], defaults: Mapping[str, int]) -> "DutyRule":
        format_name = str(value.get("format") or value.get("family") or "*")
        rule_id = str(value.get("id") or value.get("name") or format_name)
        duties = value.get("duration_seconds") or {}
        return cls(
            id=rule_id,
            format=format_name,
            required_checks=_check_set(value.get("required_checks") or value.get("checks") or ["shell"]),
            custodian=value.get("custodian") or value.get("recipient"),
            inspect_seconds=parse_duration(
                value.get("inspect_seconds", duties.get("inspect_seconds", duties.get("inspect"))),
                defaults["inspect_seconds"],
            ),
            seal_seconds=parse_duration(
                value.get("seal_seconds", duties.get("seal_seconds", duties.get("seal"))),
                defaults["seal_seconds"],
            ),
            handover_seconds=parse_duration(
                value.get("handover_seconds", duties.get("handover_seconds", duties.get("handover"))),
                defaults["handover_seconds"],
            ),
            deliver=value.get("deliver"),
            match=dict(value.get("match") or {}),
        )

    def matches(self, evidence: FormatEvidence, item: Mapping[str, Any] | None = None) -> bool:
        if self.format != "*":
            matched = self.format == evidence.format
            if not matched and self.format in FORMAT_ALIASES:
                matched = FORMAT_ALIASES[self.format] == evidence.format
                path = item.get("path") if item else None
                if matched and path:
                    matched = Path(str(path)).suffix.lower() == "." + self.format
            if not matched:
                return False
        for key, expected in self.match.items():
            actual = getattr(evidence, key, None)
            if actual is None and isinstance(evidence.details, Mapping):
                actual = evidence.details.get(key)
            if actual != expected:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "format": self.format,
            "required_checks": sorted(check.value for check in self.required_checks),
            "custodian": self.custodian,
            "inspect_seconds": self.inspect_seconds,
            "seal_seconds": self.seal_seconds,
            "handover_seconds": self.handover_seconds,
            "deliver": self.deliver,
            "match": dict(self.match),
        }


@dataclass
class _NormalizedRequest:
    clock_start: datetime
    clock_end: datetime | None
    allowed_checks: frozenset[CheckKind]
    duties: tuple[DutyRule, ...]
    custodian_windows: dict[str, tuple[TimeWindow, ...]]
    defaults: dict[str, int]
    items: list[dict[str, Any]]
    raw: Mapping[str, Any]


def _normalize_duration_defaults(raw: Mapping[str, Any]) -> dict[str, int]:
    defaults = dict(raw.get("defaults") or {})
    durations = dict(raw.get("durations") or {})
    for key in ("inspect_seconds", "seal_seconds", "handover_seconds"):
        if key not in defaults and key in durations:
            defaults[key] = durations[key]
    for key in ("inspect", "seal", "handover"):
        legacy = key + "_seconds"
        if legacy not in defaults and key in durations:
            defaults[legacy] = durations[key]
    return {
        "inspect_seconds": parse_duration(defaults.get("inspect_seconds"), 300),
        "seal_seconds": parse_duration(defaults.get("seal_seconds"), 120),
        "handover_seconds": parse_duration(defaults.get("handover_seconds"), 300),
    }


def _normalize_windows(raw: Any) -> dict[str, tuple[TimeWindow, ...]]:
    result: dict[str, tuple[TimeWindow, ...]] = {}
    if not raw:
        return result
    for custodian, values in dict(raw).items():
        if isinstance(values, Mapping) and ("start" in values or "from" in values):
            values = [values]
        result[str(custodian)] = tuple(TimeWindow.from_value(value, default_id=str(custodian)) for value in values)
    return result


def _normalize_request(request: Mapping[str, Any], *, base_dir: str | Path = ".") -> _NormalizedRequest:
    if not isinstance(request, Mapping):
        raise ValueError("request must be a JSON object")
    if not request.get("clock_start"):
        raise ValueError("request needs a virtual clock_start")
    clock_start = parse_datetime(request.get("clock_start"))
    clock_end = parse_datetime(request["clock_end"]) if request.get("clock_end") else None
    if clock_end is not None and clock_end < clock_start:
        raise ValueError("clock_end is before clock_start")
    defaults = _normalize_duration_defaults(request)
    allowed_raw = request.get("allowed_checks")
    allowed_checks = _check_set(allowed_raw) if allowed_raw is not None else frozenset({CheckKind.SHELL, CheckKind.SEALED_RECEIPT})
    duties = tuple(DutyRule.from_dict(value, defaults) for value in (request.get("duties") or request.get("duty_list") or []))
    windows = _normalize_windows(request.get("custodian_windows") or request.get("windows"))
    evidence_values = request.get("evidence") or request.get("items") or []
    if not isinstance(evidence_values, list):
        raise ValueError("evidence must be a list")
    base = Path(base_dir)
    items: list[dict[str, Any]] = []
    for value in evidence_values:
        if not isinstance(value, Mapping):
            raise ValueError("each evidence item must be an object")
        item = dict(value)
        item_id = item.get("id") or item.get("name")
        if not item_id:
            raise ValueError("each evidence item needs an id")
        item["id"] = str(item_id)
        item["_base_dir"] = base
        items.append(item)
    return _NormalizedRequest(
        clock_start=clock_start,
        clock_end=clock_end,
        allowed_checks=allowed_checks,
        duties=duties,
        custodian_windows=windows,
        defaults=defaults,
        items=items,
        raw=dict(request),
    )


def _resolve_evidence(item: Mapping[str, Any]) -> FormatEvidence:
    path = item.get("path")
    if path:
        candidate = Path(str(path))
        if not candidate.is_absolute():
            candidate = Path(item["_base_dir"]) / candidate
        return inspect_file(candidate)
    for key in ("format_evidence", "evidence", "offline_evidence"):
        value = item.get(key)
        if isinstance(value, FormatEvidence):
            return value
        if isinstance(value, Mapping):
            return FormatEvidence.from_dict(value)
    # An embedded flat evidence object is also accepted for replay-only plans.
    if any(item.get(key) is not None for key in ("format", "container", "scheme", "encrypted")):
        return FormatEvidence.from_dict(item)
    raise ValueError("evidence item needs path, format_evidence, or flat format fields")


def _select_duty(duties: Sequence[DutyRule], item: Mapping[str, Any], evidence: FormatEvidence) -> DutyRule | None:
    duty_id = item.get("duty") or item.get("duty_id")
    if duty_id is not None:
        for duty in duties:
            if duty.id == str(duty_id):
                return duty
        return None
    for duty in duties:
        if duty.matches(evidence, item):
            return duty
    return None


def _choose_check(required: frozenset[CheckKind], allowed: frozenset[CheckKind]) -> tuple[CheckKind | None, str | None]:
    required = required or frozenset({CheckKind.SHELL})
    covered = set()
    for check in allowed:
        covered.update(CHECK_COVERS.get(check, ()))
    missing = required - covered
    if missing:
        if any(check not in allowed for check in required):
            return None, "check_not_allowed"
        return None, "check_not_supported"
    candidates = [check for check in allowed if check in CHECK_COVERS and required <= CHECK_COVERS[check]]
    if not candidates:
        return None, "check_not_allowed"
    # Prefer the smallest artifact that covers the duty.  In particular, a
    # shell-only duty must not be upgraded to a sealed receipt.
    return min(candidates, key=lambda check: (len(CHECK_COVERS[check]), 0 if check == CheckKind.SHELL else 1)), None


def _deferred(
    item_id: str,
    operation: str,
    check: CheckKind | str | None,
    reason: str,
    detail: str,
    *,
    custodian: str | None = None,
    blocking: Iterable[str] = (),
    requested_from: datetime | None = None,
    requested_until: datetime | None = None,
    extension_seconds: int | None = None,
    requested_action: str | None = None,
) -> dict[str, Any]:
    check_value = check.value if isinstance(check, CheckKind) else check
    return {
        "item_id": item_id,
        "operation": operation,
        "check": check_value,
        "custodian": custodian,
        "reason": reason,
        "detail": detail,
        "location": "{}:{}:{}".format(item_id, operation, custodian or "-"),
        "blocking": list(blocking),
        "requested_from": format_datetime(requested_from) if requested_from else None,
        "requested_until": format_datetime(requested_until) if requested_until else None,
        "extension_seconds": extension_seconds,
        "requested_action": requested_action,
    }


def _operation(
    item: Mapping[str, Any],
    operation: str,
    check: CheckKind,
    start: datetime,
    end: datetime,
    *,
    custodian: str | None = None,
    artifact_kind: str | None = None,
    artifact_digest: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    evidence = item["evidence"]
    return {
        "item_id": item["id"],
        "operation": operation,
        "check": check.value,
        "start": format_datetime(start),
        "end": format_datetime(end),
        "duration_seconds": int((end - start).total_seconds()),
        "custodian": custodian,
        "artifact_kind": artifact_kind,
        "artifact_digest": artifact_digest,
        "receipt_id": receipt_id,
        "evidence_digest": evidence.evidence_digest,
        "file_sha256": evidence.file_sha256,
        "format": evidence.format,
        "scheme": evidence.scheme,
        "outer_wrapper_only": True,
    }


def _receipt_for(item: Mapping[str, Any], duty: DutyRule, custodian: str) -> dict[str, Any]:
    evidence = item["evidence"]
    payload = {
        "schema": RECEIPT_SCHEMA,
        "item_id": item["id"],
        "duty_id": duty.id,
        "format": evidence.format,
        "scheme": evidence.scheme,
        "encrypted": evidence.encrypted,
        "evidence_digest": evidence.evidence_digest,
        "file_sha256": evidence.file_sha256,
        "file_size": evidence.file_size,
        "custodian": custodian,
        "required_checks": sorted(check.value for check in item["required_checks"]),
        "sealed_from": "offline-wrapper-evidence",
    }
    digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return {**payload, "receipt_id": digest[:16], "receipt_digest": digest}


def _prepare_item(raw_item: Mapping[str, Any], request: _NormalizedRequest) -> dict[str, Any]:
    item_id = raw_item["id"]
    item: dict[str, Any] = {
        "id": item_id,
        "label": raw_item.get("label") or raw_item.get("name") or raw_item.get("path") or item_id,
        "path": str(raw_item.get("path")) if raw_item.get("path") else None,
        "duty_id": None,
        "required_checks": [],
        "selected_check": None,
        "custodian": raw_item.get("recipient") or raw_item.get("custodian"),
        "deliver": bool(raw_item.get("deliver", False)),
        "available_from": None,
        "available_until": None,
        "expires_at": None,
        "inspect_seconds": request.defaults["inspect_seconds"],
        "seal_seconds": request.defaults["seal_seconds"],
        "handover_seconds": request.defaults["handover_seconds"],
        "operations": [],
        "deferred": [],
        "status": "blocked",
        "evidence": None,
        "evidence_dict": None,
        "receipt": None,
    }
    try:
        evidence = _resolve_evidence(raw_item)
    except Exception as exc:
        item["evidence_dict"] = {
            "format": "unknown",
            "container": "unknown",
            "encrypted": False,
            "scheme": "unknown",
            "supported": False,
            "error": "{}: {}".format(type(exc).__name__, exc),
        }
        item["deferred"].append(
            _deferred(
                item_id,
                "inspect",
                None,
                "evidence_unreadable",
                "无法读取离线证据：{}: {}".format(type(exc).__name__, exc),
                requested_action="提供可读取的本地附件或已嵌入的证据",
            )
        )
        return item
    item["evidence"] = evidence
    item["evidence_dict"] = evidence.as_dict()
    if not evidence.supported or evidence.error:
        item["deferred"].append(
            _deferred(
                item_id,
                "inspect",
                None,
                "evidence_unreadable",
                evidence.error or "离线证据格式不受支持",
                requested_action="升级证据读取器，或提供受支持的加密外壳",
            )
        )
        return item

    duty = _select_duty(request.duties, raw_item, evidence)
    if duty is None and (raw_item.get("required_checks") or raw_item.get("checks")):
        duty = DutyRule(
            id="item:{}".format(item_id),
            format=evidence.format,
            required_checks=_check_set(raw_item.get("required_checks") or raw_item.get("checks")),
            custodian=item["custodian"],
            inspect_seconds=request.defaults["inspect_seconds"],
            seal_seconds=request.defaults["seal_seconds"],
            handover_seconds=request.defaults["handover_seconds"],
        )
    if duty is None:
        item["deferred"].append(
            _deferred(
                item_id,
                "plan",
                None,
                "no_duty_rule",
                "本地职责清单中没有匹配格式 {!r} 的规则".format(evidence.format),
                requested_action="为该格式补充职责规则",
            )
        )
        return item
    item["duty_id"] = duty.id
    item["inspect_seconds"] = duty.inspect_seconds
    item["seal_seconds"] = duty.seal_seconds
    item["handover_seconds"] = duty.handover_seconds
    item["custodian"] = item["custodian"] or duty.custodian
    required = set(duty.required_checks)
    required.update(_check_set(raw_item.get("required_checks") or raw_item.get("checks")))
    if raw_item.get("receipt_required"):
        required.add(CheckKind.SEALED_RECEIPT)
    if not required:
        required = {CheckKind.SHELL}
    item["required_checks"] = required
    selected, reason = _choose_check(frozenset(required), request.allowed_checks)
    if selected is None:
        item["deferred"].append(
            _deferred(
                item_id,
                "plan",
                None,
                reason or "check_not_allowed",
                "所需检查 {} 无法被允许运行的检查 {} 覆盖".format(
                    sorted(check.value for check in required),
                    sorted(check.value for check in request.allowed_checks),
                ),
                requested_action="为该职责启用一种允许运行的外壳检查",
            )
        )
        return item
    item["selected_check"] = selected
    if duty.deliver is None:
        item["deliver"] = selected == CheckKind.SEALED_RECEIPT
    else:
        item["deliver"] = bool(duty.deliver)

    available_from = raw_item.get("available_from") or raw_item.get("from") or request.clock_start
    available_until = raw_item.get("available_until") or raw_item.get("until") or raw_item.get("expires_at") or request.clock_end
    if available_until is None:
        item["deferred"].append(
            _deferred(
                item_id,
                "inspect",
                selected,
                "missing_availability",
                "附件没有 available_until/expires_at 可用期末",
                requested_action="声明附件的可用期结束时刻",
            )
        )
        return item
    item["available_from"] = parse_datetime(available_from)
    item["available_until"] = parse_datetime(available_until)
    item["expires_at"] = parse_datetime(raw_item.get("expires_at") or available_until)

    if selected == CheckKind.SEALED_RECEIPT and not item["custodian"]:
        item["deferred"].append(
            _deferred(
                item_id,
                "handover",
                selected,
                "missing_custodian",
                "封存回执需要指定保管员",
                requested_action="指定保管员",
            )
        )
        return item
    if item["expires_at"] <= request.clock_start:
        item["deferred"].append(
            _deferred(
                item_id,
                "inspect",
                selected,
                "evidence_expired",
                "证据到期时刻不晚于虚拟时钟起点",
                requested_from=request.clock_start,
                requested_until=request.clock_start + timedelta(seconds=item["inspect_seconds"]),
                extension_seconds=item["inspect_seconds"],
            )
        )
        return item
    if item["available_until"] <= request.clock_start:
        item["deferred"].append(
            _deferred(
                item_id,
                "inspect",
                selected,
                "attachment_expired",
                "附件可用期在虚拟时钟起点前结束",
                requested_from=request.clock_start,
                requested_until=request.clock_start + timedelta(seconds=item["inspect_seconds"]),
                extension_seconds=item["inspect_seconds"],
            )
        )
        return item
    if item["available_from"] >= item["expires_at"]:
        item["deferred"].append(
            _deferred(
                item_id,
                "inspect",
                selected,
                "availability_after_expiry",
                "附件在证据到期后才开始可用",
                requested_from=item["available_from"],
                requested_until=item["available_from"] + timedelta(seconds=item["inspect_seconds"]),
                extension_seconds=int((item["available_from"] - item["expires_at"]).total_seconds()) + item["inspect_seconds"],
            )
        )
        return item
    if request.clock_end is not None and item["available_from"] >= request.clock_end:
        item["deferred"].append(
            _deferred(
                item_id,
                "inspect",
                selected,
                "availability_outside_horizon",
                "附件在计划水平线之后才开始可用",
                requested_from=item["available_from"],
                requested_until=item["available_from"] + timedelta(seconds=item["inspect_seconds"]),
                extension_seconds=item["inspect_seconds"],
            )
        )
        return item
    return item


def _overlapping_ops(ops: Sequence[Mapping[str, Any]], start: datetime, end: datetime) -> list[str]:
    result = []
    for op in ops:
        op_start = parse_datetime(op["start"])
        op_end = parse_datetime(op["end"])
        if op_start < end and op_end > start:
            result.append(op["item_id"])
    return result


def _schedule_inspections(items: Sequence[dict[str, Any]], request: _NormalizedRequest) -> None:
    candidates = [item for item in items if item["selected_check"] is not None and item["status"] == "blocked" and not item["deferred"]]
    # A local examiner can inspect in any order.  Scheduling by earliest
    # attachment release avoids missing a short window merely because a later
    # deadline happened to be processed first; the custodian handover pass uses
    # deadlines instead.
    candidates.sort(key=lambda item: (item["available_from"], item["available_until"], item["expires_at"], item["id"]))
    local_busy = request.clock_start
    local_ops: list[dict[str, Any]] = []
    for item in candidates:
        start = max(local_busy, item["available_from"], request.clock_start)
        inspect_end = start + timedelta(seconds=item["inspect_seconds"])
        if inspect_end > item["available_until"]:
            blocking = _overlapping_ops(local_ops, item["available_from"], item["available_until"])
            reason = "local_inspection_conflict" if blocking else "attachment_window_too_short"
            item["deferred"].append(
                _deferred(
                    item["id"],
                    "inspect",
                    item["selected_check"],
                    reason,
                    "核验需要 {}s，但附件窗口只剩 {}s".format(
                        item["inspect_seconds"],
                        max(0, int((item["available_until"] - start).total_seconds())),
                    ),
                    blocking=blocking,
                    requested_from=start,
                    requested_until=inspect_end,
                    extension_seconds=max(0, int((inspect_end - item["available_until"]).total_seconds())),
                )
            )
            continue
        if inspect_end > item["expires_at"]:
            item["deferred"].append(
                _deferred(
                    item["id"],
                    "inspect",
                    item["selected_check"],
                    "inspection_after_expiry",
                    "核验将在证据到期之后结束",
                    requested_from=start,
                    requested_until=inspect_end,
                    extension_seconds=max(0, int((inspect_end - item["expires_at"]).total_seconds())),
                )
            )
            continue
        if request.clock_end is not None and inspect_end > request.clock_end:
            item["deferred"].append(
                _deferred(
                    item["id"],
                    "inspect",
                    item["selected_check"],
                    "beyond_clock_horizon",
                    "核验将在计划水平线之后结束",
                    requested_from=start,
                    requested_until=inspect_end,
                    extension_seconds=max(0, int((inspect_end - request.clock_end).total_seconds())),
                )
            )
            continue
        inspect_op = _operation(item, "inspect", item["selected_check"], start, inspect_end)
        item["operations"].append(inspect_op)
        local_ops.append(inspect_op)
        local_busy = inspect_end
        item["inspect_end"] = inspect_end
        item["status"] = "partial" if item["selected_check"] == CheckKind.SEALED_RECEIPT else "complete"

        if item["selected_check"] == CheckKind.SEALED_RECEIPT:
            seal_start = local_busy
            seal_end = seal_start + timedelta(seconds=item["seal_seconds"])
            if seal_end > item["expires_at"]:
                item["deferred"].append(
                    _deferred(
                        item["id"],
                        "seal",
                        item["selected_check"],
                        "seal_after_expiry",
                        "封存回执将在证据到期之后才生成",
                        custodian=item["custodian"],
                        requested_from=seal_start,
                        requested_until=seal_end,
                        extension_seconds=max(0, int((seal_end - item["expires_at"]).total_seconds())),
                    )
                )
                continue
            duty = next((duty for duty in request.duties if duty.id == item["duty_id"]), None)
            if duty is None:
                duty = DutyRule(
                    id=item["duty_id"] or "item:{}".format(item["id"]),
                    format=item["evidence"].format,
                    required_checks=frozenset(item["required_checks"]),
                    custodian=item["custodian"],
                )
            receipt = _receipt_for(item, duty, item["custodian"])
            item["receipt"] = receipt
            seal_op = _operation(
                item,
                "seal",
                item["selected_check"],
                seal_start,
                seal_end,
                custodian=item["custodian"],
                artifact_kind="sealed_receipt",
                artifact_digest=receipt["receipt_digest"],
                receipt_id=receipt["receipt_id"],
            )
            item["operations"].append(seal_op)
            local_ops.append(seal_op)
            local_busy = seal_end
            item["ready_at"] = seal_end
        else:
            item["ready_at"] = inspect_end


def _find_custodian_slot(
    windows: Sequence[TimeWindow],
    busy: Sequence[Mapping[str, Any]],
    earliest: datetime,
    duration: int,
    deadline: datetime,
) -> tuple[datetime | None, str | None, tuple[str, ...], int]:
    """Find a free handover slot and explain the failure when there is none."""
    ordered_windows = sorted(windows, key=lambda window: window.start)
    ordered_busy = sorted(busy, key=lambda interval: parse_datetime(interval["start"]))
    if not ordered_windows:
        return None, "custodian_window_missing", (), duration
    if earliest + timedelta(seconds=duration) > deadline:
        return (
            None,
            "handover_after_expiry",
            tuple(interval["item_id"] for interval in ordered_busy if parse_datetime(interval["start"]) < deadline),
            int((earliest + timedelta(seconds=duration) - deadline).total_seconds()),
        )
    blocking: list[str] = []
    for window in ordered_windows:
        start = max(earliest, window.start)
        if start >= window.end:
            continue
        if start + timedelta(seconds=duration) > window.end:
            continue
        if start + timedelta(seconds=duration) > deadline:
            continue
        for interval in ordered_busy:
            interval_start = parse_datetime(interval["start"])
            interval_end = parse_datetime(interval["end"])
            if interval_end <= start:
                continue
            if interval_start >= start + timedelta(seconds=duration):
                break
            if interval["item_id"] not in blocking:
                blocking.append(interval["item_id"])
            start = max(start, interval_end)
            if start + timedelta(seconds=duration) > window.end:
                break
        if start + timedelta(seconds=duration) <= window.end and start + timedelta(seconds=duration) <= deadline:
            return start, None, (), 0
    blocking_tuple = tuple(blocking)
    if not any(window.end > earliest for window in ordered_windows):
        return None, "custodian_window_before_ready", blocking_tuple, duration
    if all(window.end <= earliest or window.start >= deadline for window in ordered_windows):
        return None, "custodian_window_after_expiry", blocking_tuple, duration
    if blocking:
        return None, "custodian_conflict", blocking_tuple, duration
    return None, "custodian_window_too_short", blocking_tuple, duration


def _schedule_handovers(items: Sequence[dict[str, Any]], request: _NormalizedRequest) -> list[dict[str, Any]]:
    tasks = []
    for item in items:
        if item.get("ready_at") is None:
            continue
        if item["selected_check"] != CheckKind.SEALED_RECEIPT and not item["deliver"]:
            continue
        tasks.append(item)
    tasks.sort(key=lambda item: (item["expires_at"], item["ready_at"], item["id"]))
    busy: dict[str, list[dict[str, Any]]] = {}
    artifacts: list[dict[str, Any]] = []
    for item in tasks:
        custodian = item["custodian"]
        if not custodian:
            item["deferred"].append(
                _deferred(
                    item["id"],
                    "handover",
                    item["selected_check"],
                    "missing_custodian",
                    "移交需要指定保管员",
                    requested_action="指定保管员",
                )
            )
            continue
        windows = request.custodian_windows.get(custodian, ())
        earliest = max(request.clock_start, item["ready_at"])
        duration = item["handover_seconds"]
        slot, reason, blocking, extension = _find_custodian_slot(windows, busy.get(custodian, []), earliest, duration, item["expires_at"])
        if slot is None:
            detail = {
                "custodian_window_missing": "保管员没有声明的可用窗口",
                "custodian_window_before_ready": "所有保管员窗口都在产物就绪前关闭",
                "custodian_window_after_expiry": "下一个保管员窗口在证据到期后才开始",
                "custodian_conflict": "另一个移交占用了剩余窗口",
                "custodian_window_too_short": "没有保管员窗口能容纳连续办理时间",
                "handover_after_expiry": "移交将在证据到期之后完成",
                "beyond_clock_horizon": "移交将在计划水平线之后完成",
            }.get(reason or "", "没有可行的保管员时段")
            requested_from = earliest
            if blocking:
                blocked_until = [parse_datetime(interval["end"]) for interval in busy.get(custodian, []) if interval["item_id"] in blocking]
                if blocked_until:
                    requested_from = max(requested_from, max(blocked_until))
            item["deferred"].append(
                _deferred(
                    item["id"],
                    "handover",
                    item["selected_check"],
                    reason or "custodian_unavailable",
                    detail,
                    custodian=custodian,
                    blocking=blocking,
                    requested_from=requested_from,
                    requested_until=requested_from + timedelta(seconds=duration),
                    extension_seconds=extension,
                    requested_action="在证据到期前延长保管员窗口",
                )
            )
            continue
        end = slot + timedelta(seconds=duration)
        if request.clock_end is not None and end > request.clock_end:
            item["deferred"].append(
                _deferred(
                    item["id"],
                    "handover",
                    item["selected_check"],
                    "beyond_clock_horizon",
                    "移交将在计划水平线之后完成",
                    custodian=custodian,
                    requested_from=slot,
                    requested_until=end,
                    extension_seconds=max(0, int((end - request.clock_end).total_seconds())),
                    requested_action="延长计划水平线，或把移交提前",
                )
            )
            continue
        artifact_kind = "sealed_receipt" if item["selected_check"] == CheckKind.SEALED_RECEIPT else "evidence"
        digest = item["receipt"]["receipt_digest"] if item["receipt"] else item["evidence"].evidence_digest
        receipt_id = item["receipt"]["receipt_id"] if item["receipt"] else None
        handover_op = _operation(
            item,
            "handover",
            item["selected_check"],
            slot,
            end,
            custodian=custodian,
            artifact_kind=artifact_kind,
            artifact_digest=digest,
            receipt_id=receipt_id,
        )
        item["operations"].append(handover_op)
        busy.setdefault(custodian, []).append(handover_op)
        artifacts.append(
            {
                "item_id": item["id"],
                "artifact_kind": artifact_kind,
                "artifact_digest": digest,
                "receipt_id": receipt_id,
                "custodian": custodian,
                "scheduled_at": format_datetime(slot),
                "evidence_digest": item["evidence"].evidence_digest,
                "file_sha256": item["evidence"].file_sha256,
            }
        )


def _item_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    evidence: FormatEvidence | None = item.get("evidence")
    return {
        "id": item["id"],
        "label": item["label"],
        "path": item["path"],
        "format": evidence.format if evidence else item.get("evidence_dict", {}).get("format"),
        "scheme": evidence.scheme if evidence else item.get("evidence_dict", {}).get("scheme"),
        "cipher": evidence.cipher if evidence else item.get("evidence_dict", {}).get("cipher"),
        "key_bits": evidence.key_bits if evidence else item.get("evidence_dict", {}).get("key_bits"),
        "encrypted": evidence.encrypted if evidence else item.get("evidence_dict", {}).get("encrypted"),
        "evidence_digest": evidence.evidence_digest if evidence else item.get("evidence_dict", {}).get("evidence_digest"),
        "file_sha256": evidence.file_sha256 if evidence else item.get("evidence_dict", {}).get("file_sha256"),
        "format_evidence": item.get("evidence_dict"),
        "duty_id": item["duty_id"],
        "required_checks": sorted(check.value for check in item["required_checks"]),
        "selected_check": item["selected_check"].value if item["selected_check"] else None,
        "custodian": item["custodian"],
        "available_from": format_datetime(item["available_from"]) if item["available_from"] else None,
        "available_until": format_datetime(item["available_until"]) if item["available_until"] else None,
        "expires_at": format_datetime(item["expires_at"]) if item["expires_at"] else None,
        "status": item["status"],
        "operations": [op["operation"] for op in item["operations"]],
        "deferred": list(item["deferred"]),
    }


def build_plan(request: Mapping[str, Any], *, base_dir: str | Path = ".") -> dict[str, Any]:
    """Build a deterministic handover plan from a local request object.

    The returned object is JSON-safe and includes its own digest and replay
    metadata.  It does not contain a wall-clock timestamp.
    """
    normalized = _normalize_request(request, base_dir=base_dir)
    items = [_prepare_item(raw_item, normalized) for raw_item in normalized.items]
    _schedule_inspections(items, normalized)
    _schedule_handovers(items, normalized)

    operations = sorted(
        (op for item in items for op in item["operations"]),
        key=lambda op: (op["start"], OP_ORDER.get(op["operation"], 99), op["item_id"]),
    )
    deferred = sorted(
        (entry for item in items for entry in item["deferred"]),
        key=lambda entry: (entry["item_id"], OP_ORDER.get(entry["operation"], 99), entry["reason"]),
    )
    for item in items:
        if item["deferred"]:
            item["status"] = "partial" if item["operations"] else "blocked"
        elif item["operations"]:
            item["status"] = "complete"

    handovers = [
        {
            "item_id": op["item_id"],
            "operation": op["operation"],
            "check": op["check"],
            "custodian": op["custodian"],
            "start": op["start"],
            "end": op["end"],
            "artifact_kind": op["artifact_kind"],
            "artifact_digest": op["artifact_digest"],
            "receipt_id": op["receipt_id"],
        }
        for op in operations
        if op["operation"] == "handover"
    ]
    handover_requirements = []
    for item in items:
        if item["selected_check"] != CheckKind.SEALED_RECEIPT and not item["deliver"]:
            continue
        scheduled = any(op["operation"] == "handover" for op in item["operations"])
        handover_requirements.append(
            {
                "item_id": item["id"],
                "artifact_kind": "sealed_receipt" if item["selected_check"] == CheckKind.SEALED_RECEIPT else "evidence",
                "custodian": item["custodian"],
                "status": "scheduled" if scheduled else "deferred",
                "receipt_id": item["receipt"]["receipt_id"] if item.get("receipt") else None,
            }
        )
    receipts = [item["receipt"] for item in items if item.get("receipt")]
    conflicts = [
        entry
        for entry in deferred
        if entry["reason"]
        in {
            "custodian_conflict",
            "local_inspection_conflict",
            "custodian_window_after_expiry",
            "handover_after_expiry",
            "attachment_window_too_short",
            "inspection_after_expiry",
            "seal_after_expiry",
            "beyond_clock_horizon",
            "availability_outside_horizon",
        }
    ]
    clock_end = normalized.clock_end
    if clock_end is None:
        clock_end = max([parse_datetime(op["end"]) for op in operations] + [normalized.clock_start])
    request_fingerprint = {
        "clock_start": format_datetime(normalized.clock_start),
        "clock_end": format_datetime(clock_end),
        "allowed_checks": sorted(check.value for check in normalized.allowed_checks),
        "duties": [duty.to_dict() for duty in normalized.duties],
        "custodian_windows": {
            name: [{"id": window.id, "start": format_datetime(window.start), "end": format_datetime(window.end)} for window in windows]
            for name, windows in normalized.custodian_windows.items()
        },
        "items": [
            {
                "id": item["id"],
                "evidence_digest": item["evidence"].evidence_digest if item["evidence"] else None,
                "required_checks": sorted(check.value for check in item["required_checks"]),
                "selected_check": item["selected_check"].value if item["selected_check"] else None,
                "custodian": item["custodian"],
                "available_from": format_datetime(item["available_from"]) if item["available_from"] else None,
                "available_until": format_datetime(item["available_until"]) if item["available_until"] else None,
                "expires_at": format_datetime(item["expires_at"]) if item["expires_at"] else None,
            }
            for item in items
        ],
    }
    request_digest = hashlib.sha256(_canonical_json(request_fingerprint)).hexdigest()
    counts = {
        "total": len(items),
        "complete": sum(1 for item in items if item["status"] == "complete"),
        "partial": sum(1 for item in items if item["status"] == "partial"),
        "blocked": sum(1 for item in items if item["status"] == "blocked"),
        "operations": len(operations),
        "deferred": len(deferred),
        "handovers": len(handovers),
        "required_handovers": len(handover_requirements),
    }
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "generated_at": format_datetime(normalized.clock_start),
        "clock": {
            "start": format_datetime(normalized.clock_start),
            "end": format_datetime(clock_end),
            "timezone": "UTC",
        },
        "request_digest": request_digest,
        "summary": counts,
        "policy": request_fingerprint,
        "items": [_item_summary(item) for item in items],
        "operations": operations,
        "deferred": deferred,
        "conflicts": conflicts,
        "handovers": handovers,
        "handover_requirements": handover_requirements,
        "receipts": receipts,
        "replay": {
            "event_order": ["inspect", "seal", "handover"],
            "uses_wall_clock": False,
            "command": "python -m msoffcrypto.handover PLAN.json --replay --format json",
        },
    }
    plan["plan_digest"] = hashlib.sha256(_canonical_json({key: value for key, value in plan.items() if key != "plan_digest"})).hexdigest()
    return plan


def plan_handover(request: Mapping[str, Any], *, base_dir: str | Path = ".") -> dict[str, Any]:
    """Alias for :func:`build_plan`."""
    return build_plan(request, base_dir=base_dir)


def schedule_handover(request: Mapping[str, Any], *, base_dir: str | Path = ".") -> dict[str, Any]:
    """Alias for :func:`build_plan`."""
    return build_plan(request, base_dir=base_dir)


class VirtualClock:
    """A deterministic clock that only moves when a replay event asks it to."""

    def __init__(self, start: Any):
        self._now = parse_datetime(start)

    @property
    def now(self) -> datetime:
        return self._now

    def advance_to(self, value: Any) -> datetime:
        target = parse_datetime(value)
        if target < self._now:
            raise ValueError("virtual clock cannot move backwards")
        self._now = target
        return self._now

    def advance(self, seconds: int) -> datetime:
        if seconds < 0:
            raise ValueError("virtual clock cannot move backwards")
        self._now += timedelta(seconds=seconds)
        return self._now

    def sleep(self, seconds: int) -> datetime:
        """Compatibility spelling for tests that model waits."""
        return self.advance(seconds)


def _verify_plan_digest(plan: Mapping[str, Any]) -> str | None:
    expected = plan.get("plan_digest")
    if not expected:
        return "plan_digest is missing"
    actual = hashlib.sha256(_canonical_json({key: value for key, value in plan.items() if key != "plan_digest"})).hexdigest()
    if actual != expected:
        return "plan_digest mismatch"
    return None


def replay_plan(plan: Mapping[str, Any], clock: VirtualClock | None = None, *, verify_digest: bool = True) -> dict[str, Any]:
    """Replay a plan on a virtual clock and validate the schedule.

    The replay uses only the plan's embedded evidence digests and windows.  It
    never opens a source document, never decrypts a payload, and never reads
    the real clock.
    """
    errors: list[str] = []
    if not isinstance(plan, Mapping):
        return {"ok": False, "errors": ["plan must be an object"], "events": []}
    if verify_digest:
        digest_error = _verify_plan_digest(plan)
        if digest_error:
            errors.append(digest_error)
    clock_data = plan.get("clock") or {}
    if clock is None:
        start = clock_data.get("start") or plan.get("generated_at")
        if not start:
            return {"ok": False, "errors": errors + ["plan has no virtual clock start"], "events": []}
        clock = VirtualClock(start)
    items = {item["id"]: item for item in plan.get("items", [])}
    receipts = {receipt["receipt_id"]: receipt for receipt in plan.get("receipts", []) if receipt.get("receipt_id")}
    custodian_windows = (plan.get("policy") or {}).get("custodian_windows") or {}
    operations = sorted(
        plan.get("operations", []),
        key=lambda op: (op.get("start", ""), OP_ORDER.get(op.get("operation"), 99), op.get("item_id", "")),
    )
    completed: dict[str, set[str]] = {}
    custodian_busy: dict[str, datetime] = {}
    events: list[dict[str, Any]] = []
    for op in operations:
        item_id = op.get("item_id")
        operation = op.get("operation")
        if item_id not in items:
            errors.append("operation references unknown item {!r}".format(item_id))
            continue
        try:
            start = parse_datetime(op["start"])
            end = parse_datetime(op["end"])
        except Exception as exc:
            errors.append("bad operation time for {}: {}".format(item_id, exc))
            continue
        if end < start:
            errors.append("operation ends before it starts: {} {}".format(item_id, operation))
        custodian = op.get("custodian")
        if start < clock.now:
            errors.append("operation starts before the replay clock: {} {}".format(item_id, operation))
        else:
            clock.advance_to(start)
            clock.advance_to(end)
        item = items[item_id]
        format_evidence = item.get("format_evidence")
        if isinstance(format_evidence, Mapping):
            recomputed = FormatEvidence.from_dict(format_evidence).evidence_digest
            if recomputed != item.get("evidence_digest"):
                errors.append("embedded format evidence digest mismatch: {}".format(item_id))
        expiry = item.get("expires_at")
        if expiry and end > parse_datetime(expiry):
            errors.append("operation finishes after evidence expiry: {} {}".format(item_id, operation))
        if operation == "inspect":
            available_from = item.get("available_from")
            available_until = item.get("available_until")
            if available_from and start < parse_datetime(available_from):
                errors.append("inspection before attachment availability: {}".format(item_id))
            if available_until and end > parse_datetime(available_until):
                errors.append("inspection after attachment availability: {}".format(item_id))
        if operation == "handover":
            windows = custodian_windows.get(custodian) or []
            if not any(parse_datetime(window["start"]) <= start and end <= parse_datetime(window["end"]) for window in windows):
                errors.append("handover outside custodian window: {} {}".format(item_id, custodian))
            if op.get("artifact_kind") == "sealed_receipt":
                receipt = receipts.get(op.get("receipt_id"))
                if receipt is None:
                    errors.append("sealed receipt is missing from plan: {}".format(item_id))
                else:
                    payload = {key: value for key, value in receipt.items() if key not in ("receipt_id", "receipt_digest")}
                    expected_receipt = hashlib.sha256(_canonical_json(payload)).hexdigest()
                    if expected_receipt != receipt.get("receipt_digest"):
                        errors.append("sealed receipt digest mismatch: {}".format(item_id))
                    if op.get("artifact_digest") != receipt.get("receipt_digest"):
                        errors.append("handover artifact does not match receipt: {}".format(item_id))
            elif op.get("artifact_digest") != item.get("evidence_digest"):
                errors.append("handover artifact does not match evidence: {}".format(item_id))
        if op.get("evidence_digest") != item.get("evidence_digest"):
            errors.append("operation evidence digest mismatch: {}".format(item_id))
        item_completed = completed.setdefault(item_id, set())
        if operation == "seal" and "inspect" not in item_completed:
            errors.append("seal before inspect: {}".format(item_id))
        if operation == "handover" and "inspect" not in item_completed:
            errors.append("handover before inspect: {}".format(item_id))
        if operation == "handover" and op.get("artifact_kind") == "sealed_receipt" and "seal" not in item_completed:
            errors.append("sealed receipt handover before seal: {}".format(item_id))
        if custodian:
            if start < custodian_busy.get(custodian, start):
                errors.append("custodian overlap for {}: {}".format(custodian, item_id))
            custodian_busy[custodian] = max(custodian_busy.get(custodian, end), end)
        item_completed.add(operation)
        events.append(
            {
                "at": format_datetime(start),
                "until": format_datetime(end),
                "item_id": item_id,
                "operation": operation,
                "check": op.get("check"),
                "custodian": custodian,
                "artifact_kind": op.get("artifact_kind"),
                "artifact_digest": op.get("artifact_digest"),
                "receipt_id": op.get("receipt_id"),
            }
        )
    deferred = plan.get("deferred", [])
    completed_items = sorted(item_id for item_id, item in items.items() if item.get("status") == "complete")
    return {
        "ok": not errors,
        "errors": errors,
        "clock_start": plan.get("clock", {}).get("start"),
        "completed_at": format_datetime(clock.now),
        "events": events,
        "deferred": deferred,
        "inspected_items": sorted(item_id for item_id, done in completed.items() if "inspect" in done),
        "completed_items": completed_items,
        "handover_count": sum(1 for event in events if event["operation"] == "handover"),
    }


def _fmt_duration(seconds: int | None) -> str:
    if seconds is None:
        return "-"
    if seconds % 3600 == 0 and seconds >= 3600:
        return "{}h".format(seconds // 3600)
    if seconds % 60 == 0 and seconds >= 60:
        return "{}m".format(seconds // 60)
    return "{}s".format(seconds)


def render_markdown(plan: Mapping[str, Any]) -> str:
    """Render a plan as a custodian-facing Markdown handover sheet."""
    lines = [
        "# 离线证物核查移交计划",
        "",
        "- 虚拟时钟起点：`{}`".format(plan.get("clock", {}).get("start", "-")),
        "- 计划摘要：共 {} 件，完成 {}，部分 {}，受阻 {}；操作 {} 次，延期 {} 处，移交 {} / {} 次。".format(
            plan.get("summary", {}).get("total", 0),
            plan.get("summary", {}).get("complete", 0),
            plan.get("summary", {}).get("partial", 0),
            plan.get("summary", {}).get("blocked", 0),
            plan.get("summary", {}).get("operations", 0),
            plan.get("summary", {}).get("deferred", 0),
            plan.get("summary", {}).get("handovers", 0),
            plan.get("summary", {}).get("required_handovers", 0),
        ),
        "- 计划摘要指纹：`{}`".format(plan.get("plan_digest", "-")),
        "- 观察范围：仅保护外层；未使用密码、未解密载荷、未执行宏。",
        "- 回执交付只依赖已捕获的证据摘要，可晚于附件可用期，但必须早于证据到期。",
        "",
        "## 证据与职责",
        "",
        "| 证物 | 格式 | 加密方案 | 所需检查 | 采用检查 | 保管员 | 状态 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in plan.get("items", []):
        scheme = item.get("scheme") or "-"
        cipher = item.get("cipher") or "-"
        bits = item.get("key_bits")
        scheme_text = "{} {}".format(scheme, cipher + ("-" + str(bits) if bits else "")) if cipher != "-" else scheme
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {} |".format(
                item.get("id"),
                item.get("format") or "-",
                scheme_text,
                ", ".join(item.get("required_checks") or []) or "-",
                item.get("selected_check") or "-",
                item.get("custodian") or "-",
                item.get("status") or "-",
            )
        )
    lines.extend(["", "## 最小移交集合", ""])
    requirements = plan.get("handover_requirements") or []
    if not requirements:
        lines.append("无；所有职责均可留在本地外壳核验。")
    else:
        for requirement in requirements:
            lines.append(
                "- `{}` → {} / {}（{}）".format(
                    requirement.get("item_id"),
                    requirement.get("artifact_kind"),
                    requirement.get("custodian") or "未指定保管员",
                    requirement.get("status"),
                )
            )
    lines.extend(["", "## 可重放时间线", "", "| 开始 | 结束 | 证物 | 操作 | 保管员 | 产物 |", "| --- | --- | --- | --- | --- | --- |"])
    for op in plan.get("operations", []):
        artifact = op.get("receipt_id") or op.get("artifact_digest")
        if artifact and len(str(artifact)) > 20:
            artifact = str(artifact)[:16] + "..."
        lines.append(
            "| {} | {} | `{}` | {} | {} | {} |".format(
                op.get("start"),
                op.get("end"),
                op.get("item_id"),
                op.get("operation"),
                op.get("custodian") or "-",
                artifact or "-",
            )
        )
    lines.extend(["", "## 需延期的位置", ""])
    deferred = plan.get("deferred") or []
    if not deferred:
        lines.append("无。")
    else:
        for entry in deferred:
            lines.append("- `{}` / {}：{}。".format(entry.get("location"), entry.get("reason"), entry.get("detail")))
            if entry.get("blocking"):
                lines.append("  - 阻塞来自：{}".format(", ".join("`{}`".format(item) for item in entry["blocking"])))
            if entry.get("requested_from"):
                lines.append(
                    "  - 请求延期：{} → {}（{}）".format(
                        entry.get("requested_from"),
                        entry.get("requested_until"),
                        _fmt_duration(entry.get("extension_seconds")),
                    )
                )
            if entry.get("requested_action"):
                lines.append("  - 需要动作：{}".format(entry["requested_action"]))
    lines.extend(["", "## 封存回执", ""])
    receipts = plan.get("receipts") or []
    if not receipts:
        lines.append("无。")
    else:
        for receipt in receipts:
            lines.append(
                "- `{}`：证物 `{}`，回执摘要 `{}`。".format(
                    receipt.get("receipt_id"), receipt.get("item_id"), receipt.get("receipt_digest")
                )
            )
    lines.extend(
        [
            "",
            "## 重放方式",
            "",
            "```bash",
            "python -m msoffcrypto.handover plan.json --replay --format json",
            "```",
            "",
            "重放只使用计划中嵌入的证据摘要和虚拟时钟，不读取原文件，也不使用真实时间。",
            "",
        ]
    )
    return "\n".join(lines)


def render_replay_markdown(result: Mapping[str, Any]) -> str:
    lines = [
        "# 虚拟时钟重放结果",
        "",
        "- 结果：{}".format("通过" if result.get("ok") else "失败"),
        "- 完成时刻：`{}`".format(result.get("completed_at", "-")),
        "- 已完成证物：{} 件".format(len(result.get("completed_items") or [])),
        "- 移交操作：{} 次".format(result.get("handover_count", 0)),
        "",
    ]
    if result.get("errors"):
        lines.append("## 错误")
        lines.extend("- {}".format(error) for error in result["errors"])
        lines.append("")
    lines.extend(["## 事件", ""])
    for event in result.get("events") or []:
        lines.append(
            "- {} → {} `{}` {}{}".format(
                event.get("at"),
                event.get("until"),
                event.get("item_id"),
                event.get("operation"),
                " / " + event["custodian"] if event.get("custodian") else "",
            )
        )
    if result.get("deferred"):
        lines.extend(["", "## 保留的延期"])
        for entry in result["deferred"]:
            lines.append("- `{}` / {}：{}".format(entry.get("location"), entry.get("reason"), entry.get("detail")))
    lines.append("")
    return "\n".join(lines)


def _dump_json(value: Mapping[str, Any], pretty: bool = True) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2 if pretty else None, default=str)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="msoffcrypto-handover",
        description="Plan or replay an offline Office evidence handover.",
    )
    parser.add_argument("request", help="request JSON path, or plan JSON path with --replay")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", help="write the result to this path instead of stdout")
    parser.add_argument("--replay", action="store_true", help="validate a generated plan on its virtual clock")
    parser.add_argument("--evidence-root", help="base directory for relative attachment paths")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    args = parser.parse_args(argv)

    if args.request == "-":
        payload = json.load(sys.stdin)
        base_dir = Path(args.evidence_root) if args.evidence_root else Path.cwd()
    else:
        request_path = Path(args.request)
        with request_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        base_dir = Path(args.evidence_root) if args.evidence_root else request_path.parent

    if args.replay:
        result = replay_plan(payload)
        output = _dump_json(result, pretty=not args.compact) if args.format == "json" else render_replay_markdown(result)
        status = 0 if result.get("ok") else 1
    else:
        plan = build_plan(payload, base_dir=base_dir)
        output = _dump_json(plan, pretty=not args.compact) if args.format == "json" else render_markdown(plan)
        status = 0
    if args.output:
        Path(args.output).write_text(output + ("" if output.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(output)
    return status


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CheckKind",
    "DutyRule",
    "PLAN_SCHEMA",
    "RECEIPT_SCHEMA",
    "REQUEST_SCHEMA",
    "TimeWindow",
    "VirtualClock",
    "build_plan",
    "format_datetime",
    "main",
    "parse_datetime",
    "parse_duration",
    "plan_handover",
    "render_markdown",
    "render_replay_markdown",
    "replay_plan",
    "schedule_handover",
]
