"""Offline legal-hold disposition checks built on regipy plugin evidence."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

STATUS_READY = "ready_for_release"
STATUS_PRESERVE = "preserve"
STATUS_MATERIALS = "materials_required"
DISPOSITION_RELEASE = "release"
DISPOSITION_PRESERVE = "preserve"

POSITIVE_DECISIONS = {
    "approved",
    "approve",
    "release",
    "released",
    "ready_for_release",
    "同意",
    "同意解除",
    "批准",
    "准予解除",
}
NEGATIVE_DECISIONS = {
    "denied",
    "rejected",
    "hold",
    "preserve",
    "legal_hold",
    "保全",
    "继续保全",
    "驳回",
    "拒绝",
}

EVENT_ALIASES = {
    "rollback": "rollback",
    "rolled_back": "rollback",
    "backout": "rollback",
    "回滚": "rollback",
    "overwrite": "overwrite",
    "overwritten": "overwrite",
    "覆盖": "overwrite",
    "apply": "apply",
    "applied": "apply",
    "switch": "apply",
    "switched": "apply",
    "切换": "apply",
    "落地": "apply",
    "verify": "verify",
    "verified": "verify",
    "validation": "verify",
    "确认": "verify",
    "核验": "verify",
    "collect": "collect",
    "collected": "collect",
    "采集": "collect",
}


def _first(record: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return default


def parse_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            parsed = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def version_key(version: Any) -> tuple[Any, ...]:
    if version in (None, ""):
        return ()
    parts: list[Any] = []
    for chunk in str(version).strip().replace("-", ".").split("."):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            digits = ""
            suffix = chunk
            for index, char in enumerate(chunk):
                if char.isdigit():
                    digits += char
                else:
                    suffix = chunk[index:]
                    break
            if digits:
                parts.append(int(digits))
            if suffix:
                parts.append(suffix)
    return tuple(parts) or (str(version),)


def canonical_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def value_digest(value: Any) -> str:
    return hashlib.sha256(canonical_value(value).encode("utf-8")).hexdigest()


def values_equal(actual: Any, expected: Any, case_sensitive: bool = True) -> bool:
    if actual == expected:
        return True
    if not case_sensitive and isinstance(actual, str) and isinstance(expected, str):
        return actual.lower() == expected.lower()
    if isinstance(actual, (int, bool)) or isinstance(expected, (int, bool)):
        try:
            return actual == type(expected)(expected)
        except (TypeError, ValueError):
            return False
    return False


def normalize_event_type(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower().replace(" ", "_")
    return EVENT_ALIASES.get(text, EVENT_ALIASES.get(str(value).strip(), text))


def dotted_get(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def requirement_key(requirement: dict[str, Any]) -> str:
    where = requirement.get("where") or {}
    return f"{requirement.get('plugin')}:{requirement.get('field')}:{value_digest(where)[:12]}"


@dataclass
class CaseContext:
    case_path: Path | None = None
    case_dir: Path = field(default_factory=Path.cwd)
    hash_cache: dict[str, str | None] = field(default_factory=dict)
    source_files: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_path(cls, case_path: str | Path) -> CaseContext:
        path = Path(case_path).expanduser().resolve()
        return cls(case_path=path, case_dir=path.parent)

    def resolve(self, path: str | Path) -> Path:
        candidate = Path(path).expanduser()
        return candidate if candidate.is_absolute() else (self.case_dir / candidate).resolve()

    def sha256_file(self, path: str | Path) -> str | None:
        resolved = self.resolve(path)
        key = str(resolved)
        if key in self.hash_cache:
            return self.hash_cache[key]
        if not resolved.is_file():
            self.hash_cache[key] = None
            return None
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        result = digest.hexdigest()
        self.hash_cache[key] = result
        return result

    def source_ref(self, path: str | Path | None = None, locator: str | None = None) -> dict[str, Any]:
        if path is None:
            path = self.case_path if self.case_path else "<inline>"
        inline = str(path) == "<inline>"
        resolved = Path("<inline>") if inline else self.resolve(path)
        digest = None if inline else self.sha256_file(path)
        display_path = str(path)
        if not inline:
            try:
                display_path = str(resolved.relative_to(self.case_dir))
            except ValueError:
                display_path = str(path)
        ref = {
            "path": display_path,
            "absolute_path": None if inline else str(resolved),
            "sha256": digest,
            "locator": locator,
            "exists": True if inline else resolved.exists(),
        }
        if digest:
            self.source_files[display_path] = {"path": display_path, "sha256": digest}
        return ref


def _merge_source(base: dict[str, Any], raw_source: Any = None, locator: str | None = None) -> dict[str, Any]:
    source = dict(base)
    if locator and not source.get("locator"):
        source["locator"] = locator
    if isinstance(raw_source, str):
        source["path"] = raw_source
    elif isinstance(raw_source, dict):
        source.update({key: value for key, value in raw_source.items() if value is not None})
    return source


def load_structured_records(path: str | Path, ctx: CaseContext, record_kind: str) -> list[dict[str, Any]]:
    resolved = ctx.resolve(path)
    suffix = resolved.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        records = []
        with resolved.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                if line.strip():
                    item = json.loads(line)
                    if isinstance(item, dict):
                        item["_locator"] = f"line {line_number}"
                        records.append(item)
        return records
    if suffix == ".csv":
        with resolved.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        for index, row in enumerate(rows, 2):
            row["_locator"] = f"row {index}"
        return rows
    with resolved.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        records = []
        for index, item in enumerate(data):
            if isinstance(item, dict):
                item["_locator"] = f"$[{index}]"
                records.append(item)
        return records
    if isinstance(data, dict):
        for container in (record_kind, "records", "items", "entries", "data"):
            candidate = data.get(container)
            if isinstance(candidate, list):
                records = []
                for index, item in enumerate(candidate):
                    if isinstance(item, dict):
                        item["_locator"] = f"$.{container}[{index}]"
                        records.append(item)
                return records
        data["_locator"] = "$"
        return [data]
    return []


def load_approvals(case: dict[str, Any], ctx: CaseContext) -> list[dict[str, Any]]:
    approvals: list[dict[str, Any]] = []
    inline = case.get("approvals") or case.get("approval_records") or []
    if isinstance(inline, dict):
        inline = [inline]
    for index, raw in enumerate(inline):
        if isinstance(raw, dict):
            source = ctx.source_ref(ctx.case_path, f"$.approvals[{index}]")
            approvals.append(normalize_approval(raw, ctx, source))
    files = case.get("approval_files") or case.get("independent_records") or case.get("approval_archives") or []
    if isinstance(files, (str, Path)):
        files = [files]
    for file_path in files:
        for raw in load_structured_records(file_path, ctx, "approvals"):
            locator = raw.pop("_locator", None)
            source = ctx.source_ref(file_path, locator)
            approvals.append(normalize_approval(raw, ctx, source))
    return approvals


def normalize_approval(raw: dict[str, Any], ctx: CaseContext, source: dict[str, Any]) -> dict[str, Any]:
    decision_raw = _first(raw, "decision", "release_decision", "status", "approval_status", "result")
    approved_flag = raw.get("approved")
    if isinstance(approved_flag, bool):
        decision = "approved" if approved_flag else "denied"
    else:
        decision = str(decision_raw or "").strip().lower().replace(" ", "_") if decision_raw is not None else None
        if decision in POSITIVE_DECISIONS:
            decision = "approved"
        elif decision in NEGATIVE_DECISIONS:
            decision = "denied"
        elif decision:
            negative_markers = (
                "not_approved",
                "unapproved",
                "denied",
                "reject",
                "hold",
                "preserve",
                "不同意",
                "不予批准",
                "未批准",
                "保全",
                "拒绝",
                "驳回",
            )
            positive_markers = ("approved", "approve", "release", "released", "同意", "批准", "准予")
            if any(marker in decision for marker in negative_markers):
                decision = "denied"
            elif any(marker in decision for marker in positive_markers):
                decision = "approved"
    raw_source = raw.get("source") or raw.get("source_reference") or raw.get("archive_location")
    record_source = _merge_source(source, raw_source, raw.get("_locator"))
    if raw.get("source_locator"):
        record_source["locator"] = raw["source_locator"]
    return {
        "record_id": _first(
            raw, "record_id", "approval_id", "release_id", "case_record_id", "id", "ticket", default="UNKNOWN-APPROVAL"
        ),
        "device_id": _first(raw, "device_id", "device", "host_id", "hostname", "asset_id"),
        "policy_id": _first(raw, "policy_id", "policy", "control_id", "baseline_id"),
        "policy_version": _first(raw, "policy_version", "version", "baseline_version", "policy_revision"),
        "decision": decision,
        "is_positive": decision == "approved" or (approved_flag is True),
        "decided_at": iso(parse_datetime(_first(raw, "decided_at", "approved_at", "approval_time", "decision_at", "date"))),
        "effective_at": iso(parse_datetime(_first(raw, "effective_at", "release_at", "valid_from", "effective_date"))),
        "expires_at": iso(parse_datetime(_first(raw, "expires_at", "valid_until", "expiry", "expires"))),
        "approver": _first(raw, "approver", "approved_by", "owner", "custodian"),
        "reference": _first(raw, "reference", "document", "clause", "basis", "approval_basis", "url", "ticket_url"),
        "notes": _first(raw, "notes", "comment", "reason"),
        "source": record_source,
    }


def normalize_observation(
    raw: dict[str, Any],
    device_id: str,
    ctx: CaseContext,
    *,
    default_policy_id: str | None = None,
    default_policy_version: str | None = None,
    default_evidence_set: str | None = None,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    plugin_name = _first(raw, "plugin", "plugin_name")
    field_name = _first(raw, "field", "field_name", "value_name")
    where = raw.get("where") or raw.get("selector") or {}
    assertion_key = raw.get("assertion_key") or raw.get("indicator_id")
    if not assertion_key and plugin_name and field_name:
        assertion_key = f"{plugin_name}:{field_name}:{value_digest(where)[:12]}"
    elif not assertion_key:
        assertion_key = raw.get("name") or raw.get("artifact") or "observation"

    observed_raw = _first(raw, "observed_at", "event_at", "timestamp", "last_write", "time")
    collected_raw = _first(raw, "collected_at", "collected_date", "acquired_at", "collection_time")
    observed_dt = parse_datetime(observed_raw)
    collected_dt = parse_datetime(collected_raw)
    chronology_dt = parse_datetime(_first(raw, "chronology_at", "event_at", "observed_at", "timestamp", "last_write", "time"))

    expected = _first(raw, "expected_value", "expected")
    expected_values = raw.get("expected_values")
    if "compliant" in raw:
        compliant: bool | None = bool(raw["compliant"])
    elif expected is not None:
        compliant = values_equal(raw.get("value"), expected, bool(raw.get("case_sensitive", True)))
    elif expected_values is not None:
        compliant = raw.get("value") in expected_values
    else:
        compliant = None

    if source is None:
        source_path = raw.get("source_file") or raw.get("file") or (str(ctx.case_path) if ctx.case_path else "<inline>")
        source = ctx.source_ref(source_path, raw.get("source_locator"))
    record_source = _merge_source(source, raw.get("source") or raw.get("source_ref"), raw.get("source_locator"))
    policy_version = _first(raw, "policy_version", "baseline_version", "version") or default_policy_version
    raw_id = _first(raw, "id", "observation_id")
    observation_id = raw_id or f"{device_id}-obs-{value_digest(raw)[:12]}"

    return {
        "observation_id": str(observation_id),
        "device_id": raw.get("device_id") or device_id,
        "policy_id": _first(raw, "policy_id", "policy", "control_id", "baseline_id", default=default_policy_id),
        "policy_version": None if policy_version is None else str(policy_version),
        "assertion_key": str(assertion_key),
        "indicator_name": _first(raw, "indicator", "name", default=str(assertion_key)),
        "plugin_name": plugin_name,
        "field": field_name,
        "where": where,
        "value": raw.get("value"),
        "expected_value": expected,
        "compliant": compliant,
        "event_type": normalize_event_type(_first(raw, "event_type", "action", "change_type")),
        "sequence": raw.get("sequence"),
        "observed_at": iso(observed_dt),
        "collected_at": iso(collected_dt or observed_dt),
        "collection_time_explicit": collected_dt is not None,
        "chronology_at": iso(chronology_dt or observed_dt or collected_dt),
        "expires_at": iso(parse_datetime(_first(raw, "expires_at", "valid_until"))),
        "evidence_set_id": _first(raw, "evidence_set_id", "snapshot_id", "set_id", default=default_evidence_set),
        "ticket": _first(raw, "ticket", "change_ticket", "incident"),
        "notes": raw.get("notes"),
        "source": record_source,
    }


def load_policy_catalog(case: dict[str, Any], ctx: CaseContext) -> list[dict[str, Any]]:
    raw_catalog = case.get("policies") or case.get("policy_catalog") or []
    if isinstance(raw_catalog, (str, Path)):
        raw_catalog = load_structured_records(raw_catalog, ctx, "policies")
    elif isinstance(raw_catalog, dict):
        raw_catalog = raw_catalog.get("policies") or raw_catalog.get("records") or [raw_catalog]

    policies: list[dict[str, Any]] = []
    for raw in raw_catalog:
        if not isinstance(raw, dict):
            continue
        policy_id = _first(raw, "policy_id", "id", "control_id", "baseline_id")
        common = {
            "policy_id": policy_id,
            "evidence_valid_days": _first(raw, "evidence_valid_days", "valid_days", "ttl_days"),
            "requirements": raw.get("requirements", []) or [],
            "materials": raw.get("materials", []) or [],
            "source": raw.get("source"),
        }
        versions = raw.get("versions")
        if isinstance(versions, list) and versions:
            for version_spec in versions:
                merged = {**common, **(version_spec if isinstance(version_spec, dict) else {})}
                merged["policy_id"] = policy_id
                policies.append(_normalize_policy_spec(merged))
        else:
            policies.append(_normalize_policy_spec({**raw, **common}))
    return policies


def _normalize_policy_spec(raw: dict[str, Any]) -> dict[str, Any]:
    ttl = _first(raw, "evidence_valid_days", "valid_days", "ttl_days")
    return {
        "policy_id": _first(raw, "policy_id", "id", "control_id", "baseline_id"),
        "version": None if _first(raw, "version", "policy_version") is None else str(_first(raw, "version", "policy_version")),
        "evidence_valid_days": int(ttl) if ttl is not None else None,
        "requirements": raw.get("requirements", []) or [],
        "materials": raw.get("materials", []) or [],
        "source": raw.get("source"),
    }


def _policy_maps(
    policies: list[dict[str, Any]],
) -> tuple[dict[tuple[Any, str | None], dict[str, Any]], dict[Any, list[dict[str, Any]]]]:
    by_version: dict[tuple[Any, str | None], dict[str, Any]] = {}
    by_id: dict[Any, list[dict[str, Any]]] = {}
    for spec in policies:
        by_version[(spec["policy_id"], spec["version"])] = spec
        by_id.setdefault(spec["policy_id"], []).append(spec)
    return by_version, by_id


def plugin_results_to_observations(
    plugin_results: dict[str, Any],
    *,
    device_id: str,
    ctx: CaseContext,
    policy: dict[str, Any],
    snapshot: dict[str, Any],
    source: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    observations: list[dict[str, Any]] = []
    errors: list[str] = []
    snapshot_version = _first(snapshot, "policy_version", "version")
    snapshot_policy_id = _first(snapshot, "policy_id", default=policy.get("policy_id"))

    for requirement in policy.get("requirements") or []:
        plugin_name = requirement.get("plugin") or requirement.get("plugin_name")
        field_name = requirement.get("field")
        if not plugin_name or not field_name:
            continue
        plugin_result = plugin_results.get(plugin_name)
        if isinstance(plugin_result, dict) and plugin_result.get("error"):
            errors.append(f"插件 {plugin_name} 执行失败：{plugin_result['error']}")
            continue
        if plugin_result is None:
            errors.append(f"插件 {plugin_name} 未产生结果，无法验证指标 {field_name}")
            continue

        entries = plugin_result if isinstance(plugin_result, list) else [plugin_result]
        where = requirement.get("where") or {}
        matches: list[tuple[int, dict[str, Any]]] = []
        for entry_index, entry in enumerate(entries):
            if isinstance(entry, dict) and all(dotted_get(entry, key) == expected for key, expected in where.items()):
                matches.append((entry_index, entry))
        if where and not matches:
            errors.append(f"插件 {plugin_name} 中找不到选择器 {canonical_value(where)} 对应的记录")
            continue
        if not where:
            matches = [(index, entry) for index, entry in enumerate(entries) if isinstance(entry, dict)]

        for entry_index, entry in matches:
            version_field = requirement.get("policy_version_field")
            timestamp_field = requirement.get("timestamp_field", "last_write")
            raw_observation = {
                "id": f"{snapshot.get('id', 'snapshot')}:{plugin_name}:{entry_index}:{field_name}",
                "policy_id": snapshot_policy_id,
                "policy_version": snapshot_version
                or (dotted_get(entry, version_field) if version_field else None)
                or policy.get("version"),
                "plugin": plugin_name,
                "field": field_name,
                "where": where,
                "value": dotted_get(entry, field_name),
                "expected_value": requirement.get("expected", requirement.get("expected_value")),
                "expected_values": requirement.get("expected_values"),
                "case_sensitive": requirement.get("case_sensitive", True),
                "observed_at": dotted_get(entry, timestamp_field) if timestamp_field else None,
                "collected_at": snapshot.get("collected_at"),
                "event_type": snapshot.get("event_type"),
                "sequence": snapshot.get("sequence"),
                "evidence_set_id": snapshot.get("id") or snapshot.get("evidence_set_id"),
                "ticket": snapshot.get("ticket"),
            }
            obs_source = dict(source)
            base_locator = source.get("locator") or "$"
            obs_source["locator"] = f"{base_locator}.{plugin_name}[{entry_index}].{field_name}"
            observations.append(
                normalize_observation(
                    raw_observation,
                    device_id,
                    ctx,
                    default_policy_id=policy.get("policy_id"),
                    default_policy_version=policy.get("version"),
                    source=obs_source,
                )
            )
    return observations, errors


def _run_hive_snapshot(snapshot: dict[str, Any], device: dict[str, Any], ctx: CaseContext) -> dict[str, Any]:
    hive_path = _first(snapshot, "hive_path", "path") or device.get("hive_path")
    if not hive_path:
        raise FileNotFoundError("snapshot/device 未提供 hive_path")
    resolved_hive = ctx.resolve(hive_path)
    if not resolved_hive.is_file():
        raise FileNotFoundError(f"registry hive 不存在：{hive_path}")

    restored_path: str | None = None
    log1 = _first(snapshot, "primary_log_path", "log1_path", "log1")
    log2 = _first(snapshot, "secondary_log_path", "log2_path", "log2")
    if log1:
        from regipy.recovery import apply_transaction_logs

        suffix = resolved_hive.suffix or ".hive"
        with tempfile.NamedTemporaryFile(prefix="regipy-disposition-", suffix=suffix, delete=False) as temp:
            restored_path = temp.name
        apply_transaction_logs(
            str(resolved_hive),
            str(ctx.resolve(log1)),
            str(ctx.resolve(log2)) if log2 else None,
            restored_hive_path=restored_path,
        )

    import regipy.plugins  # noqa: F401
    from regipy.plugins.utils import run_relevant_plugins
    from regipy.registry import RegistryHive

    hive = RegistryHive(
        restored_path or str(resolved_hive),
        hive_type=_first(snapshot, "hive_type") or device.get("hive_type"),
        partial_hive_path=_first(snapshot, "partial_hive_path") or device.get("partial_hive_path"),
    )
    plugin_names = _first(snapshot, "plugins") or device.get("plugins")
    if isinstance(plugin_names, str):
        plugin_names = [name.strip() for name in plugin_names.split(",") if name.strip()]
    return run_relevant_plugins(
        hive,
        as_json=True,
        plugins=plugin_names,
        include_unvalidated=bool(snapshot.get("include_unvalidated", device.get("include_unvalidated", True))),
        continue_on_error=True,
    )


def collect_device_evidence(
    device: dict[str, Any],
    ctx: CaseContext,
    policies: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    device_id = str(_first(device, "device_id", "id", "hostname", "name", default="UNKNOWN-DEVICE"))
    default_policy = device.get("policy") if isinstance(device.get("policy"), dict) else {}
    default_policy_id = _first(device, "policy_id", "policy", "control_id", default=default_policy.get("policy_id"))
    default_policy_version = _first(device, "policy_version", "version", default=default_policy.get("version"))
    observations: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    errors: list[str] = []

    inline = device.get("observations") or device.get("evidence") or []
    if isinstance(inline, dict):
        inline = [inline]
    for index, raw in enumerate(inline):
        if isinstance(raw, dict):
            source = ctx.source_ref(ctx.case_path, f"$.devices[{device.get('_index', '?')}].observations[{index}]")
            observations.append(
                normalize_observation(
                    raw,
                    device_id,
                    ctx,
                    default_policy_id=default_policy_id,
                    default_policy_version=default_policy_version,
                    source=source,
                )
            )

    evidence_files = device.get("observation_files") or device.get("evidence_files") or []
    if isinstance(evidence_files, (str, Path)):
        evidence_files = [evidence_files]
    for file_path in evidence_files:
        try:
            records = load_structured_records(file_path, ctx, "observations")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"无法读取证据记录文件 {file_path}：{exc}")
            continue
        for raw in records:
            locator = raw.pop("_locator", None)
            source = ctx.source_ref(file_path, locator)
            observations.append(
                normalize_observation(
                    raw,
                    device_id,
                    ctx,
                    default_policy_id=default_policy_id,
                    default_policy_version=default_policy_version,
                    source=source,
                )
            )
        artifacts.append(ctx.source_ref(file_path, f"evidence_file:{len(records)} records"))

    snapshots = list(device.get("evidence_snapshots") or device.get("snapshots") or [])
    if device.get("plugin_output") or device.get("plugin_output_file") or device.get("hive_path"):
        snapshots.append(
            {
                "id": device.get("snapshot_id", "current-hive"),
                "collected_at": device.get("collected_at"),
                "event_type": device.get("event_type"),
                "policy_id": default_policy_id,
                "policy_version": default_policy_version,
                "plugin_output": device.get("plugin_output") or device.get("plugin_output_file"),
                "hive_path": device.get("hive_path"),
                "plugins": device.get("plugins"),
            }
        )

    for snapshot_index, snapshot in enumerate(snapshots):
        if not isinstance(snapshot, dict):
            continue
        snapshot_id = str(snapshot.get("id") or f"snapshot-{snapshot_index + 1}")
        snapshot = {**snapshot, "id": snapshot_id}
        snapshot_observations = snapshot.get("observations") or []
        if isinstance(snapshot_observations, dict):
            snapshot_observations = [snapshot_observations]
        for raw in snapshot_observations if isinstance(snapshot_observations, list) else []:
            source = ctx.source_ref(snapshot.get("source_file") or ctx.case_path, f"snapshot:{snapshot_id}")
            observations.append(
                normalize_observation(
                    raw,
                    device_id,
                    ctx,
                    default_policy_id=default_policy_id,
                    default_policy_version=default_policy_version,
                    default_evidence_set=snapshot_id,
                    source=source,
                )
            )

        plugin_results: dict[str, Any] | None = None
        plugin_output_path = snapshot.get("plugin_output") or snapshot.get("plugin_output_file")
        source: dict[str, Any] = {}
        try:
            if plugin_output_path:
                plugin_results = json.loads(ctx.resolve(plugin_output_path).read_text(encoding="utf-8-sig"))
                source = ctx.source_ref(plugin_output_path, "regipy plugin JSON")
                artifacts.append(source)
            elif snapshot.get("hive_path") or device.get("hive_path"):
                plugin_results = _run_hive_snapshot(snapshot, device, ctx)
                hive_path = snapshot.get("hive_path") or device.get("hive_path")
                source = ctx.source_ref(hive_path, "RegistryHive + run_relevant_plugins")
                artifacts.append(source)
            else:
                continue
        except Exception as exc:  # Evidence parse failure must become an auditable material request.
            errors.append(f"快照 {snapshot_id} 的 regipy 证据不可用：{type(exc).__name__}: {exc}")
            continue

        if not isinstance(plugin_results, dict):
            errors.append(f"快照 {snapshot_id} 的插件结果不是 JSON 对象")
            continue

        snapshot_policy_id = _first(snapshot, "policy_id", default=default_policy_id)
        candidate_policies = policies
        if snapshot_policy_id:
            candidate_policies = [spec for spec in policies if spec.get("policy_id") == snapshot_policy_id]
            if not candidate_policies:
                candidate_policies = [
                    {
                        "policy_id": snapshot_policy_id,
                        "version": snapshot.get("policy_version") or default_policy_version,
                        "requirements": [],
                    }
                ]
        for policy in candidate_policies:
            extracted, extraction_errors = plugin_results_to_observations(
                plugin_results,
                device_id=device_id,
                ctx=ctx,
                policy={**policy, "version": snapshot.get("policy_version") or policy.get("version")},
                snapshot=snapshot,
                source=source,
            )
            observations.extend(extracted)
            errors.extend(extraction_errors)

    return observations, artifacts, errors


def _sort_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(item: dict[str, Any]) -> tuple[int, int, float, str]:
        dt = parse_datetime(item.get("chronology_at"))
        timestamp = dt.timestamp() if dt else float("inf")
        try:
            sequence_value = int(item.get("sequence"))
            sequence_rank = 0
        except (TypeError, ValueError):
            sequence_value = 0
            sequence_rank = 1
        return sequence_rank, sequence_value, timestamp, str(item.get("observation_id", ""))

    return sorted(observations, key=sort_key)


def _build_timeline(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for observation in observations:
        grouped.setdefault(observation["assertion_key"], []).append(observation)

    timeline: list[dict[str, Any]] = []
    for assertion_key, items in grouped.items():
        ordered = _sort_observations(items)
        previous_value: Any = None
        highest_version: tuple[Any, ...] = ()
        for order, observation in enumerate(ordered):
            value = observation.get("value")
            version = observation.get("policy_version")
            inferred = None
            if order > 0 and not values_equal(previous_value, value):
                inferred = "overwrite"
                current_version = version_key(version)
                if version and highest_version and current_version and current_version < highest_version:
                    inferred = "rollback"
                elif observation.get("compliant") is False and any(item.get("compliant") for item in ordered[:order]):
                    inferred = "regression"
            explicit = observation.get("event_type")
            event_type = explicit or inferred or ("initial" if order == 0 else "unchanged")
            if explicit == "rollback":
                event_type = "rollback"
            timeline.append(
                {
                    "order": order,
                    "assertion_key": assertion_key,
                    "observation_id": observation["observation_id"],
                    "chronology_at": observation.get("chronology_at"),
                    "event_type": event_type,
                    "inferred_change": inferred,
                    "value": value,
                    "policy_version": version,
                    "compliant": observation.get("compliant"),
                    "evidence_set_id": observation.get("evidence_set_id"),
                    "ticket": observation.get("ticket"),
                    "source": observation.get("source"),
                }
            )
            previous_value = value
            if version:
                highest_version = max(highest_version, version_key(version), key=lambda item: item or ())

    timeline.sort(key=lambda item: (item.get("chronology_at") or "", item["assertion_key"], item["order"]))
    for index, item in enumerate(timeline, 1):
        item["timeline_id"] = f"EVT-{index:03d}"
    return timeline


def _matching_approvals(approvals: list[dict[str, Any]], device_id: str) -> list[dict[str, Any]]:
    key = device_id.casefold()
    return [item for item in approvals if str(item.get("device_id") or "").casefold() == key]


def _material(code: str, material: str, why: str, *, command: str | None = None) -> dict[str, Any]:
    result = {"code": code, "material": material, "why": why}
    if command:
        result["suggested_command"] = command
    return result


def _dedupe_materials(materials: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    result = []
    for item in materials:
        key = (item.get("code", ""), item.get("material", ""))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def evaluate_policy_subject(
    *,
    policy_id: Any,
    observations: list[dict[str, Any]],
    device_approvals: list[dict[str, Any]],
    policy_by_version: dict[tuple[Any, str | None], dict[str, Any]],
    policies_by_id: dict[Any, list[dict[str, Any]]],
    as_of: datetime,
    collection_errors: list[str],
    plugin_names: list[str],
    default_ttl_days: int | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    findings: list[str] = []
    materials: list[dict[str, Any]] = []

    policy_observations = [item for item in observations if item.get("policy_id") == policy_id]
    ordered = _sort_observations(policy_observations)
    timeline = _build_timeline(policy_observations)
    versions = sorted({item["policy_version"] for item in ordered if item.get("policy_version")}, key=version_key)
    chronological = _sort_observations(policy_observations)
    current_version = next((item.get("policy_version") for item in reversed(chronological) if item.get("policy_version")), None)
    highest_version = versions[-1] if versions else None
    target_version = current_version or highest_version
    spec = policy_by_version.get((policy_id, highest_version)) if highest_version else None
    policy_specs = policies_by_id.get(policy_id, [])
    if spec is None and policy_specs:
        exact = [item for item in policy_specs if item.get("version") == highest_version]
        spec = exact[0] if exact else policy_specs[-1]
    if spec is None:
        spec = {
            "policy_id": policy_id,
            "version": highest_version,
            "evidence_valid_days": default_ttl_days,
            "requirements": [],
        }

    missing_version = not versions or any(not item.get("policy_version") for item in policy_observations)
    if missing_version:
        reasons.append("MISSING_POLICY_VERSION")
        materials.append(
            _material(
                "MISSING_POLICY_VERSION",
                "版本化安全策略基线、ADMX/策略导出注册表值，以及标明 policy_id/version/hash 的变更或回滚单",
                "插件证据或审批档案中缺少可核对的政策版本，不能确认现场落地的是哪一版。",
                command="regipy-plugins-run <HIVE> -p execution_policy -o <DEVICE>_plugins.json",
            )
        )
        materials.append(
            _material(
                "MISSING_VERSIONED_APPROVAL",
                "独立档案中针对该 policy_id + policy_version 的解除保全批准或补签",
                "现有批准不能用于版本不明或版本不匹配的策略状态。",
            )
        )

    if spec.get("evidence_valid_days") is None and not any(item.get("expires_at") for item in ordered):
        reasons.append("MISSING_VALIDITY_WINDOW")
        materials.append(
            _material(
                "MISSING_VALIDITY_WINDOW",
                "合规制度中插件/注册表离线证据的有效期天数，或证据包的 valid_until 字段",
                "缺少有效期无法判断审查基准日时证据是否仍有效。",
            )
        )

    if collection_errors:
        reasons.append("EVIDENCE_COLLECTION_ERROR")
        for error in collection_errors:
            materials.append(
                _material(
                    "EVIDENCE_COLLECTION_ERROR",
                    "可成功解析的离线 hive、事务日志或 regipy-plugins-run JSON 导出",
                    error,
                    command="regipy-plugins-run <HIVE> -o <DEVICE>_plugins.json --include-unvalidated --continue-on-error",
                )
            )

    state_changes = [
        item for item in timeline if item.get("event_type") in {"apply", "overwrite", "rollback", "regression", "initial"}
    ]
    rollbacks = [item for item in timeline if item.get("event_type") == "rollback"]
    last_rollback = max(rollbacks, key=lambda item: item.get("chronology_at") or "") if rollbacks else None
    last_change = max(state_changes, key=lambda item: item.get("chronology_at") or "") if state_changes else None

    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in ordered:
        grouped.setdefault(item["assertion_key"], []).append(item)
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    final_observations = {
        key: max(items, key=lambda item: parse_datetime(item.get("chronology_at")) or epoch) for key, items in grouped.items()
    }

    required_keys = {
        requirement_key(req): req for req in (spec or {}).get("requirements", []) if req.get("plugin") and req.get("field")
    }
    missing_assertions = sorted(set(required_keys) - set(final_observations))
    if missing_assertions:
        reasons.append("MISSING_REQUIRED_PLUGIN_EVIDENCE")
        for key in missing_assertions:
            req = required_keys[key]
            plugin_name = req.get("plugin")
            materials.append(
                _material(
                    "MISSING_REQUIRED_PLUGIN_EVIDENCE",
                    f"插件 {plugin_name} 的离线 hive/JSON 证据，指标 {req.get('field')} 及选择器 {canonical_value(req.get('where') or {})}",
                    "政策基线要求的指标没有出现在证据中。",
                    command=f"regipy-plugins-run <HIVE> -p {plugin_name} -o <DEVICE>_{plugin_name}.json",
                )
            )

    unknown_compliance = [key for key, item in final_observations.items() if item.get("compliant") is None]
    if unknown_compliance:
        reasons.append("COMPLIANCE_EXPECTATION_UNKNOWN")
        materials.append(
            _material(
                "COMPLIANCE_EXPECTATION_UNKNOWN",
                "每个指标的期望值/允许值清单，或在标准化证据中补充 compliant 判定",
                f"以下指标缺少期望值：{', '.join(unknown_compliance)}",
            )
        )

    noncompliant_final = [key for key, item in final_observations.items() if item.get("compliant") is False]
    if noncompliant_final:
        reasons.append("FINAL_STATE_NONCOMPLIANT")

    recovered_after_rollback = True
    confirming_observations = list(final_observations.values())
    if last_rollback:
        rollback_dt = parse_datetime(last_rollback.get("chronology_at")) or epoch
        confirming_observations = []
        for _key, items in grouped.items():
            later_compliant = [
                item
                for item in items
                if item.get("compliant") is True and (parse_datetime(item.get("chronology_at")) or epoch) > rollback_dt
            ]
            if later_compliant:
                confirming_observations.append(
                    max(later_compliant, key=lambda item: parse_datetime(item.get("chronology_at")) or epoch)
                )
            else:
                recovered_after_rollback = False
        if not recovered_after_rollback:
            reasons.append("LAST_ROLLBACK_WITHOUT_RECOVERY")
            findings.append("最后一次状态变更是回滚，且其后没有完整、合规的插件证据证明已重新落地。")

    if not final_observations:
        reasons.append("NO_PLUGIN_OBSERVATIONS")
        materials.append(
            _material(
                "NO_PLUGIN_OBSERVATIONS",
                "该设备的离线 hive、LOG1/LOG2 或 regipy-plugins-run JSON 导出",
                "没有任何可用于确认安全策略落地的插件证据。",
                command="regipy-plugins-run <HIVE> -o <DEVICE>_plugins.json --include-unvalidated --continue-on-error",
            )
        )

    evidence_valid = True
    validity_details: dict[str, Any] = {"as_of": iso(as_of), "earliest_expires_at": None, "oldest_collected_at": None}
    if confirming_observations:
        ttl_days = (spec or {}).get("evidence_valid_days")
        expiration_dates: list[datetime] = []
        collection_dates: list[datetime] = []
        for item in confirming_observations:
            collected_dt = parse_datetime(item.get("collected_at"))
            explicit_expiry = parse_datetime(item.get("expires_at"))
            if explicit_expiry:
                expiration_dates.append(explicit_expiry)
            elif item.get("collection_time_explicit") and collected_dt and ttl_days is not None:
                expiration_dates.append(collected_dt + timedelta(days=int(ttl_days)))
            else:
                evidence_valid = False
                reasons.append("EVIDENCE_TIME_OR_TTL_UNVERIFIABLE")
                materials.append(
                    _material(
                        "EVIDENCE_TIME_OR_TTL_UNVERIFIABLE",
                        "显式 collected_at 采集时间、证据包 valid_until，或策略目录中的 evidence_valid_days",
                        "无法严格证明证据在审查基准日仍处于有效期。",
                    )
                )
            if item.get("collection_time_explicit") and collected_dt:
                collection_dates.append(collected_dt)
            if not item.get("collection_time_explicit") and not explicit_expiry:
                if "EVIDENCE_COLLECTION_TIME_INFERRED" not in reasons:
                    reasons.append("EVIDENCE_COLLECTION_TIME_INFERRED")
                materials.append(
                    _material(
                        "EVIDENCE_COLLECTION_TIME_MISSING",
                        "证据包采集时间、SHA-256 哈希清单和监管链记录",
                        "当前只能用注册表 last_write 推断时间，不能严格证明证据在有效期内采集。",
                    )
                )
        if collection_dates:
            validity_details["oldest_collected_at"] = iso(min(collection_dates))
        if expiration_dates:
            earliest_expiry = min(expiration_dates)
            validity_details["earliest_expires_at"] = iso(earliest_expiry)
            validity_details["valid"] = earliest_expiry >= as_of
            if earliest_expiry < as_of:
                evidence_valid = False
                reasons.append("EVIDENCE_EXPIRED")
                materials.append(
                    _material(
                        "EVIDENCE_EXPIRED",
                        f"审查基准日 {iso(as_of)} 之前仍在有效期内的重新采集 hive/regipy 插件 JSON",
                        f"支撑落地的证据最早于 {iso(earliest_expiry)} 到期。",
                        command="regipy-plugins-run <HIVE> -o <DEVICE>_plugins_fresh.json --include-unvalidated",
                    )
                )
        else:
            evidence_valid = False
            reasons.append("MISSING_EVIDENCE_DATE_OR_TTL")
            materials.append(
                _material(
                    "MISSING_EVIDENCE_DATE_OR_TTL",
                    "每条证据的 collected_at/valid_until，或策略目录中的 evidence_valid_days",
                    "无法计算证据到期时间。",
                )
            )

    matching_approvals = [item for item in device_approvals if item.get("policy_id") in (policy_id, None)]
    valid_approvals: list[dict[str, Any]] = []
    approval_problems: list[str] = []
    for approval in matching_approvals:
        problems: list[str] = []
        if approval.get("policy_id") is None:
            problems.append("APPROVAL_POLICY_ID_MISSING")
        if missing_version or approval.get("policy_version") in (None, ""):
            problems.append("APPROVAL_POLICY_VERSION_MISSING")
        elif target_version and str(approval.get("policy_version")) != str(target_version):
            problems.append("APPROVAL_VERSION_MISMATCH")
        if approval.get("decision") != "approved" or not approval.get("is_positive"):
            problems.append("APPROVAL_NOT_POSITIVE")
        decided_dt = parse_datetime(approval.get("decided_at"))
        last_change_dt = parse_datetime(last_change.get("chronology_at")) if last_change else None
        if not decided_dt:
            problems.append("APPROVAL_TIME_MISSING")
        elif last_change_dt and decided_dt <= last_change_dt:
            problems.append("APPROVAL_BEFORE_LAST_CHANGE")
        if approval.get("effective_at") and parse_datetime(approval["effective_at"]) > as_of:
            problems.append("APPROVAL_NOT_EFFECTIVE")
        if approval.get("expires_at") and parse_datetime(approval["expires_at"]) < as_of:
            problems.append("APPROVAL_EXPIRED")
        approval["validation_problems"] = problems
        approval_problems.extend(problems)
        if not problems:
            valid_approvals.append(approval)

    approval_basis = max(valid_approvals, key=lambda item: item.get("decided_at") or "") if valid_approvals else None
    if not approval_basis:
        reasons.append("MISSING_VALID_RELEASE_APPROVAL")
        unique_problems = sorted(set(approval_problems))
        if unique_problems:
            reasons.extend(unique_problems)
        materials.append(
            _material(
                "MISSING_VALID_RELEASE_APPROVAL",
                "独立档案中设备、policy_id、policy_version、批准时间、生效时间、批准人和条款定位齐全的解除保全记录",
                "未找到可匹配最终策略状态且在最后变更之后作出的有效批准。"
                + (f" 已见档案问题：{', '.join(unique_problems)}" if unique_problems else ""),
            )
        )

    final_compliance = bool(final_observations) and all(item.get("compliant") is True for item in final_observations.values())
    implementation_confirmed = final_compliance and (not last_rollback or recovered_after_rollback) and not missing_assertions
    releasable = (
        implementation_confirmed
        and evidence_valid
        and approval_basis is not None
        and not missing_version
        and not collection_errors
    )
    hard_preserve = "LAST_ROLLBACK_WITHOUT_RECOVERY" in reasons or "FINAL_STATE_NONCOMPLIANT" in reasons
    status = STATUS_READY if releasable else STATUS_PRESERVE if hard_preserve else STATUS_MATERIALS

    if last_rollback and not recovered_after_rollback:
        rollback_source = last_rollback.get("source") or {}
        findings.append(
            "最后回滚事件 "
            f"{last_rollback.get('timeline_id')} 发生于 {last_rollback.get('chronology_at')}，"
            "回滚后缺少完整合规证据；来源 "
            f"{rollback_source.get('path')}#{rollback_source.get('locator')}。"
        )
    elif implementation_confirmed:
        findings.append("最终插件值均符合版本化基线，来回覆盖已按时间线还原到最终状态。")

    return {
        "policy_id": policy_id,
        "disposition": DISPOSITION_RELEASE if releasable else DISPOSITION_PRESERVE,
        "status": status,
        "releasable": releasable,
        "target_policy_version": target_version,
        "current_policy_version": current_version,
        "highest_policy_version": highest_version,
        "versions_seen": versions,
        "missing_policy_version": missing_version,
        "implementation_confirmed": implementation_confirmed,
        "evidence_valid": evidence_valid,
        "validity": validity_details,
        "last_rollback": last_rollback,
        "last_state_change": last_change,
        "final_observations": list(final_observations.values()),
        "timeline": timeline,
        "approval_basis": approval_basis,
        "approval_candidates": matching_approvals,
        "reasons": sorted(set(reasons)),
        "findings": findings,
        "materials_needed": _dedupe_materials(materials),
        "plugin_names": plugin_names,
    }


def evaluate_device(
    device: dict[str, Any],
    *,
    index: int,
    ctx: CaseContext,
    approvals: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    as_of: datetime,
    default_ttl_days: int | None = None,
) -> dict[str, Any]:
    device_id = str(_first(device, "device_id", "id", "hostname", "name", default=f"DEVICE-{index + 1}"))
    device["_index"] = index
    observations, artifacts, collection_errors = collect_device_evidence(device, ctx, policies)
    device_approvals = _matching_approvals(approvals, device_id)
    policy_by_version, policies_by_id = _policy_maps(policies)

    policy_ids: list[Any] = []
    policy_sources = observations + device_approvals
    for value in [item.get("policy_id") for item in policy_sources]:
        if value not in (None, "") and value not in policy_ids:
            policy_ids.append(value)
    device_policy = device.get("policy") if isinstance(device.get("policy"), dict) else {}
    for value in [_first(device, "policy_id", "policy", "control_id"), device_policy.get("policy_id")]:
        if value not in (None, "") and value not in policy_ids:
            policy_ids.append(value)
    if not policy_ids:
        policy_ids = [None]

    plugin_names = sorted({item.get("plugin_name") for item in observations if item.get("plugin_name")})
    policy_results = [
        evaluate_policy_subject(
            policy_id=policy_id,
            observations=observations,
            device_approvals=device_approvals,
            policy_by_version=policy_by_version,
            policies_by_id=policies_by_id,
            as_of=as_of,
            collection_errors=collection_errors,
            plugin_names=plugin_names,
            default_ttl_days=_first(device, "evidence_valid_days", default=default_ttl_days),
        )
        for policy_id in policy_ids
    ]

    releasable = all(item["releasable"] for item in policy_results) and bool(policy_results)
    if releasable:
        status = STATUS_READY
    elif any(item["status"] == STATUS_PRESERVE for item in policy_results):
        status = STATUS_PRESERVE
    else:
        status = STATUS_MATERIALS

    materials: list[dict[str, Any]] = []
    reasons: list[str] = []
    findings: list[str] = []
    approval_basis = None
    last_rollback = None
    for result in policy_results:
        materials.extend(result["materials_needed"])
        reasons.extend(result["reasons"])
        findings.extend(result["findings"])
        if result.get("approval_basis") and approval_basis is None:
            approval_basis = result["approval_basis"]
        if result.get("last_rollback") and last_rollback is None:
            last_rollback = result["last_rollback"]

    return {
        "device_id": device_id,
        "batch": _first(device, "batch", "batch_name", "wave"),
        "asset": {key: device.get(key) for key in ("hostname", "ip", "owner", "case_label") if device.get(key)},
        "disposition": DISPOSITION_RELEASE if releasable else DISPOSITION_PRESERVE,
        "status": status,
        "releasable": releasable,
        "policy_results": policy_results,
        "observations": observations,
        "evidence_artifacts": artifacts,
        "collection_errors": collection_errors,
        "approval_records": device_approvals,
        "approval_basis": approval_basis,
        "last_rollback": last_rollback,
        "reasons": sorted(set(reasons)),
        "findings": findings,
        "materials_needed": _dedupe_materials(materials),
        "duplicate_group_ids": [],
    }


def build_duplicate_groups(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    occurrences: dict[tuple[Any, str, str], list[dict[str, Any]]] = {}
    for device in devices:
        for observation in device.get("observations", []):
            if observation.get("value") is None:
                continue
            digest = value_digest(observation.get("value"))
            key = (observation.get("policy_id"), str(observation.get("assertion_key")), digest)
            occurrences.setdefault(key, []).append(
                {
                    "device_id": device["device_id"],
                    "observation_id": observation["observation_id"],
                    "event_type": observation.get("event_type"),
                    "chronology_at": observation.get("chronology_at"),
                    "evidence_set_id": observation.get("evidence_set_id"),
                    "source": observation.get("source"),
                }
            )

    groups: list[dict[str, Any]] = []
    for _index, ((policy_id, assertion_key, digest), items) in enumerate(occurrences.items(), 1):
        device_ids = sorted({item["device_id"] for item in items})
        if len(device_ids) < 2:
            continue
        value: Any = None
        plugin_name = None
        field_name = None
        for device in devices:
            for observation in device["observations"]:
                if observation.get("assertion_key") == assertion_key and value_digest(observation.get("value")) == digest:
                    value = observation.get("value")
                    plugin_name = observation.get("plugin_name")
                    field_name = observation.get("field")
                    break
            if value is not None:
                break
        group_id = f"DUP-{len(groups) + 1:03d}"
        groups.append(
            {
                "group_id": group_id,
                "policy_id": policy_id,
                "assertion_key": assertion_key,
                "plugin_name": plugin_name,
                "field": field_name,
                "value": value,
                "value_sha256": digest,
                "device_ids": device_ids,
                "cross_device": True,
                "occurrence_count": len(items),
                "occurrences": sorted(items, key=lambda item: item.get("chronology_at") or ""),
            }
        )

    for index, group in enumerate(sorted(groups, key=lambda item: (item.get("policy_id") or "", item["assertion_key"])), 1):
        group["group_id"] = f"DUP-{index:03d}"
        for device in devices:
            if device["device_id"] in group["device_ids"]:
                device["duplicate_group_ids"].append(group["group_id"])
    return sorted(groups, key=lambda item: item["group_id"])


def evaluate_case(
    case: dict[str, Any],
    *,
    ctx: CaseContext | None = None,
    case_dir: str | Path | None = None,
) -> dict[str, Any]:
    if ctx is None:
        ctx = CaseContext(case_dir=Path(case_dir).resolve() if case_dir else Path.cwd().resolve())
    as_of = parse_datetime(case.get("as_of") or case.get("review_date")) or datetime.now(timezone.utc)
    policies = load_policy_catalog(case, ctx)
    approvals = load_approvals(case, ctx)
    default_ttl_days = _first(case, "evidence_valid_days", "default_evidence_valid_days")
    raw_devices = case.get("devices") or []
    devices = [
        evaluate_device(
            device,
            index=index,
            ctx=ctx,
            approvals=approvals,
            policies=policies,
            as_of=as_of,
            default_ttl_days=int(default_ttl_days) if default_ttl_days is not None else None,
        )
        for index, device in enumerate(raw_devices)
        if isinstance(device, dict)
    ]
    duplicate_groups = build_duplicate_groups(devices)

    release_list = [
        {
            "device_id": device["device_id"],
            "batch": device.get("batch"),
            "approval_basis": device.get("approval_basis"),
            "duplicate_group_ids": device.get("duplicate_group_ids"),
            "evidence_artifacts": device.get("evidence_artifacts"),
        }
        for device in devices
        if device["releasable"]
    ]
    hold_list = [
        {
            "device_id": device["device_id"],
            "status": device["status"],
            "reasons": device["reasons"],
            "last_rollback": device.get("last_rollback"),
            "materials_needed": device["materials_needed"],
        }
        for device in devices
        if not device["releasable"]
    ]

    all_materials: list[dict[str, Any]] = []
    for device in devices:
        for material in device["materials_needed"]:
            item = {"device_id": device["device_id"], **material}
            if item not in all_materials:
                all_materials.append(item)

    return {
        "case_id": _first(case, "case_id", "id", "name", default="UNNAMED-CASE"),
        "generated_at": iso(datetime.now(timezone.utc)),
        "as_of": iso(as_of),
        "reviewer": case.get("reviewer"),
        "standard": case.get("standard"),
        "summary": {
            "device_count": len(devices),
            "ready_for_release": len(release_list),
            "preserve": sum(1 for device in devices if device["status"] == STATUS_PRESERVE),
            "materials_required": sum(1 for device in devices if device["status"] == STATUS_MATERIALS),
            "cross_device_duplicate_groups": len(duplicate_groups),
        },
        "release_list": release_list,
        "hold_list": hold_list,
        "materials_required": all_materials,
        "duplicate_values": duplicate_groups,
        "devices": devices,
        "approvals": approvals,
        "source_files": list(ctx.source_files.values()),
    }


def load_case_report(case_path: str | Path) -> dict[str, Any]:
    path = Path(case_path)
    case = json.loads(path.read_text(encoding="utf-8-sig"))
    ctx = CaseContext.from_path(path)
    return evaluate_case(case, ctx=ctx)


def _short_digest(digest: str | None) -> str:
    return digest[:12] if digest else "未计算/文件缺失"


def _md_text(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text or "—"


def _source_label(source: dict[str, Any] | None) -> str:
    if not source:
        return "来源缺失"
    location = source.get("path") or "<inline>"
    locator = source.get("locator")
    if locator:
        location = f"{location}#{locator}"
    return f"{location}（sha256:{_short_digest(source.get('sha256'))}）"


def _display_value(value: Any, limit: int = 80) -> str:
    text = value if isinstance(value, str) else canonical_value(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _status_label(status: str) -> str:
    return {
        STATUS_READY: "可解除保全",
        STATUS_PRESERVE: "继续保全（已有回滚/不合规证据）",
        STATUS_MATERIALS: "继续保全（待补材料后复核）",
    }.get(status, status)


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    summary = report["summary"]
    lines.extend(
        [
            f"# {report.get('case_id')} 离线处置解除清单",
            "",
            f"- 审查基准日：{report.get('as_of')}",
            f"- 清单生成时间：{report.get('generated_at')}",
            f"- 审查人：{_md_text(report.get('reviewer'))}",
            f"- 判定标准：{_md_text(report.get('standard'))}",
            f"- 设备数：**{summary['device_count']}**；可解除：**{summary['ready_for_release']}**；"
            f"明确保全：**{summary['preserve']}**；待补材料：**{summary['materials_required']}**；"
            f"跨设备重复值组：**{summary['cross_device_duplicate_groups']}**",
            "",
            "## 一、释放清单",
            "",
        ]
    )

    if report["release_list"]:
        lines.extend(
            [
                "| 设备 | 批次 | 策略/版本 | 批准依据位置 | 批准时间 | 证据到期 | 重复值组 |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in report["release_list"]:
            approval = item.get("approval_basis") or {}
            device = next((d for d in report["devices"] if d["device_id"] == item["device_id"]), {})
            primary_policy = device.get("policy_results", [{}])[0] if device.get("policy_results") else {}
            validity = primary_policy.get("validity", {})
            version = primary_policy.get("target_policy_version") or "版本缺失"
            policy_label = f"{primary_policy.get('policy_id') or '未指定'} / {version}"
            duplicate_ids = ", ".join(item.get("duplicate_group_ids") or []) or "—"
            lines.append(
                "| {device} | {batch} | {policy} | {source}；记录 {record}；{ref} | {decided} | {expires} | {duplicates} |".format(
                    device=_md_text(item["device_id"]),
                    batch=_md_text(item.get("batch")),
                    policy=_md_text(policy_label),
                    source=_md_text(_source_label(approval.get("source"))),
                    record=_md_text(approval.get("record_id")),
                    ref=_md_text(approval.get("reference") or approval.get("approver")),
                    decided=_md_text(approval.get("decided_at")),
                    expires=_md_text(validity.get("earliest_expires_at")),
                    duplicates=_md_text(duplicate_ids),
                )
            )
        lines.append("")
    else:
        lines.extend(["**当前没有任何设备满足解除条件。**", ""])

    lines.extend(["## 二、逐台处置结论", ""])
    for device in report["devices"]:
        lines.extend(
            [
                f"### {device['device_id']} — {_status_label(device['status'])}",
                "",
                f"- 批次：{_md_text(device.get('batch'))}",
                f"- 处置决定：**{'解除保全' if device['releasable'] else '继续保全'}**",
            ]
        )
        for finding in device.get("findings", []):
            lines.append(f"- 判定事实：{_md_text(finding)}")
        if device.get("reasons"):
            lines.append(f"- 原因代码：{_md_text(', '.join(device['reasons']))}")

        for policy_result in device.get("policy_results", []):
            versions = ", ".join(policy_result.get("versions_seen") or []) or "缺失"
            lines.append(
                f"- 策略：{_md_text(policy_result.get('policy_id'))}；所见版本：{_md_text(versions)}；"
                f"最终版本：{_md_text(policy_result.get('target_policy_version') or '无法确认')}"
            )
            if policy_result.get("last_rollback"):
                rollback = policy_result["last_rollback"]
                lines.append(
                    "- 最后回滚："
                    f"{rollback.get('timeline_id')} / {rollback.get('chronology_at')} / "
                    f"值 {_display_value(rollback.get('value'))}；来源 {_source_label(rollback.get('source'))}"
                )
            approval = policy_result.get("approval_basis")
            if approval:
                lines.append(f"- 批准依据：{approval.get('record_id')}，{_source_label(approval.get('source'))}")
                if approval.get("reference"):
                    lines.append(f"  - 条款/档案位置：{_md_text(approval['reference'])}")
                lines.append(f"  - 同意时间：{approval.get('decided_at')}；批准人：{_md_text(approval.get('approver'))}")
            else:
                lines.append("- 批准依据：未找到可匹配最终版本和最后变更时间的有效独立批准。")
            invalid = [item for item in policy_result.get("approval_candidates") or [] if item.get("validation_problems")]
            if invalid:
                lines.append("- 已见但不能作为依据的批准/档案：")
                for candidate in invalid:
                    lines.append(
                        f"  - {_md_text(candidate.get('record_id'))} "
                        f"{_source_label(candidate.get('source'))}；"
                        f"问题：{_md_text(', '.join(candidate.get('validation_problems') or []))}"
                    )

            timeline = policy_result.get("timeline") or []
            if timeline:
                lines.extend(
                    [
                        "",
                        "| 事件 | 时间 | 类型 | 指标 | 版本 | 值 | 合规 | 来源 |",
                        "| --- | --- | --- | --- | --- | --- | --- | --- |",
                    ]
                )
                for event in timeline:
                    compliant = {True: "是", False: "否"}.get(event.get("compliant"), "未知")
                    lines.append(
                        "| {eid} | {when} | {kind} | {indicator} | {version} | {value} | {ok} | {source} |".format(
                            eid=_md_text(event.get("timeline_id")),
                            when=_md_text(event.get("chronology_at")),
                            kind=_md_text(event.get("event_type")),
                            indicator=_md_text(event.get("assertion_key")),
                            version=_md_text(event.get("policy_version")),
                            value=_md_text(_display_value(event.get("value"), 50)),
                            ok=compliant,
                            source=_md_text(_source_label(event.get("source"))),
                        )
                    )
        if device.get("materials_needed"):
            lines.extend(
                ["", "**需要补充的具体材料**", "", "| 代码 | 材料 | 原因/验证点 | 建议命令 |", "| --- | --- | --- | --- |"]
            )
            for material in device["materials_needed"]:
                lines.append(
                    "| {code} | {material} | {why} | {command} |".format(
                        code=_md_text(material.get("code")),
                        material=_md_text(material.get("material")),
                        why=_md_text(material.get("why")),
                        command=_md_text(material.get("suggested_command") or "—"),
                    )
                )
        lines.append("")

    lines.extend(["## 三、不同设备间重复值", ""])
    if report["duplicate_values"]:
        lines.extend(
            [
                "| 组 | 策略/指标 | 值摘要 | 值 SHA-256 | 设备 | 出现次数 | 说明 |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for group in report["duplicate_values"]:
            lines.append(
                "| {gid} | {policy} / {indicator} | {value} | {digest} | {devices} | {count} | 重复值只合并证据指纹，不合并设备结论或批准 |".format(
                    gid=_md_text(group["group_id"]),
                    policy=_md_text(group.get("policy_id")),
                    indicator=_md_text(group.get("assertion_key")),
                    value=_md_text(_display_value(group.get("value"), 48)),
                    digest=_md_text(group.get("value_sha256")),
                    devices=_md_text(", ".join(group.get("device_ids") or [])),
                    count=group.get("occurrence_count"),
                )
            )
        lines.append("")
    else:
        lines.extend(["未发现跨设备重复值组。", ""])

    lines.extend(["## 四、来源文件完整性", "", "| 文件 | SHA-256 |", "| --- | --- |"])
    for source in report.get("source_files", []):
        lines.append(f"| {_md_text(source.get('path'))} | {_md_text(source.get('sha256'))} |")
    if not report.get("source_files"):
        lines.append("| 无外部文件 | — |")
    lines.append("")
    lines.append("> 本清单由 regipy.disposition 离线生成；注册表解析来自 regipy，批准档案仅作来源关联，不替代原件核验。")
    return "\n".join(lines)


def build_arg_parser() -> Any:
    import argparse

    parser = argparse.ArgumentParser(description="Generate an auditable registry evidence legal-hold release list.")
    parser.add_argument("case_manifest", help="Path to the JSON case manifest")
    parser.add_argument("-o", "--output", help="Markdown report output path; defaults to stdout")
    parser.add_argument("--json-output", help="Optional machine-readable JSON report path")
    parser.add_argument("--as-of", help="Override review date/time (ISO 8601)")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any device is not releasable")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    case_path = Path(args.case_manifest)
    case = json.loads(case_path.read_text(encoding="utf-8-sig"))
    if args.as_of:
        case["as_of"] = args.as_of
    report = evaluate_case(case, ctx=CaseContext.from_path(case_path))

    markdown = render_markdown(report)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
    else:
        print(markdown)

    if args.json_output:
        json_path = Path(args.json_output)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    if args.strict and report["summary"]["ready_for_release"] != report["summary"]["device_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
