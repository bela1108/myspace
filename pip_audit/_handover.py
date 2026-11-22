"""
Build and reconcile disclosure-safe handover packages from offline `pip-audit` output.

The handover format is intentionally narrow. It binds the original remediation
plan and offline audit result by digest, discloses only package identities,
target versions, environment-confirmed versions, vulnerability identifiers, and
acceptance materials, and never copies index URLs, artifact URLs, or local
paths from its inputs.

Receipt closure is material-based rather than count-based. Receiving the same
item more than once is idempotent: duplicate lines are recorded, but they do not
add a second occurrence or advance an item toward closure. An item closes only
when every required material is present and the confirmed version matches the
plan target.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

SCHEMA_VERSION = 1
PACKAGE_KIND = "pip-audit-handover"
RECEIPT_KIND = "pip-audit-handover-receipt"
STATE_KIND = "pip-audit-handover-state"

DEFAULT_EVIDENCE = ("fixed_version", "vulnerability_recheck")
_MATERIAL_ALIASES = {
    "artifact_digest": "artifact_digest",
    "artifact_hash": "artifact_digest",
    "artifact_sha256": "artifact_digest",
    "clean_recheck": "vulnerability_recheck",
    "environment_confirmation": "environment_confirmation",
    "environment_version": "environment_confirmation",
    "fixed_version": "fixed_version",
    "install_version": "fixed_version",
    "recheck": "vulnerability_recheck",
    "remediated_version": "fixed_version",
    "version": "fixed_version",
    "vulnerability_recheck": "vulnerability_recheck",
}
_KNOWN_MATERIALS = frozenset(_MATERIAL_ALIASES.values())
_CLEAN_VALUES = frozenset(
    {"clean", "clear", "no-findings", "pass", "passed", "remediated", "resolved"}
)
_HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_URL_PATTERN = re.compile(r"^(?:https?|ftp|file)://", re.IGNORECASE)
_PATH_PATTERN = re.compile(r"^(?:/|~[/\\]|[A-Za-z]:[\\/]|\\\\)")
_FORBIDDEN_KEYS = frozenset(
    {
        "cache_dir",
        "file",
        "file_name",
        "filename",
        "index_url",
        "index_urls",
        "extra_index_url",
        "extra_index_urls",
        "location",
        "path",
        "paths",
        "source_path",
        "url",
        "urls",
        "uri",
        "uris",
    }
)

JsonSource = Mapping[str, Any] | Sequence[Any] | bytes | bytearray | str | Path


class HandoverError(ValueError):
    """Raised when handover inputs or state are invalid."""


class HandoverIntegrityError(HandoverError):
    """Raised when a package, item, or receipt fails its digest binding."""


class HandoverReceiptError(HandoverError):
    """Raised when a receipt cannot be applied to a handover package."""


@dataclass(frozen=True)
class PlanItem:
    """A normalized item from the original remediation plan."""

    item_id: str
    package: str
    target_version: str
    vulnerability_ids: tuple[str, ...]
    required_evidence: tuple[str, ...]


def _canonical_json(value: Any) -> bytes:
    """Serialize a value deterministically for hashing."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest for bytes."""
    return hashlib.sha256(value).hexdigest()


def _sha256_obj(value: Any) -> str:
    """Return the SHA-256 digest of a value's canonical JSON representation."""
    return _sha256(_canonical_json(value))


def _load_json_source(source: JsonSource, label: str) -> tuple[Any, str]:
    """
    Load an in-memory JSON value, JSON text, or file path and return its digest.

    A path is read once so the digest binds the exact bytes supplied, not a
    subsequent reserialization of the parsed JSON.
    """
    if isinstance(source, Path):
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise HandoverError(f"unable to read {label} input") from exc
    elif isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
    elif isinstance(source, str):
        candidate = Path(source)
        try:
            is_file = candidate.is_file()
        except OSError:
            is_file = False
        raw = candidate.read_bytes() if is_file else source.encode("utf-8")
    elif isinstance(source, (Mapping, Sequence)):
        raw = _canonical_json(source)
    else:
        raise HandoverError(f"unsupported {label} input type: {type(source).__name__}")

    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoverError(f"{label} input is not valid JSON") from exc

    return parsed, _sha256(raw)


def _load_receipt_source(source: JsonSource) -> tuple[Any, str]:
    """Load a JSON receipt or a plain-text list of rotated names."""
    if isinstance(source, Path):
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise HandoverError("unable to read receipt input") from exc
    elif isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
    elif isinstance(source, str):
        candidate = Path(source)
        try:
            is_file = candidate.is_file()
        except OSError:
            is_file = False
        raw = candidate.read_bytes() if is_file else source.encode("utf-8")
    elif isinstance(source, (Mapping, Sequence)):
        raw = _canonical_json(source)
    else:
        raise HandoverError(f"unsupported receipt input type: {type(source).__name__}")

    digest = _sha256(raw)
    try:
        return json.loads(raw), digest
    except (UnicodeDecodeError, json.JSONDecodeError):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HandoverError("receipt input is neither valid JSON nor UTF-8 text") from exc
        names = [name for name in re.split(r"[\s,;]+", text.strip()) if name]
        return {"items": names}, digest


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    """Require a JSON object at the given location."""
    if not isinstance(value, Mapping):
        raise HandoverError(f"{label} must be a JSON object")
    return cast(Mapping[str, Any], value)


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    """Return the first present, non-null value for the supplied keys."""
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _normalize_material(value: Any) -> str:
    """Normalize an evidence or required-material name."""
    if not isinstance(value, str):
        raise HandoverError("required evidence entries must be strings")
    normalized = value.strip().lower().replace("-", "_")
    material = _MATERIAL_ALIASES.get(normalized)
    if material is None:
        known = ", ".join(sorted(_KNOWN_MATERIALS))
        raise HandoverError(f"unknown required evidence {value!r}; expected one of: {known}")
    return material


def _normalize_plan(raw: Any) -> tuple[str, list[PlanItem], str]:
    """Normalize a remediation plan without copying unneeded source fields."""
    mapping = _as_mapping(raw, "remediation plan")
    plan_id = _first(mapping, "plan_id", "id", "name")
    if plan_id is None:
        plan_id = "remediation-plan"
    if not isinstance(plan_id, str) or not plan_id.strip():
        raise HandoverError("remediation plan ID must be a non-empty string")
    plan_id = plan_id.strip()
    if _URL_PATTERN.search(plan_id) or _PATH_PATTERN.search(plan_id):
        raise HandoverError("remediation plan ID is not disclosable")

    raw_items = _first(mapping, "items", "findings", "remediations", "packages")
    if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes, bytearray)):
        raise HandoverError("remediation plan must contain an items array")

    items: list[PlanItem] = []
    seen_ids: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        item = _as_mapping(raw_item, f"remediation plan item #{index}")
        target = item.get("target")
        target_mapping = target if isinstance(target, Mapping) else {}

        package_value = _first(item, "package", "name", "target_package")
        if package_value is None:
            package_value = _first(target_mapping, "package", "name")
        if not isinstance(package_value, str) or not package_value.strip():
            raise HandoverError(f"remediation plan item #{index} has no package identity")
        package = canonicalize_name(package_value)
        if not package or "/" in package or "\\" in package or ":" in package:
            raise HandoverError(f"remediation plan item #{index} has an invalid package identity")

        target_version = _first(
            item,
            "target_version",
            "fixed_version",
            "fix_version",
            "version",
        )
        if target_version is None:
            target_version = _first(target_mapping, "version", "target_version")
        if not isinstance(target_version, str) or not target_version.strip():
            raise HandoverError(f"remediation plan item #{index} has no target version")
        target_version = target_version.strip()
        try:
            Version(target_version)
        except InvalidVersion as exc:
            raise HandoverError(
                f"remediation plan item #{index} has an invalid target version"
            ) from exc

        raw_vulns = _first(item, "vulnerability_ids", "vulnerabilities", "vulns", "advisories")
        vulnerability_ids: list[str] = []
        if raw_vulns is None:
            raw_vulns = []
        if isinstance(raw_vulns, str):
            raw_vulns = [raw_vulns]
        if not isinstance(raw_vulns, Sequence) or isinstance(raw_vulns, (str, bytes, bytearray)):
            raise HandoverError(f"remediation plan item #{index} vulnerabilities must be an array")
        for raw_vuln in raw_vulns:
            if isinstance(raw_vuln, Mapping):
                raw_vuln = _first(raw_vuln, "id", "vulnerability_id")
            if not isinstance(raw_vuln, str) or not raw_vuln.strip():
                raise HandoverError(
                    f"remediation plan item #{index} contains an invalid vulnerability ID"
                )
            vuln_id = raw_vuln.strip()
            if _URL_PATTERN.search(vuln_id) or _PATH_PATTERN.search(vuln_id):
                raise HandoverError(
                    f"remediation plan item #{index} contains a non-disclosable vulnerability ID"
                )
            if vuln_id not in vulnerability_ids:
                vulnerability_ids.append(vuln_id)

        raw_evidence = _first(
            item,
            "required_evidence",
            "evidence_required",
            "acceptance_criteria",
        )
        if raw_evidence is None:
            raw_evidence = list(DEFAULT_EVIDENCE)
        if isinstance(raw_evidence, Mapping):
            raw_evidence = list(raw_evidence)
        if isinstance(raw_evidence, str):
            raw_evidence = [raw_evidence]
        if not isinstance(raw_evidence, Sequence) or isinstance(
            raw_evidence, (str, bytes, bytearray)
        ):
            raise HandoverError(
                f"remediation plan item #{index} required evidence must be an array"
            )
        required_evidence: list[str] = []
        for material in raw_evidence:
            normalized = _normalize_material(material)
            if normalized == "environment_confirmation":
                continue
            if normalized not in required_evidence:
                required_evidence.append(normalized)
        if not required_evidence:
            required_evidence = list(DEFAULT_EVIDENCE)

        item_id = _first(item, "item_id", "id", "finding_id")
        if item_id is None:
            seed = "|".join([plan_id, package, target_version, ",".join(sorted(vulnerability_ids))])
            item_id = f"item-{_sha256(seed.encode('utf-8'))[:12]}"
        if not isinstance(item_id, str) or not item_id.strip():
            raise HandoverError(f"remediation plan item #{index} has an invalid item ID")
        item_id = item_id.strip()
        if _URL_PATTERN.search(item_id) or _PATH_PATTERN.search(item_id):
            raise HandoverError(f"remediation plan item #{index} ID is not disclosable")
        if item_id in seen_ids:
            raise HandoverError(f"duplicate remediation plan item ID: {item_id}")
        seen_ids.add(item_id)

        items.append(
            PlanItem(
                item_id=item_id,
                package=package,
                target_version=target_version,
                vulnerability_ids=tuple(vulnerability_ids),
                required_evidence=tuple(required_evidence),
            )
        )

    return plan_id, items, _sha256_obj(mapping)


def _dependency_entries(raw: Any, label: str) -> list[Mapping[str, Any]]:
    """Extract dependency-like entries from a pip-audit or environment document."""
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        entries = raw
    else:
        mapping = _as_mapping(raw, label)
        entries = _first(mapping, "dependencies", "packages", "items")
        if entries is None and mapping:
            if all(isinstance(value, str) for value in mapping.values()):
                return [
                    {"name": name, "version": version}
                    for name, version in cast(Mapping[str, str], mapping).items()
                ]
        if entries is None:
            raise HandoverError(f"{label} must contain a dependencies or packages array")
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
        raise HandoverError(f"{label} dependency entries must be an array")

    result: list[Mapping[str, Any]] = []
    for index, entry in enumerate(entries):
        result.append(_as_mapping(entry, f"{label} entry #{index}"))
    return result


def _vulnerability_ids(entry: Mapping[str, Any]) -> tuple[str, ...]:
    """Collect primary and alias vulnerability IDs from one audit entry."""
    raw_vulns = _first(entry, "vulns", "vulnerabilities", "advisories")
    if raw_vulns is None:
        return ()
    if isinstance(raw_vulns, Mapping):
        raw_vulns = [raw_vulns]
    if not isinstance(raw_vulns, Sequence) or isinstance(raw_vulns, (str, bytes, bytearray)):
        return ()

    ids: list[str] = []
    for raw_vuln in raw_vulns:
        if isinstance(raw_vuln, Mapping):
            values = [_first(raw_vuln, "id", "vulnerability_id")]
            aliases = raw_vuln.get("aliases")
            if isinstance(aliases, Sequence) and not isinstance(aliases, (str, bytes, bytearray)):
                values.extend(aliases)
        else:
            values = [raw_vuln]
        for value in values:
            if not isinstance(value, str):
                continue
            value = value.strip()
            if not value or value in ids:
                continue
            if _URL_PATTERN.search(value) or _PATH_PATTERN.search(value):
                continue
            ids.append(value)
    return tuple(ids)


def _normalize_observations(raw: Any, label: str, source: str) -> dict[str, dict[str, Any]]:
    """Normalize package observations keyed by canonical package name."""
    observations: dict[str, dict[str, Any]] = {}
    for entry in _dependency_entries(raw, label):
        name = _first(entry, "name", "package", "canonical_name")
        if not isinstance(name, str) or not name.strip():
            continue
        package = canonicalize_name(name)
        version_value = _first(entry, "version", "installed_version", "confirmed_version")
        version: str | None = None
        status = "missing"
        if isinstance(version_value, str) and version_value.strip():
            try:
                Version(version_value.strip())
            except InvalidVersion:
                status = "invalid"
            else:
                version = version_value.strip()
                status = "confirmed"

        candidate = {
            "status": status,
            "version": version,
            "source": source,
            "vulnerability_ids": list(_vulnerability_ids(entry)),
        }
        previous = observations.get(package)
        if previous is None:
            observations[package] = candidate
        elif previous["version"] == candidate["version"]:
            previous["vulnerability_ids"] = sorted(
                set(previous["vulnerability_ids"]) | set(candidate["vulnerability_ids"])
            )
        else:
            observations[package] = {
                "status": "ambiguous",
                "version": None,
                "source": source,
                "vulnerability_ids": [],
            }
    return observations


def _receipt_name(plan_id: str, item: PlanItem) -> str:
    """Derive a stable, non-identifying rotated receipt name."""
    seed = "\0".join(
        [plan_id, item.item_id, item.package, item.target_version, *item.vulnerability_ids]
    )
    return f"ha-{_sha256(seed.encode('utf-8'))[:20]}"


def _versions_match(left: Any, right: str) -> bool:
    """Return whether two version strings compare equal under PEP 440."""
    if not isinstance(left, str):
        return False
    try:
        return Version(left) == Version(right)
    except InvalidVersion:
        return False


def _build_item(
    item: PlanItem,
    plan_id: str,
    observation: Mapping[str, Any] | None,
    confirmation_source: str = "offline-audit",
) -> dict[str, Any]:
    """Build one disclosure-safe handover item."""
    receipt_name = _receipt_name(plan_id, item)
    required_materials = [
        "environment_confirmation",
        "receipt_acknowledgement",
        *item.required_evidence,
    ]
    supplied_materials: list[str] = []

    confirmed = observation is not None and observation.get("status") == "confirmed"
    if confirmed:
        supplied_materials.append("environment_confirmation")

    observed_vulns = (
        tuple(cast(Iterable[str], observation.get("vulnerability_ids", ())))
        if observation is not None
        else ()
    )
    audit_version = (
        observation.get("audit_version", observation.get("version")) if observation else None
    )
    environment_matches_target = bool(
        confirmed
        and observation is not None
        and _versions_match(observation.get("version"), item.target_version)
    )
    audit_matches_target = bool(
        observation is not None and _versions_match(audit_version, item.target_version)
    )
    target_vulns_observed = any(vuln_id in observed_vulns for vuln_id in item.vulnerability_ids)
    clean_recheck_at_target = bool(audit_matches_target and not target_vulns_observed)

    if environment_matches_target and "fixed_version" in required_materials:
        supplied_materials.append("fixed_version")
    if clean_recheck_at_target and "vulnerability_recheck" in required_materials:
        supplied_materials.append("vulnerability_recheck")

    missing_materials = [
        material
        for material in required_materials
        if material != "receipt_acknowledgement" and material not in supplied_materials
    ]

    if observation is None:
        audit_status = "not-in-offline-audit"
    elif observation.get("status") != "confirmed":
        audit_status = "version-not-confirmed"
    elif target_vulns_observed:
        audit_status = "target-vulnerabilities-observed"
    elif audit_matches_target:
        audit_status = "clean-at-target"
    elif item.vulnerability_ids:
        audit_status = "target-vulnerabilities-not-observed"
    else:
        audit_status = "version-observed"

    handover_item: dict[str, Any] = {
        "receipt_names": [receipt_name],
        "plan_item_id": item.item_id,
        "target": {
            "ecosystem": "pypi",
            "name": item.package,
            "version": item.target_version,
            "identity": f"pypi:{item.package}@{item.target_version}",
        },
        "environment_confirmation": {
            "status": "confirmed" if confirmed else "missing",
            "version": observation.get("version") if confirmed and observation else None,
            "source": observation.get("source") if observation else confirmation_source,
            "target_match": environment_matches_target,
        },
        "vulnerabilities": list(item.vulnerability_ids),
        "audit_observation": {
            "status": audit_status,
            "version": audit_version,
            "vulnerability_ids": sorted(observed_vulns),
        },
        "required_materials": required_materials,
        "already_supplied_materials": supplied_materials,
        "missing_materials": missing_materials,
    }
    handover_item["item_sha256"] = _sha256_obj(handover_item)
    return handover_item


def _assert_disclosable(value: Any, location: str = "package") -> None:
    """Reject fields that could disclose index endpoints or local paths."""
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            normalized_key = key.lower().replace("-", "_")
            if normalized_key in _FORBIDDEN_KEYS or normalized_key.endswith(
                ("_url", "_urls", "_path", "_paths")
            ):
                raise HandoverIntegrityError(f"non-disclosable field at {location}.{key}")
            _assert_disclosable(child, f"{location}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _assert_disclosable(child, f"{location}[{index}]")
    elif isinstance(value, str):
        if _URL_PATTERN.search(value):
            raise HandoverIntegrityError(f"URL found at {location}")
        if _PATH_PATTERN.search(value):
            raise HandoverIntegrityError(f"local path found at {location}")
        if "pypi.org" in value.lower():
            raise HandoverIntegrityError(f"external index address found at {location}")


def _package_digest(package: Mapping[str, Any]) -> str:
    """Compute the package digest over every field except the digest itself."""
    unsigned = dict(package)
    unsigned.pop("package_sha256", None)
    return _sha256_obj(unsigned)


def build_handover(
    plan: JsonSource,
    audit: JsonSource,
    environment: JsonSource | None = None,
) -> dict[str, Any]:
    """
    Build a disclosure-safe handover package from a remediation plan and offline audit.

    `plan` and `audit` may be parsed JSON values, JSON text, or paths. The exact
    input bytes are hashed when paths or bytes are supplied. `environment` is an
    optional version snapshot; when omitted, versions from the offline audit are
    treated as the environment confirmation.
    """
    raw_plan, plan_sha256 = _load_json_source(plan, "remediation plan")
    raw_audit, audit_sha256 = _load_json_source(audit, "offline audit")
    plan_id, plan_items, normalized_plan_sha256 = _normalize_plan(raw_plan)

    audit_observations = _normalize_observations(raw_audit, "offline audit", "offline-audit")
    environment_sha256: str | None = None
    if environment is None:
        observations = audit_observations
        confirmation_source = "offline-audit"
    else:
        raw_environment, environment_sha256 = _load_json_source(environment, "environment snapshot")
        observations = _normalize_observations(
            raw_environment, "environment snapshot", "environment-snapshot"
        )
        confirmation_source = "environment-snapshot"

    handover_items: list[dict[str, Any]] = []
    missing_materials: list[dict[str, Any]] = []
    for plan_item in plan_items:
        environment_observation = observations.get(plan_item.package)
        audit_observation = audit_observations.get(plan_item.package)
        if environment is None:
            observation = audit_observation
        elif environment_observation is not None:
            observation = dict(environment_observation)
            observation["vulnerability_ids"] = list(
                audit_observation.get("vulnerability_ids", ())
                if audit_observation is not None
                else ()
            )
            observation["audit_version"] = (
                audit_observation.get("version") if audit_observation is not None else None
            )
        else:
            observation = None
        handover_item = _build_item(
            plan_item,
            plan_id,
            observation,
            confirmation_source,
        )
        handover_items.append(handover_item)
        if handover_item["missing_materials"]:
            missing_materials.append(
                {
                    "plan_item_id": plan_item.item_id,
                    "materials": list(handover_item["missing_materials"]),
                }
            )

    binding = {
        "plan_sha256": plan_sha256,
        "normalized_plan_sha256": normalized_plan_sha256,
        "audit_sha256": audit_sha256,
        "environment_sha256": environment_sha256,
        "item_sha256": [item["item_sha256"] for item in handover_items],
    }
    handover_id = f"HO-{_sha256_obj(binding)[:16].upper()}"

    environment_missing = [
        item for item in handover_items if item["environment_confirmation"]["status"] != "confirmed"
    ]
    package: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": PACKAGE_KIND,
        "handover_id": handover_id,
        "status": "ready" if not environment_missing else "partial",
        "plan": {
            "plan_id": plan_id,
            "sha256": plan_sha256,
            "normalized_sha256": normalized_plan_sha256,
            "item_count": len(plan_items),
        },
        "offline_audit": {
            "sha256": audit_sha256,
            "format": "pip-audit-json",
        },
        "environment": {
            "sha256": environment_sha256,
            "confirmation_source": confirmation_source,
        },
        "disclosure": {
            "index_addresses_included": False,
            "local_paths_included": False,
            "policy": "identity-version-and-evidence-only",
        },
        "receipt_contract": {
            "binding_field": "handover_sha256",
            "rotated_name_field": "name",
            "version_field": "confirmed_version",
            "evidence_field": "evidence",
            "closure_rule": "all-required-materials-and-version-match",
            "duplicate_rule": "same-item-is-idempotent",
            "name_only_receipt": True,
            "acknowledgement_material": "receipt_acknowledgement",
        },
        "items": handover_items,
        "missing_materials": missing_materials,
        "summary": {
            "items": len(handover_items),
            "environment_confirmed": len(handover_items) - len(environment_missing),
            "environment_missing": len(environment_missing),
            "evidence_pending": sum(1 for item in handover_items if item["missing_materials"]),
        },
        "package_sha256": "",
    }
    package["package_sha256"] = _package_digest(package)
    verify_handover(package)
    return package


def verify_handover(package: Mapping[str, Any]) -> None:
    """
    Verify package structure, item digests, and disclosure policy.

    Raises `HandoverIntegrityError` if any check fails.
    """
    if not isinstance(package, Mapping):
        raise HandoverIntegrityError("handover package must be a JSON object")
    if package.get("kind") != PACKAGE_KIND:
        raise HandoverIntegrityError("unexpected handover package kind")
    if package.get("schema_version") != SCHEMA_VERSION:
        raise HandoverIntegrityError("unsupported handover package schema version")

    digest = package.get("package_sha256")
    if not isinstance(digest, str) or not _HEX_SHA256.fullmatch(digest):
        raise HandoverIntegrityError("handover package has no valid SHA-256 digest")
    if not hmac.compare_digest(digest, _package_digest(package)):
        raise HandoverIntegrityError("handover package digest does not match its contents")

    items = package.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        raise HandoverIntegrityError("handover package has no items array")
    for index, raw_item in enumerate(items):
        if not isinstance(raw_item, Mapping):
            raise HandoverIntegrityError(f"handover item #{index} is not an object")
        item_digest = raw_item.get("item_sha256")
        if not isinstance(item_digest, str) or not _HEX_SHA256.fullmatch(item_digest):
            raise HandoverIntegrityError(f"handover item #{index} has no valid digest")
        unsigned_item = dict(raw_item)
        unsigned_item.pop("item_sha256", None)
        if not hmac.compare_digest(item_digest, _sha256_obj(unsigned_item)):
            raise HandoverIntegrityError(f"handover item #{index} digest does not match")

    _assert_disclosable(package)


def _summarize_state(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build the state summary from item records."""
    closed = sum(1 for item in items if item.get("state") == "closed")
    in_progress = len(items) - closed
    missing = [
        {
            "plan_item_id": item.get("plan_item_id"),
            "materials": list(cast(Iterable[str], item.get("missing_materials", ()))),
        }
        for item in items
        if item.get("missing_materials")
    ]
    return {
        "items": len(items),
        "closed": closed,
        "in_progress": in_progress,
        "missing_materials": missing,
    }


def new_state(package: Mapping[str, Any]) -> dict[str, Any]:
    """
    Create the initial reconciliation state for a handover package.

    Items start in `in_progress` unless the package itself already supplies all
    required materials. An item with a missing environment confirmation cannot
    be closed by receipts.
    """
    verify_handover(package)
    raw_items = cast(Sequence[Mapping[str, Any]], package["items"])
    state_items: list[dict[str, Any]] = []
    for raw_item in raw_items:
        required = list(cast(Iterable[str], raw_item.get("required_materials", ())))
        supplied = list(cast(Iterable[str], raw_item.get("already_supplied_materials", ())))
        missing = [material for material in required if material not in supplied]
        state_items.append(
            {
                "plan_item_id": raw_item["plan_item_id"],
                "receipt_names": list(raw_item["receipt_names"]),
                "target": copy.deepcopy(raw_item["target"]),
                "vulnerabilities": list(raw_item.get("vulnerabilities", ())),
                "required_materials": required,
                "received_materials": supplied,
                "missing_materials": missing,
                "state": "closed" if not missing else "in_progress",
                "receipt_ids": [],
                "unique_receipt_lines": 0,
                "duplicate_lines": 0,
            }
        )

    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": STATE_KIND,
        "handover_id": package["handover_id"],
        "handover_sha256": package["package_sha256"],
        "plan_sha256": package["plan"]["sha256"],
        "items": state_items,
        "receipts": [],
        "summary": _summarize_state(state_items),
    }
    state["status"] = "closed" if state["summary"]["in_progress"] == 0 else "in_progress"
    return state


def _ensure_state_matches_package(package: Mapping[str, Any], state: Mapping[str, Any]) -> None:
    """Reject state that belongs to a different handover package."""
    if state.get("kind") != STATE_KIND:
        raise HandoverReceiptError("unexpected reconciliation state kind")
    if state.get("schema_version") != SCHEMA_VERSION:
        raise HandoverReceiptError("unsupported reconciliation state schema version")
    if state.get("handover_id") != package.get("handover_id"):
        raise HandoverReceiptError("receipt state belongs to a different handover")
    if state.get("handover_sha256") != package.get("package_sha256"):
        raise HandoverReceiptError("receipt state is bound to a different package digest")


def _receipt_items(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize receipt line items, including name-only shorthand."""
    raw_items = _first(receipt, "items", "receipt_items", "lines")
    if raw_items is None:
        raw_names = _first(receipt, "names", "receipt_names", "rotated_names")
        if isinstance(raw_names, str):
            raw_items = [name.strip() for name in re.split(r"[\s,;]+", raw_names) if name.strip()]
        elif isinstance(raw_names, Sequence) and not isinstance(raw_names, (str, bytes, bytearray)):
            raw_items = list(raw_names)
    if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes, bytearray)):
        raise HandoverReceiptError("receipt must contain an items array")

    result: list[dict[str, Any]] = []
    for index, raw_item in enumerate(raw_items):
        if isinstance(raw_item, str):
            result.append({"name": raw_item})
        else:
            result.append(dict(_as_mapping(raw_item, f"receipt item #{index}")))
    return result


def _receipt_alias(item: Mapping[str, Any]) -> str | None:
    """Extract a rotated receipt name from a line item."""
    value = _first(item, "receipt_name", "name", "rotated_name", "alias")
    return value.strip() if isinstance(value, str) and value.strip() else None


def _receipt_version(item: Mapping[str, Any]) -> str | None:
    """Extract a vendor-confirmed version from a line item."""
    value = _first(
        item,
        "confirmed_version",
        "installed_version",
        "environment_version",
        "fixed_version",
    )
    if value is None:
        evidence = _first(item, "evidence", "materials")
        if isinstance(evidence, Mapping):
            value = _first(evidence, "fixed_version", "confirmed_version", "version")
    return value.strip() if isinstance(value, str) and value.strip() else None


def _is_clean_recheck(value: Any, vulnerable_ids: Sequence[str]) -> bool:
    """Return whether a recheck value represents a clean result for this item."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _CLEAN_VALUES
    if isinstance(value, Mapping):
        status = _first(value, "status", "result", "state")
        if not isinstance(status, str) or status.strip().lower() not in _CLEAN_VALUES:
            return False
        reported = _first(value, "vulnerability_ids", "vulnerabilities", "ids")
        if reported is None:
            return True
        if isinstance(reported, str):
            reported_ids = {reported}
        elif isinstance(reported, Sequence) and not isinstance(reported, (str, bytes, bytearray)):
            reported_ids = {str(item) for item in reported}
        else:
            return False
        return set(vulnerable_ids).issubset(reported_ids)
    return False


def _receipt_materials(
    item: Mapping[str, Any],
    required: Sequence[str],
    vulnerable_ids: Sequence[str],
    target_version: str,
) -> tuple[list[str], list[str], dict[str, str]]:
    """
    Extract supplied materials from one receipt line.

    Returns supplied materials, mismatch notes, and a version comparison detail.
    """
    supplied: list[str] = []
    mismatches: list[str] = []
    details: dict[str, str] = {}

    if "receipt_acknowledgement" in required:
        supplied.append("receipt_acknowledgement")

    confirmed_version = _receipt_version(item)
    version_matches = _versions_match(confirmed_version, target_version)
    if confirmed_version is not None:
        try:
            Version(confirmed_version)
        except InvalidVersion:
            mismatches.append("invalid-confirmed-version")
        if not version_matches:
            mismatches.append("confirmed-version-does-not-match-target")

    evidence = _first(item, "evidence", "materials")
    evidence_names: set[str] = set()
    evidence_values: Mapping[str, Any] = {}
    if isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes, bytearray)):
        for raw_name in evidence:
            if isinstance(raw_name, str):
                try:
                    evidence_names.add(_normalize_material(raw_name))
                except HandoverError:
                    continue
    elif isinstance(evidence, Mapping):
        evidence_values = cast(Mapping[str, Any], evidence)
        for raw_name, value in evidence_values.items():
            if value is None or value is False:
                continue
            try:
                evidence_names.add(_normalize_material(raw_name))
            except HandoverError:
                continue

    if "fixed_version" in required and version_matches:
        supplied.append("fixed_version")
        details["confirmed_version"] = cast(str, confirmed_version)

    recheck_value = _first(
        item,
        "recheck",
        "vulnerability_recheck",
        "scan",
        "clean_scan",
    )
    if recheck_value is None:
        recheck_value = _first(evidence_values, "vulnerability_recheck", "recheck")
    if "vulnerability_recheck" in required:
        if _is_clean_recheck(recheck_value, vulnerable_ids):
            supplied.append("vulnerability_recheck")
        elif "vulnerability_recheck" in evidence_names:
            supplied.append("vulnerability_recheck")

    artifact_digest = _first(
        item,
        "artifact_sha256",
        "artifact_digest",
        "digest",
    )
    if artifact_digest is None:
        artifact_digest = _first(evidence_values, "artifact_digest", "artifact_sha256")
    if "artifact_digest" in required and isinstance(artifact_digest, str):
        if _HEX_SHA256.fullmatch(artifact_digest):
            supplied.append("artifact_digest")
            details["artifact_digest"] = artifact_digest.lower()

    return supplied, mismatches, details


def _state_item_by_alias(
    state_items: Sequence[dict[str, Any]], alias: str
) -> dict[str, Any] | None:
    """Find one state item by any of its rotated receipt names."""
    for item in state_items:
        if alias in item["receipt_names"]:
            return item
    return None


def _refresh_state_summary(state: dict[str, Any]) -> None:
    """Refresh item status and aggregate summary fields."""
    for item in state["items"]:
        missing = [
            material
            for material in item["required_materials"]
            if material not in item["received_materials"]
        ]
        item["missing_materials"] = missing
        item["state"] = "closed" if not missing else "in_progress"
    state["summary"] = _summarize_state(state["items"])
    state["status"] = "closed" if state["summary"]["in_progress"] == 0 else "in_progress"


def apply_receipt(
    package: Mapping[str, Any],
    state: Mapping[str, Any],
    receipt: JsonSource,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Apply one receipt and return `(new_state, report)`.

    A replayed receipt ID is ignored, and duplicate lines for the same rotated
    name are recorded without incrementing a unique occurrence. Missing
    materials are returned even when the rest of the receipt is acceptable.
    """
    verify_handover(package)
    _ensure_state_matches_package(package, state)
    raw_receipt, receipt_sha256 = _load_receipt_source(receipt)
    if isinstance(raw_receipt, str):
        raw_receipt = {
            "items": [name.strip() for name in re.split(r"[\n,;]+", raw_receipt) if name.strip()]
        }
    elif isinstance(raw_receipt, Sequence) and not isinstance(
        raw_receipt, (str, bytes, bytearray, Mapping)
    ):
        raw_receipt = {"items": list(raw_receipt)}
    receipt_mapping = _as_mapping(raw_receipt, "receipt")
    if receipt_mapping.get("kind") not in (None, RECEIPT_KIND):
        raise HandoverReceiptError("unexpected receipt kind")

    receipt_id_value = _first(receipt_mapping, "receipt_id", "id")
    if receipt_id_value is None:
        receipt_id = f"RCPT-{receipt_sha256[:12].upper()}"
    elif isinstance(receipt_id_value, str) and receipt_id_value.strip():
        receipt_id = receipt_id_value.strip()
    else:
        raise HandoverReceiptError("receipt ID must be a non-empty string")

    for logged in cast(Sequence[Mapping[str, Any]], state.get("receipts", ())):
        if logged.get("receipt_id") != receipt_id:
            continue
        duplicate_report = {
            "status": "duplicate_receipt",
            "receipt_id": receipt_id,
            "receipt_sha256": receipt_sha256,
            "handover_id": package["handover_id"],
            "duplicate": True,
            "items": [],
            "missing_materials": copy.deepcopy(state["summary"]["missing_materials"]),
            "state_status": state["status"],
            "summary": copy.deepcopy(state["summary"]),
        }
        if logged.get("receipt_sha256") != receipt_sha256:
            duplicate_report["status"] = "rejected"
            duplicate_report["error"] = "receipt ID reused with different content"
        return copy.deepcopy(dict(state)), duplicate_report

    receipt_handover_id = receipt_mapping.get("handover_id")
    if receipt_handover_id is not None and receipt_handover_id != package["handover_id"]:
        raise HandoverReceiptError("receipt is bound to a different handover ID")
    receipt_digest = receipt_mapping.get("handover_sha256")
    if receipt_digest is not None and receipt_digest != package["package_sha256"]:
        raise HandoverIntegrityError("receipt is bound to a different package digest")

    line_items = _receipt_items(receipt_mapping)
    if not line_items:
        raise HandoverReceiptError("receipt contains no items")

    updated = copy.deepcopy(dict(state))
    state_items = cast(list[dict[str, Any]], updated["items"])

    unknown_aliases: list[str] = []
    for line in line_items:
        alias = _receipt_alias(line)
        if alias is None:
            unknown_aliases.append("<missing-name>")
        elif _state_item_by_alias(state_items, alias) is None:
            unknown_aliases.append(alias)
    if unknown_aliases:
        report = {
            "status": "rejected",
            "receipt_id": receipt_id,
            "receipt_sha256": receipt_sha256,
            "handover_id": package["handover_id"],
            "duplicate": False,
            "unknown_receipt_names": sorted(set(unknown_aliases)),
            "items": [],
            "missing_materials": copy.deepcopy(state["summary"]["missing_materials"]),
            "state_status": state["status"],
            "summary": copy.deepcopy(state["summary"]),
        }
        return copy.deepcopy(dict(state)), report

    processed: set[str] = set()
    duplicate_aliases: list[str] = []
    report_items: list[dict[str, Any]] = []
    already_received = {
        alias
        for item in state_items
        if item.get("receipt_ids")
        for alias in cast(Sequence[str], item["receipt_names"])
    }
    for line in line_items:
        alias = _receipt_alias(line)
        assert alias is not None
        state_item = _state_item_by_alias(state_items, alias)
        assert state_item is not None
        if alias in processed:
            if alias not in duplicate_aliases:
                duplicate_aliases.append(alias)
            state_item["duplicate_lines"] = int(state_item.get("duplicate_lines", 0)) + 1
            continue
        processed.add(alias)

        duplicate_item = alias in already_received
        if duplicate_item:
            if alias not in duplicate_aliases:
                duplicate_aliases.append(alias)
            state_item["duplicate_lines"] = int(state_item.get("duplicate_lines", 0)) + 1
        else:
            state_item["unique_receipt_lines"] = int(state_item.get("unique_receipt_lines", 0)) + 1

        target = cast(Mapping[str, Any], state_item["target"])
        vulnerable_ids = cast(Sequence[str], state_item.get("vulnerabilities", ()))
        supplied, mismatches, details = _receipt_materials(
            line,
            cast(Sequence[str], state_item["required_materials"]),
            vulnerable_ids,
            str(target["version"]),
        )
        for material in supplied:
            if material not in state_item["received_materials"]:
                state_item["received_materials"].append(material)
        if receipt_id not in state_item["receipt_ids"]:
            state_item["receipt_ids"].append(receipt_id)
        _refresh_state_summary(updated)
        report_items.append(
            {
                "plan_item_id": state_item["plan_item_id"],
                "receipt_name": alias,
                "target_identity": target["identity"],
                "state": state_item["state"],
                "duplicate": duplicate_item,
                "supplied_materials": supplied,
                "missing_materials": list(state_item["missing_materials"]),
                "mismatches": mismatches,
                **details,
            }
        )

    _refresh_state_summary(updated)
    overall_status = "closed" if updated["summary"]["in_progress"] == 0 else "partial"
    report: dict[str, Any] = {
        "status": overall_status,
        "receipt_id": receipt_id,
        "receipt_sha256": receipt_sha256,
        "handover_id": package["handover_id"],
        "duplicate": False,
        "items": report_items,
        "duplicate_items": duplicate_aliases,
        "missing_materials": copy.deepcopy(updated["summary"]["missing_materials"]),
        "state_status": updated["status"],
        "summary": copy.deepcopy(updated["summary"]),
    }
    updated.setdefault("receipts", []).append(
        {
            "receipt_id": receipt_id,
            "receipt_sha256": receipt_sha256,
            "status": overall_status,
            "item_count": len(line_items),
            "duplicate_items": duplicate_aliases,
        }
    )
    return updated, report


def reconcile(
    package: Mapping[str, Any],
    receipts: Iterable[JsonSource],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Apply receipts in order and return the final state plus per-receipt reports."""
    state = new_state(package)
    reports: list[dict[str, Any]] = []
    for receipt in receipts:
        state, report = apply_receipt(package, state, receipt)
        reports.append(report)
    return state, reports


def dumps(value: Mapping[str, Any]) -> str:
    """Serialize a package or report as readable, deterministic JSON."""
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def load_file(path: Path) -> dict[str, Any]:
    """Load one JSON object from a path."""
    raw, _ = _load_json_source(path, "JSON")
    return dict(_as_mapping(raw, "JSON document"))


__all__ = [
    "DEFAULT_EVIDENCE",
    "HandoverError",
    "HandoverIntegrityError",
    "HandoverReceiptError",
    "PACKAGE_KIND",
    "PlanItem",
    "RECEIPT_KIND",
    "SCHEMA_VERSION",
    "STATE_KIND",
    "apply_receipt",
    "build_handover",
    "dumps",
    "load_file",
    "new_state",
    "reconcile",
    "verify_handover",
]
