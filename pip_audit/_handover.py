"""
Build signable handover packages from offline `pip-audit` results.

The handover builder reconciles three kinds of offline material:

* a remediation plan supplied by the project team,
* a JSON result produced by ``pip-audit`` in an isolated environment, and
* zero or more receipts supplied by the remediation vendor.

The resulting package is deliberately disclosure-safe.  Index URLs, registry
locations, and local filesystem paths are removed (or replaced with a redaction
marker), while stable item identifiers and SHA-256 bindings remain available so
an approver can reconcile each plan item without access to the private inputs.

Receipts are matched to plan items through stable item IDs, package identities,
target identities, or rotating vendor aliases.  Duplicate receipts never add
new evidence: an item closes only when every required material is present and
the environment confirms the planned version.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

SCHEMA_VERSION = "pip-audit-handover/1"
"""The handover package schema emitted by this module."""

_CLOSED = "closed"
_IN_PROGRESS = "in_progress"
_ENVIRONMENT_MATERIAL = "environment_version"
_DEFAULT_SIGNING_KEY_ENV = "PIP_AUDIT_HANDOVER_SIGNING_KEY"

_SENSITIVE_KEYS = {
    "index_url",
    "index_urls",
    "extra_index_url",
    "extra_index_urls",
    "registry",
    "registry_url",
    "repository_url",
    "source_url",
    "download_url",
    "artifact_path",
    "cache_dir",
    "cache_path",
    "file",
    "filename",
    "location",
    "path",
    "url",
    "uri",
}

_URL_RE = re.compile(
    r"""
    \b(?:https?|ftp|file|ssh|git)://[^\s"'<>\[\]{},;]+
    |\bgit\+[a-z0-9+.-]+://[^\s"'<>\[\]{},;]+
    |\bgit@[^\s"'<>]+:[^\s"'<>]+
    """,
    re.IGNORECASE | re.VERBOSE,
)

_PATH_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_.:])
    (
        /(?:Users|home|tmp|var|opt|srv|etc|usr|root|mnt|private|workspace|data|app|build|repo)
        (?:/[A-Za-z0-9._@+-]+)+
        |/[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)+
        |(?:\.{1,2}/)+[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*
        |[A-Za-z]:\\(?:[^\\\s"'<>|]+\\)*[^\\\s"'<>|]*
        |\\\\[A-Za-z0-9._$-]+\\[^\s"'<>|]+
    )
    """,
    re.VERBOSE,
)


class HandoverError(Exception):
    """Raised when handover input is malformed or cannot be reconciled."""


def _normalise_key(value: str) -> str:
    """Normalise a JSON key to lower snake case for tolerant lookup."""

    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _as_mapping(value: Any, *, field: str) -> dict[str, Any]:
    """Return a copy of ``value`` with normalised keys, or raise ``HandoverError``."""

    if not isinstance(value, Mapping):
        raise HandoverError(f"{field} must be a JSON object")

    normalised: dict[str, Any] = {}
    for key, item in value.items():
        normalised[_normalise_key(str(key))] = item
    return normalised


def _lookup(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    """Look up the first matching key in a normalised mapping."""

    for name in names:
        key = _normalise_key(name)
        if key in mapping:
            return mapping[key]
    return default


def _as_sequence(value: Any) -> list[Any]:
    """Coerce a JSON value into a list of entries."""

    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    return [value]


def _as_string(value: Any) -> str | None:
    """Return a trimmed string representation, or ``None`` for a missing value."""

    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _as_string_list(value: Any) -> list[str]:
    """Return a de-duplicated, sorted list of non-empty strings."""

    if value is None:
        return []
    if isinstance(value, Mapping):
        raw_values = list(value.keys())
    else:
        raw_values = _as_sequence(value)

    values: set[str] = set()
    for raw_value in raw_values:
        text = _as_string(raw_value)
        if text is not None:
            values.add(text)
    return sorted(values, key=str.casefold)


def _canonical_json(value: Any) -> str:
    """Serialise JSON deterministically for hashing and signatures."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_bytes(value: bytes) -> str:
    """Return the hexadecimal SHA-256 digest of ``value``."""

    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    """Return the hexadecimal SHA-256 digest of canonical JSON."""

    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


class _Redactor:
    """Remove disclosure-sensitive strings and fields from handover output."""

    def __init__(self) -> None:
        """Create an empty redaction counter."""

        self._counts: dict[str, int] = defaultdict(int)

    def _redact_string(self, value: str) -> str:
        """Redact URLs and absolute filesystem paths inside a string."""

        value, url_count = _URL_RE.subn("[redacted:url]", value)
        if url_count:
            self._counts["url"] += url_count

        value, path_count = _PATH_RE.subn("[redacted:path]", value)
        if path_count:
            self._counts["path"] += path_count

        return value

    def redact(self, value: Any) -> Any:
        """Recursively redact sensitive keys and string values."""

        if isinstance(value, str):
            return self._redact_string(value)
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                if _normalise_key(key) in _SENSITIVE_KEYS:
                    self._counts["field"] += 1
                    continue
                result[key] = self.redact(item)
            return result
        if isinstance(value, tuple):
            return [self.redact(item) for item in value]
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        return value

    def add_omitted_fields(self, count: int) -> None:
        """Record sensitive input fields that were never copied into the package."""

        if count:
            self._counts["field"] += count

    def summary(self) -> dict[str, Any]:
        """Return a stable redaction summary for the handover package."""

        kinds = {key: self._counts[key] for key in sorted(self._counts)}
        return {
            "count": sum(kinds.values()),
            "kinds": kinds,
            "policy": {
                "external_index_addresses": "omitted",
                "internal_paths": "redacted",
            },
        }


def _count_sensitive_fields(value: Any) -> int:
    """Count disclosure-sensitive fields present in an input document."""

    if isinstance(value, Mapping):
        total = 0
        for raw_key, item in value.items():
            if _normalise_key(str(raw_key)) in _SENSITIVE_KEYS:
                total += 1
            else:
                total += _count_sensitive_fields(item)
        return total
    if isinstance(value, (list, tuple)):
        return sum(_count_sensitive_fields(item) for item in value)
    return 0


def _parse_required_materials(value: Any) -> dict[str, int]:
    """Parse required material names and optional minimum evidence counts."""

    if value is None:
        return {}

    result: dict[str, int] = {}
    if isinstance(value, Mapping):
        entries: list[Any] = [{key: count} for key, count in value.items()]
    else:
        entries = _as_sequence(value)

    for entry in entries:
        if isinstance(entry, Mapping):
            normalised = _as_mapping(entry, field="required material")
            name = _as_string(_lookup(normalised, "name", "material", "type", "evidence", "kind"))
            count_value = _lookup(normalised, "count", "minimum", "required", default=1)
            if name is None and len(normalised) == 1:
                name = next(iter(normalised))
                count_value = next(iter(normalised.values()))
        else:
            name = _as_string(entry)
            count_value = 1

        if name is None or count_value is False or count_value is None:
            continue

        if isinstance(count_value, Mapping):
            count_value = _lookup(count_value, "count", "minimum", "required", default=1)
        if count_value is True:
            count = 1
        else:
            try:
                count = int(count_value)
            except (TypeError, ValueError):
                count = 1

        if count > 0:
            key = _normalise_key(name)
            result[key] = max(result.get(key, 0), count)

    return result


def _parse_plan(plan: Any) -> dict[str, Any]:
    """Parse a remediation plan into a normalised structure."""

    if isinstance(plan, list):
        plan_object: dict[str, Any] = {}
        raw_items: Any = plan
    else:
        plan_object = _as_mapping(plan, field="plan")
        wrapped_plan = _lookup(plan_object, "remediation_plan", "handover_plan")
        if isinstance(wrapped_plan, Mapping):
            plan_object = _as_mapping(wrapped_plan, field="remediation plan")
        raw_items = _lookup(
            plan_object,
            "items",
            "entries",
            "remediation_items",
            "plan_items",
            "dependencies",
        )
        if raw_items is None:
            raise HandoverError("plan must contain an 'items' array")

    if isinstance(raw_items, Mapping):
        item_entries: list[Any] = []
        for key, value in raw_items.items():
            if isinstance(value, Mapping):
                item = dict(value)
            else:
                item = {"package": value}
            item.setdefault("item_id", key)
            item_entries.append(item)
    else:
        item_entries = _as_sequence(raw_items)

    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_item in enumerate(item_entries):
        item = _as_mapping(raw_item, field=f"plan item {index + 1}")
        item_id = _as_string(
            _lookup(item, "item_id", "id", "ref", "key", "remediation_id"),
        )
        if item_id is None:
            item_id = f"RMD-{index + 1:03d}"

        if item_id in seen_ids:
            raise HandoverError(f"duplicate plan item id: {item_id}")
        seen_ids.add(item_id)

        target = _lookup(item, "target")
        target_mapping: dict[str, Any] = {}
        if isinstance(target, Mapping):
            target_mapping = _as_mapping(target, field=f"target for {item_id}")
        elif isinstance(target, str) and target.strip():
            target_text = target.strip()
            if "@" in target_text:
                target_package, target_version_text = target_text.rsplit("@", 1)
                target_mapping = {
                    "package": target_package,
                    "version": target_version_text,
                }
            else:
                target_mapping = {"target_id": target_text}

        package_value = _lookup(
            item,
            "package",
            "name",
            "dependency",
            "component",
            "project",
            "distribution",
        )
        package_mapping: dict[str, Any] = {}
        if isinstance(package_value, Mapping):
            package_mapping = _as_mapping(package_value, field=f"package for {item_id}")
            package = _as_string(_lookup(package_mapping, "name", "package", "dependency"))
        else:
            package = _as_string(package_value)
        if package is None:
            package = _as_string(_lookup(target_mapping, "package", "name", "dependency"))
        if package is None:
            package = _as_string(_lookup(package_mapping, "name", "package", "dependency"))
        if package is None:
            raise HandoverError(f"plan item {item_id} is missing a package name")

        target_version = _as_string(
            _lookup(
                item,
                "target_version",
                "version",
                "fixed_version",
                "required_version",
                "remediated_version",
            )
        )
        if target_version is None:
            target_version = _as_string(
                _lookup(target_mapping, "version", "target_version", "fixed_version")
            )
        if target_version is None:
            target_version = _as_string(_lookup(package_mapping, "version", "target_version"))

        aliases = _as_string_list(
            _lookup(
                item,
                "aliases",
                "codenames",
                "rotating_names",
                "names",
                "known_as",
                "receipt_names",
            )
        )
        disclosure_value = _lookup(
            item,
            "disclosure_id",
            "disclosure",
            "public_id",
            "public_name",
            "public_identity",
            "target_identity",
        )
        disclosure_id = _as_string(disclosure_value)
        if disclosure_id is None and isinstance(disclosure_value, Mapping):
            disclosure_mapping = _as_mapping(
                disclosure_value, field=f"disclosure identity for {item_id}"
            )
            disclosure_id = _as_string(
                _lookup(disclosure_mapping, "id", "name", "target_id", "public_id")
            )
        required_materials = _parse_required_materials(
            _lookup(
                item,
                "required_materials",
                "required_evidence",
                "materials",
                "evidence_required",
            )
        )
        advisories = _as_string_list(
            _lookup(item, "advisories", "vulnerabilities", "advisory_ids", "vulnerability_ids")
        )

        items.append(
            {
                "item_id": item_id,
                "package": package,
                "canonical_package": canonicalize_name(package),
                "target_version": target_version,
                "aliases": aliases,
                "disclosure_id": disclosure_id,
                "required_materials": required_materials,
                "advisories": advisories,
                "item_sha256": _sha256_json(raw_item),
            }
        )

    return {
        "plan_id": _as_string(_lookup(plan_object, "plan_id", "id", "name")) or "UNSPECIFIED",
        "title": _as_string(_lookup(plan_object, "title", "name")),
        "items": items,
    }


def _parse_audit(audit: Any) -> dict[str, Any]:
    """Parse a pip-audit JSON result into per-dependency records."""

    source: list[Any]
    if isinstance(audit, Mapping):
        audit_object = _as_mapping(audit, field="audit")
        dependencies = _lookup(audit_object, "dependencies", "components", "packages")
        if dependencies is None:
            if all(
                not isinstance(value, (Mapping, list, tuple)) for value in audit_object.values()
            ):
                source = [{"name": key, "version": value} for key, value in audit_object.items()]
            else:
                raise HandoverError("audit must contain a 'dependencies' array")
        elif isinstance(dependencies, Mapping):
            if all(
                not isinstance(value, (Mapping, list, tuple)) for value in dependencies.values()
            ):
                source = [{"name": key, "version": value} for key, value in dependencies.items()]
            else:
                source = []
                for key, value in dependencies.items():
                    if isinstance(value, Mapping):
                        source.append({"name": key, **value})
                    else:
                        source.append({"name": key, "version": value})
        else:
            source = _as_sequence(dependencies)
    else:
        source = _as_sequence(audit)

    records: dict[str, dict[str, Any]] = {}
    conflicts: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for index, raw_dependency in enumerate(source):
        dependency = _as_mapping(raw_dependency, field=f"audit dependency {index + 1}")
        name = _as_string(_lookup(dependency, "name", "package", "dependency", "component"))
        if name is None:
            raise HandoverError(f"audit dependency {index + 1} is missing a name")

        canonical_name = canonicalize_name(name)
        skip_reason = _as_string(_lookup(dependency, "skip_reason", "reason", "error"))
        version = _as_string(
            _lookup(dependency, "version", "installed_version", "confirmed_version")
        )
        if skip_reason is not None and version is None:
            skipped.append({"name": name, "canonical_name": canonical_name, "reason": skip_reason})
            continue

        vulnerabilities: list[dict[str, Any]] = []
        for raw_vulnerability in _as_sequence(
            _lookup(dependency, "vulns", "vulnerabilities", "advisories")
        ):
            if isinstance(raw_vulnerability, Mapping):
                vulnerability = _as_mapping(raw_vulnerability, field=f"vulnerability for {name}")
                vulnerability_id = _as_string(
                    _lookup(
                        vulnerability,
                        "id",
                        "vulnerability_id",
                        "advisory",
                        "advisory_id",
                        "osv_id",
                    )
                )
                if vulnerability_id is None:
                    continue
                vulnerabilities.append(
                    {
                        "id": vulnerability_id,
                        "aliases": _as_string_list(_lookup(vulnerability, "aliases", "alias_ids")),
                        "fix_versions": _as_string_list(
                            _lookup(
                                vulnerability,
                                "fix_versions",
                                "fixed_versions",
                                "fixes",
                            )
                        ),
                    }
                )
            else:
                vulnerability_id = _as_string(raw_vulnerability)
                if vulnerability_id is not None:
                    vulnerabilities.append(
                        {
                            "id": vulnerability_id,
                            "aliases": [],
                            "fix_versions": [],
                        }
                    )

        record = {
            "name": name,
            "canonical_name": canonical_name,
            "version": version,
            "vulnerabilities": vulnerabilities,
            "sha256": _sha256_json(raw_dependency),
        }

        existing = records.get(canonical_name)
        if existing is None:
            records[canonical_name] = record
            continue

        if existing["version"] != record["version"]:
            conflict = {
                "package": canonical_name,
                "versions": sorted(
                    {
                        str(existing["version"]),
                        str(record["version"]),
                    }
                ),
            }
            conflicts.append(conflict)
            existing["version"] = None
            existing["versions"] = conflict["versions"]
        existing_vulns = {
            (vuln["id"], tuple(vuln["aliases"]), tuple(vuln["fix_versions"]))
            for vuln in existing["vulnerabilities"]
        }
        for vulnerability in record["vulnerabilities"]:
            fingerprint = (
                vulnerability["id"],
                tuple(vulnerability["aliases"]),
                tuple(vulnerability["fix_versions"]),
            )
            if fingerprint not in existing_vulns:
                existing["vulnerabilities"].append(vulnerability)
                existing_vulns.add(fingerprint)

    return {
        "records": records,
        "conflicts": conflicts,
        "skipped": skipped,
    }


def _material_present(value: Any) -> bool:
    """Return whether a material value represents delivered evidence."""

    if isinstance(value, Mapping):
        flag = _lookup(value, "provided", "present", "accepted", "delivered")
        if flag is not None:
            return bool(flag)
        status = _as_string(_lookup(value, "status", "state"))
        if status is not None and status.casefold() in {
            "accepted",
            "complete",
            "delivered",
            "provided",
            "received",
        }:
            return True
        return bool(value)
    return value not in (None, False, "", [], {})


def _parse_materials(value: Any) -> dict[str, Any]:
    """Parse receipt materials into a name-to-evidence mapping."""

    if value is None:
        return {}
    if isinstance(value, Mapping):
        return {_normalise_key(str(name)): item for name, item in value.items()}
    if isinstance(value, str):
        return {_normalise_key(value): True}

    materials: dict[str, Any] = {}
    for entry in _as_sequence(value):
        if isinstance(entry, Mapping):
            material = _as_mapping(entry, field="receipt material")
            name = _as_string(_lookup(material, "name", "material", "type", "evidence", "kind"))
            if name is None:
                continue
            provided = _lookup(material, "provided", "present", "accepted", "value", default=True)
            materials[_normalise_key(name)] = provided
        else:
            name = _as_string(entry)
            if name is not None:
                materials[_normalise_key(name)] = True
    return materials


def _parse_receipts(
    receipts: Iterable[Any],
    receipt_raws: Sequence[str | bytes] | None,
) -> list[dict[str, Any]]:
    """Parse vendor receipts into a normalised list."""

    receipt_list: list[Any]
    if isinstance(receipts, (str, bytes, Mapping)):
        receipt_list = [receipts]
    else:
        receipt_list = list(receipts)
    if len(receipt_list) == 1 and isinstance(receipt_list[0], (list, tuple)):
        receipt_list = list(receipt_list[0])
    if len(receipt_list) == 1 and isinstance(receipt_list[0], Mapping):
        wrapper = _as_mapping(receipt_list[0], field="receipts")
        receipt_keys = {
            "receipt_id",
            "receipt",
            "id",
            "target",
            "targets",
            "item",
            "item_id",
            "materials",
            "material",
            "evidence",
        }
        if not receipt_keys.intersection(wrapper):
            wrapped = _lookup(wrapper, "receipts", "items", "acknowledgements")
            if wrapped is not None:
                receipt_list = _as_sequence(wrapped)

    parsed: list[dict[str, Any]] = []
    for index, raw_receipt in enumerate(receipt_list):
        if isinstance(raw_receipt, str):
            receipt = {"target": raw_receipt}
        else:
            receipt = _as_mapping(raw_receipt, field=f"receipt {index + 1}")
        receipt_id = _as_string(
            _lookup(
                receipt,
                "receipt_id",
                "receipt",
                "number",
                "id",
                "ack_id",
                "acknowledgement_id",
                "document_id",
            )
        )
        if receipt_id is None:
            receipt_id = f"RCPT-{index + 1:03d}"

        refs: set[str] = set()
        for key in (
            "target",
            "targets",
            "target_identity",
            "target_id",
            "item",
            "item_id",
            "plan_item",
            "plan_item_id",
            "alias",
            "aliases",
            "codename",
            "codenames",
            "rotating_name",
            "rotating_names",
            "name",
            "names",
            "package",
            "dependency",
        ):
            raw_ref = _lookup(receipt, key)
            if isinstance(raw_ref, Mapping):
                raw_ref = _lookup(
                    _as_mapping(raw_ref, field=f"{key} for receipt {receipt_id}"),
                    "id",
                    "name",
                    "target_id",
                    "target_identity",
                    "disclosure_id",
                    "item_id",
                    "package",
                    "alias",
                    "codename",
                )
            for ref in _as_string_list(raw_ref):
                refs.add(ref)

        package = _as_string(_lookup(receipt, "package", "dependency", "component"))
        version = _as_string(
            _lookup(
                receipt, "version", "confirmed_version", "installed_version", "remediated_version"
            )
        )
        materials = _parse_materials(
            _lookup(
                receipt,
                "materials",
                "material",
                "evidence",
                "deliverables",
                "artifacts",
                "documents",
            )
        )
        present_materials = sorted(
            name for name, material_value in materials.items() if _material_present(material_value)
        )
        material_fingerprint = _sha256_json({name: materials[name] for name in present_materials})

        raw_digest: str | None = None
        if receipt_raws is not None and index < len(receipt_raws):
            raw_value = receipt_raws[index]
            raw_bytes = raw_value.encode("utf-8") if isinstance(raw_value, str) else raw_value
            raw_digest = _sha256_bytes(raw_bytes)

        parsed.append(
            {
                "receipt_id": receipt_id,
                "refs": sorted(refs, key=str.casefold),
                "package": package,
                "canonical_package": canonicalize_name(package) if package else None,
                "version": version,
                "materials": materials,
                "present_materials": present_materials,
                "material_fingerprint": material_fingerprint,
                "received_at": _as_string(
                    _lookup(receipt, "received_at", "received", "timestamp", "date")
                ),
                "vendor": _as_string(_lookup(receipt, "vendor", "supplier", "provider")),
                "notes": _as_string(_lookup(receipt, "notes", "note", "comment")),
                "raw_sha256": raw_digest,
                "canonical_sha256": _sha256_json(raw_receipt),
            }
        )

    return parsed


def _target_id(canonical_package: str, target_version: str | None) -> str:
    """Return a human-readable, disclosure-safe target identity."""

    if target_version is None:
        return canonical_package
    return f"{canonical_package}@{target_version}"


def _disclosure_id(canonical_package: str, target_version: str | None) -> str:
    """Return a stable opaque identity suitable for external disclosure."""

    seed = _target_id(canonical_package, target_version).encode("utf-8")
    return f"TGT-{_sha256_bytes(seed)[:12].upper()}"


def _build_match_index(items: Sequence[Mapping[str, Any]]) -> dict[str, set[str]]:
    """Build a case-insensitive index from receipt references to plan item IDs."""

    index: dict[str, set[str]] = defaultdict(set)
    for item in items:
        item_id = str(item["item_id"])
        keys = {
            item_id,
            str(item["package"]),
            str(item["canonical_package"]),
            _target_id(str(item["canonical_package"]), item["target_version"]),
        }
        if item["disclosure_id"]:
            keys.add(str(item["disclosure_id"]))
        keys.update(str(alias) for alias in item["aliases"])
        for key in keys:
            index[key.casefold()].add(item_id)
    return index


def _match_receipt(
    receipt: Mapping[str, Any],
    items: Sequence[Mapping[str, Any]],
    index: Mapping[str, set[str]],
) -> tuple[str | None, str | None]:
    """Match a receipt to exactly one plan item, if possible."""

    candidates: set[str] = set()
    for ref in receipt["refs"]:
        candidates.update(index.get(str(ref).casefold(), set()))

    package = receipt["canonical_package"]
    version = receipt["version"]
    if package is not None and version is not None:
        target_key = _target_id(str(package), str(version)).casefold()
        exact_version_matches = index.get(target_key, set())
        if exact_version_matches:
            candidates = set(exact_version_matches)

    if len(candidates) > 1 and package is not None:
        package_matches = {
            str(item["item_id"]) for item in items if item["canonical_package"] == package
        }
        narrowed = candidates & package_matches
        if narrowed:
            candidates = narrowed

    if len(candidates) == 1:
        item_id = next(iter(candidates))
        item = next(item for item in items if item["item_id"] == item_id)
        if package is not None and item["canonical_package"] != package:
            return None, "package_conflict"
        return item_id, "matched"

    if len(candidates) > 1:
        return None, "ambiguous"
    return None, "unmatched"


def _is_specifier(value: str) -> bool:
    """Return whether ``value`` is a PEP 440 version specifier rather than a version."""

    return any(character in value for character in "<>=!~,*") or value.startswith("=")


def _confirm_version(
    record: Mapping[str, Any] | None,
    target_version: str | None,
) -> tuple[bool, str | None, str]:
    """Check the audited version against the plan's target version."""

    if record is None:
        return False, None, "missing"

    actual_version = _as_string(record.get("version"))
    if actual_version is None:
        return False, None, "missing"
    if target_version is None:
        return True, actual_version, "present"

    if _is_specifier(target_version):
        try:
            specifier = SpecifierSet(target_version)
            parsed_actual = Version(actual_version)
        except (InvalidSpecifier, InvalidVersion):
            return False, actual_version, "invalid"
        return parsed_actual in specifier, actual_version, "specifier"

    try:
        target = Version(target_version)
        actual = Version(actual_version)
    except InvalidVersion:
        return actual_version == target_version, actual_version, "string"

    return actual == target, actual_version, "exact"


def _receipt_summary(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Return the disclosure-safe reconciliation view of a receipt."""

    return {
        "receipt_id": receipt["receipt_id"],
        "materials": receipt["present_materials"],
        "version": receipt["version"],
        "received_at": receipt["received_at"],
        "vendor": receipt["vendor"],
        "sha256": receipt["canonical_sha256"],
    }


def _public_target(item: Mapping[str, Any]) -> dict[str, Any]:
    """Return the disclosure-safe target identity for a plan item."""

    canonical_package = str(item["canonical_package"])
    target_version = item["target_version"]
    return {
        "target_id": _target_id(canonical_package, target_version),
        "disclosure_id": item["disclosure_id"] or _disclosure_id(canonical_package, target_version),
        "package": canonical_package,
        "display_name": item["package"],
        "version": target_version,
        "aliases": list(item["aliases"]),
    }


def build_handover(
    plan: Any,
    audit: Any,
    receipts: Iterable[Any] = (),
    *,
    plan_raw: str | bytes | None = None,
    audit_raw: str | bytes | None = None,
    receipt_raws: Sequence[str | bytes] | None = None,
    generated_at: str | None = None,
    package_id: str | None = None,
    signer: str | None = None,
    signing_key: str | bytes | None = None,
) -> dict[str, Any]:
    """
    Build a disclosure-safe handover package.

    ``plan`` is the original remediation plan, ``audit`` is an offline
    ``pip-audit -f json`` result, and ``receipts`` is an iterable of vendor
    receipts.  Raw input values may be supplied to bind exact file bytes; the
    builder otherwise binds the canonical JSON representation.

    Receipts that repeat the same item and the same material set are recorded as
    duplicates and contribute no additional evidence.  An item is closed only
    when all required materials are present and the audited environment version
    matches the plan's target version.
    """

    parsed_plan = _parse_plan(plan)
    parsed_audit = _parse_audit(audit)
    receipt_list: list[Any]
    if isinstance(receipts, (str, bytes, Mapping)):
        receipt_list = [receipts]
    else:
        receipt_list = list(receipts)
    parsed_receipts = _parse_receipts(receipt_list, receipt_raws)
    omitted_fields = (
        _count_sensitive_fields(plan)
        + _count_sensitive_fields(audit)
        + sum(_count_sensitive_fields(receipt) for receipt in receipt_list)
    )

    items = parsed_plan["items"]
    match_index = _build_match_index(items)
    audit_records: Mapping[str, Mapping[str, Any]] = parsed_audit["records"]

    plan_raw_digest = (
        _sha256_bytes(plan_raw.encode("utf-8") if isinstance(plan_raw, str) else plan_raw)
        if plan_raw is not None
        else None
    )
    audit_raw_digest = (
        _sha256_bytes(audit_raw.encode("utf-8") if isinstance(audit_raw, str) else audit_raw)
        if audit_raw is not None
        else None
    )

    duplicate_receipts: list[dict[str, Any]] = []
    unmatched_receipts: list[dict[str, Any]] = []
    receipt_conflicts: list[dict[str, Any]] = []
    matched_by_item: dict[str, list[dict[str, Any]]] = defaultdict(list)

    seen_receipt_ids: dict[str, dict[str, Any]] = {}
    for receipt in parsed_receipts:
        receipt_id = str(receipt["receipt_id"])
        previous = seen_receipt_ids.get(receipt_id)
        if previous is not None:
            if previous["canonical_sha256"] == receipt["canonical_sha256"]:
                duplicate_receipts.append(
                    {
                        "receipt_id": receipt_id,
                        "duplicate_of": receipt_id,
                        "reason": "same_receipt_id",
                    }
                )
            else:
                receipt_conflicts.append(
                    {
                        "receipt_id": receipt_id,
                        "reason": "same_receipt_id_different_content",
                    }
                )
            continue
        seen_receipt_ids[receipt_id] = receipt

        item_id, match_reason = _match_receipt(receipt, items, match_index)
        if item_id is None:
            unmatched_receipts.append(
                {
                    "receipt_id": receipt_id,
                    "reason": match_reason or "unmatched",
                    "refs": receipt["refs"],
                }
            )
            continue

        receipt["matched_item_id"] = item_id
        matched_by_item[item_id].append(receipt)

    item_output: list[dict[str, Any]] = []
    missing_materials: dict[str, list[str]] = {}
    next_actions: list[dict[str, Any]] = []

    for item in items:
        item_id = str(item["item_id"])
        canonical_package = str(item["canonical_package"])
        target_version = item["target_version"]
        target = _public_target(item)

        environment_confirmed, actual_version, version_match = _confirm_version(
            audit_records.get(canonical_package),
            target_version,
        )
        audit_record = audit_records.get(canonical_package)
        environment = {
            "confirmed": environment_confirmed,
            "version": actual_version,
            "target_version": target_version,
            "match": version_match,
            "source": "pip-audit-offline",
            "evidence_sha256": audit_record.get("sha256") if audit_record else None,
        }
        if audit_record is not None:
            environment["vulnerabilities"] = audit_record.get("vulnerabilities", [])
            if audit_record.get("versions"):
                environment["conflicting_versions"] = audit_record["versions"]

        required = dict(item["required_materials"])
        if target_version is not None:
            required.setdefault(_ENVIRONMENT_MATERIAL, 1)

        received: dict[str, list[str]] = defaultdict(list)
        if environment_confirmed:
            received[_ENVIRONMENT_MATERIAL].append("environment")

        item_receipts: list[dict[str, Any]] = []
        item_duplicates: list[dict[str, Any]] = []
        item_conflicts: list[dict[str, Any]] = []
        seen_material_fingerprints: dict[str, str] = {}

        for receipt in matched_by_item.get(item_id, []):
            receipt_id = str(receipt["receipt_id"])
            fingerprint = str(receipt["material_fingerprint"])
            first_receipt_id = seen_material_fingerprints.get(fingerprint)
            if first_receipt_id is not None:
                duplicate = {
                    "receipt_id": receipt_id,
                    "duplicate_of": first_receipt_id,
                    "reason": "same_item_same_material_set",
                }
                duplicate_receipts.append(duplicate)
                item_duplicates.append(duplicate)
                continue

            seen_material_fingerprints[fingerprint] = receipt_id
            item_receipts.append(_receipt_summary(receipt))

            if receipt["version"] is not None and actual_version is not None:
                if str(receipt["version"]) != str(actual_version):
                    item_conflicts.append(
                        {
                            "receipt_id": receipt_id,
                            "reason": "receipt_version_differs_from_environment",
                            "receipt_version": receipt["version"],
                            "environment_version": actual_version,
                        }
                    )

            for material in receipt["present_materials"]:
                received[material].append(receipt_id)

        if "vulnerability_clearance" in required:
            vulnerabilities = environment.get("vulnerabilities", [])
            if not vulnerabilities:
                received["vulnerability_clearance"].append("environment")
            elif item["advisories"]:
                remaining = [
                    vulnerability
                    for vulnerability in vulnerabilities
                    if vulnerability.get("id") in item["advisories"]
                    or set(vulnerability.get("aliases", [])) & set(item["advisories"])
                ]
                if not remaining:
                    received["vulnerability_clearance"].append("environment")

        missing = sorted(
            material
            for material, required_count in required.items()
            if len(set(received.get(material, []))) < required_count
        )
        missing_materials[item_id] = missing

        status = _CLOSED if not missing else _IN_PROGRESS
        if status == _CLOSED:
            closeout = {
                "eligible": True,
                "closed": True,
                "blocked_by": [],
                "reason": "all_required_evidence_present",
            }
        else:
            closeout = {
                "eligible": False,
                "closed": False,
                "blocked_by": [f"missing_material:{material}" for material in missing],
                "reason": "incomplete_evidence",
            }
            action = {
                "item_id": item_id,
                "target_id": target["target_id"],
                "missing_materials": missing,
                "action": "request_missing_materials"
                if missing != [_ENVIRONMENT_MATERIAL]
                else "confirm_environment_version",
            }
            if _ENVIRONMENT_MATERIAL in missing and len(missing) > 1:
                action["action"] = "request_missing_materials_and_confirm_version"
            next_actions.append(action)

        evidence_payload = {
            "plan_item_sha256": item["item_sha256"],
            "environment_sha256": environment["evidence_sha256"],
            "receipt_sha256": sorted(str(receipt["sha256"]) for receipt in item_receipts),
            "required_materials": required,
            "missing_materials": missing,
            "status": status,
        }

        item_output.append(
            {
                "plan_item_id": item_id,
                "target": target,
                "required_materials": {
                    material: required[material] for material in sorted(required)
                },
                "received_materials": {
                    material: sorted(set(received.get(material, [])))
                    for material in sorted(required)
                },
                "missing_materials": missing,
                "environment": environment,
                "receipts": item_receipts,
                "duplicate_receipts": item_duplicates,
                "conflicts": item_conflicts,
                "status": status,
                "closeout": closeout,
                "reconciliation_sha256": _sha256_json(evidence_payload),
            }
        )

    closed_items = [item["plan_item_id"] for item in item_output if item["status"] == _CLOSED]
    pending_items = [item["plan_item_id"] for item in item_output if item["status"] != _CLOSED]
    complete = not pending_items

    plan_canonical_digest = _sha256_json(plan)
    audit_canonical_digest = _sha256_json(audit)
    receipt_bindings = [
        {
            "receipt_id": receipt["receipt_id"],
            "raw_sha256": receipt["raw_sha256"],
            "canonical_sha256": receipt["canonical_sha256"],
        }
        for receipt in parsed_receipts
    ]

    if package_id is None:
        seed = {
            "plan": plan_canonical_digest,
            "audit": audit_canonical_digest,
            "receipts": sorted(binding["canonical_sha256"] for binding in receipt_bindings),
        }
        package_id = f"HO-{_sha256_json(seed)[:12].upper()}"

    targets = [item["target"] for item in item_output]
    duplicate_by_id: dict[str, dict[str, Any]] = {}
    for duplicate in duplicate_receipts:
        duplicate_by_id.setdefault(str(duplicate["receipt_id"]), duplicate)
    unmatched_by_id = {str(receipt["receipt_id"]): receipt for receipt in unmatched_receipts}
    conflict_ids = {str(conflict["receipt_id"]) for conflict in receipt_conflicts}
    receipt_register = [
        {
            "receipt_id": receipt["receipt_id"],
            "matched_item_id": receipt.get("matched_item_id"),
            "materials": receipt["present_materials"],
            "version": receipt["version"],
            "received_at": receipt["received_at"],
            "vendor": receipt["vendor"],
            "sha256": receipt["canonical_sha256"],
            "duplicate": str(receipt["receipt_id"]) in duplicate_by_id,
            "duplicate_of": duplicate_by_id.get(str(receipt["receipt_id"]), {}).get("duplicate_of"),
            "conflict": str(receipt["receipt_id"]) in conflict_ids,
            "unmatched_reason": unmatched_by_id.get(str(receipt["receipt_id"]), {}).get("reason"),
        }
        for receipt in parsed_receipts
    ]
    confirmed_versions = {
        str(item["target"]["package"]): item["environment"]["version"]
        for item in item_output
        if item["environment"]["confirmed"]
    }

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "package_id": package_id,
        "plan_id": parsed_plan["plan_id"],
        "status": _CLOSED if complete else _IN_PROGRESS,
        "status_reason": "all_items_closed" if complete else "incomplete_evidence",
        "complete": complete,
        "policy": {
            "external_index_addresses": "omitted",
            "internal_paths": "redacted",
            "reconciliation": "per_plan_item",
            "duplicate_receipts": "deduplicated",
            "bindings": "sha256",
        },
        "bindings": {
            "plan": {
                "plan_id": parsed_plan["plan_id"],
                "title": parsed_plan["title"],
                "raw_sha256": plan_raw_digest,
                "canonical_sha256": plan_canonical_digest,
            },
            "audit": {
                "source": "pip-audit-offline",
                "raw_sha256": audit_raw_digest,
                "canonical_sha256": audit_canonical_digest,
                "audit_conflicts": parsed_audit["conflicts"],
                "skipped": parsed_audit["skipped"],
            },
            "receipts": receipt_bindings,
        },
        "summary": {
            "item_count": len(item_output),
            "closed_items": len(closed_items),
            "in_progress_items": len(pending_items),
            "receipt_count": len(parsed_receipts),
            "duplicate_receipts": len(duplicate_receipts),
            "unmatched_receipts": len(unmatched_receipts),
            "missing_material_count": sum(len(missing) for missing in missing_materials.values()),
        },
        "targets": targets,
        "environment": {
            "source": "pip-audit-offline",
            "confirmed_versions": confirmed_versions,
        },
        "receipts": receipt_register,
        "items": item_output,
        "missing_materials": missing_materials,
        "pending_missing_materials": {
            item_id: materials for item_id, materials in missing_materials.items() if materials
        },
        "next_actions": next_actions,
        "duplicates": duplicate_receipts,
        "unmatched_receipts": unmatched_receipts,
        "conflicts": receipt_conflicts + parsed_audit["conflicts"],
    }

    if generated_at is not None:
        payload["generated_at"] = generated_at

    redactor = _Redactor()
    redactor.add_omitted_fields(omitted_fields)
    payload = cast(dict[str, Any], redactor.redact(payload))
    payload["redactions"] = redactor.summary()

    payload_sha256 = _sha256_json(payload)
    signature_method = "sha256"
    signature_value = payload_sha256
    if signing_key is not None:
        key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        signature_method = "hmac-sha256"
        signature_value = hmac.new(key, payload_sha256.encode("ascii"), hashlib.sha256).hexdigest()

    payload["signoff"] = {
        "ready": complete,
        "ready_items": closed_items,
        "pending_items": pending_items,
        "payload_sha256": payload_sha256,
        "signature": {
            "method": signature_method,
            "value": signature_value,
            "signer": signer or "unassigned",
        },
        "instructions": (
            "Remove the 'signoff' member and hash the canonical JSON "
            "(sorted keys, compact separators) to verify payload_sha256."
        ),
    }

    return payload


build_handover_package = build_handover
"""Alias for :func:`build_handover`."""

reconcile_handover = build_handover
"""Alias for :func:`build_handover`."""


def verify_handover(
    package: Mapping[str, Any],
    *,
    signing_key: str | bytes | None = None,
) -> bool:
    """
    Verify the integrity digest and optional HMAC signature of a package.

    The ``signoff`` member is excluded from the payload digest, matching the
    instructions embedded in every generated package.
    """

    if "signoff" not in package:
        return False

    payload = {key: value for key, value in package.items() if key != "signoff"}
    payload_sha256 = _sha256_json(payload)
    signoff = package["signoff"]
    if not isinstance(signoff, Mapping):
        return False
    if signoff.get("payload_sha256") != payload_sha256:
        return False

    signature = signoff.get("signature")
    if not isinstance(signature, Mapping):
        return False
    if signature.get("method") == "sha256":
        return signature.get("value") == payload_sha256
    if signature.get("method") == "hmac-sha256":
        if signing_key is None:
            return False
        key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        expected = hmac.new(key, payload_sha256.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(str(signature.get("value")), expected)
    return False


def _markdown_cell(value: Any) -> str:
    """Escape a value for use inside a Markdown table cell."""

    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(package: Mapping[str, Any]) -> str:
    """Render a human-readable, signable reconciliation sheet."""

    summary = package.get("summary", {})
    signoff = package.get("signoff", {})
    lines: list[str] = [
        "# Dependency Remediation Handover",
        "",
        f"- Package: `{package.get('package_id', '')}`",
        f"- Schema: `{package.get('schema_version', '')}`",
        f"- Status: **{package.get('status', '')}**",
        f"- Items: {summary.get('closed_items', 0)} closed / "
        f"{summary.get('in_progress_items', 0)} in progress",
        f"- Receipts: {summary.get('receipt_count', 0)} received, "
        f"{summary.get('duplicate_receipts', 0)} duplicate",
        "",
        "## Disclosure",
        "",
        "External index addresses are omitted. Internal filesystem paths are "
        "redacted. Item identities and SHA-256 bindings below remain sufficient "
        "for item-by-item reconciliation against the original plan.",
        "",
        "## Reconciliation",
        "",
        "| Plan item | Target identity | Package | Target version | Confirmed | "
        "Required | Missing | Receipts | Status |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for item in package.get("items", []):
        target = item.get("target", {})
        environment = item.get("environment", {})
        required = ", ".join(item.get("required_materials", {}).keys())
        missing = ", ".join(item.get("missing_materials", [])) or "-"
        receipts = (
            ", ".join(str(receipt.get("receipt_id")) for receipt in item.get("receipts", [])) or "-"
        )
        confirmed = environment.get("version") or "-"
        if not environment.get("confirmed"):
            confirmed = f"{confirmed} (unconfirmed)"
        lines.append(
            "| "
            + " | ".join(
                _markdown_cell(value)
                for value in (
                    item.get("plan_item_id"),
                    target.get("disclosure_id"),
                    target.get("package"),
                    target.get("version"),
                    confirmed,
                    required,
                    missing,
                    receipts,
                    item.get("status"),
                )
            )
            + " |"
        )

    lines.extend(["", "## Missing Materials", ""])
    if package.get("missing_materials"):
        for item_id, materials in package["missing_materials"].items():
            rendered = ", ".join(materials) if materials else "none"
            lines.append(f"- `{item_id}`: {rendered}")
    else:
        lines.append("- None.")

    lines.extend(["", "## Receipt Reconciliation", ""])
    receipt_rows: list[dict[str, Any]] = []
    for item in package.get("items", []):
        receipt_rows.extend(
            {**receipt, "item_id": item.get("plan_item_id")} for receipt in item.get("receipts", [])
        )
    if receipt_rows:
        lines.extend(
            [
                "| Receipt | Plan item | Version | Materials |",
                "| --- | --- | --- | --- |",
            ]
        )
        lines.extend(
            "| "
            + " | ".join(
                _markdown_cell(value)
                for value in (
                    receipt.get("receipt_id"),
                    receipt.get("item_id"),
                    receipt.get("version") or "-",
                    ", ".join(receipt.get("materials", [])),
                )
            )
            + " |"
            for receipt in receipt_rows
        )
    else:
        lines.append("- No receipts matched a plan item.")

    if package.get("duplicates"):
        lines.extend(["", "## Duplicate Receipts", ""])
        lines.extend(
            (
                f"- `{duplicate.get('receipt_id')}` duplicates "
                f"`{duplicate.get('duplicate_of')}` "
                f"({duplicate.get('reason')}); no additional evidence counted."
            )
            for duplicate in package["duplicates"]
        )

    if package.get("unmatched_receipts"):
        lines.extend(["", "## Unmatched Receipts", ""])
        lines.extend(
            f"- `{receipt.get('receipt_id')}`: {receipt.get('reason')}"
            for receipt in package["unmatched_receipts"]
        )

    lines.extend(
        [
            "",
            "## Sign-off",
            "",
            f"- Ready for sign-off: **{'yes' if signoff.get('ready') else 'no'}**",
            f"- Payload SHA-256: `{signoff.get('payload_sha256', '')}`",
            f"- Signature: `{signoff.get('signature', {}).get('method', '')}` "
            f"`{signoff.get('signature', {}).get('value', '')}`",
            f"- Signer: {signoff.get('signature', {}).get('signer', '')}",
            "",
            "Approver: ______________________________",
            "",
            "Date: ______________________________",
            "",
            "Signature: ______________________________",
            "",
        ]
    )
    return "\n".join(lines)


def _read_input(path: str) -> tuple[Any, bytes]:
    """Read and parse a JSON input file, using ``-`` for standard input."""

    if path == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(path).read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HandoverError(f"invalid JSON in {path}: {exc}") from exc
    return value, raw


def _writer_parser() -> argparse.ArgumentParser:
    """Create the argument parser for ``pip-audit-handover``."""

    parser = argparse.ArgumentParser(
        prog="pip-audit-handover",
        description=(
            "build a disclosure-safe, signable handover package from an offline "
            "pip-audit result and vendor receipts"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--plan", required=True, help="remediation plan JSON file")
    parser.add_argument(
        "--audit",
        required=True,
        help="offline pip-audit JSON result, or '-' for standard input",
    )
    parser.add_argument(
        "--receipt",
        action="append",
        default=[],
        dest="receipts",
        metavar="RECEIPT",
        help="vendor receipt JSON file; may be supplied multiple times",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="output format when writing to a single destination",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--output",
        type=Path,
        help="write the selected format to this file instead of standard output",
    )
    output_group.add_argument(
        "--output-dir",
        type=Path,
        help="write handover.json and HANDOVER.md into this directory",
    )
    parser.add_argument(
        "--generated-at",
        help="optional timestamp to embed in the package",
    )
    parser.add_argument(
        "--package-id",
        help="optional stable package identifier",
    )
    parser.add_argument(
        "--signer",
        help="label identifying the signer role or system",
    )
    parser.add_argument(
        "--signing-key-env",
        default=_DEFAULT_SIGNING_KEY_ENV,
        help="environment variable containing an optional HMAC signing key",
    )
    parser.add_argument(
        "--fail-on-incomplete",
        action="store_true",
        help="exit with status 2 when any plan item remains in progress",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``pip-audit-handover`` command-line interface."""

    parser = _writer_parser()
    args = parser.parse_args(argv)

    try:
        plan, plan_raw = _read_input(args.plan)
        audit, audit_raw = _read_input(args.audit)
        receipt_objects: list[Any] = []
        receipt_raws: list[bytes] = []
        for receipt_path in args.receipts:
            receipt, receipt_raw = _read_input(receipt_path)
            receipt_objects.append(receipt)
            receipt_raws.append(receipt_raw)

        signing_key = os.environ.get(args.signing_key_env) or None
        package = build_handover(
            plan,
            audit,
            receipt_objects,
            plan_raw=plan_raw,
            audit_raw=audit_raw,
            receipt_raws=receipt_raws,
            generated_at=args.generated_at,
            package_id=args.package_id,
            signer=args.signer,
            signing_key=signing_key,
        )

        if args.output_dir is not None:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            json_path = args.output_dir / "handover.json"
            markdown_path = args.output_dir / "HANDOVER.md"
            json_path.write_text(
                json.dumps(package, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            markdown_path.write_text(render_markdown(package), encoding="utf-8")
            print(
                f"Wrote {json_path} and {markdown_path} "
                f"({package['summary']['closed_items']} closed, "
                f"{package['summary']['in_progress_items']} in progress)",
                file=sys.stderr,
            )
        else:
            rendered = (
                json.dumps(package, indent=2, ensure_ascii=False) + "\n"
                if args.format == "json"
                else render_markdown(package)
            )
            if args.output is None:
                print(rendered)
            else:
                args.output.write_text(rendered, encoding="utf-8")
    except (HandoverError, OSError) as exc:
        print(f"pip-audit-handover: {exc}", file=sys.stderr)
        return 1

    if args.fail_on_incomplete and not package["complete"]:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
