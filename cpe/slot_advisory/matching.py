"""CPE identity and version matching helpers for slot-scoped adjudication."""

from __future__ import annotations

import hashlib
import json
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .. import CPE


WILDCARD_VALUES = {"*", "?", "ANY", "NA", ""}


def canonical_json(value: Any) -> str:
    """Serialize data in a stable form for fingerprints and hashes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def identity_fingerprint(identity: Dict[str, Any]) -> str:
    return sha256_text(canonical_json(identity))


def _clean_cpe_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value.replace(chr(92), "")


def _first_cpe_value(cpe: CPE, getter: str) -> Optional[str]:
    try:
        values = getattr(cpe, getter)()
    except Exception:
        return None
    if not values:
        return None
    return _clean_cpe_value(values[0])


def cpe_fields(cpe_name: str) -> Dict[str, Optional[str]]:
    """Return the small CPE field subset used by slot advisories."""
    cpe = CPE(cpe_name)
    fields = {}
    for name in ("part", "vendor", "product", "version"):
        fields[name] = _first_cpe_value(cpe, "get_" + name)
    if fields["version"] in WILDCARD_VALUES:
        fields["version"] = None
    return fields


def version_key(version: Optional[str]) -> Tuple[Tuple[int, int, str], ...]:
    """Return a comparable key for common numeric software versions."""
    if version is None:
        return ()

    tokens: List[Tuple[int, int, str]] = []
    text = str(version).strip()
    for chunk in text.replace("-", ".").replace("_", ".").split("."):
        number = ""
        for char in chunk:
            if char.isdigit():
                number += char
                continue
            if number:
                tokens.append((1, int(number), ""))
                number = ""
            tokens.append((0, 0, char.lower()))
        if number:
            tokens.append((1, int(number), ""))
    return tuple(tokens)


def compare_versions(left: Optional[str], right: Optional[str]) -> int:
    left_key = version_key(left)
    right_key = version_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _operator_match(version: str, operator: str, expected: str) -> bool:
    comparison = compare_versions(version, expected)
    if operator == "<":
        return comparison < 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == ">=":
        return comparison >= 0
    if operator in ("=", "=="):
        return comparison == 0
    if operator == "!=":
        return comparison != 0
    raise ValueError("Unsupported version operator: " + operator)


def version_matches_constraint(version: Optional[str], constraint: str) -> bool:
    if not version:
        return False
    operators = ("<=", ">=", "==", "!=", "=", "<", ">")
    for raw_clause in str(constraint).split(","):
        clause = raw_clause.strip()
        if not clause:
            continue
        for operator in operators:
            if clause.startswith(operator):
                expected = clause[len(operator):].strip()
                if not _operator_match(version, operator, expected):
                    return False
                break
        else:
            if compare_versions(version, clause) != 0:
                return False
    return True


def _wildcard_match(pattern: Optional[str], value: Optional[str]) -> bool:
    if pattern is None or pattern in WILDCARD_VALUES:
        return True
    if value is None:
        return False
    return fnmatchcase(value.lower(), pattern.lower())


def cpe_match(condition_cpe: str, component_cpe: str, use_version: bool = True) -> bool:
    condition = cpe_fields(condition_cpe)
    component = cpe_fields(component_cpe)
    for field_name in ("part", "vendor", "product"):
        if not _wildcard_match(condition.get(field_name), component.get(field_name)):
            return False
    if use_version:
        condition_version = condition.get("version")
        if condition_version and not _wildcard_match(
            condition_version, component.get("version")
        ):
            return False
    return True


def product_matches(condition: Dict[str, Any], component: Dict[str, Any]) -> bool:
    return cpe_match(condition["cpe"], component["cpe"], use_version=False)


def component_version(component: Dict[str, Any]) -> Optional[str]:
    version = component.get("version")
    if version:
        return str(version)
    return cpe_fields(component["cpe"]).get("version")


def is_affected_component(condition: Dict[str, Any], component: Dict[str, Any]) -> bool:
    if not product_matches(condition, component):
        return False

    version = component_version(component)
    affected_versions = condition.get("affected_versions")
    constraint = condition.get("version_constraint")

    if affected_versions:
        return any(compare_versions(version, item) == 0 for item in affected_versions)
    if constraint:
        return version_matches_constraint(version, constraint)
    return cpe_match(condition["cpe"], component["cpe"], use_version=True)


def component_fingerprint(component: Dict[str, Any]) -> str:
    identity = {
        "component_id": component.get("component_id") or component["cpe"],
        "cpe": component["cpe"],
        "version": component_version(component),
        "digest": component.get("digest"),
        "path": component.get("path"),
    }
    return identity_fingerprint(identity)


def normalize_component(raw: Any, default_scope: Optional[str] = None) -> Dict[str, Any]:
    if hasattr(raw, "to_dict"):
        raw = raw.to_dict()
    if not isinstance(raw, dict):
        raise TypeError("component must be a mapping or model object")

    cpe_name = raw.get("cpe")
    if not cpe_name:
        raise ValueError("component is missing cpe")

    normalized = dict(raw)
    normalized["version"] = raw.get("version") or component_version(raw)
    normalized["component_id"] = raw.get("component_id") or cpe_name
    normalized["scope"] = raw.get("scope") or default_scope
    normalized["fingerprint"] = component_fingerprint(normalized)
    return normalized


def normalize_components(
    raw_items: Optional[Iterable[Any]], default_scope: str
) -> List[Dict[str, Any]]:
    return [normalize_component(item, default_scope) for item in (raw_items or [])]
