"""Differential interpretation of registry findings.

The module is intentionally opt-in: callers provide one or more *rule sets*
that describe how a registry value should be interpreted.  The same collected
material (a hive plus optionally pre-collected plugin output) is evaluated
against every rule set.  Conclusions stay ``pending`` unless every supplied
interpretation agrees and every condition is backed by evidence.

Rules can depend on other keys.  A dependency that cannot be read makes the
rule pending; it never makes a configuration item "enabled by default".

Every condition result keeps its raw registry source and, when available, the
plugin entry that produced the same value (including the entry path and list
indices).  That provenance is what lets an investigator challenge a prior
one-line finding without re-collecting evidence.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException, RegistryParsingException
from regipy.plugins.plugin import PLUGINS
from regipy.registry import RegistryHive

logger = logging.getLogger(__name__)


class ReviewError(ValueError):
    """Raised when a rule set or a review request is malformed."""


SUPPORTED_OPERATORS = frozenset(
    {
        "eq",
        "ne",
        "in",
        "not_in",
        "exists",
        "missing",
        "non_empty",
        "empty",
        "truthy",
        "falsy",
        "contains",
        "not_contains",
        "startswith",
        "endswith",
        "regex",
        "gt",
        "ge",
        "lt",
        "le",
    }
)

# Operators for which an ``expected`` operand is optional.
_NO_EXPECTED_OPERATORS = frozenset(
    {
        "exists",
        "missing",
        "non_empty",
        "empty",
        "truthy",
        "falsy",
    }
)

_MISSING = object()


def _clean_id(value: Any) -> str:
    text = str(value).strip()
    if not text:
        raise ReviewError("IDs must be non-empty strings")
    return text


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, default=_json_default)
    return str(value)


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    return str(value)


def _jsonable(value: Any) -> Any:
    """Recursively convert hive/plugin values to JSON-safe primitives."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, set):
        return sorted(_jsonable(v) for v in value)
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _normalize_path(path: str) -> str:
    path = str(path).strip().replace("/", "\\")
    if not path.startswith("\\"):
        path = "\\" + path
    if len(path) > 1:
        path = path.rstrip("\\")
    return path


def _normalized_text(value: Any, case_sensitive: bool = False) -> str:
    text = _as_text(value) or ""
    return text if case_sensitive else text.casefold()


def _values_equal(actual: Any, expected: Any, case_sensitive: bool = False) -> bool:
    if isinstance(actual, list) and isinstance(expected, list):
        if len(actual) != len(expected):
            return False
        return all(_values_equal(a, e, case_sensitive=case_sensitive) for a, e in zip(actual, expected))

    if isinstance(actual, (bytes, bytearray)) and isinstance(expected, str):
        for encoding in ("utf-8", "utf-16-le"):
            try:
                actual = bytes(actual).decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            actual = bytes(actual).hex()

    if isinstance(expected, (bytes, bytearray)) and isinstance(actual, str):
        for encoding in ("utf-8", "utf-16-le"):
            try:
                expected = bytes(expected).decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            expected = bytes(expected).hex()

    if isinstance(actual, bool) or isinstance(expected, bool):
        return bool(actual) == bool(expected)

    if isinstance(actual, int) and isinstance(expected, str):
        with contextlib.suppress(TypeError, ValueError):
            expected = int(expected, 0)
    elif isinstance(expected, int) and isinstance(actual, str):
        with contextlib.suppress(TypeError, ValueError):
            actual = int(actual, 0)

    if isinstance(actual, str) and isinstance(expected, str):
        return actual == expected if case_sensitive else actual.casefold() == expected.casefold()

    return actual == expected


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return None
    return None


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (str, bytes, bytearray, list, tuple, dict, set)):
        return len(value) == 0
    return False


def _compare(actual: Any, op: str, expected: Any, case_sensitive: bool = False) -> bool:
    if op == "exists":
        return actual is not _MISSING
    if op == "missing":
        return actual is _MISSING
    if actual is _MISSING:
        return False

    if op == "eq":
        return _values_equal(actual, expected, case_sensitive=case_sensitive)
    if op == "ne":
        return not _values_equal(actual, expected, case_sensitive=case_sensitive)
    if op == "in":
        return any(_values_equal(actual, item, case_sensitive=case_sensitive) for item in _as_list(expected))
    if op == "not_in":
        return not any(_values_equal(actual, item, case_sensitive=case_sensitive) for item in _as_list(expected))
    if op == "non_empty":
        return not _is_empty(actual)
    if op == "empty":
        return _is_empty(actual)
    if op == "truthy":
        return bool(actual)
    if op == "falsy":
        return not bool(actual)
    if op == "contains":
        if isinstance(actual, str):
            return _normalized_text(expected, case_sensitive) in _normalized_text(actual, case_sensitive)
        try:
            return expected in actual
        except TypeError:
            return False
    if op == "not_contains":
        if isinstance(actual, str):
            return _normalized_text(expected, case_sensitive) not in _normalized_text(actual, case_sensitive)
        try:
            return expected not in actual
        except TypeError:
            return True
    if op == "startswith":
        return _normalized_text(actual, case_sensitive).startswith(_normalized_text(expected, case_sensitive))
    if op == "endswith":
        return _normalized_text(actual, case_sensitive).endswith(_normalized_text(expected, case_sensitive))
    if op == "regex":
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.search(str(expected), _as_text(actual) or "", flags=flags) is not None
        except re.error as ex:
            raise ReviewError(f"Invalid regular expression {expected!r}: {ex}") from ex

    actual_number = _as_number(actual)
    expected_number = _as_number(expected)
    if actual_number is None or expected_number is None:
        return False
    if op == "gt":
        return actual_number > expected_number
    if op == "ge":
        return actual_number >= expected_number
    if op == "lt":
        return actual_number < expected_number
    if op == "le":
        return actual_number <= expected_number

    raise ReviewError(f"Unsupported operator: {op!r}")


@dataclass
class Condition:
    """A single condition over one registry value.

    ``path`` may begin with ``\\CurrentControlSet`` (or use the
    ``{current_control_set}`` token); it is resolved through ``\\Select\\Current``
    before reading the hive.

    ``evidence`` is an optional hint telling the reviewer where the same value
    appears in pre-collected plugin output, for example::

        {"plugin": "host_domain_name", "entry_index": "current", "field": "domain"}
    """

    id: str
    path: str
    value: str
    op: str = "eq"
    expected: Any = None
    case_sensitive: bool = False
    assumptions: list[str] = field(default_factory=list)
    description: str | None = None
    evidence: dict[str, Any] | None = None
    raw_entry_range: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], default_id: str) -> Condition:
        if not isinstance(data, Mapping):
            raise ReviewError(f"Condition {default_id!r} must be an object")

        path = data.get("path", data.get("key"))
        value = data.get("value", data.get("value_name", data.get("name")))
        if not path:
            raise ReviewError(f"Condition {default_id!r} is missing 'path'")
        if value is None:
            raise ReviewError(f"Condition {default_id!r} is missing 'value'")

        condition_id = _clean_id(data.get("id", default_id))
        op = str(data.get("op", "eq")).strip().lower()
        if op not in SUPPORTED_OPERATORS:
            raise ReviewError(
                f"Condition {condition_id!r} uses unsupported operator {op!r}; "
                f"supported operators: {', '.join(sorted(SUPPORTED_OPERATORS))}"
            )

        if op not in _NO_EXPECTED_OPERATORS and "expected" not in data:
            raise ReviewError(f"Condition {condition_id!r} requires 'expected' for operator {op!r}")

        assumptions = data.get("assumptions", data.get("assumption", []))
        if isinstance(assumptions, str):
            assumptions = [assumptions]
        if not isinstance(assumptions, list):
            raise ReviewError(f"Condition {condition_id!r} 'assumptions' must be a list or string")

        evidence = data.get("evidence")
        if evidence is not None and not isinstance(evidence, Mapping):
            raise ReviewError(f"Condition {condition_id!r} 'evidence' must be an object")

        raw_entry_range = data.get("raw_entry_range")
        if raw_entry_range is not None and not isinstance(raw_entry_range, Mapping):
            raise ReviewError(f"Condition {condition_id!r} 'raw_entry_range' must be an object")

        return cls(
            id=condition_id,
            path=_normalize_path(str(path)),
            value=str(value),
            op=op,
            expected=data.get("expected"),
            case_sensitive=bool(data.get("case_sensitive", False)),
            assumptions=[str(item) for item in assumptions],
            description=data.get("description"),
            evidence=dict(evidence) if evidence is not None else None,
            raw_entry_range=dict(raw_entry_range) if raw_entry_range is not None else None,
        )


@dataclass
class Rule:
    id: str
    subject: str
    conclusion: str
    conditions: list[Condition] = field(default_factory=list)
    assumptions: dict[str, str] = field(default_factory=dict)
    description: str | None = None
    plugin: str | None = None
    raw_entry_range: dict[str, Any] | None = None

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        default_id: str,
        rule_set_assumptions: Mapping[str, str],
        rule_set_plugins: Iterable[str],
    ) -> Rule:
        if not isinstance(data, Mapping):
            raise ReviewError(f"Rule {default_id!r} must be an object")

        rule_id = _clean_id(data.get("id", default_id))
        subject = data.get("subject")
        conclusion = data.get("conclusion")
        if not subject:
            raise ReviewError(f"Rule {rule_id!r} is missing 'subject'")
        if conclusion is None:
            raise ReviewError(f"Rule {rule_id!r} is missing 'conclusion'")

        assumptions = dict(rule_set_assumptions)
        local_assumptions = data.get("assumptions", {})
        if local_assumptions:
            if not isinstance(local_assumptions, Mapping):
                raise ReviewError(f"Rule {rule_id!r} 'assumptions' must be an object")
            assumptions.update({str(k): str(v) for k, v in local_assumptions.items()})

        conditions_data = data.get("conditions", [])
        if isinstance(conditions_data, Mapping):
            conditions_data = [conditions_data]
        if not isinstance(conditions_data, list):
            raise ReviewError(f"Rule {rule_id!r} 'conditions' must be a list")

        conditions = [
            Condition.from_dict(condition, f"{rule_id}.condition_{index}")
            for index, condition in enumerate(conditions_data, start=1)
        ]

        plugin = data.get("plugin")
        if plugin is not None:
            plugin = str(plugin)

        # Preserve explicitly supplied provenance if a plugin entry cannot be
        # located later (for example when reviewing an already-normalized dump).
        raw_entry_range = data.get("raw_entry_range")
        if raw_entry_range is not None and not isinstance(raw_entry_range, Mapping):
            raise ReviewError(f"Rule {rule_id!r} 'raw_entry_range' must be an object")

        return cls(
            id=rule_id,
            subject=str(subject),
            conclusion=str(conclusion),
            conditions=conditions,
            assumptions=assumptions,
            description=data.get("description"),
            plugin=plugin,
            raw_entry_range=dict(raw_entry_range) if raw_entry_range is not None else None,
        )


@dataclass
class RuleSet:
    name: str
    rules: list[Rule]
    description: str | None = None
    assumptions: dict[str, str] = field(default_factory=dict)
    plugins: list[str] = field(default_factory=list)
    source: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], source: str | None = None) -> RuleSet:
        if not isinstance(data, Mapping):
            raise ReviewError("A rule set must be an object")

        name = data.get("name", data.get("id"))
        if not name:
            raise ReviewError("A rule set is missing its 'name'")
        name = _clean_id(name)

        assumptions = data.get("assumptions", {})
        if assumptions is None:
            assumptions = {}
        if not isinstance(assumptions, Mapping):
            raise ReviewError(f"Rule set {name!r} 'assumptions' must be an object")
        assumptions = {str(k): str(v) for k, v in assumptions.items()}

        plugins = data.get("plugins", [])
        if isinstance(plugins, str):
            plugins = [plugins]
        if not isinstance(plugins, list):
            raise ReviewError(f"Rule set {name!r} 'plugins' must be a list or string")
        plugin_names = [str(plugin) for plugin in plugins]

        rules_data = data.get("rules")
        if not isinstance(rules_data, list) or not rules_data:
            raise ReviewError(f"Rule set {name!r} must contain a non-empty 'rules' list")

        rules: list[Rule] = []
        seen_rule_ids = set()
        for index, rule_data in enumerate(rules_data, start=1):
            rule = Rule.from_dict(rule_data, f"{name}.rule_{index}", assumptions, plugin_names)
            if rule.id in seen_rule_ids:
                raise ReviewError(f"Rule set {name!r} contains duplicate rule id {rule.id!r}")
            seen_rule_ids.add(rule.id)

            for plugin in [
                rule.plugin,
                *[condition.evidence.get("plugin") for condition in rule.conditions if condition.evidence],
            ]:
                if plugin and plugin not in plugin_names:
                    plugin_names.append(str(plugin))
            rules.append(rule)

        return cls(
            name=name,
            rules=rules,
            description=data.get("description"),
            assumptions=assumptions,
            plugins=plugin_names,
            source=source or data.get("source"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "assumptions": dict(self.assumptions),
            "plugins": list(self.plugins),
            "rules": [asdict(rule) for rule in self.rules],
        }


def _load_json(source: str | Path) -> Any:
    path = Path(source)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_rule_sets(
    sources: RuleSet | Mapping[str, Any] | str | Path | Sequence[RuleSet | Mapping[str, Any] | str | Path],
) -> list[RuleSet]:
    """Load one or more rule sets from objects, JSON files, or a mixed list."""
    if isinstance(sources, RuleSet):
        return [sources]

    if isinstance(sources, (str, Path)):
        data = _load_json(sources)
        source_name = str(sources)
        if isinstance(data, list):
            return [RuleSet.from_dict(item, source=source_name) for item in data]
        if isinstance(data, Mapping) and "rule_sets" in data:
            return [RuleSet.from_dict(item, source=source_name) for item in data["rule_sets"]]
        return [RuleSet.from_dict(data, source=source_name)]

    if isinstance(sources, Mapping):
        if "rule_sets" in sources:
            return [RuleSet.from_dict(item, source=item.get("source")) for item in sources["rule_sets"]]
        return [RuleSet.from_dict(sources)]

    if isinstance(sources, (list, tuple)):
        loaded: list[RuleSet] = []
        for source in sources:
            loaded.extend(load_rule_sets(source))
        if not loaded:
            raise ReviewError("At least one rule set is required")
        return loaded

    raise ReviewError(f"Unsupported rule set source: {type(sources).__name__}")


def _current_control_set_path(registry_hive: RegistryHive) -> str | None:
    try:
        select_key = registry_hive.get_key(r"\Select")
        current = select_key.get_value("Current", as_json=True)
        current_number = int(current)
    except (RegistryKeyNotFoundException, RegistryParsingException, TypeError, ValueError):
        return None
    return f"\\ControlSet{current_number:03d}"


def _resolve_condition_path(registry_hive: RegistryHive, path: str) -> tuple[str | None, str | None]:
    path = path.replace("{current_control_set}", "\\CurrentControlSet").replace("%CurrentControlSet%", "\\CurrentControlSet")
    path = _normalize_path(path)

    current_prefix = "\\CurrentControlSet"
    if path.casefold() == current_prefix.casefold() or path.casefold().startswith(current_prefix.casefold() + "\\"):
        current = _current_control_set_path(registry_hive)
        if current is None:
            return None, "current_control_set_unavailable"
        suffix = path[len(current_prefix) :]
        return _normalize_path(current + suffix), None
    return path, None


def _find_value_record(key: Any, value_name: str, case_sensitive: bool) -> Any:
    for value in key.iter_values(as_json=True):
        candidate = value.name
        if candidate == value_name:
            return value
        if not case_sensitive and candidate.casefold() == value_name.casefold():
            return value
    return None


def _hive_evidence(
    key_path: str,
    value_name: str,
    found: bool,
    actual: Any = None,
    value_type: str | None = None,
    corrupted: bool = False,
) -> dict[str, Any]:
    return {
        "kind": "hive_value",
        "plugin": None,
        "key_path": key_path,
        "value_name": value_name,
        "value": _jsonable(actual),
        "value_type": value_type,
        "found": found,
        "corrupted": corrupted,
        "entry_path": None,
        "entry_indices": [],
        "raw_entry_range": None,
        "raw_entry": None,
    }


def _display_join(base: str, key: Any) -> str:
    text = str(key)
    if not base:
        return text
    if text.startswith("["):
        return f"{base}{text}"
    return f"{base}.{text}"


def _walk_plugin_entries(
    value: Any,
    display_path: str = "",
    list_indices: list[int] | None = None,
) -> Iterable[tuple[dict[str, Any], str, list[int]]]:
    """Yield key records in plugin output that carry a ``path`` and ``values``."""
    if list_indices is None:
        list_indices = []

    if isinstance(value, Mapping):
        if isinstance(value.get("path"), str) and isinstance(value.get("values"), list):
            yield dict(value), display_path or "$", list(list_indices)

        for key, child in value.items():
            child_path = _display_join(display_path, key)
            yield from _walk_plugin_entries(child, child_path, list_indices)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            label = None
            if isinstance(child, Mapping):
                label = child.get("name") or child.get("subkey_name")
            part = f"[{index}:{label}]" if label else f"[{index}]"
            child_path = _display_join(display_path, part)
            yield from _walk_plugin_entries(child, child_path, list_indices + [index])


def _raw_entry_range(
    plugin: str,
    entry_path: str,
    entry_indices: list[int],
    value_index: int | None = None,
    field_name: str | None = None,
) -> dict[str, Any]:
    return {
        "plugin": plugin,
        "entry_path": entry_path,
        "entry_indices": list(entry_indices),
        "start": entry_indices[-1] if entry_indices else None,
        "end": (entry_indices[-1] + 1) if entry_indices else None,
        "range": ([entry_indices[-1], entry_indices[-1] + 1] if entry_indices else None),
        "value_index": value_index,
        "field": field_name,
    }


def _plugin_evidence_from_record(
    plugin: str,
    record: Mapping[str, Any],
    entry_path: str,
    entry_indices: list[int],
    value_name: str,
    value_record: Mapping[str, Any] | None,
    value_index: int | None,
    field_name: str | None = None,
    explicit_value: Any = _MISSING,
) -> dict[str, Any]:
    if value_record is not None:
        actual = value_record.get("value")
        value_type = value_record.get("value_type")
        corrupted = bool(value_record.get("is_corrupted", False))
        found = True
    elif explicit_value is not _MISSING:
        actual = explicit_value
        value_type = type(explicit_value).__name__
        corrupted = False
        found = True
    else:
        actual = None
        value_type = None
        corrupted = False
        found = False

    if value_record is not None:
        raw_entry = {
            "path": record.get("path"),
            "subkey_name": record.get("subkey_name"),
            "timestamp": record.get("timestamp"),
            "value": dict(value_record),
        }
    else:
        # Explicit field lookups often point at compact, plugin-specific
        # entries (for example host_domain_name's {"hostname", "domain"}).
        # Keep those fields as the raw entry, but avoid copying a large
        # ``values`` list when the record is a normal registry-key record.
        raw_entry = {key: value for key, value in record.items() if key != "values"}
        raw_entry["field"] = field_name
        raw_entry["field_value"] = _jsonable(actual) if actual is not _MISSING else None

    return {
        "kind": "plugin_entry",
        "plugin": plugin,
        "key_path": record.get("path"),
        "value_name": value_name,
        "value": _jsonable(actual),
        "value_type": value_type,
        "found": found,
        "corrupted": corrupted,
        "entry_path": entry_path,
        "entry_indices": list(entry_indices),
        "raw_entry_range": _raw_entry_range(plugin, entry_path, entry_indices, value_index, field_name),
        "raw_entry": _jsonable(raw_entry),
    }


def _match_path(record_path: str, expected_path: str) -> bool:
    left = _normalize_path(record_path).casefold()
    right = _normalize_path(expected_path).casefold()
    return left == right or left.endswith("\\" + right.lstrip("\\"))


def _find_recursive_plugin_evidence(
    plugin_results: Mapping[str, Any],
    key_path: str,
    value_name: str,
    case_sensitive: bool,
) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for plugin, entries in plugin_results.items():
        for record, entry_path, entry_indices in _walk_plugin_entries(entries):
            if not _match_path(str(record.get("path", "")), key_path):
                continue

            matched_value = False
            for value_index, value_record in enumerate(record.get("values", [])):
                name = str(value_record.get("name", ""))
                same_name = name == value_name if case_sensitive else name.casefold() == value_name.casefold()
                if not same_name:
                    continue
                matched_value = True
                found.append(
                    _plugin_evidence_from_record(
                        plugin,
                        record,
                        entry_path,
                        entry_indices,
                        value_name,
                        value_record,
                        value_index,
                    )
                )

            if not matched_value:
                found.append(
                    _plugin_evidence_from_record(
                        plugin,
                        record,
                        entry_path,
                        entry_indices,
                        value_name,
                        None,
                        None,
                    )
                )

    return _dedupe_evidence(found)


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen = set()
    for item in items:
        key = (
            item.get("kind"),
            item.get("plugin"),
            tuple(item.get("entry_indices", [])),
            item.get("entry_path"),
            item.get("value_name"),
            item.get("found"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _dotted_get(value: Any, dotted_path: str) -> Any:
    current = value
    for part in dotted_path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return _MISSING
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _select_explicit_entries(
    entries: Any,
    hint: Mapping[str, Any],
    registry_hive: RegistryHive,
) -> list[tuple[str, list[int], Any]]:
    selected: list[tuple[str, list[int], Any]] = []

    entry_index = hint.get("entry_index")
    if entry_index == "current":
        current_path = _current_control_set_path(registry_hive)
        existing = []
        for candidate in (r"\ControlSet001", r"\ControlSet002"):
            try:
                registry_hive.get_key(candidate)
            except RegistryKeyNotFoundException:
                continue
            existing.append(candidate)
        if current_path in existing:
            entry_index = existing.index(current_path)
        else:
            entry_index = None

    if entry_index is not None and entry_index != "*":
        index = int(entry_index)
        if isinstance(entries, list):
            if 0 <= index < len(entries):
                selected.append((f"[{index}]", [index], entries[index]))
        elif isinstance(entries, Mapping):
            keys = list(entries.keys())
            if 0 <= index < len(keys):
                key = keys[index]
                selected.append((_display_join("", key), [], entries[key]))
        return selected

    if entry_index == "*":
        if isinstance(entries, list):
            return [(f"[{index}]", [index], entry) for index, entry in enumerate(entries)]
        if isinstance(entries, Mapping):
            return [(_display_join("", key), [], entry) for key, entry in entries.items()]

    entry_path = hint.get("entry_path")
    if entry_path:
        current = entries
        parts = str(entry_path).split(".")
        for part in parts:
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                return []
        selected.append((str(entry_path), [], current))
        return selected

    match = hint.get("match")
    if isinstance(match, Mapping):
        for record, display_path, indices in _walk_plugin_entries(entries):
            if all(_values_equal(record.get(key), value) for key, value in match.items()):
                selected.append((display_path, indices, record))
        return selected

    if isinstance(entries, list):
        return [(f"[{index}]", [index], entry) for index, entry in enumerate(entries)]
    if isinstance(entries, Mapping):
        return [(_display_join("", key), [], entry) for key, entry in entries.items()]
    return []


def _find_explicit_plugin_evidence(
    condition: Condition,
    plugin_results: Mapping[str, Any],
    registry_hive: RegistryHive,
) -> list[dict[str, Any]]:
    if not condition.evidence:
        return []

    hint = condition.evidence
    plugin = hint.get("plugin")
    if not plugin or plugin not in plugin_results:
        return []

    field_name = hint.get("field")
    value_name = str(hint.get("value_name", hint.get("value", condition.value)))
    evidence: list[dict[str, Any]] = []

    for entry_path, entry_indices, entry in _select_explicit_entries(plugin_results[plugin], hint, registry_hive):
        if not isinstance(entry, Mapping):
            continue

        if field_name:
            explicit = _dotted_get(entry, str(field_name))
            evidence.append(
                _plugin_evidence_from_record(
                    str(plugin),
                    entry,
                    entry_path,
                    entry_indices,
                    value_name,
                    None,
                    None,
                    field_name=str(field_name),
                    explicit_value=explicit if explicit is not _MISSING else _MISSING,
                )
            )
            continue

        values = entry.get("values")
        if not isinstance(values, list):
            continue

        matched_value = False
        for value_index, value_record in enumerate(values):
            name = str(value_record.get("name", ""))
            same_name = name == value_name if condition.case_sensitive else name.casefold() == value_name.casefold()
            if not same_name:
                continue
            matched_value = True
            evidence.append(
                _plugin_evidence_from_record(
                    str(plugin),
                    entry,
                    entry_path,
                    entry_indices,
                    value_name,
                    value_record,
                    value_index,
                )
            )

        if not matched_value:
            evidence.append(
                _plugin_evidence_from_record(
                    str(plugin),
                    entry,
                    entry_path,
                    entry_indices,
                    value_name,
                    None,
                    None,
                )
            )

    return _dedupe_evidence(evidence)


def _evaluate_condition(
    condition: Condition,
    registry_hive: RegistryHive,
    plugin_results: Mapping[str, Any],
) -> dict[str, Any]:
    resolved_path, path_error = _resolve_condition_path(registry_hive, condition.path)
    evidence: list[dict[str, Any]] = []

    if path_error:
        return {
            "id": condition.id,
            "description": condition.description,
            "requested_path": condition.path,
            "path": condition.path,
            "value": condition.value,
            "op": condition.op,
            "expected": _jsonable(condition.expected),
            "actual": None,
            "found": False,
            "matched": False,
            "unknown": True,
            "reason": path_error,
            "assumptions": list(condition.assumptions),
            "evidence": evidence,
        }

    assert resolved_path is not None
    actual: Any = _MISSING
    value_type: str | None = None
    corrupted = False
    reason: str | None = None

    try:
        key = registry_hive.get_key(resolved_path)
    except RegistryKeyNotFoundException:
        key = None
        reason = "missing_key"
    except RegistryParsingException as ex:
        key = None
        reason = f"unreadable_key: {ex}"

    value_record = None
    if key is not None:
        try:
            value_record = _find_value_record(key, condition.value, condition.case_sensitive)
        except RegistryParsingException as ex:
            reason = f"unreadable_value: {ex}"

        if value_record is not None:
            actual = value_record.value
            value_type = value_record.value_type
            corrupted = bool(value_record.is_corrupted)
            if corrupted:
                reason = "corrupted_value"
        elif reason is None:
            reason = "missing_value"

    found = actual is not _MISSING

    if found:
        evidence.append(
            _hive_evidence(
                resolved_path,
                condition.value,
                True,
                actual=actual,
                value_type=value_type,
                corrupted=corrupted,
            )
        )
    else:
        evidence.append(_hive_evidence(resolved_path, condition.value, False))

    try:
        explicit_plugin_evidence = _find_explicit_plugin_evidence(condition, plugin_results, registry_hive)
    except (ReviewError, ValueError, TypeError) as ex:
        logger.debug(f"Could not resolve explicit plugin evidence for {condition.id}: {ex}")
        explicit_plugin_evidence = []

    if explicit_plugin_evidence:
        evidence.extend(explicit_plugin_evidence)
    elif found:
        evidence.extend(
            _find_recursive_plugin_evidence(
                plugin_results,
                resolved_path,
                condition.value,
                condition.case_sensitive,
            )
        )

    if condition.raw_entry_range and not any(item.get("kind") == "plugin_entry" for item in evidence):
        evidence.append(
            {
                "kind": "declared_entry_range",
                "plugin": condition.raw_entry_range.get("plugin"),
                "key_path": resolved_path,
                "value_name": condition.value,
                "value": _jsonable(actual if found else None),
                "value_type": value_type,
                "found": found,
                "corrupted": corrupted,
                "entry_path": condition.raw_entry_range.get("entry_path"),
                "entry_indices": list(condition.raw_entry_range.get("entry_indices", [])),
                "raw_entry_range": _jsonable(condition.raw_entry_range),
                "raw_entry": None,
            }
        )

    plugin_value_mismatches: list[dict[str, Any]] = []
    if found:
        for item in evidence:
            if item.get("kind") != "plugin_entry" or not item.get("found"):
                continue
            if not _values_equal(item.get("value"), _jsonable(actual), condition.case_sensitive):
                plugin_value_mismatches.append(
                    {
                        "plugin": item.get("plugin"),
                        "entry_path": item.get("entry_path"),
                        "plugin_value": item.get("value"),
                        "hive_value": _jsonable(actual),
                    }
                )

    unknown = False
    matched = False

    if condition.op == "missing":
        matched = not found
        unknown = bool(path_error)
    elif condition.op == "exists":
        matched = found
        unknown = bool(path_error)
    elif not found or corrupted:
        unknown = True
        matched = False
    else:
        try:
            matched = _compare(actual, condition.op, condition.expected, condition.case_sensitive)
        except ReviewError:
            raise
        except Exception as ex:
            logger.debug(f"Condition {condition.id} failed to compare values: {ex}")
            matched = False

    if plugin_value_mismatches:
        matched = False
        unknown = True
        reason = "plugin_hive_mismatch"
    elif matched:
        reason = None
    elif unknown and reason is None:
        reason = "unreadable_source"
    elif not unknown and reason is None:
        reason = "condition_not_met"

    return {
        "id": condition.id,
        "description": condition.description,
        "requested_path": condition.path,
        "path": resolved_path,
        "value": condition.value,
        "op": condition.op,
        "expected": _jsonable(condition.expected),
        "actual": _jsonable(None if actual is _MISSING else actual),
        "found": found,
        "matched": matched,
        "unknown": unknown,
        "reason": reason,
        "assumptions": list(condition.assumptions),
        "consistency": {"plugin_value_mismatches": plugin_value_mismatches},
        "evidence": evidence,
    }


def _flatten_evidence(condition_results: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for condition_result in condition_results:
        for item in condition_result.get("evidence", []):
            entry = dict(item)
            entry["condition_id"] = condition_result.get("id")
            flattened.append(entry)
    return flattened


def _evaluate_rule(
    rule: Rule,
    registry_hive: RegistryHive,
    plugin_results: Mapping[str, Any],
) -> dict[str, Any]:
    condition_results = [_evaluate_condition(condition, registry_hive, plugin_results) for condition in rule.conditions]
    matched = all(condition["matched"] for condition in condition_results)
    unknown = any(condition["unknown"] for condition in condition_results)

    if matched:
        status = "matched"
        reason = None
    elif unknown:
        status = "pending"
        reason = next(
            (condition["reason"] for condition in condition_results if condition["unknown"] and condition.get("reason")),
            "insufficient_evidence",
        )
    else:
        status = "not_matched"
        reason = "conditions_not_met"

    evidence = _flatten_evidence(condition_results)
    plugin_evidence = [item for item in evidence if item.get("kind") in {"plugin_entry", "declared_entry_range"}]
    plugins = sorted({str(item.get("plugin")) for item in plugin_evidence if item.get("plugin")})
    raw_entry_ranges = [item["raw_entry_range"] for item in plugin_evidence if item.get("raw_entry_range")]

    if rule.raw_entry_range and not raw_entry_ranges:
        raw_entry_ranges.append(_jsonable(rule.raw_entry_range))

    return {
        "rule_id": rule.id,
        "description": rule.description,
        "subject": rule.subject,
        "status": status,
        "conclusion": rule.conclusion if matched else None,
        "reason": reason,
        "assumptions": dict(rule.assumptions),
        "conditions": condition_results,
        "evidence": evidence,
        "plugins": plugins,
        "raw_entry_ranges": raw_entry_ranges,
    }


def _summarize_rule_set(
    rule_set: RuleSet,
    subject: str,
    rule_results: list[dict[str, Any]],
) -> dict[str, Any]:
    matched = [result for result in rule_results if result["status"] == "matched"]
    pending = [result for result in rule_results if result["status"] == "pending"]

    if matched:
        conclusions = sorted({str(result["conclusion"]) for result in matched})
        if len(conclusions) == 1:
            selected = matched[0]
            status = "matched"
            conclusion: str | None = conclusions[0]
            reason = None
        else:
            selected = matched[0]
            status = "conflict"
            conclusion = None
            reason = "rule_set_matched_multiple_conclusions"
    elif pending:
        selected = pending[0]
        status = "pending"
        conclusion = None
        reason = selected.get("reason") or "insufficient_evidence"
    elif rule_results:
        selected = rule_results[0]
        status = "not_matched"
        conclusion = None
        reason = "conditions_not_met"
    else:
        selected = {}
        status = "absent"
        conclusion = None
        reason = "no_rule_for_subject"

    return {
        "rule_set": rule_set.name,
        "description": rule_set.description,
        "source": rule_set.source,
        "subject": subject,
        "status": status,
        "conclusion": conclusion,
        "reason": reason,
        "rule_id": selected.get("rule_id"),
        "assumptions": selected.get("assumptions", {}),
        "conditions": selected.get("conditions", []),
        "evidence": selected.get("evidence", []),
        "plugins": selected.get("plugins", []),
        "raw_entry_ranges": selected.get("raw_entry_ranges", []),
        "evaluated_rules": [
            {
                "rule_id": result["rule_id"],
                "status": result["status"],
                "conclusion": result["conclusion"],
                "reason": result["reason"],
                "assumptions": result["assumptions"],
                "conditions": result["conditions"],
            }
            for result in rule_results
        ],
    }


def _condition_references_for_assumption(result: Mapping[str, Any], dimension: str) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for condition in result.get("conditions", []):
        if dimension not in condition.get("assumptions", []):
            continue
        references.append(
            {
                "condition_id": condition.get("id"),
                "path": condition.get("path"),
                "value": condition.get("value"),
                "op": condition.get("op"),
                "expected": condition.get("expected"),
                "actual": condition.get("actual"),
                "matched": condition.get("matched"),
                "reason": condition.get("reason"),
            }
        )

    if references:
        return references

    for evaluated_rule in result.get("evaluated_rules", []):
        for condition in evaluated_rule.get("conditions", []):
            if dimension not in condition.get("assumptions", []):
                continue
            references.append(
                {
                    "condition_id": condition.get("id"),
                    "path": condition.get("path"),
                    "value": condition.get("value"),
                    "op": condition.get("op"),
                    "expected": condition.get("expected"),
                    "actual": condition.get("actual"),
                    "matched": condition.get("matched"),
                    "reason": condition.get("reason"),
                }
            )
    return references


def _condition_signature(condition: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        _normalized_text(condition.get("path")),
        _normalized_text(condition.get("value")),
        condition.get("op"),
        _invalidatable_json(condition.get("expected")),
    )


def _invalidatable_json(value: Any) -> str:
    return json.dumps(_jsonable(value), sort_keys=True, default=_json_default)


def _compute_divergence(subject: str, concrete: list[dict[str, Any]]) -> dict[str, Any]:
    conclusions = {result["rule_set"]: result["conclusion"] for result in concrete}
    dimensions: dict[str, dict[str, Any]] = {}

    for result in concrete:
        for dimension, statement in result.get("assumptions", {}).items():
            dimensions.setdefault(dimension, {})[result["rule_set"]] = statement

    divergent_assumptions: list[dict[str, Any]] = []
    shared_assumptions: dict[str, str] = {}

    for dimension in sorted(dimensions):
        values = dimensions[dimension]
        normalized = {_normalized_text(value) for value in values.values() if value is not None}
        covered_all = all(result["rule_set"] in values for result in concrete)
        if covered_all and len(normalized) == 1:
            shared_assumptions[dimension] = next(iter(values.values()))
            continue
        if len(normalized) <= 1 and covered_all:
            continue

        divergent_assumptions.append(
            {
                "dimension": dimension,
                "values": {name: values.get(name) for name in sorted(values)},
                "conditions": {
                    result["rule_set"]: _condition_references_for_assumption(result, dimension) for result in concrete
                },
            }
        )

    if not divergent_assumptions:
        # No explicit assumption dimensions were declared.  Keep the report
        # useful by pointing at the conditions that differ.
        condition_differences: list[dict[str, Any]] = []
        for left_index, left in enumerate(concrete):
            for right in concrete[left_index + 1 :]:
                left_conditions = {
                    _condition_signature(condition): condition
                    for rule in left.get("evaluated_rules", [])
                    for condition in rule.get("conditions", [])
                }
                right_conditions = {
                    _condition_signature(condition): condition
                    for rule in right.get("evaluated_rules", [])
                    for condition in rule.get("conditions", [])
                }
                only_left = [
                    {
                        "condition_id": condition.get("id"),
                        "path": condition.get("path"),
                        "value": condition.get("value"),
                    }
                    for signature, condition in left_conditions.items()
                    if signature not in right_conditions
                ]
                only_right = [
                    {
                        "condition_id": condition.get("id"),
                        "path": condition.get("path"),
                        "value": condition.get("value"),
                    }
                    for signature, condition in right_conditions.items()
                    if signature not in left_conditions
                ]
                if only_left or only_right:
                    condition_differences.append(
                        {
                            "dimension": "conditions",
                            "rule_sets": [left["rule_set"], right["rule_set"]],
                            "only_in_left": only_left,
                            "only_in_right": only_right,
                        }
                    )
        divergent_assumptions = condition_differences

    return {
        "reason": "conclusions_differ",
        "subject": subject,
        "conclusions": conclusions,
        "assumptions": divergent_assumptions,
        "assumption_count": len(divergent_assumptions),
        "shared_assumptions": shared_assumptions,
    }


def _normalize_prior_claims(
    prior_claims: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    if not prior_claims:
        return {}

    normalized: dict[str, dict[str, Any]] = {}
    if isinstance(prior_claims, Mapping):
        for subject, value in prior_claims.items():
            if isinstance(value, Mapping):
                conclusion = value.get("conclusion")
                if conclusion is None:
                    raise ReviewError(f"Prior claim for {subject!r} is missing 'conclusion'")
                normalized[str(subject)] = {"subject": str(subject), **dict(value)}
            else:
                normalized[str(subject)] = {"subject": str(subject), "conclusion": str(value)}
        return normalized

    for index, claim in enumerate(prior_claims):
        if not isinstance(claim, Mapping):
            raise ReviewError(f"Prior claim #{index + 1} must be an object")
        subject = claim.get("subject")
        conclusion = claim.get("conclusion")
        if not subject or conclusion is None:
            raise ReviewError(f"Prior claim #{index + 1} requires 'subject' and 'conclusion'")
        normalized[str(subject)] = {"subject": str(subject), **dict(claim)}
    return normalized


def _prior_claim_result(
    claim: Mapping[str, Any],
    subject_result: Mapping[str, Any],
) -> dict[str, Any]:
    conclusion = str(claim["conclusion"])
    interpretations = subject_result.get("interpretations", [])
    concrete = [
        interpretation
        for interpretation in interpretations
        if interpretation.get("status") == "matched" and interpretation.get("conclusion") is not None
    ]
    supporting = [item for item in concrete if str(item["conclusion"]) == conclusion]
    refuting = [item for item in concrete if str(item["conclusion"]) != conclusion]

    if subject_result.get("status") == "confirmed":
        if subject_result.get("verdict") == conclusion:
            status = "supported"
        else:
            status = "refuted"
    elif refuting and supporting:
        status = "disputed"
    elif refuting:
        status = "refuted"
    elif supporting:
        status = "unconfirmed"
    else:
        status = "unverified"

    def _brief(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "rule_set": item.get("rule_set"),
            "conclusion": item.get("conclusion"),
            "rule_id": item.get("rule_id"),
            "assumptions": item.get("assumptions", {}),
            "evidence": item.get("evidence", []),
            "raw_entry_ranges": item.get("raw_entry_ranges", []),
        }

    notes = {
        "supported": "Every supplied interpretation agrees with the prior claim and has complete evidence.",
        "refuted": "At least one sourced interpretation contradicts the prior claim.",
        "disputed": (
            "The prior claim is only one of several sourced interpretations; "
            "it is not safe to present it as the single confirmed conclusion."
        ),
        "unconfirmed": "The prior claim is supported by an interpretation but the item is still pending.",
        "unverified": "No interpretation produced enough evidence to support or refute the prior claim.",
    }

    return {
        "conclusion": conclusion,
        "status": status,
        "supporting_interpretations": [_brief(item) for item in supporting],
        "refuting_interpretations": [_brief(item) for item in refuting],
        "note": notes[status],
    }


def _summarize_subject(
    subject: str,
    rule_set_results: list[dict[str, Any]],
    prior_claim: Mapping[str, Any] | None,
) -> dict[str, Any]:
    concrete = [
        result for result in rule_set_results if result.get("status") == "matched" and result.get("conclusion") is not None
    ]
    candidates = sorted({str(result["conclusion"]) for result in concrete})

    if not rule_set_results:
        status = "pending"
        reason = "no_rule_for_subject"
    elif any(result.get("status") == "absent" for result in rule_set_results):
        status = "pending"
        reason = "interpretation_missing_for_subject"
    elif all(result.get("status") == "matched" for result in rule_set_results):
        if len(candidates) == 1:
            status = "confirmed"
            reason = None
        else:
            status = "pending"
            reason = "interpretations_disagree"
    elif len(candidates) > 1:
        status = "pending"
        reason = "interpretations_disagree"
    elif concrete:
        status = "pending"
        reason = "not_all_interpretations_support_conclusion"
    elif any(result.get("status") == "pending" for result in rule_set_results):
        status = "pending"
        reason = "insufficient_evidence"
    else:
        status = "pending"
        reason = "no_interpretation_matched"

    verdict = candidates[0] if status == "confirmed" and len(candidates) == 1 else None
    divergence = _compute_divergence(subject, concrete) if len(candidates) > 1 else None

    result: dict[str, Any] = {
        "subject": subject,
        "status": status,
        "verdict": verdict,
        "reason": reason,
        "candidates": candidates,
        "interpretations": rule_set_results,
        "divergence": divergence,
    }

    if prior_claim is not None:
        result["prior_claim"] = _prior_claim_result(prior_claim, result)

    return result


def _run_requested_plugins(
    registry_hive: RegistryHive,
    plugin_names: Iterable[str],
    as_json: bool = True,
) -> tuple[dict[str, Any], dict[str, str]]:
    plugin_classes = {plugin_class.NAME: plugin_class for plugin_class in PLUGINS if plugin_class.NAME}
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for plugin_name in sorted(set(plugin_names)):
        plugin_class = plugin_classes.get(plugin_name)
        if plugin_class is None:
            errors[plugin_name] = "plugin not found"
            continue

        plugin = plugin_class(registry_hive, as_json=as_json)
        try:
            if not plugin.can_run():
                results[plugin_name] = []
                errors[plugin_name] = f"plugin is not compatible with hive type {registry_hive.hive_type!r}"
                continue
            plugin.run()
            results[plugin_name] = plugin.entries
        except Exception as ex:  # noqa: BLE001 - review must not abort other plugins
            logger.exception(f"Failure while running review plugin {plugin_name}: {ex}")
            results[plugin_name] = []
            errors[plugin_name] = f"{type(ex).__name__}: {ex}"

    return results, errors


def _hive_metadata(registry_hive: RegistryHive, hive_path: str | Path | None) -> dict[str, Any]:
    return {
        "path": str(hive_path) if hive_path is not None else None,
        "name": registry_hive.name,
        "hive_type": registry_hive.hive_type,
        "partial_hive_path": registry_hive.partial_hive_path,
    }


def review_hive(
    hive: str | Path | RegistryHive,
    rule_sets: RuleSet | Mapping[str, Any] | str | Path | Sequence[RuleSet | Mapping[str, Any] | str | Path],
    plugin_results: Mapping[str, Any] | None = None,
    prior_claims: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
    run_plugins: bool = True,
    as_json: bool = True,
) -> dict[str, Any]:
    """Evaluate caller-supplied interpretation rules against one collected hive.

    Args:
        hive: A :class:`RegistryHive`, or a path to a hive file.
        rule_sets: One or more rule sets (objects, JSON files, or a list of both).
        plugin_results: Optional pre-collected ``{plugin_name: entries}`` output.
            Supplying it makes the review reproducible from a prior collection run.
        prior_claims: Optional ``{subject: conclusion}`` mapping (or a list of
            ``{"subject": ..., "conclusion": ...}`` objects) used to show whether
            a historical one-line finding is supported or disputed.
        run_plugins: When true, run the plugins referenced by the rule sets if
            ``plugin_results`` was not supplied.  This is only used to attach
            provenance; condition truth is always read from the hive.
        as_json: Normalize hive and plugin values for JSON output.

    Returns:
        A JSON-serializable review report.
    """
    if isinstance(hive, (str, Path)):
        hive_path: str | Path | None = hive
        registry_hive = RegistryHive(str(hive))
    elif isinstance(hive, RegistryHive):
        hive_path = None
        registry_hive = hive
    else:
        raise ReviewError("hive must be a RegistryHive or a hive file path")

    loaded_rule_sets = load_rule_sets(rule_sets)
    if len(loaded_rule_sets) < 1:
        raise ReviewError("At least one rule set is required")
    rule_set_names = [rule_set.name for rule_set in loaded_rule_sets]
    if len(rule_set_names) != len(set(rule_set_names)):
        raise ReviewError("Rule set names must be unique; rename one of the supplied interpretations")

    normalized_prior_claims = _normalize_prior_claims(prior_claims)

    requested_plugins = sorted(
        {plugin for rule_set in loaded_rule_sets for plugin in rule_set.plugins if plugin}
        | {rule.plugin for rule_set in loaded_rule_sets for rule in rule_set.rules if rule.plugin}
    )

    plugin_errors: dict[str, str] = {}
    if plugin_results is None:
        if run_plugins:
            plugin_results, plugin_errors = _run_requested_plugins(
                registry_hive,
                requested_plugins,
                as_json=as_json,
            )
        else:
            plugin_results = {}
            for plugin_name in requested_plugins:
                plugin_errors[plugin_name] = "plugin execution disabled and no plugin output was supplied"
    else:
        plugin_results = dict(plugin_results)
        for plugin_name in requested_plugins:
            if plugin_name not in plugin_results:
                plugin_errors[plugin_name] = "plugin output was not supplied"

    subjects: list[str] = []
    for rule_set in loaded_rule_sets:
        for rule in rule_set.rules:
            if rule.subject not in subjects:
                subjects.append(rule.subject)

    all_rule_set_names = [rule_set.name for rule_set in loaded_rule_sets]
    results: dict[str, Any] = {}

    for subject in sorted(subjects):
        rule_set_results: list[dict[str, Any]] = []
        for rule_set in loaded_rule_sets:
            rules = [rule for rule in rule_set.rules if rule.subject == subject]
            if not rules:
                rule_set_results.append(
                    {
                        "rule_set": rule_set.name,
                        "description": rule_set.description,
                        "source": rule_set.source,
                        "subject": subject,
                        "status": "absent",
                        "conclusion": None,
                        "reason": "no_rule_for_subject",
                        "rule_id": None,
                        "assumptions": {},
                        "conditions": [],
                        "evidence": [],
                        "plugins": [],
                        "raw_entry_ranges": [],
                        "evaluated_rules": [],
                    }
                )
                continue

            evaluated_rules = [_evaluate_rule(rule, registry_hive, plugin_results) for rule in rules]
            rule_set_results.append(_summarize_rule_set(rule_set, subject, evaluated_rules))

        results[subject] = _summarize_subject(
            subject,
            rule_set_results,
            normalized_prior_claims.get(subject),
        )

    pending_subjects = sorted(subject for subject, result in results.items() if result["status"] != "confirmed")
    confirmed_subjects = sorted(subject for subject, result in results.items() if result["status"] == "confirmed")

    return _jsonable(
        {
            "hive": _hive_metadata(registry_hive, hive_path),
            "rule_sets": [
                {
                    "name": rule_set.name,
                    "description": rule_set.description,
                    "source": rule_set.source,
                    "assumptions": dict(rule_set.assumptions),
                    "plugins": list(rule_set.plugins),
                }
                for rule_set in loaded_rule_sets
            ],
            "interpretation_coverage": {
                "rule_sets": all_rule_set_names,
                "subjects": sorted(subjects),
            },
            "plugins": {
                "requested": requested_plugins,
                "available": sorted(plugin_results.keys()),
                "errors": plugin_errors,
            },
            "results": results,
            "confirmed": confirmed_subjects,
            "pending": pending_subjects,
        }
    )


def review_plugin_results(
    plugin_results: Mapping[str, Any],
    rule_sets: RuleSet | Mapping[str, Any] | str | Path | Sequence[RuleSet | Mapping[str, Any] | str | Path],
    hive: str | Path | RegistryHive | None = None,
    prior_claims: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Review pre-collected plugin results.

    A hive is still required when rules depend on other keys.  Without a hive,
    those conditions are reported as pending rather than inferred.
    """
    if hive is None:
        raise ReviewError(
            "review_plugin_results requires a hive for rule conditions; use review_hive() when the hive is available"
        )
    return review_hive(
        hive,
        rule_sets,
        plugin_results=plugin_results,
        prior_claims=prior_claims,
        run_plugins=False,
    )
