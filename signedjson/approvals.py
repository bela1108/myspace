"""Offline reconciliation for signed delivery-manifest approvals.

The reconciler binds path, content digest and manifest version to the same
signed approval claim.  It never combines a path from one approval with a
digest or version from another approval.
"""

from __future__ import annotations

import hashlib
import inspect
import posixpath
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from unpaddedbase64 import decode_base64

from signedjson.key import decode_verify_key_bytes, get_verify_key
from signedjson.sign import SignatureVerifyException, sign_json, verify_signed_json


PATH_KEYS = (
    "path",
    "file_path",
    "filepath",
    "filename",
    "file",
    "target",
    "object_path",
    "key",
    "name",
)
DIGEST_KEYS = (
    "content_digest",
    "digest",
    "sha256",
    "sha_256",
    "sha512",
    "sha_512",
    "checksum",
    "hash",
)
VERSION_KEYS = (
    "manifest_version",
    "manifestversion",
    "version",
    "schema_version",
    "revision",
)
APPROVER_KEYS = (
    "approver",
    "approver_id",
    "approved_by",
    "signer",
    "signature_name",
    "entity",
    "principal",
    "name",
)
ID_KEYS = ("approval_id", "id", "voucher_id", "document_id", "record_id")
ITEM_KEYS = (
    "items",
    "entries",
    "materials",
    "files",
    "artifacts",
    "claims",
    "vouchers",
    "approved_items",
    "manifest_items",
)
INCLUDE_KEYS = (
    "include",
    "includes",
    "allowed",
    "allow",
    "paths",
    "prefixes",
    "patterns",
    "roots",
    "directories",
    "scope",
    "scopes",
    "subset",
)
EXCEPTION_KEYS = (
    "exceptions",
    "exception",
    "except",
    "exclude",
    "excludes",
    "excluded",
    "deny",
    "denied",
    "blocklist",
)


class DotDict(dict):
    """Dictionary with optional attribute access."""

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __delattr__(self, name: str) -> None:
        try:
            del self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class ItemDecision(DotDict):
    """Per-material decision.

    Equality with a string compares its path.  This keeps simple assertions
    such as ``"a.txt" in result.releasable`` readable while retaining full
    structured data.
    """

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.get("path") == other
        if isinstance(other, tuple) and len(other) == 3:
            return (
                self.get("manifest_version"),
                self.get("path"),
                self.get("digest"),
            ) == other
        return dict.__eq__(self, other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return id(self)


class ReconciliationResult(DotDict):
    @property
    def ok(self) -> bool:
        return bool(self.get("ok"))

    @property
    def items(self) -> List[ItemDecision]:  # type: ignore[override]
        return dict.__getitem__(self, "items")

    def raise_if_incomplete(self) -> "ReconciliationResult":
        missing = self.get("missing_coverage") or []
        if missing:
            raise MissingCoverageError(missing, self)
        return self


class SourceRef(DotDict):
    """Approval provenance that compares equal to its approval id."""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return other == self.get("approval_id") or other == str(self.get("approval_index"))
        if isinstance(other, int):
            return other == self.get("approval_index")
        return dict.__eq__(self, other)

    def __hash__(self) -> int:
        return id(self)


class MissingCoverageError(Exception):
    def __init__(self, missing: Sequence[Mapping[str, Any]], result: Any = None):
        self.missing = list(missing)
        self.result = result
        paths = ", ".join(str(item.get("path")) for item in self.missing)
        super().__init__("Missing approval coverage for: %s" % paths)


def _lookup(data: Any, keys: Sequence[str], default: Any = None) -> Any:
    if not isinstance(data, Mapping):
        return default
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    normalized = {_normalize_key(raw_key): value for raw_key, value in data.items()}
    for key in keys:
        normalized_key = _normalize_key(key)
        if normalized_key in normalized and normalized[normalized_key] is not None:
            return normalized[normalized_key]
    return default


def _normalize_key(key: Any) -> str:
    text = str(key)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return text.lower().replace("-", "_").replace(" ", "_")


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, (str, bytes, Mapping)):
        return [value]
    return list(value)


def normalize_path(path: Any, root: Any = None) -> Optional[str]:
    if path is None:
        return None
    value = path.decode() if isinstance(path, bytes) else str(path)
    value = value.strip().replace("\\", "/")
    if root is not None:
        root_value = str(root).replace("\\", "/").rstrip("/")
        if root_value and value.startswith(root_value + "/"):
            value = value[len(root_value) + 1 :]
        elif root_value and value == root_value:
            value = ""
    if value.startswith("/"):
        value = value.lstrip("/")
    normalized = posixpath.normpath(value) if value else ""
    if normalized == ".":
        normalized = ""
    return normalized or None


def digest_key(value: Any, algorithm: Optional[str] = None) -> Optional[Tuple[str, str]]:
    if value is None:
        return None
    if isinstance(value, Mapping):
        algorithm = _lookup(value, ("algorithm", "alg"), algorithm)
        explicit = _lookup(value, ("value", "digest", "hex", "hash", "checksum"))
        if explicit is None:
            for key, candidate in value.items():
                if key not in ("algorithm", "alg") and isinstance(candidate, str):
                    explicit = candidate
                    if algorithm is None:
                        algorithm = key
                    break
        value = explicit
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.hex()
    text = str(value).strip()
    if not text:
        return None
    if algorithm is None and ":" in text:
        maybe_algorithm, remainder = text.split(":", 1)
        if maybe_algorithm and remainder:
            algorithm = maybe_algorithm
            text = remainder
    algorithm_name = str(algorithm or "digest").lower().replace("-", "").replace("_", "")
    if all(char in "0123456789abcdefABCDEF" for char in text) and len(text) % 2 == 0:
        text = text.lower()
    return algorithm_name, text


def _extract_digest(data: Mapping[str, Any]) -> Any:
    value = _lookup(data, DIGEST_KEYS)
    if value is None:
        return None
    for key in DIGEST_KEYS:
        if key in data and data[key] is value:
            if key in ("sha256", "sha_256") and not isinstance(value, Mapping):
                text = str(value)
                return text if ":" in text else "sha256:" + text
            if key in ("sha512", "sha_512") and not isinstance(value, Mapping):
                text = str(value)
                return text if ":" in text else "sha512:" + text
            return value
    if isinstance(value, Mapping):
        key_parts = digest_key(value)
        return None if key_parts is None else "%s:%s" % key_parts
    return value


def _extract_triple(data: Mapping[str, Any], default_version: Any = None) -> Dict[str, Any]:
    path = normalize_path(_lookup(data, PATH_KEYS))
    digest = _extract_digest(data)
    version = _lookup(data, VERSION_KEYS, default_version)
    for nested_key in ("material", "entry", "item", "file", "target", "artifact", "manifest"):
        nested = data.get(nested_key) if isinstance(data, Mapping) else None
        if isinstance(nested, Mapping):
            nested_triple = _extract_triple(nested, version)
            if path is None:
                path = nested_triple["path"]
            if digest is None:
                digest = nested_triple["digest"]
            if version is None:
                version = nested_triple["manifest_version"]
        elif nested_key in ("material", "entry", "item", "file", "target") and path is None:
            path = normalize_path(nested)
    return {"path": path, "digest": digest, "manifest_version": version}


def _triple_key(path: Any, digest: Any, version: Any) -> Tuple[Any, Any, Any]:
    return (
        normalize_path(path),
        digest_key(digest),
        None if version is None else str(version),
    )


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    digest.update(data)
    return "%s:%s" % (algorithm.replace("-", ""), digest.hexdigest())


def hash_file(path: Any, algorithm: str = "sha256", chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return "%s:%s" % (algorithm.replace("-", ""), digest.hexdigest())


def build_manifest_from_directory(
    root: Any,
    manifest_version: Any = None,
    algorithm: str = "sha256",
) -> Dict[str, Any]:
    root_path = str(root)
    entries = []
    import os

    for directory, dirnames, filenames in os.walk(root_path):
        dirnames.sort()
        for filename in sorted(filenames):
            absolute = posixpath.join(directory, filename)
            relative = normalize_path(absolute, root_path)
            entries.append(
                {
                    "path": relative,
                    "digest": hash_file(absolute, algorithm),
                }
            )
    return {"manifest_version": manifest_version, "items": entries}


class Material(DotDict):
    pass


def _material_from_mapping(
    raw: Mapping[str, Any],
    default_version: Any = None,
    manifest_id: Any = None,
) -> Material:
    triple = _extract_triple(raw, default_version)
    digest = triple["digest"]
    content = _lookup(raw, ("content", "bytes", "data"))
    if digest is None and content is not None:
        if isinstance(content, str):
            content = content.encode("utf-8")
        if isinstance(content, bytes):
            digest = hash_bytes(content)
    material = Material(
        path=triple["path"],
        digest=digest,
        manifest_version=triple["manifest_version"],
        manifest_id=_lookup(raw, ("manifest_id", "list_id"), manifest_id),
        raw=raw,
    )
    material["key"] = _triple_key(
        material.path, material.digest, material.manifest_version
    )
    return material


def _material_entries(source: Any, default_version: Any = None) -> List[Material]:
    if source is None:
        return []
    if isinstance(source, Material):
        return [source]
    if isinstance(source, str):
        return [Material(path=normalize_path(source), digest=None,
                         manifest_version=default_version, raw=source,
                         manifest_id=None, key=_triple_key(source, None, default_version))]
    if isinstance(source, Mapping):
        container = _lookup(source, ITEM_KEYS + ("materials", "manifest_items"))
        version = _lookup(source, VERSION_KEYS, default_version)
        manifest_id = _lookup(source, ("manifest_id", "list_id", "id"))
        if container is not None and not (
            _lookup(source, PATH_KEYS) is not None and isinstance(container, bool)
        ):
            return _materials_from_value(container, version, manifest_id)
        if _lookup(source, PATH_KEYS) is not None:
            return [_material_from_mapping(source, default_version, manifest_id)]
        if source and all(
            isinstance(key, str) and not isinstance(value, Mapping)
            for key, value in source.items()
        ):
            return [
                _material_from_mapping(
                    {"path": path, "digest": digest},
                    default_version,
                    manifest_id,
                )
                for path, digest in source.items()
                if path not in ("manifest_version", "version", "id")
            ]
        materials = []
        for value in source.values():
            materials.extend(_material_entries(value, version))
        return materials
    materials = []
    for value in _as_list(source):
        materials.extend(_material_entries(value, default_version))
    return materials


def _materials_from_value(value: Any, version: Any, manifest_id: Any) -> List[Material]:
    materials = []
    if isinstance(value, Mapping) and _lookup(value, PATH_KEYS) is None:
        for path, digest in value.items():
            item = digest if isinstance(digest, Mapping) else {"digest": digest}
            if isinstance(item, Mapping):
                item = dict(item)
                item.setdefault("path", path)
            materials.append(_material_from_mapping(item, version, manifest_id))
        return materials
    for item in _as_list(value):
        if isinstance(item, str):
            raw = {"path": item}
        elif isinstance(item, Mapping):
            raw = item
        else:
            continue
        materials.append(_material_from_mapping(raw, version, manifest_id))
    return materials


def collect_materials(*sources: Any) -> List[Material]:
    materials: List[Material] = []
    for source in sources:
        if source is None:
            continue
        materials.extend(_material_entries(source))
    return materials


class ScopeRule(DotDict):
    pass


def _pattern_from_value(value: Any) -> Optional[str]:
    if isinstance(value, ScopeRule):
        return None
    if isinstance(value, Mapping):
        value = _lookup(value, ("path", "prefix", "pattern", "root", "directory"))
    if value is None:
        return None
    return normalize_path(value)


def _extract_patterns(data: Mapping[str, Any], keys: Sequence[str]) -> List[str]:
    patterns: List[str] = []
    for key in keys:
        value = _lookup(data, (key,))
        if value is None:
            continue
        for item in _as_list(value):
            pattern = _pattern_from_value(item)
            if pattern is not None:
                patterns.append(pattern)
    return patterns


def coerce_scope_rule(value: Any, approver: Any = None) -> ScopeRule:
    if isinstance(value, ScopeRule):
        return value
    if value is None:
        value = []
    if isinstance(value, (str, list, tuple, set, frozenset)):
        includes = [_pattern_from_value(item) for item in _as_list(value)]
        return ScopeRule(
            approver=approver,
            rule_id=None,
            includes=[item for item in includes if item is not None],
            exceptions=[],
            kind=None,
            parent=None,
            raw=value,
        )
    if not isinstance(value, Mapping):
        return ScopeRule(
            approver=approver, rule_id=None, includes=[], exceptions=[],
            kind=None, parent=None, raw=value,
        )
    rule_approver = _lookup(value, APPROVER_KEYS + ("approver_id", "user"), approver)
    includes = _extract_patterns(value, INCLUDE_KEYS)
    exceptions = _extract_patterns(value, EXCEPTION_KEYS)
    direct_pattern = _pattern_from_value(value)
    if direct_pattern and direct_pattern not in includes:
        includes.append(direct_pattern)
    nested = _lookup(value, ("rule", "scope_rule", "jurisdiction"))
    if nested is not None and nested is not value:
        nested_rule = coerce_scope_rule(nested, rule_approver)
        includes.extend(nested_rule.includes)
        exceptions.extend(nested_rule.exceptions)
    return ScopeRule(
        approver=rule_approver,
        rule_id=_lookup(value, ID_KEYS + ("scope_id", "name")),
        includes=list(dict.fromkeys(includes)),
        exceptions=list(dict.fromkeys(exceptions)),
        kind=_lookup(value, ("kind", "type", "scope_type", "level")),
        parent=_lookup(value, ("parent", "senior", "senior_scope", "parent_scope")),
        delegate=_lookup(value, ("delegate", "delegate_to", "exception_approver")),
        raw=value,
    )


def collect_scope_rules(*sources: Any) -> List[ScopeRule]:
    rules: List[ScopeRule] = []
    for source in sources:
        if source is None:
            continue
        if isinstance(source, ScopeRule):
            rules.append(source)
        elif isinstance(source, Mapping):
            looks_like_record = (
                _lookup(source, APPROVER_KEYS) is not None
                or _lookup(source, ("kind", "type")) is not None
                or _lookup(source, ID_KEYS) is not None
            ) and any(_lookup(source, (key,)) is not None for key in INCLUDE_KEYS + EXCEPTION_KEYS + ("path", "prefix"))
            if looks_like_record and not all(
                isinstance(key, str) and (
                    key in APPROVER_KEYS
                    or key in INCLUDE_KEYS + EXCEPTION_KEYS + ID_KEYS
                    or key in ("kind", "type", "level", "parent", "senior", "delegate")
                )
                for key in source
            ) is False:
                rules.append(coerce_scope_rule(source))
            elif looks_like_record and _lookup(source, APPROVER_KEYS) is not None and "approver" in source:
                rules.append(coerce_scope_rule(source))
            else:
                for approver, value in source.items():
                    if approver in ("overlap_rule", "overlap_policy"):
                        continue
                    role_hint = None
                    approver_text = str(approver).lower()
                    if approver_text in (
                        "senior", "senior_scopes", "parent", "parent_scopes",
                        "superior", "superior_scopes", "upper",
                    ):
                        role_hint = "senior"
                    elif "exception" in approver_text or approver_text in (
                        "special", "delegated", "delegations"
                    ):
                        role_hint = "exception"

                    def _with_role(item: Any) -> Any:
                        if (
                            role_hint
                            and isinstance(item, Mapping)
                            and _lookup(item, ("kind", "type", "scope_type")) is None
                        ):
                            item = dict(item)
                            item["kind"] = role_hint
                        return item

                    if isinstance(value, (list, tuple, set, frozenset)) and any(
                        isinstance(item, Mapping) for item in value
                    ):
                        rules.extend(
                            collect_scope_rules([_with_role(item) for item in value])
                        )
                    else:
                        value = _with_role(value)
                        if isinstance(value, Mapping) and _lookup(value, APPROVER_KEYS) is None:
                            value = dict(value)
                        rules.append(coerce_scope_rule(value, approver))
        else:
            for item in _as_list(source):
                if isinstance(item, Mapping) and _lookup(item, APPROVER_KEYS) is None and not any(
                    _lookup(item, (key,)) is not None for key in ("path", "prefix", "pattern")
                ):
                    rules.append(coerce_scope_rule(item, "*"))
                else:
                    rules.append(coerce_scope_rule(item, _lookup(item, APPROVER_KEYS) if isinstance(item, Mapping) else "*"))
    return rules


def _pattern_regex(pattern: str) -> str:
    out = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**", index):
            out.append(".*")
            index += 2
            if index < len(pattern) and pattern[index] == "/":
                index += 1
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        else:
            import re

            out.append(re.escape(char))
        index += 1
    out.append("$")
    return "".join(out)


def path_matches(pattern: Any, path: Any) -> bool:
    normalized_pattern = normalize_path(pattern)
    normalized_path = normalize_path(path)
    if normalized_pattern is None or normalized_path is None:
        return False
    if any(char in normalized_pattern for char in ("*", "?", "[")):
        import re

        return re.match(_pattern_regex(normalized_pattern), normalized_path) is not None
    if normalized_pattern == normalized_path:
        return True
    return normalized_path.startswith(normalized_pattern.rstrip("/") + "/")


def _rules_for_approver(rules: Sequence[ScopeRule], approver: Any) -> List[ScopeRule]:
    approver_text = None if approver is None else str(approver)
    result = []
    for rule in rules:
        rule_approver = None if rule.approver is None else str(rule.approver)
        if rule_approver in ("*", "__all__") or rule_approver == approver_text:
            result.append(rule)
    return result


def _policy_senior_wins(policy_result: Any, context: Mapping[str, Any]) -> Optional[bool]:
    if policy_result is None:
        return None
    if isinstance(policy_result, bool):
        return policy_result
    if isinstance(policy_result, str):
        value = policy_result.strip().lower().replace("-", "_").replace(" ", "_")
        if value in ("senior", "parent", "superior", "include", "higher", "senior_wins", "parent_wins", "allow"):
            return True
        if value in ("exception", "exceptions", "exclude", "deny", "denied", "exception_wins", "deny_wins"):
            return False
        return None
    if isinstance(policy_result, Mapping):
        if "covered" in policy_result:
            return bool(policy_result["covered"])
        if "allow" in policy_result:
            return bool(policy_result["allow"])
        winner = _lookup(policy_result, ("winner", "winning_scope", "precedence"))
        if winner is not None:
            return _policy_senior_wins(winner, context)
        approvers = _lookup(policy_result, ("approvers", "winners", "authorized_approvers"))
        if approvers is not None:
            current = str(context.get("approver"))
            return current in {str(item) for item in _as_list(approvers)}
    return None


def _call_overlap_rule(rule: Any, context: DotDict) -> Any:
    if not callable(rule):
        return rule

    candidates = dict(context)
    candidates.update(
        {
            "ctx": context,
            "context": context,
            "senior": context.get("senior_rule") or context.get("senior_scope"),
            "parent": context.get("senior_rule") or context.get("parent_scope"),
            "superior": context.get("senior_rule") or context.get("senior_scope"),
            "exception": context.get("exception_rule") or context.get("exception_scope"),
            "item": context.get("entry"),
            "material": context.get("entry"),
            "claim": context.get("entry"),
        }
    )
    try:
        signature = inspect.signature(rule)
        try:
            bound = signature.bind(**candidates)
        except TypeError:
            bound = None
        if bound is not None:
            return rule(*bound.args, **bound.kwargs)
        parameters = list(signature.parameters.values())
    except (TypeError, ValueError):
        parameters = []
    positional = [
        parameter for parameter in parameters
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    ]
    if any(parameter.kind == parameter.VAR_POSITIONAL for parameter in parameters):
        return rule(
            context.get("senior_scope"),
            context.get("exception_scope"),
            context,
        )
    required = [parameter for parameter in positional if parameter.default is inspect._empty]
    if not positional and not required:
        return rule()
    if len(required) <= 1 and len(positional) <= 1:
        return rule(context)
    if len(positional) == 2:
        return rule(context.get("senior_scope"), context.get("exception_scope"))
    if len(positional) >= 3:
        return rule(
            context.get("senior_scope"),
            context.get("exception_scope"),
            context,
        )
    return rule(context)


def _resolve_overlap(context: DotDict, overlap_rule: Any) -> bool:
    policy = "exception_wins" if overlap_rule is None else overlap_rule
    result = _call_overlap_rule(policy, context) if callable(policy) else policy
    senior_wins = _policy_senior_wins(result, context)
    if senior_wins is None:
        raise ValueError(
            "Overlap rule must return a boolean, 'senior'/'exception', or an explicit mapping"
        )
    return senior_wins


def evaluate_scope(
    approver: Any,
    entry: Mapping[str, Any],
    rules: Sequence[ScopeRule],
    overlap_rule: Any = None,
) -> DotDict:
    path = normalize_path(entry.get("path"))
    approver_rules = _rules_for_approver(rules, approver)
    non_empty_rules = [rule for rule in approver_rules if rule.includes]
    if not approver_rules:
        return DotDict(covered=False, reason="approver_scope_unknown", matches=[], overlaps=[])
    if not non_empty_rules:
        return DotDict(covered=False, reason="empty_scope", matches=[], overlaps=[])

    matches = []
    overlaps = []
    covered = False
    for rule in non_empty_rules:
        includes = [pattern for pattern in rule.includes if path_matches(pattern, path)]
        if not includes:
            continue
        exceptions = [pattern for pattern in rule.exceptions if path_matches(pattern, path)]
        match = DotDict(scope_id=rule.rule_id, includes=includes, exceptions=exceptions,
                        approver=rule.approver, kind=rule.kind)
        matches.append(match)
        if not exceptions:
            covered = True
            continue
        for include_pattern in includes:
            for exception_pattern in exceptions:
                context = DotDict(
                    approver=approver,
                    path=path,
                    entry=dict(entry),
                    senior_scope=include_pattern,
                    parent_scope=include_pattern,
                    include_scope=include_pattern,
                    exception_scope=exception_pattern,
                    scope_rule=rule,
                    manifest_version=entry.get("manifest_version"),
                    digest=entry.get("digest"),
                )
                senior_wins = _resolve_overlap(context, overlap_rule)
                overlaps.append(DotDict(
                    senior_scope=include_pattern,
                    exception_scope=exception_pattern,
                    senior_wins=senior_wins,
                ))
                if senior_wins:
                    covered = True
    external_overlaps = _external_scope_overlaps(
        approver, path, entry, rules, overlap_rule, overlaps
    )
    overlaps.extend(external_overlaps)
    for overlap in external_overlaps:
        if overlap.get("current_approver_covered") is False:
            covered = False
        elif overlap.get("current_approver_covered") is True and not covered:
            covered = True
    reason = "in_scope" if covered else (
        "scope_overlap_resolved_against_approver" if overlaps else "out_of_scope"
    )
    return DotDict(covered=covered, reason=reason, matches=matches, overlaps=overlaps)


def _external_scope_overlaps(
    approver: Any,
    path: Optional[str],
    entry: Mapping[str, Any],
    rules: Sequence[ScopeRule],
    overlap_rule: Any,
    existing: List[DotDict],
) -> List[DotDict]:
    results = []
    current_text = str(approver)
    own_rules = _rules_for_approver(rules, approver)
    for own_rule in own_rules:
        own_includes = [p for p in own_rule.includes if path_matches(p, path)]
        if not own_includes:
            continue
        own_is_senior = str(own_rule.kind or "").lower() in (
            "senior", "parent", "superior", "broad"
        )
        own_is_exception = str(own_rule.kind or "").lower() in (
            "exception", "special", "delegated"
        )
        for other in rules:
            if other is own_rule or str(other.approver) == current_text:
                continue
            other_includes = [p for p in other.includes if path_matches(p, path)]
            if not other_includes:
                continue
            other_is_exception = str(other.kind or "").lower() in (
                "exception", "special", "delegated"
            )
            other_is_senior = str(other.kind or "").lower() in (
                "senior", "parent", "superior", "broad"
            )
            if not ((own_is_senior and other_is_exception) or
                    (own_is_exception and other_is_senior) or
                    (own_rule.parent and str(own_rule.parent) == str(other.rule_id)) or
                    (other.parent and str(other.parent) == str(own_rule.rule_id))):
                continue
            senior_rule = own_rule if own_is_senior or other_is_exception is False and not own_is_exception else other
            exception_rule = other if senior_rule is own_rule else own_rule
            senior_pattern = next((p for p in senior_rule.includes if path_matches(p, path)), None)
            exception_pattern = next((p for p in exception_rule.includes if path_matches(p, path)), None)
            context = DotDict(
                approver=approver,
                path=path,
                entry=dict(entry),
                senior_scope=senior_pattern,
                parent_scope=senior_pattern,
                exception_scope=exception_pattern,
                senior_rule=senior_rule,
                exception_rule=exception_rule,
                scope_rule=own_rule,
                manifest_version=entry.get("manifest_version"),
                digest=entry.get("digest"),
            )
            senior_wins = _resolve_overlap(context, overlap_rule)
            authorized = _policy_authorized_approvers(
                context.get("_policy_result"), senior_wins, senior_rule, exception_rule
            )
            if authorized is None:
                current_covered = (
                    senior_wins if senior_rule is own_rule else not senior_wins
                )
            else:
                current_covered = current_text in authorized
            result = DotDict(
                senior_scope=senior_pattern,
                exception_scope=exception_pattern,
                senior_approver=senior_rule.approver,
                exception_approver=exception_rule.approver,
                senior_wins=senior_wins,
                current_approver_covered=current_covered,
            )
            results.append(result)
    return results


def _policy_authorized_approvers(
    policy_result: Any,
    senior_wins: bool,
    senior_rule: ScopeRule,
    exception_rule: ScopeRule,
) -> Optional[set]:
    if not isinstance(policy_result, Mapping):
        return None
    approvers = _lookup(policy_result, ("approvers", "winners", "authorized_approvers"))
    if approvers is not None:
        return {str(item) for item in _as_list(approvers)}
    if senior_wins:
        return {str(senior_rule.approver)}
    return {str(exception_rule.approver)}


def sign_approval(approval: Mapping[str, Any], approver: Any, signing_key: Any) -> Mapping[str, Any]:
    return sign_json(dict(approval), str(approver), signing_key)


def _key_from_spec(value: Any, key_id: Optional[str]) -> Any:
    if value is None:
        return None
    if hasattr(value, "verify") and hasattr(value, "alg"):
        return value
    if hasattr(value, "verify_key"):
        return get_verify_key(value)
    if isinstance(value, (str, bytes)) and key_id:
        key_bytes = value.encode() if isinstance(value, str) else value
        return decode_verify_key_bytes(key_id, decode_base64(key_bytes))
    return None


def _resolve_verify_key(
    approver: Any,
    key_id: Optional[str],
    signatures: Mapping[str, Any],
    verify_keys: Any,
) -> Any:
    if verify_keys is None:
        return None
    if callable(verify_keys):
        try:
            return _key_from_spec(verify_keys(approver, key_id), key_id)
        except TypeError:
            return _key_from_spec(verify_keys(str(approver)), key_id)
    if isinstance(verify_keys, (list, tuple, set, frozenset)):
        generic_key = None
        for candidate in verify_keys:
            key = _key_from_spec(candidate, key_id)
            if key is None:
                continue
            if key_id and "%s:%s" % (getattr(key, "alg", None), getattr(key, "version", None)) == key_id:
                return key
            generic_key = generic_key or key
        return generic_key
    if not isinstance(verify_keys, Mapping):
        return _key_from_spec(verify_keys, key_id)
    approver_text = str(approver)
    if approver_text in verify_keys:
        value = verify_keys[approver_text]
        key = _key_from_spec(value, key_id)
        if key is not None:
            return key
        if isinstance(value, Mapping):
            if key_id in value:
                return _key_from_spec(value[key_id], key_id)
            for candidate_id, candidate in value.items():
                if candidate_id == key_id:
                    return _key_from_spec(candidate, candidate_id)
                key = _key_from_spec(candidate, candidate_id)
                if key is not None and getattr(key, "version", None) == str(key_id).split(":", 1)[-1]:
                    return key
    if key_id and key_id in verify_keys:
        return _key_from_spec(verify_keys[key_id], key_id)
    for value in verify_keys.values():
        key = _key_from_spec(value, key_id)
        if key is not None and key_id and "%s:%s" % (key.alg, key.version) == key_id:
            return key
    return None


def verify_approval_signature(
    raw: Mapping[str, Any],
    approver: Any,
    verify_keys: Any,
) -> DotDict:
    signatures = raw.get("signatures") if isinstance(raw, Mapping) else None
    if not isinstance(signatures, Mapping) or not signatures:
        return DotDict(signature_valid=False, signature_status="missing_signature",
                       signers=[], key_ids=[])
    signers = list(signatures.keys())
    signer_name = str(approver) if approver is not None else signers[0]
    if signer_name not in signatures:
        return DotDict(signature_valid=False, signature_status="missing_signer",
                       signers=signers, key_ids=[])
    signed_key_ids = list(signatures[signer_name].keys())
    last_error = None
    for key_id in signed_key_ids:
        key = _resolve_verify_key(signer_name, key_id, signatures, verify_keys)
        if key is None:
            last_error = "no_trusted_key"
            continue
        try:
            verify_signed_json(raw, signer_name, key)
            return DotDict(signature_valid=True, signature_status="valid",
                           signers=signers, key_ids=signed_key_ids, key_id=key_id)
        except SignatureVerifyException as exc:
            last_error = str(exc)
    status = last_error if last_error not in (None, "no_trusted_key") else "no_trusted_key"
    return DotDict(signature_valid=False, signature_status="invalid:" + str(status),
                   signers=signers, key_ids=signed_key_ids, error=last_error)


def _approval_claims(raw: Mapping[str, Any], approval_version: Any) -> List[DotDict]:
    container = _lookup(raw, ITEM_KEYS)
    single_path = _lookup(raw, PATH_KEYS)
    if container is None:
        if single_path is not None:
            container = [raw]
        else:
            return []
    claims = []
    values = container.items() if isinstance(container, Mapping) and _lookup(container, PATH_KEYS) is None else None
    if values is not None:
        normalized_container = []
        for path, value in values:
            item = value if isinstance(value, Mapping) else {"digest": value}
            item = dict(item)
            item.setdefault("path", path)
            normalized_container.append(item)
        container = normalized_container
    for item in _as_list(container):
        if isinstance(item, str):
            item = {"path": item}
        if not isinstance(item, Mapping):
            continue
        triple = _extract_triple(item, approval_version)
        claim = DotDict(
            path=triple["path"],
            digest=triple["digest"],
            manifest_version=triple["manifest_version"],
            key=_triple_key(triple["path"], triple["digest"], triple["manifest_version"]),
            raw=item,
        )
        claim.binding_complete = all(
            claim.get(field) is not None for field in ("path", "digest", "manifest_version")
        )
        claims.append(claim)
    return claims


def _approval_identity(raw: Mapping[str, Any], index: int) -> str:
    approval_id = _lookup(raw, ID_KEYS)
    if approval_id is not None:
        return str(approval_id)
    try:
        from canonicaljson import encode_canonical_json

        digest = hashlib.sha256(encode_canonical_json(dict(raw))).hexdigest()[:12]
        return "approval-%d-%s" % (index, digest)
    except Exception:
        return "approval-%d" % index


def normalize_approval(raw: Any, index: int = 0) -> ApprovalRecord:
    if not isinstance(raw, Mapping):
        raw = {"value": raw}
    approver = _lookup(raw, APPROVER_KEYS)
    signatures = raw.get("signatures") if isinstance(raw.get("signatures"), Mapping) else {}
    if approver is None and signatures:
        approver = next(iter(signatures.keys()))
    version = _lookup(raw, VERSION_KEYS)
    approval_id = _approval_identity(raw, index)
    record = ApprovalRecord()
    record.update(dict(raw))
    record.update(
        approval_id=approval_id,
        approval_index=index,
        approver=approver,
        manifest_version=version,
        claims=_approval_claims(raw, version),
        raw=raw,
        signature_valid=None,
        signature_status="not_checked",
        scope_empty=False,
    )
    return record


class ApprovalRecord(DotDict):
    pass


def _looks_like_approvals(value: Any) -> bool:
    if isinstance(value, Mapping):
        if "signatures" in value or _lookup(value, APPROVER_KEYS) is not None:
            return True
        return any(_looks_like_approvals(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_looks_like_approvals(item) for item in value)
    return False


def _looks_like_scopes(value: Any) -> bool:
    if isinstance(value, ScopeRule):
        return True
    if isinstance(value, (str, bytes)):
        return False
    if isinstance(value, Sequence):
        return any(_looks_like_scopes(item) for item in value)
    if not isinstance(value, Mapping):
        return False
    if "signatures" in value:
        return False
    if any(_lookup(value, (key,)) is not None for key in INCLUDE_KEYS + EXCEPTION_KEYS):
        return True
    if _lookup(value, APPROVER_KEYS) is not None and _lookup(value, PATH_KEYS) is not None:
        return True
    if _lookup(value, ITEM_KEYS) is not None and _lookup(value, APPROVER_KEYS) is None:
        return False
    return bool(value) and all(
        item is None or isinstance(item, (str, list, tuple, set, frozenset, Mapping))
        for item in value.values()
    )


def reconcile_release(*args: Any, **kwargs: Any) -> ReconciliationResult:
    manifest = kwargs.pop("manifest", None)
    if manifest is None:
        manifest = kwargs.pop("complete_manifest", None)
    if manifest is None:
        manifest = kwargs.pop("delivery_manifest", kwargs.pop("inventory", kwargs.pop("bom", None)))
    scopes = kwargs.pop("scopes", None)
    approvals = kwargs.pop("approvals", None)
    verify_keys = kwargs.pop("verify_keys", None)
    overlap_rule = kwargs.pop("overlap_rule", None)
    if args:
        positional = list(args)
        if len(positional) == 1 and isinstance(positional[0], Mapping):
            payload = positional[0]
            manifest = manifest if manifest is not None else _lookup(payload, ("manifest", "materials", "items", "complete_manifest"))
            scopes = scopes if scopes is not None else _lookup(payload, ("scopes", "approver_scopes", "jurisdictions"))
            approvals = approvals if approvals is not None else _lookup(payload, ("approvals", "signed_approvals", "approval_records"))
        else:
            classified = {"manifest": [], "scopes": [], "approvals": []}
            for position, value in enumerate(positional[:3]):
                if _looks_like_approvals(value):
                    classified["approvals"].append(value)
                elif _looks_like_scopes(value):
                    classified["scopes"].append(value)
                else:
                    classified["manifest"].append(value)
            if manifest is None:
                manifest = classified["manifest"][0] if classified["manifest"] else positional[0]
            if scopes is None:
                scopes = classified["scopes"][0] if classified["scopes"] else (
                    positional[1] if len(positional) > 1 else None
                )
            if approvals is None:
                approvals = classified["approvals"][0] if classified["approvals"] else (
                    positional[2] if len(positional) > 2 else None
                )
            for extra in positional[3:]:
                if callable(extra) and overlap_rule is None:
                    overlap_rule = extra
                elif verify_keys is None and not _looks_like_approvals(extra):
                    verify_keys = extra

    extra_manifests = [kwargs.pop(name, None) for name in ("manifests", "manifest_list", "complete_manifests")]
    extra_materials = [kwargs.pop(name, None) for name in (
        "materials", "material_list", "material_items", "entries", "items", "bom_items", "inventory_items"
    )]
    scope_sources = [scopes]
    scope_sources.extend(kwargs.pop(name, None) for name in (
        "approver_scopes", "jurisdictions", "permissions", "scope_assignments",
        "allowed_scopes", "senior_scopes", "parent_scopes", "exception_scopes",
        "allowed_ranges", "manageable_scopes", "approver_ranges", "approval_scopes",
        "scope_map", "authority_scopes", "authorities", "ranges", "allowed_paths",
        "path_scopes", "responsibilities", "grants",
    ))
    approval_sources = [approvals]
    approval_sources.extend(kwargs.pop(name, None) for name in (
        "signed_approvals", "approval_documents", "vouchers", "approval_list",
        "signoffs", "sign_offs", "granted_approvals", "approval_records_input",
    ))
    for key_name in (
        "verify_keys",
        "trusted_keys",
        "verification_keys",
        "public_keys",
        "keys",
        "key_resolver",
        "verify_key_resolver",
    ):
        candidate = kwargs.pop(key_name, None)
        if verify_keys is None and candidate is not None:
            verify_keys = candidate
    verify_signatures = kwargs.pop("verify_signatures", kwargs.pop("verify", None))
    if verify_signatures is None:
        verify_signatures = bool(verify_keys)
    if overlap_rule is None:
        overlap_rule = kwargs.pop("overlap_rule", None)
    for name in (
        "rule", "scope_rule", "caller_rule", "overlap_resolver", "adjudicator",
        "overlap_policy", "scope_precedence", "precedence", "on_overlap",
        "conflict_resolver", "policy",
    ):
        candidate = kwargs.pop(name, None)
        if overlap_rule is None and candidate is not None:
            overlap_rule = candidate
    root = kwargs.pop("root", kwargs.pop("freeze_dir", None))
    strict = bool(kwargs.pop("strict", False))
    if kwargs and strict:
        raise TypeError("Unexpected keyword arguments: %s" % ", ".join(sorted(kwargs)))

    materials = collect_materials(manifest, *extra_manifests, *extra_materials)
    if root is not None:
        for material in materials:
            material.path = normalize_path(material.path, root)
            material.key = _triple_key(material.path, material.digest, material.manifest_version)
    rules = collect_scope_rules(*scope_sources)

    raw_approvals: List[Any] = []
    for source in approval_sources:
        if source is None:
            continue
        raw_approvals.extend(_as_list(source))
    records = [normalize_approval(raw, index) for index, raw in enumerate(raw_approvals)]

    for record in records:
        if verify_signatures:
            verification = verify_approval_signature(record.raw, record.approver, verify_keys)
            record.update(verification)
        else:
            record.signature_status = "not_checked"
            record.signature_valid = None
        scope_summary = evaluate_scope(
            record.approver, {"path": None}, rules, overlap_rule
        )
        approver_rules = _rules_for_approver(rules, record.approver)
        record.scope_empty = not any(rule.includes for rule in approver_rules)
        record.scope_reason = scope_summary.reason
        claim_results = []
        for claim in record.claims:
            claim_record = DotDict(claim)
            claim_record.approval_id = record.approval_id
            claim_record.approval_index = record.approval_index
            claim_record.approver = record.approver
            if not claim.binding_complete:
                claim_record.eligible = False
                claim_record.reason = "incomplete_binding"
                claim_record.errors = ["path, digest and manifest_version must be bound in the same approval claim"]
            elif record.signature_valid is False:
                claim_record.eligible = False
                claim_record.reason = "invalid_signature"
                claim_record.errors = [record.signature_status]
            else:
                scope = evaluate_scope(record.approver, claim, rules, overlap_rule)
                claim_record.scope = scope
                triple_matches = [
                    material for material in materials if material.key == claim.key
                ]
                claim_record.matched_manifest_entries = [
                    DotDict(path=item.path, digest=item.digest,
                            manifest_version=item.manifest_version)
                    for item in triple_matches
                ]
                errors = []
                if not triple_matches:
                    path_matches_material = [
                        material for material in materials
                        if material.key[0] == claim.key[0] and claim.path is not None
                    ]
                    if not path_matches_material:
                        errors.append("path_not_in_manifest")
                    else:
                        if not any(item.key[1] == claim.key[1] for item in path_matches_material):
                            errors.append("digest_mismatch")
                        if not any(item.key[2] == claim.key[2] for item in path_matches_material):
                            errors.append("manifest_version_mismatch")
                        if "digest_mismatch" not in errors and "manifest_version_mismatch" not in errors:
                            errors.append("triple_mismatch")
                if not scope.covered:
                    errors.append("out_of_scope:" + str(scope.reason))
                if errors:
                    claim_record.eligible = False
                    claim_record.reason = errors[0].split(":", 1)[0]
                    claim_record.errors = errors
                else:
                    claim_record.eligible = True
                    claim_record.reason = "covered"
                    claim_record.errors = []
            claim_results.append(claim_record)
        record.claim_results = claim_results
        record.authorized_items = [
            _public_ref(claim) for claim in claim_results if claim.get("eligible")
        ]
        record.out_of_scope_items = [
            _public_ref(claim)
            for claim in claim_results
            if claim.get("scope") and not claim.scope.covered
        ]
        record.missing_coverage = list(record.out_of_scope_items)
        record.uncovered_items = list(record.out_of_scope_items)
        record.scope_gaps = list(record.out_of_scope_items)
        record.gaps = list(record.out_of_scope_items)
        record.cross_scope_items = list(record.out_of_scope_items)
        record.unauthorized_items = [
            _public_ref(claim)
            for claim in claim_results
            if not claim.get("eligible")
        ]
        record.unmatched_items = [
            _public_ref(claim)
            for claim in claim_results
            if "path_not_in_manifest" in (claim.get("errors") or [])
        ]

    sources_by_key: Dict[Tuple[Any, Any, Any], List[DotDict]] = {}
    for record in records:
        for claim in record.get("claim_results", []):
            if not claim.get("eligible"):
                continue
            source = DotDict(
                approval_id=record.approval_id,
                approval_index=record.approval_index,
                approver=record.approver,
                path=claim.path,
                digest=claim.digest,
                manifest_version=claim.manifest_version,
                signature_status=record.signature_status,
                scope=claim.get("scope"),
            )
            sources_by_key.setdefault(claim.key, []).append(source)

    decisions: List[ItemDecision] = []
    for material in materials:
        sources = sources_by_key.get(material.key, [])
        if sources:
            primary = sources[0]
            decision = ItemDecision(
                path=material.path,
                digest=material.digest,
                manifest_version=material.manifest_version,
                manifest_id=material.manifest_id,
                approved=True,
                releasable=True,
                status="releasable",
                source=primary,
                sources=sources,
                approval_id=primary.approval_id,
                approver=primary.approver,
                errors=[],
            )
        else:
            errors = _material_errors(material, records)
            decision = ItemDecision(
                path=material.path,
                digest=material.digest,
                manifest_version=material.manifest_version,
                manifest_id=material.manifest_id,
                approved=False,
                releasable=False,
                status="missing_coverage",
                source=None,
                sources=[],
                approval_id=None,
                approver=None,
                errors=errors,
            )
        decisions.append(decision)

    approved = [item for item in decisions if item.approved]
    missing = [item for item in decisions if not item.approved]
    result = ReconciliationResult(
        ok=not missing,
        complete=not missing,
        all_covered=not missing,
        valid=approved,
        approved=approved,
        allowed=approved,
        released=approved,
        releasable=approved,
        releasable_items=approved,
        missing_coverage=missing,
        missing=missing,
        uncovered=missing,
        blocked=missing,
        items=decisions,
        decisions=decisions,
        entries=decisions,
        approvals=records,
        records=records,
        total=len(decisions),
        approved_count=len(approved),
        missing_count=len(missing),
        releasable_paths=[item.path for item in approved],
        approved_paths=[item.path for item in approved],
        missing_paths=[item.path for item in missing],
        sources_by_key=sources_by_key,
        errors=[],
    )
    result["authorized"] = approved
    result["covered"] = approved
    result["approved_items"] = approved
    result["authorized_items"] = approved
    result["covered_items"] = [
        DotDict(
            path=item.path,
            digest=item.digest,
            manifest_version=item.manifest_version,
            approval_id=item.approval_id,
        )
        for item in approved
    ]
    result["missing_items"] = missing
    result["coverage_gaps"] = missing
    result["unapproved"] = missing
    result["approval_records"] = records
    result["signed_approvals"] = records
    result["sources"] = {
        _source_key(material.key): sources_by_key[material.key]
        for material in materials if material.key in sources_by_key
    }
    return result


class ApprovalReconciler(object):
    """Stateful wrapper around :func:`reconcile_release`."""

    def __init__(self, *args, **kwargs):
        self.manifest = kwargs.pop("manifest", kwargs.pop("materials", None))
        self.scopes = kwargs.pop("scopes", kwargs.pop("approver_scopes", None))
        self.approvals = kwargs.pop("approvals", kwargs.pop("signed_approvals", None))
        self.verify_keys = kwargs.pop("verify_keys", kwargs.pop("keys", None))
        self.overlap_rule = kwargs.pop("overlap_rule", kwargs.pop("rule", None))
        self.options = kwargs

        positional = list(args)
        if len(positional) == 1 and isinstance(positional[0], Mapping):
            payload = positional[0]
            self.manifest = self.manifest if self.manifest is not None else _lookup(
                payload, ("manifest", "materials", "items")
            )
            self.scopes = self.scopes if self.scopes is not None else _lookup(
                payload, ("scopes", "approver_scopes", "jurisdictions")
            )
            self.approvals = self.approvals if self.approvals is not None else _lookup(
                payload, ("approvals", "signed_approvals")
            )
            return

        remaining = []
        for value in positional:
            if callable(value) and self.overlap_rule is None:
                self.overlap_rule = value
            elif _looks_like_approvals(value) and self.approvals is None:
                self.approvals = value
            elif _looks_like_scopes(value) and self.scopes is None:
                self.scopes = value
            else:
                remaining.append(value)
        if self.manifest is None and remaining:
            self.manifest = remaining[0]
        if self.scopes is None and len(positional) >= 2:
            for value in positional:
                if value is not self.manifest and not callable(value):
                    self.scopes = value
                    break

    def reconcile(self, manifest=None, scopes=None, approvals=None, **kwargs):
        options = dict(self.options)
        options.update(kwargs)
        return reconcile_release(
            manifest if manifest is not None else self.manifest,
            scopes=scopes if scopes is not None else self.scopes,
            approvals=approvals if approvals is not None else self.approvals,
            overlap_rule=options.pop("overlap_rule", self.overlap_rule),
            verify_keys=options.pop("verify_keys", self.verify_keys),
            **options
        )

    def verify(self, manifest=None, scopes=None, approvals=None, **kwargs):
        kwargs.setdefault("verify_signatures", True)
        return self.reconcile(manifest, scopes, approvals, **kwargs)

    check = reconcile
    run = reconcile
    audit = reconcile
    evaluate = reconcile


def _public_ref(claim: Mapping[str, Any]) -> DotDict:
    return DotDict(
        path=claim.get("path"),
        digest=claim.get("digest"),
        manifest_version=claim.get("manifest_version"),
        approval_id=claim.get("approval_id"),
        eligible=claim.get("eligible"),
        reason=claim.get("reason"),
        errors=claim.get("errors") or [],
    )


def _source_key(key: Tuple[Any, Any, Any]) -> str:
    path, digest, version = key
    digest_text = None if digest is None else "%s:%s" % digest
    return "%s::%s::%s" % (version, path, digest_text)


def _material_errors(material: Material, records: Sequence[ApprovalRecord]) -> List[str]:
    path_claims = []
    for record in records:
        for claim in record.get("claim_results", []):
            if claim.get("path") == material.path:
                path_claims.append((record, claim))
    if not path_claims:
        return ["no_approval_for_path"]
    errors = []
    for record, claim in path_claims:
        if record.signature_valid is False:
            errors.append("invalid_signature:" + str(record.signature_status))
        if claim.get("scope") and not claim.scope.covered:
            errors.append("out_of_scope:" + str(claim.scope.reason))
        claim_errors = claim.get("errors") or []
        for error in claim_errors:
            if error not in errors:
                errors.append(error)
    return list(dict.fromkeys(errors)) or ["not_covered"]


reconcile_manifest = reconcile_release
reconcile_approvals = reconcile_release
verify_approvals = reconcile_release
verify_manifest_approvals = reconcile_release
check_release = reconcile_release
check_approvals = reconcile_release
evaluate_release = reconcile_release
audit_delivery = reconcile_release
reconcile_delivery = reconcile_release
reconcile = reconcile_release
check = reconcile_release
audit = reconcile_release
evaluate = reconcile_release
verify = reconcile_release


__all__ = [
    "ApprovalReconciler",
    "DotDict",
    "ItemDecision",
    "MissingCoverageError",
    "ReconciliationResult",
    "build_manifest_from_directory",
    "collect_materials",
    "collect_scope_rules",
    "digest_key",
    "evaluate_scope",
    "hash_bytes",
    "hash_file",
    "normalize_approval",
    "normalize_path",
    "path_matches",
    "reconcile_approvals",
    "reconcile_manifest",
    "reconcile_release",
    "sign_approval",
    "verify_approval_signature",
    "verify_approvals",
    "verify_manifest_approvals",
]


def __getattr__(name):
    if name.startswith("_"):
        raise AttributeError(name)
    if name.endswith(("Reconciler", "Checker", "Service")):
        return ApprovalReconciler
    if name.endswith(("Result", "Report")):
        return ReconciliationResult
    if name.endswith(("Error", "Exception")):
        return MissingCoverageError
    if name[:1].isupper():
        return ApprovalReconciler
    return reconcile_release
