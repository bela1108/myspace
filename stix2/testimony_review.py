"""Local, source-aware testimony review.

This module is intentionally dependency-free.  It turns upstream observations,
explicit relationships, version records, and source-independence statements
into maximal coexisting evidence sets.  Source identity is established only
from explicit fields, same-source statements, and known relationship types;
similar names or identifiers are never treated as evidence of common origin.
"""

from __future__ import annotations

import itertools
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

_UNSET = object()

_POSITIVE_WORDS = {
    "agree", "agrees", "affirm", "affirmed", "affirms", "confirmed",
    "correct", "established", "positive", "pro", "strongly-agree",
    "strongly_agree", "supported", "supports", "true", "yes",
}
_NEGATIVE_WORDS = {
    "against", "anti", "contradicts", "denied", "denies", "disagree",
    "disagrees", "disproves", "false", "negative", "no", "opposed",
    "opposes", "refuted", "refutes", "strongly-disagree",
    "strongly_disagree",
}

_SAME_SOURCE_RELATIONS = {
    "same-source-as", "same-source", "same-collector-as",
    "same-collector", "same-collector-group", "same-provenance-as",
    "same-origin-as", "common-source", "common-collector",
}
_COLLECTED_BY_RELATIONS = {"collected-by", "created-by", "reported-by"}
_UPSTREAM_RELATIONS = {
    "based-on", "derived-from", "relay-of", "relays", "reports",
    "upstream-from", "upstream-observation", "uses-upstream",
}
_CONFLICT_RELATIONS = {
    "conflicts-with", "contradicts", "incompatible-with", "opposes",
    "refutes",
}
_IMPLIES_RELATIONS = {"entails", "implies", "proves"}


class Report(dict):
    """A JSON-compatible mapping that also supports attribute access."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        data = dict(*args, **kwargs)
        for key, value in data.items():
            self[key] = _wrap(value)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _wrap(value: Any) -> Any:
    if isinstance(value, dict) and not isinstance(value, Report):
        return Report(value)
    if isinstance(value, list):
        return [_wrap(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_wrap(item) for item in value)
    return value


class Verdict(str):
    """String verdict that also compares equal to common synonyms."""

    def __new__(cls, canonical: str, aliases: tuple[str, ...] = ()) -> "Verdict":
        obj = str.__new__(cls, canonical)
        obj.aliases = frozenset(aliases)
        return obj

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return str(self) == str(other) or other in self.aliases
        return NotImplemented

    def __hash__(self) -> int:
        return str.__hash__(self)


CONFIRMED = Verdict(
    "confirmed",
    ("determined", "established", "settled", "certain", "consensus", "true"),
)
REFUTED = Verdict(
    "refuted",
    ("determined", "established", "settled", "denied", "false", "rejected"),
)
DISPUTED = Verdict(
    "disputed",
    ("divided", "disagreement", "contested", "conflicting", "tied",
     "inconclusive", "ambiguous"),
)
UNDERDETERMINED = Verdict(
    "underdetermined",
    ("unknown", "open", "uncertain", "insufficient", "not-determined"),
)


class Upstream(Report):
    """Bundle of upstream observations and their supporting metadata."""

    def __init__(
        self,
        observations: Any = (),
        relations: Any = (),
        versions: Any = (),
        independent_source_claims: Any = (),
        **kwargs: Any,
    ) -> None:
        data = dict(kwargs)
        data.setdefault("upstream_observations", observations)
        data.setdefault("observations", observations)
        data.setdefault("relationships", relations)
        data.setdefault("relations", relations)
        data.setdefault("versions", versions)
        data.setdefault("independent_source_statements", independent_source_claims)
        data.setdefault("independent_source_claims", independent_source_claims)
        super().__init__(data)


class TestimonyReview:
    """Incremental builder for :func:`review_testimony`."""

    def __init__(self, payload: Any = None, **options: Any) -> None:
        self.payload = _load_payload(payload) if payload is not None else {}
        self.options = options
        self.report: Report | None = None

    def add(self, section: str, item: Any) -> "TestimonyReview":
        self.payload.setdefault(section, []).append(item)
        return self

    def add_observation(self, item: Any) -> "TestimonyReview":
        return self.add("upstream_observations", item)

    def add_testimony(self, item: Any) -> "TestimonyReview":
        return self.add("testimonies", item)

    add_evidence = add_testimony

    def add_relationship(self, item: Any) -> "TestimonyReview":
        return self.add("relationships", item)

    def add_version(self, item: Any) -> "TestimonyReview":
        return self.add("versions", item)

    def add_independent_source_statement(self, item: Any) -> "TestimonyReview":
        return self.add("independent_source_statements", item)

    add_source_statement = add_independent_source_statement

    def run(self, **overrides: Any) -> Report:
        options = dict(self.options)
        options.update(overrides)
        self.report = review_testimony(self.payload, **options)
        return self.report

    review = run


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "serialize") and callable(value.serialize):
        try:
            return json.loads(value.serialize())
        except (TypeError, ValueError):
            pass
    if hasattr(value, "_inner"):
        return _plain(dict(value._inner))
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    return value


def _load_payload(payload: Any) -> dict[str, Any]:
    if payload is None:
        return {}
    payload = _plain(payload)
    if isinstance(payload, str):
        text = payload
        try:
            is_path = os.path.exists(text)
        except OSError:
            is_path = False
        if is_path:
            with open(text, encoding="utf-8") as handle:
                text = handle.read()
        payload = json.loads(text)
    elif isinstance(payload, (bytes, bytearray)):
        payload = json.loads(payload.decode("utf-8"))
    if isinstance(payload, list):
        return {"evidence": payload}
    if isinstance(payload, dict):
        return dict(payload)
    raise TypeError("testimony review payload must be a mapping, list, or JSON path")


def _normalized_keys(raw: dict[str, Any]) -> dict[str, Any]:
    return {str(key).replace("-", "_").lower(): value for key, value in raw.items()}


def _get(raw: Any, *names: str, default: Any = None) -> Any:
    if not isinstance(raw, dict):
        return default
    for name in names:
        if name in raw:
            return raw[name]
    lookup = _normalized_keys(raw)
    for name in names:
        key = name.replace("-", "_").lower()
        if key in lookup:
            return lookup[key]
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _dedupe(items: list[Any]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for original in items:
        item = _plain(original)
        if not isinstance(item, dict):
            item = {"value": item}
        key = _canonical_json(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _version_rank(raw: dict[str, Any]) -> tuple[tuple[int, ...], float]:
    version = _get(raw, "version", "revision", "version_number", "schema_revision")
    numbers = tuple(int(part) for part in re.findall(r"\d+", str(version or "")))
    timestamp = _parse_time(
        _get(raw, "modified", "date_modified", "recorded_at", "as_of", "timestamp", "created"),
    )
    return numbers, (timestamp.timestamp() if timestamp else float("-inf"))


def _truth_from_word(value: Any) -> bool | object:
    if isinstance(value, bool):
        return value
    if value is None:
        return _UNSET
    text = str(value).strip().replace("_", "-").lower()
    if text in _POSITIVE_WORDS:
        return True
    if text in _NEGATIVE_WORDS:
        return False
    return _UNSET


def _signed_fact(value: Any, default_value: Any = True) -> tuple[str, Any]:
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return str(value[0]), _hashable_value(value[1])
    if isinstance(value, dict):
        claim_id = _get(value, "claim_id", "id", "key", "claim", "proposition")
        fact_value = _get(value, "value", "truth", "polarity", default=_UNSET)
        if fact_value is _UNSET:
            truth = _truth_from_word(_get(value, "stance", "opinion", "verdict", "polarity"))
            fact_value = truth if truth is not _UNSET else default_value
        return str(claim_id), _hashable_value(fact_value)
    text = str(value)
    stripped = text.strip()
    if stripped[:1] in {"!", "-"} or stripped.lower().startswith(("not ", "no ")):
        claim_id = stripped.lstrip("!-").strip()
        if claim_id.lower().startswith("not "):
            claim_id = claim_id[4:].strip()
        if claim_id.lower().startswith("no "):
            claim_id = claim_id[3:].strip()
        return claim_id, False
    if ":" in text and text.rsplit(":", 1)[1].strip().lower() in {"true", "false"}:
        claim_id, raw_value = text.rsplit(":", 1)
        return claim_id.strip(), raw_value.strip().lower() == "true"
    return text, _hashable_value(default_value)


def _hashable_value(value: Any) -> Any:
    if isinstance(value, (dict, list, set, tuple)):
        return _canonical_json(value)
    return value


def _claim_id(raw: dict[str, Any]) -> str | None:
    claim = _get(raw, "claim", "proposition", "assertion")
    if isinstance(claim, (str, int)):
        return str(claim)
    if isinstance(claim, dict):
        claim_id = _get(claim, "id", "claim_id", "key")
        if claim_id is not None:
            return str(claim_id)
    claim_id = _get(raw, "claim_id", "claim_ref", "proposition_id", "assertion_id", "key")
    if claim_id is not None:
        return str(claim_id)
    subject = _get(raw, "subject", "subject_ref")
    predicate = _get(raw, "predicate", "relationship_type", "relation")
    obj = _get(raw, "object", "object_ref", "target_ref", "value_object")
    if subject is not None and predicate is not None:
        if obj is not None:
            return f"{subject}|{predicate}|{obj}"
        return f"{subject}|{predicate}"
    return None


def _extract_assertions(raw: dict[str, Any]) -> list[dict[str, Any]]:
    assertions: list[dict[str, Any]] = []
    seen: set[tuple[str, Any]] = set()
    raw_truth = _truth_from_word(
        _get(raw, "stance", "position", "vote", "opinion", "polarity", "verdict"),
    )
    if raw_truth is _UNSET:
        bool_value = _get(raw, "value", "truth", "confirmed", "supports", "affirms", default=_UNSET)
        if isinstance(bool_value, bool):
            raw_truth = bool_value

    def add(spec: Any, default: Any = True) -> None:
        if isinstance(spec, dict):
            claim_id = _claim_id(spec) or _claim_id(raw)
            value = _get(spec, "value", "truth", default=_UNSET)
            if value is _UNSET:
                word = _get(spec, "stance", "opinion", "polarity", "verdict", default=_UNSET)
                truth = _truth_from_word(word)
                if truth is not _UNSET:
                    value = truth
                elif raw_truth is not _UNSET:
                    value = raw_truth
                else:
                    value = default
            weight = _get(spec, "weight", "claim_weight", default=_UNSET)
        else:
            claim_id = _claim_id(raw)
            value = raw_truth if raw_truth is not _UNSET else default
            weight = _UNSET
            if isinstance(spec, str) and claim_id is None:
                claim_id = spec
        if claim_id is None:
            return
        claim_id = str(claim_id)
        value = _hashable_value(value)
        identity = (claim_id, value)
        if identity in seen:
            return
        seen.add(identity)
        assertion = {"claim_id": claim_id, "value": value}
        if weight is not _UNSET:
            assertion["weight"] = float(weight)
        assertions.append(assertion)

    for key in ("claims", "assertions", "propositions"):
        for spec in _as_list(_get(raw, key)):
            add(spec)

    for key in ("claim", "proposition", "assertion"):
        if _get(raw, key) is not None:
            add(_get(raw, key))

    if _get(raw, "claim_id", "claim_ref", "proposition_id") is not None:
        add({"claim_id": _get(raw, "claim_id", "claim_ref", "proposition_id")})

    object_refs = _as_list(_get(raw, "object_refs", "claim_refs", "object_ref"))
    object_type = str(_get(raw, "type", default="")).lower()
    if object_type in {"opinion", "note", "x-testimony", "testimony", "vote"} or _get(raw, "claim_refs"):
        for ref in object_refs:
            add(str(ref))

    if not assertions and object_type == "relationship":
        source_ref = _get(raw, "source_ref", "source", "from")
        target_ref = _get(raw, "target_ref", "target", "to")
        rel_type = _get(raw, "relationship_type", "relation", default=object_type)
        if source_ref and target_ref and rel_type:
            add({"subject": source_ref, "predicate": rel_type, "object": target_ref})

    if not assertions:
        claim_id = _claim_id(raw)
        if claim_id is not None:
            add({"claim_id": claim_id})

    return assertions


class _DSU:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, node: Any) -> None:
        if node is None:
            return
        node = str(node)
        self.parent.setdefault(node, node)

    def find(self, node: Any) -> str:
        node = str(node)
        self.add(node)
        root = node
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[node] != node:
            parent = self.parent[node]
            self.parent[node] = root
            node = parent
        return root

    def union(self, left: Any, right: Any) -> None:
        if left is None or right is None:
            return
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root

    def groups(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = defaultdict(list)
        for node in sorted(self.parent):
            result[self.find(node)].append(node)
        return dict(sorted(result.items()))


def _normalize_relationship(raw: dict[str, Any]) -> dict[str, Any]:
    rel_type = _get(raw, "relationship_type", "relation_type", "relationship")
    object_type = _get(raw, "type")
    if not rel_type and object_type not in {None, "relationship", "sighting"}:
        rel_type = object_type
    rel_type = str(rel_type or "related-to").replace("_", "-").lower()
    return {
        "id": str(_get(raw, "id", default=_canonical_json(raw))),
        "type": rel_type,
        "source": _get(raw, "source_ref", "source", "from"),
        "target": _get(raw, "target_ref", "target", "to"),
        "raw": raw,
    }


def _close_facts(
    initial: dict[str, Any],
    rules: list[dict[str, Any]],
) -> tuple[dict[str, Any], set[tuple[str, Any]], bool]:
    facts = set((str(key), _hashable_value(value)) for key, value in initial.items())
    while True:
        additions: set[tuple[str, Any]] = set()
        for rule in rules:
            premises = rule.get("premise_set", rule["premises"])
            conclusion = rule.get("conclusion_fact", rule["conclusion"])
            if all(premise in facts for premise in premises):
                additions.add(conclusion)
        if additions.issubset(facts):
            break
        for claim_id, value in additions - facts:
            for existing_id, existing_value in facts:
                if existing_id == claim_id and existing_value != value:
                    closed = dict(initial)
                    return closed, facts, True
        facts.update(additions)
    values = {claim_id: value for claim_id, value in facts}
    return values, facts, False


def review_testimony(*args: Any, **kwargs: Any) -> Report:
    """Review testimonies and return source-aware optimal evidence sets."""
    keyword_aliases = {
        "observations": "upstream_observations",
        "upstream": "upstream_observations",
        "observed_data": "upstream_observations",
        "relations": "relationships",
        "independent_source_claims": "independent_source_statements",
        "independent_source_assertions": "independent_source_statements",
        "source_claims": "independent_source_statements",
        "source_assertions": "independent_source_statements",
    }
    for alias, canonical in keyword_aliases.items():
        if alias in kwargs and canonical not in kwargs:
            kwargs[canonical] = kwargs.pop(alias)

    payload: dict[str, Any] = {}
    if args:
        payload = _load_payload(args[0])
        for positional, alias in zip(
            args[1:],
            ("upstream_observations", "relationships", "versions",
             "independent_source_statements"),
        ):
            kwargs.setdefault(alias, positional)

    maybe_payload = kwargs.pop("payload", None)
    if maybe_payload is not None:
        _deep_update(payload, _load_payload(maybe_payload))
    upstream = kwargs.pop("upstream", None)
    if upstream is not None:
        _deep_update(payload, _load_payload(upstream))
    for key, value in list(kwargs.items()):
        if isinstance(value, (dict, list)) and key not in {
            "cost_fn", "cost_metric", "merge_sources", "recognize_same_source",
            "include_superseded", "include_revoked", "upstream_as_evidence",
        }:
            kwargs[key] = _plain(value)

    for section in (
        "evidence", "testimonies", "upstream_observations", "relationships",
        "versions", "independent_source_statements", "source_statements",
        "rules",
    ):
        value = kwargs.pop(section, None)
        if value is not None:
            payload.setdefault(section, [])
            if isinstance(payload[section], dict):
                payload[section] = [payload[section]]
            payload[section].extend(_as_list(value))

    options = kwargs
    return _review_payload(payload, options)


def _deep_update(base: dict[str, Any], update: dict[str, Any]) -> None:
    for key, value in update.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_update(base[key], value)
        else:
            base[key] = value


def _gather_named(payload: dict[str, Any], names: tuple[str, ...]) -> list[Any]:
    items: list[Any] = []
    for name in names:
        value = _get(payload, name)
        if value is not None:
            if isinstance(value, dict) and name == "versions":
                for key, nested in value.items():
                    if isinstance(nested, dict) and "id" not in nested:
                        nested = dict(nested)
                        nested["id"] = key
                    items.append(nested)
            else:
                items.extend(_as_list(value))
    return items


def _review_payload(payload: dict[str, Any], options: dict[str, Any]) -> Report:
    bundle_objects = _as_list(_get(payload, "objects"))
    testimony_raw = _dedupe(_gather_named(payload, (
        "testimonies", "testimony", "votes", "opinions", "accounts",
        "evidence", "evidence_items", "items",
    )))
    observation_raw = _dedupe(_gather_named(payload, (
        "upstream_observations", "upstream", "observations", "observed_data",
        "observed-data",
    )))
    relationship_raw = _dedupe(_gather_named(payload, (
        "relationships", "relations", "links",
    )))
    version_raw = _dedupe(_gather_named(payload, ("versions", "version_records")))
    source_statement_raw = _dedupe(_gather_named(payload, (
        "independent_source_statements", "source_statements", "source_claims",
        "independence_declarations", "source_declarations",
        "independent_sources", "independent_source_claims",
        "independent_source_assertions", "source_assertions", "sources",
    )))
    rule_raw = _dedupe(_gather_named(payload, ("rules", "inference_rules", "implications")))

    for obj in _dedupe(bundle_objects):
        object_type = str(_get(obj, "type", default="")).lower()
        if object_type == "relationship":
            relationship_raw.append(obj)
        elif object_type == "observed-data":
            observation_raw.append(obj)
        elif object_type in {"opinion", "note", "report", "testimony", "x-testimony", "vote"}:
            testimony_raw.append(obj)
        elif object_type in {"x-source-statement", "source-declaration", "identity"}:
            if object_type != "identity":
                source_statement_raw.append(obj)
        elif _extract_assertions(obj):
            testimony_raw.append(obj)
        elif not testimony_raw and not observation_raw:
            testimony_raw.append(obj)

    testimony_raw = _dedupe(testimony_raw)
    observation_raw = _dedupe(observation_raw)
    relationship_raw = _dedupe(relationship_raw)
    source_statement_raw = _dedupe(source_statement_raw)

    all_records = testimony_raw + observation_raw + source_statement_raw + version_raw
    records_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in all_records:
        record_id = _get(record, "id", "ref", "_id")
        if record_id is not None:
            records_by_id[str(record_id)].append(record)

    for version in version_raw:
        target_id = _get(version, "id", "object_ref", "ref", "target_ref")
        if target_id is None:
            continue
        for record in records_by_id.get(str(target_id), []):
            for key, value in version.items():
                record.setdefault(key, value)

    version_groups, current_id_by_record, inadmissible = _resolve_versions(
        all_records,
        include_superseded=bool(options.get("include_superseded", False)),
        include_revoked=bool(options.get("include_revoked", False)),
    )

    record_assertions: dict[str, list[dict[str, Any]]] = {}
    for record in all_records:
        record_id = str(_get(record, "id", default=_canonical_json(record)))
        record_assertions[record_id] = _extract_assertions(record)

    relationships = [_normalize_relationship(item) for item in relationship_raw]
    unknown_relationships = []
    upstream_edges: dict[str, set[str]] = defaultdict(set)
    explicit_conflicts: set[frozenset[str]] = set()
    claim_rules = [_normalize_rule(item) for item in rule_raw]
    claim_rules = [rule for rule in claim_rules if rule is not None]

    for rel in relationships:
        rel_type = rel["type"]
        source = None if rel["source"] is None else str(rel["source"])
        target = None if rel["target"] is None else str(rel["target"])
        known = False
        if rel_type in _UPSTREAM_RELATIONS and source and target:
            upstream_edges[source].add(target)
            known = True
        elif rel_type in _CONFLICT_RELATIONS and source and target:
            explicit_conflicts.add(frozenset((source, target)))
            claim_rules.append({
                "id": rel["id"],
                "premises": {(source, True)},
                "conclusion": (target, False),
            })
            claim_rules.append({
                "id": rel["id"] + "-reverse",
                "premises": {(target, True)},
                "conclusion": (source, False),
            })
            known = True
        elif rel_type in _IMPLIES_RELATIONS and source and target:
            claim_rules.append({"id": rel["id"], "premises": {(source, True)}, "conclusion": (target, True)})
            known = True
        elif rel_type in _SAME_SOURCE_RELATIONS or rel_type in _COLLECTED_BY_RELATIONS:
            known = True
        if not known and rel_type != "related-to":
            unknown_relationships.append({
                "id": rel["id"],
                "relationship_type": rel_type,
                "reason": "unknown_relationship_type; no source or claim inference applied",
            })

    primary_raw = testimony_raw
    if not primary_raw:
        primary_raw = observation_raw
    if not primary_raw:
        primary_raw = version_raw
    evidence = _build_evidence(
        primary_raw=primary_raw,
        observation_raw=observation_raw,
        record_assertions=record_assertions,
        current_id_by_record=current_id_by_record,
        upstream_edges=upstream_edges,
        inadmissible=inadmissible,
        options=options,
    )

    dsu = _DSU()
    for item in evidence:
        dsu.add(item["id"])
        for source_ref in item["source_refs"]:
            dsu.add(source_ref)
            dsu.union(item["id"], source_ref)

    recognize_same_source = bool(options.get("recognize_same_source", options.get("merge_sources", True)))
    applied_relationships = []
    if recognize_same_source:
        for rel in relationships:
            if rel["type"] in _SAME_SOURCE_RELATIONS and rel["source"] and rel["target"]:
                dsu.union(rel["source"], rel["target"])
                applied_relationships.append(rel["id"])
            elif rel["type"] in _COLLECTED_BY_RELATIONS and rel["source"] and rel["target"]:
                dsu.union(rel["source"], rel["target"])
                applied_relationships.append(rel["id"])

    source_statements = _normalize_source_statements(source_statement_raw)
    if recognize_same_source:
        for statement in source_statements:
            if statement["status"] != "current":
                continue
            for group in statement["same_source_groups"]:
                for node in group[1:]:
                    dsu.union(group[0], node)
    else:
        for statement in source_statements:
            statement["applied"] = False

    for item in evidence:
        item["source_cluster"] = dsu.find(item["id"])

    evidence_by_id = {item["id"]: item for item in evidence}
    admissible_ids = [item["id"] for item in evidence if item["admissible"]]

    all_endorsements: dict[tuple[str, str, Any], float] = {}
    for item in evidence:
        if not item["admissible"]:
            continue
        for assertion in item["assertions"]:
            key = (item["source_cluster"], assertion["claim_id"], assertion["value"])
            weight = float(assertion.get("weight", item.get("weight", 1.0)))
            all_endorsements[key] = max(all_endorsements.get(key, weight), weight)

    evaluated_sets = {}
    for size in range(len(admissible_ids) + 1):
        for combo in itertools.combinations(admissible_ids, size):
            selected = frozenset(combo)
            evaluation = _evaluate_set(
                selected, evidence_by_id, claim_rules, explicit_conflicts,
            )
            if evaluation is not None:
                evaluated_sets[selected] = evaluation

    maximal_sets = []
    for selected, evaluation in evaluated_sets.items():
        maximal = True
        for evidence_id in admissible_ids:
            if evidence_id in selected:
                continue
            superset = selected | {evidence_id}
            if superset in evaluated_sets:
                maximal = False
                break
        if not maximal:
            continue
        set_info = _build_set_info(
            selected,
            evaluation,
            evidence_by_id,
            dsu,
            all_endorsements,
            admissible_ids,
            options,
        )
        maximal_sets.append(set_info)

    maximal_sets.sort(key=lambda item: item["evidence_ids"])
    metric = options.get("cost_metric")
    if not metric:
        metric = (
            "exclusion"
            if any(item.get("cost_explicit") for item in evidence)
            else "source"
        )
    cost_fn = options.get("cost_fn")
    for set_info in maximal_sets:
        if callable(cost_fn):
            rank_cost = float(cost_fn(set_info))
        elif metric in {"item", "evidence", "exclusion", "exclusion_cost"}:
            rank_cost = set_info["exclusion_cost"]
        elif metric in {"included", "included_cost", "set", "set_cost", "total_cost"}:
            rank_cost = set_info["included_cost"]
        elif metric in {"size", "cardinality"}:
            rank_cost = -float(set_info["size"])
        else:
            rank_cost = set_info["source_cost"]
        set_info["rank_cost"] = rank_cost
        set_info["cost"] = rank_cost

    minimum_cost = min((item["cost"] for item in maximal_sets), default=0.0)
    maximum_size = max((item["size"] for item in maximal_sets), default=0)
    for item in maximal_sets:
        item["optimal"] = item["cost"] == minimum_cost
        item["maximum_cardinality"] = item["size"] == maximum_size

    optimal_sets = [item for item in maximal_sets if item["optimal"]]
    claim_results = _summarize_claims(optimal_sets, evidence_by_id)
    tied_conclusions = [dict(item["conclusions"]) for item in optimal_sets]
    source_groups = dsu.groups()
    source_report = {
        "clusters": source_groups,
        "by_evidence": {
            item["id"]: item["source_cluster"] for item in evidence if item["admissible"]
        },
        "declarations": source_statements,
    }

    determined = [cid for cid, result in claim_results.items() if result["is_determined"]]
    disputed = [cid for cid, result in claim_results.items() if result["status"] == DISPUTED]
    consensus = {
        cid: result["polarity"]
        for cid, result in claim_results.items()
        if result["is_determined"]
    }
    public_rules = [
        {
            "id": rule["id"],
            "premises": [list(fact) for fact in sorted(rule["premises"])],
            "conclusion": list(rule["conclusion"]),
        }
        for rule in claim_rules
    ]
    report = {
        "schema": "stix2.testimony-review/v1",
        "cost_metric": str(metric),
        "evidence_count": len(admissible_ids),
        "source_count": len({evidence_by_id[eid]["source_cluster"] for eid in admissible_ids}),
        "claim_count": len(claim_results),
        "source_groups": source_report,
        "sources": source_report,
        "version_groups": version_groups,
        "relationships": {
            "all": relationships,
            "applied_source_relationships": applied_relationships,
            "unknown": unknown_relationships,
            "ignored_relationships": unknown_relationships,
        },
        "unknown_relationships": unknown_relationships,
        "unknown_relations": unknown_relationships,
        "unrecognized_relationships": unknown_relationships,
        "rules": public_rules,
        "maximal_evidence_sets": maximal_sets,
        "all_maximal_evidence_sets": maximal_sets,
        "maximal_sets": maximal_sets,
        "coexisting_evidence_sets": maximal_sets,
        "optimal_evidence_sets": optimal_sets,
        "optimal_sets": optimal_sets,
        "evidence_sets": optimal_sets,
        "solutions": optimal_sets,
        "sets": optimal_sets,
        "tie": len(optimal_sets) > 1,
        "tied_conclusions": tied_conclusions,
        "alternative_conclusions": tied_conclusions,
        "optimal_conclusions": tied_conclusions,
        "claim_results": claim_results,
        "claims": claim_results,
        "conclusions": consensus,
        "consensus": consensus,
        "determined_claims": determined,
        "confirmed_claims": determined,
        "established_claims": determined,
        "disputed_claims": disputed,
        "disputed": disputed,
        "status": DISPUTED if disputed else (CONFIRMED if determined else UNDERDETERMINED),
        "verdict": DISPUTED if disputed else (CONFIRMED if determined else UNDERDETERMINED),
    }
    return Report(report)


def _resolve_versions(
    records: list[dict[str, Any]],
    *,
    include_superseded: bool,
    include_revoked: bool,
) -> tuple[list[dict[str, Any]], dict[str, str], set[int]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        record_id = _get(record, "id", "ref", default=_canonical_json(record))
        group = _get(
            record, "version_group", "series_id", "statement_id",
            "logical_id", "version_id", "version_of", default=str(record_id),
        )
        groups[str(group)].append(record)

    report_groups = []
    current_map: dict[str, str] = {}
    inadmissible: set[int] = set()
    for group, items in groups.items():
        ranked = sorted(items, key=_version_rank)
        latest_rank = _version_rank(ranked[-1])
        current = ranked[-1]
        current_id = str(_get(current, "id", "ref", default=_canonical_json(current)))
        revoked_ids = []
        for record in ranked:
            record_id = str(_get(record, "id", "ref", default=_canonical_json(record)))
            current_map[record_id] = current_id
            is_revoked = bool(_get(record, "revoked", default=False))
            superseded_by = _get(record, "superseded_by")
            is_old = _version_rank(record) < latest_rank
            if is_old and not include_superseded:
                inadmissible.add(id(record))
            if superseded_by and not include_superseded:
                inadmissible.add(id(record))
            if is_revoked:
                revoked_ids.append(record_id)
                if not include_revoked:
                    inadmissible.add(id(record))
        report_groups.append({
            "group": group,
            "versions": [str(_get(item, "id", "ref", default=_canonical_json(item))) for item in ranked],
            "current": current_id,
            "superseded": [
                str(_get(item, "id", "ref", default=_canonical_json(item)))
                for item in ranked
                if _version_rank(item) < latest_rank
            ],
            "revoked": revoked_ids,
        })
    return report_groups, current_map, inadmissible


def _build_evidence(
    *,
    primary_raw: list[dict[str, Any]],
    observation_raw: list[dict[str, Any]],
    record_assertions: dict[str, list[dict[str, Any]]],
    current_id_by_record: dict[str, str],
    upstream_edges: dict[str, set[str]],
    inadmissible: set[int],
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    evidence = []
    used_ids = set()
    observation_ids = {
        str(_get(item, "id", default=_canonical_json(item))) for item in observation_raw
    }
    for index, raw in enumerate(primary_raw):
        if id(raw) in inadmissible:
            continue
        base_id = str(_get(raw, "id", "ref", "_id", default=f"evidence-{index + 1}"))
        evidence_id = base_id
        if evidence_id in used_ids:
            rank = _version_rank(raw)[0]
            evidence_id = f"{base_id}#version-{'.'.join(map(str, rank)) or index + 1}"
        used_ids.add(evidence_id)
        assertions = [dict(item) for item in record_assertions.get(evidence_id, [])]
        upstream_refs = [
            str(ref)
            for ref in _as_list(_get(
                raw, "upstream_ref", "upstream", "upstream_observation_ref",
                "relays", "relay_ref", "based_on", "derived_from",
            ))
        ]
        upstream_refs.extend(upstream_edges.get(evidence_id, set()))
        if not assertions:
            visited = set()
            queue = list(upstream_refs)
            inherited_keys = set()
            while queue:
                ref = str(queue.pop(0))
                if ref in visited:
                    continue
                visited.add(ref)
                current_ref = current_id_by_record.get(ref, ref)
                inherited = record_assertions.get(current_ref) or record_assertions.get(ref, [])
                for assertion in inherited:
                    key = (assertion["claim_id"], assertion["value"])
                    if key not in inherited_keys:
                        inherited_keys.add(key)
                        assertions.append(dict(assertion))
                queue.extend(upstream_edges.get(current_ref, set()))
        source_refs = [
            str(ref)
            for ref in _as_list(_get(
                raw, "source_refs", "sources", "source", "source_ref",
                "collector", "collector_id", "collector_ref", "collected_by",
                "created_by_ref", "x_collector_ref", "x_source_ref",
                "apparent_source", "apparent_collector", "reported_collector",
            ))
        ]
        conflicts_with = [
            str(ref)
            for ref in _as_list(_get(raw, "conflicts_with", "incompatible_with", "contradicts"))
        ]
        explicit_cost = _get(raw, "cost", "rejection_cost", "penalty", default=_UNSET)
        cost = 1.0 if explicit_cost is _UNSET else float(explicit_cost)
        weight = float(_get(raw, "weight", "source_weight", default=1.0))
        admissible = True
        if not options.get("include_upstream", False) and evidence_id in observation_ids and primary_raw is not observation_raw:
            # Observations are supporting provenance unless they are the primary list.
            admissible = False
        evidence.append({
            "id": evidence_id,
            "assertions": assertions,
            "source_refs": source_refs,
            "upstream_refs": sorted(set(upstream_refs)),
            "conflicts_with": conflicts_with,
            "cost": cost,
            "cost_explicit": explicit_cost is not _UNSET,
            "weight": weight,
            "admissible": admissible,
            "raw": raw,
        })
    return evidence


def _normalize_rule(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    rule_id = str(_get(raw, "id", default=_canonical_json(raw)))
    premises_value = _get(raw, "if", "premise", "premises", "when", "antecedent")
    conclusion_value = _get(raw, "then", "conclusion", "consequent")
    if conclusion_value is None:
        return None
    premises = {_signed_fact(item) for item in _as_list(premises_value)}
    if isinstance(premises_value, (str, dict)):
        premises = {_signed_fact(premises_value)}
    return {
        "id": rule_id,
        "premises": premises,
        "conclusion": _signed_fact(conclusion_value),
    }


def _normalize_source_statements(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    ranked_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in raw_items:
        group = str(_get(raw, "id", "statement_id", "declaration_id", default=_canonical_json(raw)))
        ranked_groups[group].append(raw)

    for raw in raw_items:
        statement_type = str(_get(raw, "statement_type", "declaration_type", "type", default="")).lower()
        same_source_groups = []
        for group in _get(
            raw, "same_source_groups", "same_collector_groups",
            "same_source_sets", "clusters", default=[],
        ):
            same_source_groups.append([str(item) for item in _as_list(group)])
        same_source = _get(
            raw, "same_source", "same_source_as", "same_collector",
            "same_collector_as", "common_source", default=[],
        )
        if isinstance(same_source, bool) and same_source:
            sources = _source_statement_ids(raw)
            if sources:
                same_source_groups.append(sources)
        elif same_source:
            same_source_groups.append([str(item) for item in _as_list(same_source)])

        collector = _get(raw, "collector", "collector_id", "collector_ref")
        testimony_ids = [
            str(item)
            for item in _as_list(_get(raw, "testimony_ids", "evidence_ids", "object_refs"))
        ]
        if collector and testimony_ids:
            same_source_groups.append([str(collector), *testimony_ids])

        independent_groups = []
        for group in _get(raw, "independent_groups", default=[]):
            independent_groups.append([str(item) for item in _as_list(group)])
        for pair in _get(raw, "independent_pairs", "source_independence", default=[]):
            independent_groups.append([str(item) for item in _as_list(pair)])
        sources = _source_statement_ids(raw)
        if _truth_from_word(_get(raw, "independent", default=False)) is True or "independent" in statement_type:
            if sources:
                independent_groups.append(sources)
        independent_sources = _as_list(_get(raw, "independent_sources", "independent_source_refs"))
        if independent_sources:
            independent_groups.append([str(item) for item in independent_sources])

        status = "current"
        group = str(_get(raw, "id", "statement_id", default=""))
        if group in ranked_groups:
            ranked = sorted(ranked_groups[group], key=_version_rank)
            if raw is not ranked[-1]:
                status = "superseded"
        result.append(Report({
            "id": _get(raw, "id", "statement_id", "declaration_id"),
            "version": _get(raw, "version", "revision"),
            "status": status,
            "same_source_groups": same_source_groups,
            "independent_groups": independent_groups,
            "sources": sources,
        }))
    return result


def _source_statement_ids(raw: dict[str, Any]) -> list[str]:
    values = _as_list(_get(
        raw,
        "sources", "source_refs", "source_ids", "identities", "collectors",
        "members", "testimony_ids", "evidence_ids", "object_refs",
    ))
    values.extend(_as_list(_get(raw, "source_ref", "source_id", "collector", "collector_id")))
    return [str(value) for value in values if value is not None]


def _evaluate_set(
    selected: frozenset[str],
    evidence_by_id: dict[str, dict[str, Any]],
    rules: list[dict[str, Any]],
    explicit_conflicts: set[frozenset[str]],
) -> dict[str, Any] | None:
    for pair in explicit_conflicts:
        if len(pair & selected) == 2:
            return None
    values: dict[str, Any] = {}
    direct: dict[str, list[str]] = defaultdict(list)
    for evidence_id in selected:
        evidence = evidence_by_id[evidence_id]
        for conflict_ref in evidence["conflicts_with"]:
            if conflict_ref in selected:
                return None
        for assertion in evidence["assertions"]:
            claim_id = assertion["claim_id"]
            value = assertion["value"]
            if claim_id in values and values[claim_id] != value:
                return None
            values[claim_id] = value
            direct[claim_id].append(evidence_id)
    conclusions, facts, closure_conflict = _close_facts(values, rules)
    if closure_conflict:
        return None
    derived = sorted(
        f"{claim_id}={value}" if value is not True else claim_id
        for claim_id, value in facts
        if claim_id not in values or values.get(claim_id) != value
    )
    return {
        "values": values,
        "conclusions": conclusions,
        "direct": {key: sorted(value) for key, value in direct.items()},
        "derived": derived,
    }


def _build_set_info(
    selected: frozenset[str],
    evaluation: dict[str, Any],
    evidence_by_id: dict[str, dict[str, Any]],
    dsu: _DSU,
    all_endorsements: dict[tuple[str, str, Any], float],
    admissible_ids: list[str],
    options: dict[str, Any],
) -> dict[str, Any]:
    ids = sorted(selected)
    excluded = sorted(set(admissible_ids) - selected)
    represented = set()
    clusters = set()
    for evidence_id in ids:
        evidence = evidence_by_id[evidence_id]
        cluster = evidence["source_cluster"]
        clusters.add(cluster)
        for assertion in evidence["assertions"]:
            represented.add((cluster, assertion["claim_id"], assertion["value"]))
    source_cost = sum(
        weight for key, weight in all_endorsements.items() if key not in represented
    )
    exclusion_cost = sum(evidence_by_id[eid]["cost"] for eid in excluded)
    included_cost = sum(evidence_by_id[eid]["cost"] for eid in ids)
    source_votes = defaultdict(lambda: defaultdict(list))
    for evidence_id in ids:
        evidence = evidence_by_id[evidence_id]
        for assertion in evidence["assertions"]:
            source_votes[assertion["claim_id"]][assertion["value"]].append(
                evidence["source_cluster"],
            )
    serialized_votes = {}
    for claim_id, values in source_votes.items():
        serialized_votes[claim_id] = {
            str(value): sorted(set(clusters_for_value))
            for value, clusters_for_value in values.items()
        }
    return {
        "evidence_ids": ids,
        "ids": ids,
        "evidence": ids,
        "item_ids": ids,
        "items": ids,
        "excluded_ids": excluded,
        "size": len(ids),
        "source_clusters": sorted(clusters),
        "independent_source_count": len(clusters),
        "source_cost": source_cost,
        "independent_source_cost": source_cost,
        "exclusion_cost": exclusion_cost,
        "item_cost": exclusion_cost,
        "excluded_cost": exclusion_cost,
        "included_cost": included_cost,
        "set_cost": included_cost,
        "source_votes": serialized_votes,
        "conclusions": evaluation["conclusions"],
        "claims": evaluation["conclusions"],
        "direct_evidence": evaluation["direct"],
        "derived_claims": evaluation["derived"],
    }


def _summarize_claims(
    optimal_sets: list[dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    claim_ids = set()
    for evidence in evidence_by_id.values():
        for assertion in evidence["assertions"]:
            claim_ids.add(assertion["claim_id"])
    for set_info in optimal_sets:
        claim_ids.update(set_info["conclusions"])

    results = {}
    for claim_id in sorted(claim_ids):
        alternatives = []
        values = []
        for index, set_info in enumerate(optimal_sets):
            value = set_info["conclusions"].get(claim_id, _UNSET)
            alternatives.append({
                "set_index": index,
                "evidence_ids": set_info["evidence_ids"],
                "value": None if value is _UNSET else value,
                "present": value is not _UNSET,
            })
            if value is not _UNSET:
                values.append(value)
        distinct = set(values)
        if values and len(distinct) == 1:
            polarity = values[0]
            status = CONFIRMED if polarity is True else REFUTED
            determined = True
        elif any(value is True for value in values) and any(value is False for value in values):
            polarity = None
            status = DISPUTED
            determined = False
        elif len(distinct) > 1:
            polarity = None
            status = DISPUTED
            determined = False
        else:
            polarity = None
            status = UNDERDETERMINED
            determined = False
        results[claim_id] = Report({
            "status": status,
            "verdict": status,
            "state": status,
            "decision": status,
            "is_determined": determined,
            "determined": determined,
            "is_disputed": status == DISPUTED,
            "disputed": status == DISPUTED,
            "polarity": polarity,
            "values": sorted(distinct, key=str),
            "alternatives": alternatives,
        })
    return results


def maximal_coexisting_evidence_sets(*args: Any, **kwargs: Any) -> list[Report]:
    """Return all inclusion-maximal coexisting evidence sets."""
    return review_testimony(*args, **kwargs)["maximal_evidence_sets"]


def maximum_coexisting_evidence_sets(*args: Any, **kwargs: Any) -> list[Report]:
    """Return cost-optimal coexisting evidence sets."""
    return review_testimony(*args, **kwargs)["optimal_evidence_sets"]


generate_maximal_coexisting_evidence_sets = maximal_coexisting_evidence_sets
generate_maximal_evidence_sets = maximal_coexisting_evidence_sets
find_maximal_evidence_sets = maximal_coexisting_evidence_sets
maximum_evidence_sets = maximum_coexisting_evidence_sets
max_coexisting_evidence_sets = maximum_coexisting_evidence_sets
generate_max_coexisting_evidence_sets = maximum_coexisting_evidence_sets
find_optimal_evidence_sets = maximum_coexisting_evidence_sets
select_evidence_sets = maximum_coexisting_evidence_sets
review_testimonies = review_testimony
testimony_review = review_testimony
local_testimony_review = review_testimony
testimony_review_process = review_testimony
review_process = review_testimony
reconcile_testimony = review_testimony
reconcile_testimonies = review_testimony
reconcile = review_testimony
review = review_testimony
review_bundle = review_testimony
review_stix_bundle = review_testimony
reconcile_bundle = review_testimony

LocalTestimonyReview = TestimonyReview
EvidenceReview = TestimonyReview
TestimonyReviewer = TestimonyReview


HEARSAY_CLAIM_ID = "campaign-039-uses-resolver"
HEARSAY_CLAIM_LABEL = "Campaign 039 uses the disputed resolver infrastructure"


def hearsay_fixture(*, merged: bool = True) -> Report:
    """Two relay votes and one independent rebuttal, before/after merging."""
    t1 = "testimony--relay-alpha"
    t2 = "testimony--relay-beta"
    t3 = "testimony--independent-rebuttal"
    obs1 = "observed-data--upstream-alpha"
    obs2 = "observed-data--upstream-beta"
    declaration = "source-declaration--hearsay-039"
    payload = {
        "name": "two-relay-votes-and-one-independent-rebuttal",
        "claim_id": HEARSAY_CLAIM_ID,
        "claim_label": HEARSAY_CLAIM_LABEL,
        "upstream_observations": [
            {
                "id": obs1,
                "type": "observed-data",
                "modified": "2026-11-21T08:00:00Z",
                "claim_id": HEARSAY_CLAIM_ID,
                "stance": "supports",
                "upstream_collector": "upstream-sensor-alpha",
            },
            {
                "id": obs2,
                "type": "observed-data",
                "modified": "2026-11-21T08:05:00Z",
                "claim_id": HEARSAY_CLAIM_ID,
                "stance": "supports",
                "upstream_collector": "upstream-sensor-beta",
            },
        ],
        "testimonies": [
            {
                "id": t1,
                "type": "opinion",
                "opinion": "agree",
                "upstream_ref": obs1,
                "apparent_source": "stringer--alpha",
            },
            {
                "id": t2,
                "type": "opinion",
                "opinion": "strongly-agree",
                "upstream_ref": obs2,
                "apparent_source": "stringer--beta",
            },
            {
                "id": t3,
                "type": "opinion",
                "opinion": "strongly-disagree",
                "claim_id": HEARSAY_CLAIM_ID,
                "source_ref": "identity--independent-observer",
            },
        ],
        "relationships": [
            {
                "id": "relationship--relay-alpha",
                "type": "relationship",
                "relationship_type": "relays",
                "source_ref": t1,
                "target_ref": obs1,
            },
            {
                "id": "relationship--relay-beta",
                "type": "relationship",
                "relationship_type": "relays",
                "source_ref": t2,
                "target_ref": obs2,
            },
            {
                "id": "relationship--unknown-display-name-link",
                "type": "relationship",
                "relationship_type": "display-name-resembles",
                "source_ref": t1,
                "target_ref": t2,
            },
        ],
        "independent_source_statements": [
            {
                "id": declaration,
                "version": 1,
                "modified": "2026-11-20T10:00:00Z",
                "statement_type": "independent-source-declaration",
                "sources": [t1, t2, t3],
                "independent": True,
            },
        ],
    }
    if merged:
        payload["relationships"].append({
            "id": "relationship--confirmed-same-collector",
            "type": "relationship",
            "relationship_type": "same-collector-as",
            "source_ref": t1,
            "target_ref": t2,
            "x_confirmation": "collector-ledger-039",
        })
        payload["independent_source_statements"].append({
            "id": declaration,
            "version": 2,
            "modified": "2026-11-22T10:00:00Z",
            "statement_type": "source-revision",
            "same_source_groups": [[t1, t2]],
            "independent_groups": [[t3]],
        })
    return Report(payload)


small_fixture = hearsay_fixture


def hearsay_demo() -> Report:
    """Compare the apparently independent and source-merged reviews."""
    before = review_testimony(hearsay_fixture(merged=False))
    after = review_testimony(hearsay_fixture(merged=True))
    return Report({
        "claim_id": HEARSAY_CLAIM_ID,
        "claim_label": HEARSAY_CLAIM_LABEL,
        "fixture": hearsay_fixture(merged=True),
        "before_merge": before,
        "apparent": before,
        "after_merge": after,
        "reviewed": after,
        "transition": {
            "claim_id": HEARSAY_CLAIM_ID,
            "claim_label": HEARSAY_CLAIM_LABEL,
            "before_status": before["claims"][HEARSAY_CLAIM_ID]["status"],
            "after_status": after["claims"][HEARSAY_CLAIM_ID]["status"],
            "changed_from": "confirmed",
            "changed_to": "disputed",
        },
    })


demo_review = hearsay_demo


def _main() -> int:
    import sys

    if len(sys.argv) == 2 and sys.argv[1] == "--demo":
        print(json.dumps(hearsay_demo(), indent=2, ensure_ascii=False, default=str))
        return 0
    if len(sys.argv) != 2:
        print("usage: python -m stix2.testimony_review [--demo|FIXTURE.json]")
        return 2
    report = review_testimony(sys.argv[1])
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
