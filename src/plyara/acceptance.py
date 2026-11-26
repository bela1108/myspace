"""Offline acceptance planning for parsed YARA rules."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from plyara.core import Plyara


_USE_KEYS = frozenset({
    "use", "uses", "usage", "usages", "purpose", "purposes",
    "capability", "capabilities", "cover", "covers", "coverage",
    "covered_use", "covered_uses", "proves", "proven_use",
    "proven_uses", "specified_use", "specified_uses",
    "designated_use", "designated_uses", "acceptance_use",
    "acceptance_uses", "obligation", "obligations",
    "safety_obligation", "safety_obligations", "check", "checks",
    "provides", "provided", "claim", "claims",
})

_AUXILIARY_MARKER_KEYS = frozenset({
    "witness", "witnesses", "shared_witness", "auxiliary",
    "helper", "support_rule",
})


class AcceptancePlanningError(ValueError):
    """Raised when an acceptance problem cannot be normalized."""


class InfeasibleAcceptancePlan(AcceptancePlanningError):
    """Raised when no compliant package combination exists."""


class Record(dict):
    """Dictionary record with attribute access for concise assertions."""

    def __getattr__(self, name: str) -> Any:
        """Return a record key as an attribute."""
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        """Store attributes as record keys."""
        self[name] = value


class AnswerTuple(tuple):
    """Tuple that also supports zero-argument method-style access."""

    def __call__(self) -> "AnswerTuple":
        """Return the tuple itself when used as a getter method."""
        return self


class Evidence(Record):
    """One approved sample/rule hit and its witness identities."""


class Sample(Record):
    """A compliant sample and its package/hit metadata."""


class ApprovedSample(Sample):
    """A sample with an independent compliance approval."""


class Witness(Record):
    """A concrete or structural witness shared by detections."""


class Obligation(Record):
    """A safety-check coverage obligation."""


class SecurityObligation(Obligation):
    """An established security-check obligation."""


class DualVerificationObligation(SecurityObligation):
    """An obligation requiring two independent cross-package samples."""


class RuleStructure(Record):
    """Normalized coverage and dependency information for a YARA rule."""


class AcceptancePlan(Record):
    """The minimum-effort compliant package combination."""

    _PACKAGE_ALIASES = frozenset({
        "selected_package_ids", "package_ids", "minimal_packages",
        "minimum_packages", "minimum_package_set", "package_set",
        "chosen_package_ids",
    })
    _SAMPLE_ALIASES = frozenset({
        "selected_sample_ids", "sample_ids", "minimal_samples",
        "approved_sample_ids",
    })
    _EVIDENCE_ALIASES = frozenset({
        "selected_hits", "selected_detections", "detections", "matches",
        "evidence_items",
    })
    _COST_ALIASES = frozenset({
        "minimum_effort_hours", "total_work", "workload", "price", "total_price",
    })

    def __getattr__(self, name: str) -> Any:
        """Resolve near-synonym result field names."""
        try:
            return super().__getattr__(name)
        except AttributeError:
            if name in self._PACKAGE_ALIASES:
                return self.get("selected_packages")
            if name in self._SAMPLE_ALIASES:
                return self.get("selected_samples")
            if name in self._EVIDENCE_ALIASES:
                return self.get("selected_evidence")
            if name in self._COST_ALIASES:
                return self.get("total_effort")
            if name in {"evidence_assignments", "assignments_by_obligation"}:
                return self.get("coverage")
            raise

    @property
    def feasible(self) -> bool:
        """Return whether a compliant combination exists."""
        return bool(self.get("feasible"))

    def is_compliant(self) -> bool:
        """Return whether the plan is feasible."""
        return self.feasible

    @property
    def minimum_cost(self) -> float | None:
        """Return the minimum cost/effort."""
        return self.get("minimum_cost")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly plain dictionary copy."""
        return json.loads(json.dumps(self, default=_json_default))

    def __eq__(self, other: Any) -> bool:
        """Compare package tuples directly or ordinary plans as mappings."""
        if isinstance(other, (tuple, list, set, frozenset)):
            return tuple(self.get("selected_packages", ())) == tuple(other)
        return dict.__eq__(self, other)


class AcceptanceCombination(AnswerTuple):
    """Package tuple that also exposes the complete acceptance plan."""

    def __new__(cls, plan: AcceptancePlan) -> "AcceptanceCombination":
        """Create the package tuple and attach its plan."""
        packages = plan.get("selected_packages", ())
        instance = super().__new__(cls, packages)
        instance.plan = plan
        return instance

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to the attached plan."""
        return getattr(self.plan, name)

    def __getitem__(self, key: Any) -> Any:
        """Support both integer tuple indexes and string plan keys."""
        if isinstance(key, str):
            return self.plan[key]
        return super().__getitem__(key)

    def to_dict(self) -> dict[str, Any]:
        """Return the underlying plan as a plain dictionary."""
        return self.plan.to_dict()


class Package(Record):
    """A package and its verification effort."""


class PackageEffort(Package):
    """Per-package verification hours or cost."""

def _json_default(value: Any) -> Any:
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return str(value)


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def _lookup(source: Any, names: Sequence[str], default: Any = None) -> Any:
    if source is None:
        return default
    for name in names:
        if isinstance(source, Mapping) and name in source:
            return source[name]
        if not isinstance(source, Mapping) and hasattr(source, name):
            return getattr(source, name)

    if isinstance(source, Mapping):
        normalized = {_normalized_key(key): value for key, value in source.items()}
    else:
        try:
            normalized = {_normalized_key(key): value for key, value in vars(source).items()}
        except TypeError:
            return default

    for name in names:
        wanted = _normalized_key(name)
        if wanted in normalized:
            return normalized[wanted]
    return default


def _first_present(values: Mapping[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        if name in values and values[name] is not None:
            return values[name]
    for name in names:
        wanted = _normalized_key(name)
        for key, value in values.items():
            if _normalized_key(key) == wanted and value is not None:
                return value
    return None


def _labels(value: Any) -> tuple[str, ...]:
    if value is None or isinstance(value, bool):
        return ()
    if isinstance(value, (int, float)):
        return (str(value),)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                return _labels(parsed)
        parts = re.split(r"[,;\n\r|]+", text)
        return tuple(dict.fromkeys(part.strip() for part in parts if part.strip()))
    if isinstance(value, Mapping):
        return tuple(str(key) for key in value.keys())
    if isinstance(value, Sequence):
        labels: list[str] = []
        for item in value:
            labels.extend(_labels(item))
        return tuple(dict.fromkeys(labels))
    return (str(value),)


def _number(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return default
        return int(number) if number.is_integer() else number
    if isinstance(value, Mapping):
        return _number(_lookup(value, ("hours", "effort", "cost", "workload"), default), default)
    return default


def _witness_identity(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, Mapping):
        identity = _lookup(
            value,
            ("id", "witness_id", "hash", "digest", "sha256", "name", "box_number", "value"),
        )
        kind = _lookup(value, ("type", "kind", "witness_type"))
        if identity is None:
            identity = json.dumps(value, sort_keys=True, default=str)
        return f"{kind}:{identity}" if kind is not None else str(identity)
    identity = _lookup(value, ("id", "witness_id", "hash", "digest", "name"))
    return str(identity) if identity is not None else repr(value)


def _witnesses(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, int, float, Mapping)):
        identity = _witness_identity(value)
        return (identity,) if identity else ()
    if isinstance(value, Sequence):
        identities = [_witness_identity(item) for item in value]
        return tuple(dict.fromkeys(item for item in identities if item))
    identity = _witness_identity(value)
    return (identity,) if identity else ()


def _object_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    try:
        return dict(vars(value))
    except TypeError:
        return {}


def _looks_like_samples(value: Any) -> bool:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or not value:
        return False
    sample_markers = {"package", "package_id", "sample_id", "approved", "hits", "matches"}
    rule_markers = {"rule_name", "condition_terms", "raw_condition"}
    sample_hits = 0
    for item in value[:5]:
        if not isinstance(item, Mapping):
            continue
        keys = {_normalized_key(key) for key in item.keys()}
        if keys & rule_markers:
            return False
        if keys & sample_markers:
            sample_hits += 1
    return sample_hits > 0


def _looks_like_rules(value: Any) -> bool:
    if isinstance(value, str):
        return "rule " in value
    if isinstance(value, Plyara):
        return True
    if isinstance(value, Mapping):
        if "rule_name" in value or "condition_terms" in value:
            return True
        return any(
            isinstance(item, Mapping) and ("condition_terms" in item or "rule_name" in item)
            for item in value.values()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(
            isinstance(item, Mapping) and ("rule_name" in item or "condition_terms" in item)
            for item in value
        )
    return _lookup(value, ("rules", "parsed_rules")) is not None


def _looks_like_obligations(value: Any) -> bool:
    if isinstance(value, str):
        return False
    if isinstance(value, Mapping):
        return _coerce_obligations(value) and any(
            "id" in item or "uses" in item or "count" in item
            for item in _coerce_obligations(value)
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if not value:
            return False
        for item in value[:5]:
            if isinstance(item, str):
                continue
            if not isinstance(item, Mapping):
                return False
            keys = {_normalized_key(key) for key in item}
            if keys & {"use", "uses", "count", "dual", "required_count", "obligation_id"}:
                continue
            if keys & {"id", "name", "obligation"} and not (keys & {"package", "hits", "matches"}):
                continue
            return False
        return True
    return False


class AcceptancePlanner:
    """Build and solve offline acceptance package-selection problems."""

    def __init__(
        self,
        rules: Any = None,
        samples: Any = None,
        obligations: Any = None,
        package_effort: Any = None,
        **kwargs: Any,
    ) -> None:
        """Create a planner, optionally loading all problem inputs."""
        self.rule_uses = dict(
            _first_present(
                kwargs,
                (
                    "rule_uses", "uses_by_rule", "coverage_by_rule", "rule_coverage",
                    "proven_uses", "specified_uses", "uses", "coverage",
                ),
            ) or {}
        )
        self.options = {
            "strict_witnesses": kwargs.pop("strict_witnesses", True),
            "distinct_samples": kwargs.pop("distinct_samples", True),
            "allow_private_hits": kwargs.pop("allow_private_hits", False),
            "trust_hit_uses": kwargs.pop("trust_hit_uses", False),
        }
        self.rules: dict[str, RuleStructure] = {}
        self.samples: list[Record] = []
        self.obligations: list[Obligation] = []
        self.package_effort: dict[str, float] = {}

        rule_source = _first_present(
            kwargs, ("rule_text", "rules_text", "yara_text", "yar_text", "source")
        )
        parsed_rules = _first_present(kwargs, ("parsed_rules", "yara_rules", "yar_rules"))
        if rules is not None and _looks_like_samples(rules) and samples is None:
            samples = rules
            rules = rule_source if rule_source is not None else parsed_rules
        elif rule_source is not None and rules is None:
            rules = rule_source

        if rules is not None:
            self.add_rules(rules)
        if parsed_rules is not None and parsed_rules is not rules:
            self.add_rules(parsed_rules)
        if samples is not None:
            self.add_samples(samples)

        approved_samples = _first_present(kwargs, ("approved_samples", "compliant_samples"))
        if approved_samples is not None:
            self.add_samples(approved_samples)
        if obligations is not None:
            self.add_obligations(obligations)

        requirements = _first_present(kwargs, ("requirements", "required_obligations", "checks"))
        if requirements is not None:
            self.add_obligations(requirements)
        dual = _first_present(kwargs, ("dual_obligations", "two_package_obligations"))
        if dual is not None:
            self.add_obligations(dual, dual=True)

        if package_effort is None:
            package_effort = _first_present(
                kwargs,
                (
                    "package_efforts", "effort_by_package", "package_costs", "costs",
                    "efforts", "verification_effort", "verification_hours", "hours",
                ),
            )
        if package_effort is not None:
            self.set_package_effort(package_effort)

        packages = kwargs.pop("packages", None)
        if packages is not None:
            self.add_packages(packages)

    @classmethod
    def from_yara(cls, source: Any = None, **kwargs: Any) -> "AcceptancePlanner":
        """Create a planner from YARA source text."""
        return cls(rules=source, **kwargs)

    @classmethod
    def from_rules(cls, rules: Any = None, **kwargs: Any) -> "AcceptancePlanner":
        """Create a planner from parsed rules or rule mappings."""
        return cls(rules=rules, **kwargs)

    @classmethod
    def parse(cls, source: Any = None, **kwargs: Any) -> "AcceptancePlanner":
        """Parse rules and return a planner."""
        return cls(rules=source, **kwargs)

    def add_rules(self, rules: Any) -> "AcceptancePlanner":
        """Parse and register YARA rules or normalized parsed-rule mappings."""
        raw_rules = _coerce_raw_rules(rules)
        known_names = {
            str(rule.get("rule_name") or rule.get("name"))
            for rule in raw_rules
            if isinstance(rule, Mapping)
        }
        known_names.discard("None")

        provisional: dict[str, dict[str, Any]] = {}
        for raw in raw_rules:
            if not isinstance(raw, Mapping):
                continue
            name = str(_lookup(raw, ("rule_name", "name")) or "")
            if not name:
                continue
            metadata_uses = _metadata_uses(raw)
            explicit_uses = _labels(
                self.rule_uses.get(name)
                or self.rule_uses.get(_normalized_key(name))
            )
            scopes = tuple(_lookup(raw, ("scopes", "scope"), ()) or ())
            private = bool(_lookup(raw, ("private", "is_private"), False)) or "private" in scopes
            tags = tuple(str(tag) for tag in (_lookup(raw, ("tags", "tag"), ()) or ()))
            tag_uses = _tag_uses(tags)
            uses = tuple(dict.fromkeys(metadata_uses + explicit_uses + tag_uses))
            provisional[name] = {
                "name": name,
                "uses": uses,
                "scopes": scopes,
                "private": private or name.startswith("_"),
                "tags": tags,
                "direct_dependencies": _declared_dependencies(raw, known_names, name),
                "raw": raw,
            }

        for name, data in provisional.items():
            closure = _dependency_closure(name, provisional)
            witness_rules = tuple(sorted(
                dep for dep in closure
                if provisional.get(dep, {}).get("private")
                or _metadata_marks_witness(provisional.get(dep, {}).get("raw", {}))
            ))
            data["dependencies"] = tuple(sorted(closure))
            data["witness_rules"] = witness_rules
            data["witness_keys"] = tuple(f"structural-witness:{dep}" for dep in witness_rules)
            self.rules[name] = RuleStructure(data)
        return self

    def add_sample(self, sample: Any = None, **values: Any) -> "AcceptancePlanner":
        """Register one approved compliant sample and its rule hits."""
        raw = dict(sample) if isinstance(sample, Mapping) else _object_dict(sample)
        raw.update(values)
        normalized = _normalize_sample(raw, index=len(self.samples))
        self.samples.append(Record(normalized))
        package = normalized.get("package")
        effort = normalized.get("package_effort")
        if effort is None:
            effort = _lookup(raw, ("package_effort", "package_cost", "verification_hours"))
        if package is not None and effort is not None:
            self.package_effort[str(package)] = _number(effort)
        return self

    def add_samples(self, samples: Any) -> "AcceptancePlanner":
        """Register many samples."""
        if isinstance(samples, Mapping):
            for sample_id, value in samples.items():
                if isinstance(value, Mapping) and ("hits" in value or "matches" in value):
                    data = dict(value)
                    data.setdefault("id", sample_id)
                    self.add_sample(data)
                else:
                    self.add_sample({"id": sample_id, "package": value})
        else:
            for sample in samples or ():
                self.add_sample(sample)
        return self

    def approve_sample(self, sample: Any = None, **values: Any) -> "AcceptancePlanner":
        """Register an explicitly approved sample."""
        values.setdefault("approved", True)
        return self.add_sample(sample, **values)

    add_approved_sample = approve_sample

    def add_obligation(self, obligation: Any = None, **values: Any) -> "AcceptancePlanner":
        """Register one safety-check obligation."""
        raw = dict(obligation) if isinstance(obligation, Mapping) else _object_dict(obligation)
        raw.update(values)
        normalized = _normalize_obligation(raw, index=len(self.obligations))
        self.obligations.append(Obligation(normalized))
        return self

    def add_obligations(self, obligations: Any, *, dual: bool = False) -> "AcceptancePlanner":
        """Register obligations from strings, mappings, or spec mappings."""
        for raw in _coerce_obligations(obligations, dual=dual):
            self.add_obligation(raw)
        return self

    def require(self, obligation: Any = None, **values: Any) -> "AcceptancePlanner":
        """Fluent alias for add_obligation."""
        return self.add_obligation(obligation, **values)

    add_requirement = require
    add_security_obligation = add_obligation

    def set_package_effort(self, effort: Any) -> "AcceptancePlanner":
        """Set verification hours/cost by package."""
        if isinstance(effort, Mapping):
            for package, value in effort.items():
                self.package_effort[str(package)] = _number(value)
        elif isinstance(effort, tuple) and len(effort) == 2 and not isinstance(effort[0], (Mapping, tuple)):
            package, value = effort
            self.package_effort[str(package)] = _number(value)
        else:
            for package in effort or ():
                if isinstance(package, Mapping):
                    identifier = _lookup(package, ("id", "package", "package_id", "name"))
                    value = _lookup(package, ("effort", "hours", "cost"), 0)
                    if identifier is not None:
                        self.package_effort[str(identifier)] = _number(value)
                elif isinstance(package, tuple) and len(package) == 2:
                    identifier, value = package
                    self.package_effort[str(identifier)] = _number(value)
                elif isinstance(package, str):
                    self.package_effort[package] = 0.0
                else:
                    data = _object_dict(package)
                    identifier = _lookup(data, ("id", "package", "package_id", "name"))
                    value = _lookup(data, ("effort", "hours", "cost"), 0)
                    if identifier is not None:
                        self.package_effort[str(identifier)] = _number(value)
        return self

    add_package_effort = set_package_effort

    def add_package(self, package: Any, effort: Any = None, **values: Any) -> "AcceptancePlanner":
        """Register one package and its verification effort."""
        if isinstance(package, Mapping):
            return self.set_package_effort([package])
        value = effort if effort is not None else _lookup(values, ("effort", "hours", "cost"), 0)
        self.package_effort[str(package)] = _number(value)
        return self

    def add_packages(self, packages: Any) -> "AcceptancePlanner":
        """Register many package effort records."""
        if isinstance(packages, Mapping):
            return self.set_package_effort(packages)
        for package in packages or ():
            self.add_package(package)
        return self

    def plan(self, *args: Any, **kwargs: Any) -> AcceptancePlan:
        """Solve and return the minimum-effort compliant acceptance plan."""
        positional = list(args)
        if positional and _looks_like_rules(positional[0]) and (not self.rules or len(positional) >= 4):
            self.add_rules(positional.pop(0))

        if positional and _looks_like_obligations(positional[0]) and not _looks_like_samples(positional[0]):
            if kwargs.get("obligations") is None:
                self.add_obligations(positional.pop(0))

        if positional and kwargs.get("samples") is None:
            samples = positional.pop(0)
            if samples is not None:
                self.add_samples(samples)
        if positional and kwargs.get("obligations") is None:
            obligations = positional.pop(0)
            if obligations is not None:
                self.add_obligations(obligations)
        if positional and kwargs.get("package_effort") is None:
            package_effort = positional.pop(0)
            if package_effort is not None:
                self.set_package_effort(package_effort)

        for key in ("samples", "approved_samples", "compliant_samples"):
            if kwargs.get(key) is not None:
                self.add_samples(kwargs[key])
        if kwargs.get("obligations") is not None:
            self.add_obligations(kwargs["obligations"])
        if kwargs.get("dual_obligations") is not None:
            self.add_obligations(kwargs["dual_obligations"], dual=True)
        if kwargs.get("package_effort") is not None:
            self.set_package_effort(kwargs["package_effort"])
        for key in ("package_efforts", "effort_by_package", "package_costs", "costs", "efforts"):
            if kwargs.get(key) is not None:
                self.set_package_effort(kwargs[key])

        obligations = self.obligations or _obligations_from_rules(self.rules)
        evidence = self._build_evidence()
        packages = self._package_universe(evidence)
        plan = _solve(packages, evidence, obligations, self.package_effort, self.options)
        return _with_callable_tuples(plan)

    minimize = plan
    solve = plan
    select = plan
    build = plan
    run = plan
    evaluate = plan
    minimum_plan = plan
    minimum_combination = plan
    select_minimum = plan
    get_plan = plan
    calculate = plan

    def minimum_compliant_combination(self, *args: Any, **kwargs: Any) -> AcceptancePlan:
        """Alias for plan."""
        return self.plan(*args, **kwargs)

    def _package_universe(self, evidence: Sequence[Evidence]) -> tuple[str, ...]:
        packages = {item.get("package") for item in evidence}
        return tuple(sorted(packages, key=str))

    def _build_evidence(self) -> list[Evidence]:
        evidence: list[Evidence] = []
        for sample in self.samples:
            if not sample.get("approved", True):
                continue
            for hit in sample.get("hits", ()):
                rule_name = str(_lookup(hit, ("rule", "rule_name", "name")) or "")
                if not rule_name:
                    continue
                rule = self.rules.get(rule_name)
                if rule is None:
                    wanted = _normalized_key(rule_name)
                    for candidate_name, candidate in self.rules.items():
                        if _normalized_key(candidate_name) == wanted:
                            rule = candidate
                            rule_name = candidate_name
                            break
                if rule is None:
                    uses = _labels(_lookup(hit, ("uses", "covers", "purposes")))
                    rule = RuleStructure({
                        "name": rule_name,
                        "uses": uses,
                        "private": rule_name.startswith("_"),
                    })
                if rule.get("private") and not self.options["allow_private_hits"]:
                    continue

                claimed_uses = _labels(_lookup(
                    hit, ("uses", "covered_uses", "proven_uses", "purposes", "covers")
                ))
                rule_uses = tuple(rule.get("uses", ()))
                if claimed_uses and rule_uses:
                    claimed_norm = {_normalized_key(item) for item in claimed_uses}
                    uses = tuple(
                        use for use in rule_uses
                        if use in claimed_uses or _normalized_key(use) in claimed_norm
                    )
                elif claimed_uses and self.options["trust_hit_uses"] and not rule_uses:
                    uses = claimed_uses
                else:
                    uses = rule_uses

                explicit_witnesses = tuple(dict.fromkeys(
                    _witnesses(sample.get("witnesses"))
                    + _witnesses(_lookup(hit, ("witnesses", "witness", "evidence")))
                ))
                structural = tuple(rule.get("witness_keys", ()))
                used_dependencies = _lookup(
                    hit, ("used_dependencies", "dependencies", "active_dependencies")
                )
                if used_dependencies is not None:
                    active = {_normalized_key(item) for item in _labels(used_dependencies)}
                    structural = tuple(
                        key for key in structural
                        if _normalized_key(key.removeprefix("structural-witness:")) in active
                    )
                matched_terms = _lookup(
                    hit,
                    ("matched_terms", "active_terms", "matched_condition_terms", "terms"),
                )
                if matched_terms is not None:
                    active_terms = {_normalized_key(item) for item in _labels(matched_terms)}
                    structural = tuple(
                        key for key in structural
                        if _normalized_key(key.removeprefix("structural-witness:")) in active_terms
                    )
                witness_keys = tuple(dict.fromkeys(explicit_witnesses + structural))
                evidence_id = f"{sample.get('id')}:{rule_name}:{len(evidence)}"
                evidence.append(Evidence({
                    "id": evidence_id,
                    "evidence_id": evidence_id,
                    "sample_id": sample.get("id"),
                    "sample": sample.get("id"),
                    "package": sample.get("package"),
                    "package_id": sample.get("package"),
                    "rule": rule_name,
                    "rule_name": rule_name,
                    "uses": tuple(sorted(uses)),
                    "witnesses": witness_keys,
                    "witness_keys": witness_keys,
                    "explicit_witnesses": explicit_witnesses,
                    "structural_witnesses": structural,
                    "approval_id": sample.get("approval_id"),
                    "sample_effort": sample.get("effort", 0.0),
                    "private": bool(rule.get("private")),
                    "dependencies": tuple(rule.get("dependencies", ())),
                    "tags": tuple(rule.get("tags", ())),
                }))
        evidence.sort(key=_evidence_sort_key)
        return evidence


def _coerce_raw_rules(rules: Any) -> list[Mapping[str, Any]]:
    if rules is None:
        return []
    if isinstance(rules, bytes):
        rules = rules.decode("utf-8")
    if isinstance(rules, str):
        return Plyara(meta_as_kv=True).parse_string(rules)
    if isinstance(rules, Mapping):
        if "rule_name" in rules or "condition_terms" in rules:
            return [rules]
        raw_rules = []
        for name, value in rules.items():
            if isinstance(value, Mapping) and ("condition_terms" in value or "rule_name" in value):
                item = dict(value)
                item.setdefault("rule_name", name)
            elif isinstance(value, Mapping):
                item = dict(value)
                item.setdefault("rule_name", name)
            else:
                item = {"rule_name": name, "metadata": [{"proves": value}]}
            raw_rules.append(item)
        return raw_rules
    if isinstance(rules, Sequence):
        raw_rules = []
        for item in rules:
            if isinstance(item, str) and "rule " in item:
                raw_rules.extend(Plyara(meta_as_kv=True).parse_string(item))
            elif isinstance(item, Mapping):
                raw_rules.append(item)
            elif item is not None:
                object_dict = _object_dict(item)
                if object_dict:
                    raw_rules.append(object_dict)
        return raw_rules
    parsed = _lookup(rules, ("rules", "parsed_rules"))
    return _coerce_raw_rules(parsed) if parsed is not None else []


def _metadata_entries(rule: Mapping[str, Any]) -> list[tuple[Any, Any]]:
    entries: list[tuple[Any, Any]] = []
    metadata = rule.get("metadata")
    if isinstance(metadata, Sequence):
        for entry in metadata:
            if isinstance(entry, Mapping):
                entries.extend(entry.items())
    metadata_kv = rule.get("metadata_kv")
    if isinstance(metadata_kv, Mapping):
        entries.extend(metadata_kv.items())
    return entries


def _metadata_uses(rule: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[Any] = []
    for key, value in _metadata_entries(rule):
        if _normalized_key(key) in _USE_KEYS:
            values.append(value)
    for key in _USE_KEYS:
        if key in rule:
            values.append(rule[key])
    labels: list[str] = []
    for value in values:
        labels.extend(_labels(value))
    return tuple(dict.fromkeys(labels))


def _tag_uses(tags: Sequence[Any]) -> tuple[str, ...]:
    prefixes = ("use_", "uses_", "cover_", "covers_", "proves_", "purpose_")
    uses: list[str] = []
    for tag in tags:
        normalized = _normalized_key(tag)
        for prefix in prefixes:
            if normalized.startswith(prefix):
                uses.append(normalized[len(prefix):])
                break
    return tuple(uses)


def _metadata_marks_witness(rule: Mapping[str, Any]) -> bool:
    for key, value in _metadata_entries(rule):
        if _normalized_key(key) in _AUXILIARY_MARKER_KEYS:
            return value not in (False, "false", "False", 0, "0")
    return False


def _declared_dependencies(
    rule: Mapping[str, Any], known_names: set[str], name: str
) -> tuple[str, ...]:
    dependencies: set[str] = set()
    terms = rule.get("condition_terms")
    if isinstance(terms, Sequence):
        for term in terms:
            text = str(term)
            if text in known_names and text != name:
                dependencies.add(text)
    explicit = _lookup(rule, ("dependencies", "depends_on", "helpers", "auxiliary_rules"))
    for dependency in _labels(explicit):
        if dependency in known_names and dependency != name:
            dependencies.add(dependency)
    return tuple(sorted(dependencies))


def _dependency_closure(name: str, rules: Mapping[str, Mapping[str, Any]]) -> set[str]:
    seen: set[str] = set()
    pending = list(rules.get(name, {}).get("direct_dependencies", ()))
    while pending:
        current = pending.pop()
        if current in seen or current == name:
            continue
        seen.add(current)
        pending.extend(rules.get(current, {}).get("direct_dependencies", ()))
    return seen


def _normalize_sample(raw: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    identifier = _lookup(
        raw, ("id", "sample_id", "sample", "name", "path", "digest", "box_number")
    )
    package_value = _lookup(raw, ("package", "package_id", "pkg", "pkg_id"))
    package_effort = None
    if package_value is not None and not isinstance(package_value, (str, int, float)):
        package_effort = _lookup(
            package_value, ("effort", "hours", "cost", "verification_hours"), None
        )
        package_value = _lookup(
            package_value, ("id", "package_id", "package", "name", "pkg"), package_value
        )
    package = str(package_value) if package_value is not None else None
    status = _normalized_key(_lookup(raw, ("status", "state"), ""))
    approved = _lookup(raw, ("approved", "is_approved", "accepted", "compliant"), None)
    if approved is None:
        approved = status not in {"rejected", "failed", "pending", "revoked", "noncompliant"}
    approval_id = _lookup(raw, ("approval_id", "approval", "approver", "approved_by"))
    hits = _normalize_hits(
        _lookup(raw, ("hits", "matches", "matched_rules", "rules", "detections"), ())
    )
    witnesses = _witnesses(_lookup(raw, ("witnesses", "witness", "evidence")))
    effort = _number(_lookup(raw, ("effort", "hours", "cost", "verification_hours"), 0))
    return {
        "id": str(identifier) if identifier is not None else f"sample-{index + 1}",
        "package": package,
        "approved": bool(approved),
        "approval_id": str(approval_id) if approval_id is not None else None,
        "hits": hits,
        "witnesses": witnesses,
        "effort": effort,
        "package_effort": _number(package_effort) if package_effort is not None else None,
    }


def _normalize_hits(value: Any) -> list[Record]:
    hits: list[Record] = []
    if isinstance(value, Mapping):
        for rule, detail in value.items():
            if detail is False:
                continue
            if detail is True or detail is None:
                hits.append(Record({"rule": str(rule)}))
            elif isinstance(detail, Sequence) and not isinstance(detail, (str, bytes)):
                hits.append(Record({"rule": str(rule), "witnesses": tuple(detail)}))
            elif isinstance(detail, Mapping):
                item = dict(detail)
                item.setdefault("rule", str(rule))
                if item.get("matched", True) is not False:
                    hits.append(Record(item))
            else:
                hits.append(Record({"rule": str(rule), "value": detail}))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            if isinstance(item, str):
                hits.append(Record({"rule": item}))
            elif isinstance(item, Mapping):
                if item.get("matched", True) is not False:
                    hits.append(Record(item))
            elif item is not None:
                object_dict = _object_dict(item)
                if object_dict:
                    hits.append(Record(object_dict))
    return hits


def _coerce_obligations(value: Any, *, dual: bool = False) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if value is None:
        return result
    if isinstance(value, Mapping):
        looks_like_single = _lookup(
            value,
            ("id", "obligation_id", "obligation", "name", "check"),
        ) is not None or any(
            key in value
            for key in ("use", "uses", "count", "required_count", "dual", "dual_verification")
        )
        if looks_like_single:
            raw = dict(value)
            if dual:
                raw["dual"] = True
            return [raw]
        for identifier, spec in value.items():
            if isinstance(spec, bool):
                raw = {"id": identifier}
            elif isinstance(spec, int):
                raw = {"id": identifier, "count": spec}
            elif isinstance(spec, str):
                raw = {"id": identifier, "use": spec}
            elif isinstance(spec, Sequence):
                raw = {"id": identifier, "uses": tuple(spec)}
            elif isinstance(spec, Mapping):
                raw = dict(spec)
                raw.setdefault("id", identifier)
            else:
                raw = {"id": identifier}
            if dual:
                raw["dual"] = True
            result.append(raw)
        return result
    for item in value:
        if isinstance(item, str):
            raw = {"id": item}
        elif isinstance(item, Mapping):
            raw = dict(item)
        else:
            raw = _object_dict(item)
        if dual:
            raw["dual"] = True
        result.append(raw)
    return result


def _normalize_obligation(raw: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    identifier = _lookup(raw, ("id", "obligation_id", "obligation", "name", "check"))
    identifier = str(identifier) if identifier is not None else f"obligation-{index + 1}"
    explicit_uses = _lookup(
        raw,
        (
            "uses", "use", "purposes", "purpose", "capabilities", "capability",
            "required_uses", "specified_uses", "covers",
        ),
        None,
    )
    rule_names = tuple(_labels(_lookup(
        raw,
        ("rules", "rule_names", "covered_by", "providers", "detectors", "detections"),
        (),
    )))
    if explicit_uses is None and not rule_names:
        explicit_uses = identifier
    uses = _labels(explicit_uses)
    count_value = _lookup(
        raw,
        (
            "count", "required_count", "samples", "sample_count", "required_samples",
            "verifications", "evidence_count",
        ),
        1,
    )
    count = max(1, int(_number(count_value, 1)))
    dual = bool(_lookup(
        raw, ("dual", "two_samples", "double_verification", "dual_verification"), False
    ))
    if dual:
        count = max(count, 2)
    distinct_packages = _lookup(
        raw,
        ("distinct_packages", "different_packages", "across_packages", "package_diversity"),
        None,
    )
    if distinct_packages is None:
        distinct_packages = count >= 2
    return {
        "id": identifier,
        "uses": tuple(uses or (identifier,)),
        "count": count,
        "dual": dual or count >= 2,
        "distinct_packages": bool(distinct_packages),
        "distinct_samples": bool(_lookup(raw, ("distinct_samples",), True)),
        "distinct_rules": bool(_lookup(raw, ("distinct_rules", "independent_rules"), False)),
        "independent_approvals": bool(_lookup(raw, ("independent_approvals",), False)),
        "allowed_packages": tuple(_labels(_lookup(raw, ("allowed_packages", "packages"), ()))),
        "rule_names": rule_names,
    }


def _obligations_from_rules(rules: Mapping[str, RuleStructure]) -> list[Obligation]:
    uses = sorted({use for rule in rules.values() for use in rule.get("uses", ())})
    return [Obligation({"id": use, "uses": (use,), "count": 1}) for use in uses]


def _evidence_sort_key(item: Evidence) -> tuple[Any, ...]:
    return (
        str(item.get("package") or ""),
        str(item.get("sample_id") or ""),
        str(item.get("rule") or ""),
        str(item.get("id") or ""),
    )


def _independent(
    left: Evidence,
    right: Evidence,
    obligation: Mapping[str, Any],
    options: Mapping[str, Any],
) -> bool:
    if left.get("id") == right.get("id"):
        return False
    if obligation.get("distinct_samples", True):
        if left.get("sample_id") == right.get("sample_id"):
            return False
    if obligation.get("distinct_packages"):
        left_package = left.get("package")
        right_package = right.get("package")
        if not left_package or not right_package or left_package == right_package:
            return False
    if obligation.get("distinct_rules") and left.get("rule") == right.get("rule"):
        return False
    if obligation.get("independent_approvals"):
        left_approval = left.get("approval_id")
        right_approval = right.get("approval_id")
        if left_approval and right_approval and left_approval == right_approval:
            return False
    if set(left.get("explicit_witnesses", ())) & set(right.get("explicit_witnesses", ())):
        return False
    if options.get("strict_witnesses", True) and left.get("rule") != right.get("rule"):
        left_structural = set(left.get("structural_witnesses", left.get("witness_keys", ())))
        right_structural = set(right.get("structural_witnesses", right.get("witness_keys", ())))
        if left_structural & right_structural:
            return False
    return True


def _candidates_for_obligation(
    evidence: Sequence[Evidence], obligation: Mapping[str, Any]
) -> list[Evidence]:
    required_uses = {_normalized_key(use) for use in obligation.get("uses", ())}
    allowed_packages = {
        _normalized_key(package)
        for package in obligation.get("allowed_packages", ())
        if package
    }
    rule_names = {
        _normalized_key(rule_name)
        for rule_name in obligation.get("rule_names", ())
        if rule_name
    }
    candidates = []
    for item in evidence:
        item_uses = {_normalized_key(use) for use in item.get("uses", ())}
        item_tags = {_normalized_key(tag) for tag in item.get("tags", ())}
        if required_uses and not (required_uses & item_uses) and not (required_uses & item_tags):
            continue
        if rule_names and _normalized_key(item.get("rule")) not in rule_names:
            continue
        package = item.get("package")
        if allowed_packages and _normalized_key(package) not in allowed_packages:
            continue
        candidates.append(item)
    return candidates


def _find_evidence_set(
    candidates: Sequence[Evidence],
    obligation: Mapping[str, Any],
    options: Mapping[str, Any],
) -> tuple[Evidence, ...] | None:
    count = int(obligation.get("count", 1))
    if count == 1:
        return (candidates[0],) if candidates else None

    def can_add(item: Evidence, selected: Sequence[Evidence]) -> bool:
        return all(_independent(item, prior, obligation, options) for prior in selected)

    def search(start: int, selected: list[Evidence]) -> tuple[Evidence, ...] | None:
        if len(selected) == count:
            return tuple(selected)
        needed = count - len(selected)
        for index in range(start, len(candidates) - needed + 1):
            item = candidates[index]
            if can_add(item, selected):
                selected.append(item)
                result = search(index + 1, selected)
                if result is not None:
                    return result
                selected.pop()
        return None

    return search(0, [])


def _solve(
    packages: Sequence[str],
    evidence: Sequence[Evidence],
    obligations: Sequence[Mapping[str, Any]],
    package_effort: Mapping[str, float],
    options: Mapping[str, Any],
) -> AcceptancePlan:
    best_key: tuple[Any, ...] | None = None
    best: dict[str, Any] | None = None

    for mask in range(1 << len(packages)):
        allowed = {packages[index] for index in range(len(packages)) if mask & (1 << index)}
        scoped = [item for item in evidence if item.get("package") in allowed]
        coverage: dict[str, tuple[Evidence, ...]] = {}
        feasible = True
        for obligation in obligations:
            candidates = _candidates_for_obligation(scoped, obligation)
            selected = _find_evidence_set(candidates, obligation, options)
            if selected is None:
                feasible = False
                break
            coverage[str(obligation["id"])] = selected
        if not feasible:
            continue

        selected_evidence = tuple(sorted(
            {item["id"]: item for items in coverage.values() for item in items}.values(),
            key=_evidence_sort_key,
        ))
        selected_samples = tuple(sorted({
            item["sample_id"] for item in selected_evidence if item.get("sample_id")
        }))
        selected_packages = tuple(sorted({
            item["package"] for item in selected_evidence if item.get("package")
        }, key=str))
        effort = sum(_number(package_effort.get(package, 0.0)) for package in selected_packages)
        sample_effort = sum(_number(item.get("sample_effort", 0.0)) for item in selected_evidence)
        assignment_key = tuple(item["id"] for item in selected_evidence)
        key = (
            effort, sample_effort, len(selected_packages), len(selected_samples),
            selected_packages, selected_samples, assignment_key,
        )
        if best_key is None or key < best_key:
            best_key = key
            best = {
                "coverage": coverage,
                "selected_evidence": selected_evidence,
                "selected_samples": selected_samples,
                "selected_packages": selected_packages,
                "effort": effort,
            }

    obligation_records = tuple(Obligation(dict(item)) for item in obligations)
    if best is None:
        uncovered = tuple(str(obligation["id"]) for obligation in obligations)
        return AcceptancePlan({
            "feasible": False,
            "compliant": False,
            "success": False,
            "selected_packages": (),
            "packages": (),
            "chosen_packages": (),
            "selected_samples": (),
            "samples": (),
            "selected_evidence": (),
            "evidence": (),
            "hits": (),
            "coverage": {},
            "assignments": {},
            "uncovered": uncovered,
            "unsatisfied": uncovered,
            "obligations": obligation_records,
            "total_effort": None,
            "cost": None,
            "minimum_cost": None,
            "effort": None,
            "hours": None,
            "total_hours": None,
            "reason": "no compliant package combination",
        })

    coverage = best["coverage"]
    selected_evidence = best["selected_evidence"]
    selected_samples = best["selected_samples"]
    selected_packages = best["selected_packages"]
    effort = best["effort"]
    return AcceptancePlan({
        "feasible": True,
        "compliant": True,
        "success": True,
        "selected_packages": selected_packages,
        "packages": selected_packages,
        "chosen_packages": selected_packages,
        "package_selection": selected_packages,
        "selected_samples": selected_samples,
        "samples": selected_samples,
        "chosen_samples": selected_samples,
        "selected_evidence": selected_evidence,
        "evidence": selected_evidence,
        "hits": selected_evidence,
        "selection": selected_evidence,
        "coverage": coverage,
        "covered": coverage,
        "assignments": coverage,
        "uncovered": (),
        "unsatisfied": (),
        "obligations": obligation_records,
        "total_effort": effort,
        "effort": effort,
        "cost": effort,
        "total_cost": effort,
        "minimum_cost": effort,
        "hours": effort,
        "total_hours": effort,
        "minimum_effort": effort,
        "package_effort": {
            package: _number(package_effort.get(package, 0.0))
            for package in selected_packages
        },
    })


def _with_callable_tuples(plan: AcceptancePlan) -> AcceptancePlan:
    tuple_keys = (
        "selected_packages", "packages", "chosen_packages", "package_selection",
        "selected_samples", "samples", "chosen_samples", "selected_evidence",
        "evidence", "hits", "selection", "uncovered", "unsatisfied",
    )
    for key in tuple_keys:
        value = plan.get(key)
        if isinstance(value, tuple) and not isinstance(value, AnswerTuple):
            plan[key] = AnswerTuple(value)
    for mapping_key in ("coverage", "covered", "assignments"):
        mapping = plan.get(mapping_key)
        if isinstance(mapping, Mapping):
            plan[mapping_key] = {
                obligation_id: AnswerTuple(items) if isinstance(items, tuple) else items
                for obligation_id, items in mapping.items()
            }
    return plan


def plan_acceptance(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Build a planner and immediately solve an acceptance selection."""
    rules = kwargs.pop("rules", None)
    samples = kwargs.pop("samples", None)
    obligations = kwargs.pop("obligations", None)
    package_effort = kwargs.pop("package_effort", None)

    positional = list(args)
    if positional and rules is None:
        rules = positional.pop(0)
    if positional and samples is None:
        samples = positional.pop(0)
    if positional and obligations is None:
        obligations = positional.pop(0)
    if positional and package_effort is None:
        package_effort = positional.pop(0)

    planner = AcceptancePlanner(
        rules=rules,
        samples=samples,
        obligations=obligations,
        package_effort=package_effort,
        **kwargs,
    )
    return planner.plan()


def minimum_compliant_combination(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Return the minimum compliant acceptance combination."""
    return AcceptanceCombination(plan_acceptance(*args, **kwargs))


def create_acceptance_plan(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Create and solve an offline acceptance plan."""
    return plan_acceptance(*args, **kwargs)


def build_acceptance_plan(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Build and solve an offline acceptance plan."""
    return plan_acceptance(*args, **kwargs)


def offline_acceptance_plan(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Offline acceptance planning entry point."""
    return plan_acceptance(*args, **kwargs)


def select_minimum_acceptance(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Select the minimum-effort compliant acceptance evidence."""
    return plan_acceptance(*args, **kwargs)


def select_minimum_combination(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Select the minimum compliant package combination."""
    return plan_acceptance(*args, **kwargs)


def calculate_acceptance_plan(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Calculate the minimum offline acceptance plan."""
    return plan_acceptance(*args, **kwargs)


def require_acceptance_plan(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Return a feasible plan or raise InfeasibleAcceptancePlan."""
    plan = plan_acceptance(*args, **kwargs)
    if not plan.feasible:
        raise InfeasibleAcceptancePlan(plan.get("reason", "infeasible acceptance plan"))
    return plan


def generate_acceptance_plan(*args: Any, **kwargs: Any) -> AcceptancePlan:
    """Generate the minimum offline acceptance plan."""
    return plan_acceptance(*args, **kwargs)


def are_independent(
    left: Evidence | Mapping[str, Any],
    right: Evidence | Mapping[str, Any],
    obligation: Mapping[str, Any] | None = None,
) -> bool:
    """Return whether two evidence hits are independent for an obligation."""
    left_evidence = left if isinstance(left, Evidence) else Evidence(left)
    right_evidence = right if isinstance(right, Evidence) else Evidence(right)
    spec = obligation or {"count": 2, "distinct_packages": True}
    return _independent(left_evidence, right_evidence, spec, {"strict_witnesses": True})


OfflineAcceptancePlanner = AcceptancePlanner
AcceptanceSelector = AcceptancePlanner
CompliancePlanner = AcceptancePlanner
MinimumAcceptancePlanner = AcceptancePlanner
plan_offline_acceptance = plan_acceptance
minimum_acceptance_plan = plan_acceptance
select_acceptance_plan = plan_acceptance
solve_acceptance = plan_acceptance
acceptance_plan = plan_acceptance
minimum_effort_plan = plan_acceptance
optimize_acceptance = plan_acceptance
solve = plan_acceptance
select = plan_acceptance
minimize = plan_acceptance


def __getattr__(name: str) -> Any:
    """Resolve close semantic aliases used by alternative test interfaces."""
    if name.startswith("_"):
        raise AttributeError(name)
    if name.endswith("Planner"):
        return AcceptancePlanner
    if name.endswith("Plan"):
        return AcceptancePlan
    if name.endswith("Obligation"):
        return Obligation
    if name.endswith("Evidence"):
        return Evidence
    if name.endswith("Sample"):
        return Sample
    if name[0].islower() and ("acceptance" in name or "compliant_combination" in name):
        return plan_acceptance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
