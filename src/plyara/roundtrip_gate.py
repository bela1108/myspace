"""Offline semantic round-trip gate for a small, explicit YARA subset.

The gate uses Plyara parse results rather than a YARA scanner.  It compares
two versions of the same rule names and searches a finite match/count model for
Boolean condition counterexamples.
"""

from __future__ import annotations

import argparse
import difflib
import itertools
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from plyara import Plyara
from plyara.utils import rebuild_yara_rule


SCHEMA_VERSION = "plyara-roundtrip-gate/v1"
DEFAULT_MAX_ASSIGNMENTS = 250_000

COMPARATORS = {"==", "!=", ">=", "<=", ">", "<"}
STRING_RE = re.compile(r"^\$[A-Za-z_0-9*]*$")
COUNT_RE = re.compile(r"^#[A-Za-z_0-9*]*$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

UNCERTAIN_CAPABILITIES = [
    "imported module functions such as pe.*, math.*, and hash.*",
    "for/of and for/in iteration clauses",
    "string position and length operators @a[i] and !a[i]",
    "offset/range predicates using 'at' or 'in'",
    "arithmetic, bitwise, and shift expressions",
    "filesize, entrypoint, and other scan-environment integers",
    "hash, regex, and byte pattern value equivalence beyond opaque atoms",
    "public, global, or external rule references; only private same-pack helpers are linked",
    "include directives and preprocessing",
    "wildcard/anonymous aggregate count expressions such as #a* or bare #",
]


class UnsupportedCondition(ValueError):
    """Raised when a condition uses syntax outside the accepted subset."""

    def __init__(self, code: str, message: str, token: str | None = None):
        self.code = code
        self.token = token
        super().__init__(message)


@dataclass(frozen=True)
class StringVariable:
    """One rule-local string declaration in the abstract match model."""

    rule: str
    index: int
    name: str
    declared_value: Any
    string_type: str

    @property
    def key(self) -> str:
        return f"{self.rule}\0{self.index}"

    @property
    def label(self) -> str:
        if self.name == "$":
            return f"{self.rule}.$#{self.index + 1}"
        return f"{self.rule}.{self.name}"


class ConditionParser:
    """Recursive-descent parser for the documented local Boolean subset."""

    def __init__(self, tokens: list[str], rule_name: str, private_rules: set[str]):
        self.tokens = tokens
        self.rule_name = rule_name
        self.private_rules = private_rules
        self.pos = 0

    def parse(self) -> dict[str, Any]:
        if not self.tokens:
            raise UnsupportedCondition("empty_condition", "Condition has no terms")
        node = self.parse_or()
        if self.pos < len(self.tokens):
            token = self.tokens[self.pos]
            raise UnsupportedCondition(
                "unexpected_trailing_token",
                f"Unsupported condition syntax near {token!r}",
                token,
            )
        return node

    def peek(self, offset: int = 0) -> str | None:
        index = self.pos + offset
        if index >= len(self.tokens):
            return None
        return self.tokens[index]

    def consume(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None:
            raise UnsupportedCondition("unexpected_end", "Condition ended unexpectedly")
        if expected is not None and token != expected:
            raise UnsupportedCondition(
                "expected_token", f"Expected {expected!r}, found {token!r}", token
            )
        self.pos += 1
        return token

    def parse_or(self) -> dict[str, Any]:
        children = [self.parse_and()]
        while self.peek() == "or":
            self.consume("or")
            children.append(self.parse_and())
        if len(children) == 1:
            return children[0]
        return {"type": "or", "children": children}

    def parse_and(self) -> dict[str, Any]:
        children = [self.parse_not()]
        while self.peek() == "and":
            self.consume("and")
            children.append(self.parse_not())
        if len(children) == 1:
            return children[0]
        return {"type": "and", "children": children}

    def parse_not(self) -> dict[str, Any]:
        if self.peek() == "not":
            self.consume("not")
            return {"type": "not", "child": self.parse_not()}
        return self.parse_primary()

    def parse_primary(self) -> dict[str, Any]:
        token = self.peek()
        if token is None:
            raise UnsupportedCondition("unexpected_end", "Condition ended unexpectedly")

        if token == "(":
            self.consume("(")
            node = self.parse_or()
            self.consume(")")
            return node

        if token in ("true", "false"):
            self.consume()
            return {"type": "bool", "value": token == "true"}

        if token in ("any", "all", "none") or (token.isdigit() and self.peek(1) == "of"):
            return self.parse_quantifier()

        if token.startswith("#"):
            return self.parse_count()

        if token.startswith("$"):
            if not STRING_RE.match(token):
                raise UnsupportedCondition(
                    "unsupported_string_syntax", f"Unsupported string reference {token!r}", token
                )
            if self.peek(1) in ("at", "in", "["):
                raise UnsupportedCondition(
                    "string_offset_predicate",
                    "String 'at', offset 'in', and indexed predicates are outside the subset",
                    token,
                )
            self.consume()
            return {"type": "string", "ref": token}

        if IDENTIFIER_RE.match(token):
            self.consume()
            if token in self.private_rules:
                return {"type": "helper", "name": token}
            if token in {"them", "filesize", "entrypoint"}:
                raise UnsupportedCondition(
                    "unsupported_builtin", f"Built-in {token!r} is outside the subset", token
                )
            raise UnsupportedCondition(
                "unknown_or_unsupported_identifier",
                f"Identifier {token!r} is not a linked private helper or supported atom",
                token,
            )

        raise UnsupportedCondition(
            "unsupported_token", f"Token {token!r} is outside the accepted subset", token
        )

    def parse_quantifier(self) -> dict[str, Any]:
        first = self.consume()
        if first == "any":
            mode, threshold = "at_least", 1
        elif first == "all":
            mode, threshold = "all", None
        elif first == "none":
            mode, threshold = "none", 0
        else:
            mode, threshold = "at_least", int(first)

        self.consume("of")
        next_token = self.peek()

        if next_token == "them":
            self.consume("them")
            target = {"kind": "them"}
        elif next_token == "$*":
            self.consume("$*")
            target = {"kind": "all_strings"}
        elif next_token == "(":
            self.consume("(")
            patterns: list[str] = []
            while self.peek() != ")":
                token = self.peek()
                if token is None:
                    raise UnsupportedCondition("unexpected_end", "Unclosed string set")
                if token == ",":
                    self.consume(",")
                    continue
                if not token.startswith("$") or "{" in token:
                    raise UnsupportedCondition(
                        "unsupported_string_set",
                        f"String set entry {token!r} is not a name or wildcard reference",
                        token,
                    )
                patterns.append(self.consume())
            self.consume(")")
            target = {"kind": "patterns", "patterns": patterns}
        else:
            raise UnsupportedCondition(
                "unsupported_quantifier_set", "Quantifier must target them, $*, or ($name, ...)"
            )

        return {"type": "quantifier", "mode": mode, "threshold": threshold, "target": target}

    def parse_count(self) -> dict[str, Any]:
        ref = self.consume()
        if ref == "#" or "*" in ref:
            raise UnsupportedCondition(
                "aggregate_count_uncertain",
                "Only #exact_name comparisons are accepted; aggregate counts are uncertain",
                ref,
            )
        if not COUNT_RE.match(ref):
            raise UnsupportedCondition("unsupported_count", f"Unsupported count expression {ref!r}", ref)

        next_token = self.peek()
        if next_token in COMPARATORS:
            op = self.consume()
            value_token = self.consume()
            if not value_token.isdigit():
                raise UnsupportedCondition(
                    "non_integer_count_bound", "Count comparison requires a non-negative integer"
                )
            return {
                "type": "count_compare",
                "ref": "$" + ref[1:],
                "op": op,
                "value": int(value_token),
            }

        if next_token == "in":
            self.consume("in")
            self.consume("(")
            low_token = self.consume()
            self.consume("..")
            high_token = self.consume()
            self.consume(")")
            if not low_token.isdigit() or not high_token.isdigit():
                raise UnsupportedCondition("bad_count_range", "Count range requires integer bounds")
            low, high = int(low_token), int(high_token)
            if low > high:
                raise UnsupportedCondition("bad_count_range", "Count range lower bound exceeds upper bound")
            return {"type": "count_range", "ref": "$" + ref[1:], "low": low, "high": high}

        raise UnsupportedCondition(
            "unsupported_count_predicate",
            "Count must be used with an integer comparator or 'in (low..high)'",
            ref,
        )


@dataclass
class RuleModel:
    """A Plyara rule plus its parsed supported-subset AST."""

    name: str
    raw: dict[str, Any]
    ast: dict[str, Any] | None
    unsupported: UnsupportedCondition | None

    @property
    def strings(self) -> list[dict[str, Any]]:
        return list(self.raw.get("strings", []))

    @property
    def private(self) -> bool:
        return "private" in self.raw.get("scopes", [])


@dataclass
class Bundle:
    """Parsed rules from one YARA source."""

    label: str
    text: str
    rules: dict[str, RuleModel]
    parse_error: str | None = None


def parse_bundle(text: str, label: str) -> Bundle:
    """Parse YARA text with Plyara and link accepted private helpers."""
    try:
        raw_rules = Plyara().parse_string(text)
    except Exception as exc:  # Plyara uses a small exception hierarchy plus PLY errors.
        return Bundle(label=label, text=text, rules={}, parse_error=f"{type(exc).__name__}: {exc}")

    raw_by_name: dict[str, dict[str, Any]] = {}
    for raw in raw_rules:
        raw_by_name[raw["rule_name"]] = raw

    private_rules = {
        name for name, raw in raw_by_name.items() if "private" in raw.get("scopes", [])
    }
    models: dict[str, RuleModel] = {}
    for name, raw in raw_by_name.items():
        tokens = list(raw.get("condition_terms", []))
        try:
            ast = ConditionParser(tokens, name, private_rules).parse()
            unsupported = None
        except UnsupportedCondition as exc:
            ast = {"type": "unsupported", "code": exc.code, "message": str(exc), "token": exc.token}
            unsupported = exc
        models[name] = RuleModel(name=name, raw=raw, ast=ast, unsupported=unsupported)

    return Bundle(label=label, text=text, rules=models)


def plyara_rebuild(text: str, condition_indents: bool = True) -> str:
    """Perform the parse → Plyara rebuild half of an offline round trip."""
    rules = Plyara().parse_string(text)
    return "\n".join(
        rebuild_yara_rule(rule, condition_indents=condition_indents) for rule in rules
    )


def stable_json(value: Any) -> str:
    """Return stable JSON for parsed structures."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def canonical_strings(rule: RuleModel) -> list[dict[str, Any]]:
    """Canonicalize Plyara string descriptors for semantic declaration comparison."""
    result = []
    for entry in rule.strings:
        result.append(
            {
                "name": entry.get("name"),
                "type": entry.get("type"),
                "value": entry.get("value"),
                "modifiers": entry.get("modifiers", []),
            }
        )
    return result


def canonical_scopes(rule: RuleModel) -> list[str]:
    return sorted(rule.raw.get("scopes", []))


def string_variables(rule: RuleModel) -> list[StringVariable]:
    return [
        StringVariable(
            rule=rule.name,
            index=index,
            name=entry.get("name", "$"),
            declared_value=entry.get("value"),
            string_type=entry.get("type", "unknown"),
        )
        for index, entry in enumerate(rule.strings)
    ]


def name_matches_pattern(name: str, pattern: str) -> bool:
    """Match YARA's trailing wildcard string reference syntax."""
    if pattern == "$*":
        return name.startswith("$")
    if "*" not in pattern:
        return name == pattern
    if not pattern.endswith("*") or "*" in pattern[:-1]:
        return False
    return name.startswith(pattern[:-1])


def resolve_string_variables(rule: RuleModel, target: dict[str, Any] | str) -> list[StringVariable]:
    variables = string_variables(rule)
    if isinstance(target, str):
        pattern = target
        return [variable for variable in variables if name_matches_pattern(variable.name, pattern)]

    kind = target.get("kind")
    if kind in ("them", "all_strings"):
        return variables
    if kind == "patterns":
        patterns = target.get("patterns", [])
        return [
            variable
            for variable in variables
            if any(name_matches_pattern(variable.name, pattern) for pattern in patterns)
        ]
    raise UnsupportedCondition("bad_target", "Unknown string target")


def eval_node(
    node: dict[str, Any],
    bundle: Bundle,
    current_rule: str,
    env: dict[str, int],
    stack: frozenset[str] = frozenset(),
) -> bool:
    """Evaluate a supported AST under one finite count assignment."""
    kind = node["type"]

    if kind == "bool":
        return bool(node["value"])
    if kind == "not":
        return not eval_node(node["child"], bundle, current_rule, env, stack)
    if kind == "and":
        return all(eval_node(child, bundle, current_rule, env, stack) for child in node["children"])
    if kind == "or":
        return any(eval_node(child, bundle, current_rule, env, stack) for child in node["children"])

    rule = bundle.rules[current_rule]

    if kind == "string":
        variables = resolve_string_variables(rule, node["ref"])
        if not variables:
            raise UnsupportedCondition(
                "unresolved_string_reference",
                f"String {node['ref']!r} is not declared in {current_rule!r}",
            )
        return any(env.get(variable.key, 0) > 0 for variable in variables)

    if kind == "quantifier":
        variables = resolve_string_variables(rule, node["target"])
        if not variables:
            raise UnsupportedCondition(
                "empty_string_set", "Quantifier target does not resolve to any declared string"
            )
        matched = sum(env.get(variable.key, 0) > 0 for variable in variables)
        mode = node["mode"]
        if mode == "all":
            return len(variables) > 0 and matched == len(variables)
        if mode == "none":
            return matched == 0
        return matched >= int(node["threshold"])

    if kind in ("count_compare", "count_range"):
        variables = resolve_string_variables(rule, node["ref"])
        if not variables:
            raise UnsupportedCondition(
                "unresolved_count_reference",
                f"Count reference {node['ref']!r} is not declared in {current_rule!r}",
            )
        count = sum(env.get(variable.key, 0) for variable in variables)
        if kind == "count_range":
            return int(node["low"]) <= count <= int(node["high"])
        op = node["op"]
        bound = int(node["value"])
        comparisons = {
            "==": count == bound,
            "!=": count != bound,
            ">=": count >= bound,
            "<=": count <= bound,
            ">": count > bound,
            "<": count < bound,
        }
        return comparisons[op]

    if kind == "helper":
        helper_name = node["name"]
        if helper_name in stack:
            raise UnsupportedCondition("recursive_helper", f"Recursive helper {helper_name!r}")
        helper = bundle.rules.get(helper_name)
        if helper is None or helper.ast is None or helper.unsupported is not None:
            raise UnsupportedCondition("unlinked_helper", f"Helper {helper_name!r} is not evaluable")
        return eval_node(
            helper.ast,
            bundle,
            helper_name,
            env,
            stack | {current_rule, helper_name},
        )

    if kind == "unsupported":
        raise UnsupportedCondition(node.get("code", "unsupported"), node.get("message", "Unsupported"))

    raise UnsupportedCondition("unknown_ast_node", f"Unknown AST node {kind!r}")


def walk_ast(node: dict[str, Any] | None) -> Iterable[dict[str, Any]]:
    if not node:
        return
    yield node
    for value in node.values():
        if isinstance(value, dict) and "type" in value:
            yield from walk_ast(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "type" in item:
                    yield from walk_ast(item)


def reachable_rule_names(bundle: Bundle, rule_name: str) -> set[str]:
    result = {rule_name}
    rule = bundle.rules.get(rule_name)
    if rule is None or rule.ast is None:
        return result
    for node in walk_ast(rule.ast):
        if node.get("type") == "helper":
            name = node["name"]
            if name in bundle.rules and name not in result:
                result.update(reachable_rule_names(bundle, name))
    return result


def collect_variables(
    baseline: Bundle, candidate: Bundle, rule_name: str
) -> list[StringVariable]:
    names: set[str] = set()
    for bundle in (baseline, candidate):
        names.update(reachable_rule_names(bundle, rule_name))

    variables: dict[str, StringVariable] = {}
    for bundle in (baseline, candidate):
        for name in names:
            rule = bundle.rules.get(name)
            if rule is None:
                continue
            for variable in string_variables(rule):
                variables[variable.key] = variable
    return sorted(variables.values(), key=lambda item: item.label)


def count_bounds(node: dict[str, Any]) -> set[int]:
    if node["type"] == "count_compare":
        bound = int(node["value"])
        return {bound - 1, bound, bound + 1}
    low, high = int(node["low"]), int(node["high"])
    return {low - 1, low, high, high + 1}


def build_domains(
    baseline: Bundle, candidate: Bundle, rule_name: str, variables: list[StringVariable]
) -> list[list[int]]:
    bounds_by_ref: dict[tuple[str, str], set[int]] = {}
    reachable = set()
    for bundle in (baseline, candidate):
        reachable.update(reachable_rule_names(bundle, rule_name))
        for current_name in reachable:
            rule = bundle.rules.get(current_name)
            if rule is None or rule.ast is None:
                continue
            for node in walk_ast(rule.ast):
                if node.get("type") in ("count_compare", "count_range"):
                    key = (current_name, node["ref"])
                    bounds_by_ref.setdefault(key, set()).update(count_bounds(node))

    domains = []
    for variable in variables:
        bounds = bounds_by_ref.get((variable.rule, variable.name), set())
        if bounds:
            values = {0, 1}
            values.update(value for value in bounds if value >= 0)
            domain = sorted(values)
        else:
            domain = [0, 1]
        domains.append(domain)
    return domains


def assignment_product_size(domains: list[list[int]]) -> int:
    size = 1
    for domain in domains:
        size *= len(domain)
    return size


def make_counterexample(
    baseline: Bundle,
    candidate: Bundle,
    rule_name: str,
    variables: list[StringVariable],
    domains: list[list[int]],
    max_assignments: int,
) -> dict[str, Any] | None:
    product_size = assignment_product_size(domains)
    if product_size > max_assignments:
        raise UnsupportedCondition(
            "search_budget_exceeded",
            f"Finite model needs {product_size} assignments, exceeding {max_assignments}",
        )

    for values in itertools.product(*domains):
        env = {variable.key: count for variable, count in zip(variables, values)}
        try:
            before = eval_node(baseline.rules[rule_name].ast, baseline, rule_name, env)
            after = eval_node(candidate.rules[rule_name].ast, candidate, rule_name, env)
        except UnsupportedCondition:
            raise
        if before != after:
            assignments = []
            abstract_sample: dict[str, int] = {}
            for variable, count in zip(variables, values):
                assignments.append(
                    {
                        "atom": variable.label,
                        "rule": variable.rule,
                        "string": variable.name,
                        "string_index": variable.index,
                        "declared_value": variable.declared_value,
                        "type": variable.string_type,
                        "occurrences": count,
                        "matches": count > 0,
                    }
                )
                abstract_sample[variable.label] = count
            return {
                "abstract_occurrence_counts": abstract_sample,
                "assignments": assignments,
                "baseline_result": before,
                "candidate_result": after,
                "searched_assignments": product_size,
            }
    return None


def unified_text_diff(baseline_text: str, candidate_text: str, baseline_label: str, candidate_label: str) -> str:
    diff = difflib.unified_diff(
        baseline_text.splitlines(),
        candidate_text.splitlines(),
        fromfile=baseline_label,
        tofile=candidate_label,
        lineterm="",
        n=3,
    )
    return "\n".join(diff)


def compare_rule(
    name: str,
    baseline: Bundle,
    candidate: Bundle,
    max_assignments: int,
) -> dict[str, Any]:
    before_rule = baseline.rules.get(name)
    after_rule = candidate.rules.get(name)
    report: dict[str, Any] = {
        "rule": name,
        "status": "equivalent",
        "counterexample": None,
        "limitations": [],
        "condition_terms_equal": False,
        "string_definitions_equal": False,
        "scopes_equal": False,
        "baseline_condition_terms": before_rule.raw.get("condition_terms") if before_rule else None,
        "candidate_condition_terms": after_rule.raw.get("condition_terms") if after_rule else None,
    }

    if before_rule is None or after_rule is None:
        report["status"] = "missing_rule"
        report["missing_in_baseline"] = before_rule is None
        report["missing_in_candidate"] = after_rule is None
        return report

    report["condition_terms_equal"] = stable_json(before_rule.raw.get("condition_terms")) == stable_json(
        after_rule.raw.get("condition_terms")
    )
    report["string_definitions_equal"] = stable_json(canonical_strings(before_rule)) == stable_json(
        canonical_strings(after_rule)
    )
    report["scopes_equal"] = canonical_scopes(before_rule) == canonical_scopes(after_rule)

    if not report["string_definitions_equal"]:
        report["status"] = "string_definition_change"
        report["string_changes"] = {
            "baseline": canonical_strings(before_rule),
            "candidate": canonical_strings(after_rule),
        }
        return report

    if not report["scopes_equal"]:
        report["status"] = "scope_change"
        report["scope_changes"] = {
            "baseline": canonical_scopes(before_rule),
            "candidate": canonical_scopes(after_rule),
        }
        return report

    dependency_names = reachable_rule_names(baseline, name) | reachable_rule_names(candidate, name)
    for dependency_name in sorted(dependency_names - {name}):
        before_dependency = baseline.rules.get(dependency_name)
        after_dependency = candidate.rules.get(dependency_name)
        if before_dependency is None or after_dependency is None:
            continue
        strings_equal = stable_json(canonical_strings(before_dependency)) == stable_json(
            canonical_strings(after_dependency)
        )
        scopes_equal = canonical_scopes(before_dependency) == canonical_scopes(after_dependency)
        if not strings_equal or not scopes_equal:
            report["status"] = "dependency_definition_change"
            report["dependency"] = dependency_name
            report["dependency_string_definitions_equal"] = strings_equal
            report["dependency_scopes_equal"] = scopes_equal
            return report

    limitations = []
    if before_rule.unsupported:
        limitations.append({"side": "baseline", **before_rule.ast})
    if after_rule.unsupported:
        limitations.append({"side": "candidate", **after_rule.ast})
    if limitations:
        report["status"] = "uncertain"
        report["limitations"] = limitations
        return report

    try:
        variables = collect_variables(baseline, candidate, name)
        domains = build_domains(baseline, candidate, name, variables)
        counterexample = make_counterexample(
            baseline, candidate, name, variables, domains, max_assignments
        )
    except UnsupportedCondition as exc:
        report["status"] = "uncertain"
        report["limitations"] = [
            {"type": "unsupported", "code": exc.code, "message": str(exc), "token": exc.token}
        ]
        return report

    report["model_variables"] = [item.label for item in variables]
    report["assignment_space"] = assignment_product_size(domains)
    if counterexample is not None:
        report["status"] = "condition_change"
        report["counterexample"] = counterexample
    return report


def compare_yara_texts(
    baseline_text: str,
    candidate_text: str,
    *,
    baseline_label: str = "baseline.yar",
    candidate_label: str = "candidate.yar",
    max_assignments: int = DEFAULT_MAX_ASSIGNMENTS,
) -> dict[str, Any]:
    """Compare two YARA sources and return a serializable gate report."""
    baseline = parse_bundle(baseline_text, baseline_label)
    candidate = parse_bundle(candidate_text, candidate_label)
    diff = unified_text_diff(baseline_text, candidate_text, baseline_label, candidate_label)

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "baseline_label": baseline_label,
        "candidate_label": candidate_label,
        "has_text_differences": bool(diff),
        "whitespace_only": "".join(baseline_text.split()) == "".join(candidate_text.split()),
        "format_diff": diff,
        "baseline_parse_error": baseline.parse_error,
        "candidate_parse_error": candidate.parse_error,
        "rules": [],
        "status": "pass",
    }

    if baseline.parse_error or candidate.parse_error:
        report["status"] = "parse_error"
        return report

    rule_names = sorted(set(baseline.rules) | set(candidate.rules))
    report["rules"] = [compare_rule(name, baseline, candidate, max_assignments) for name in rule_names]
    report["summary"] = summarize_rule_reports(report["rules"])

    statuses = {item["status"] for item in report["rules"]}
    hard_changes = {
        "condition_change",
        "string_definition_change",
        "scope_change",
        "dependency_definition_change",
        "missing_rule",
    }
    if statuses & hard_changes:
        report["status"] = "fail"
    elif "uncertain" in statuses:
        report["status"] = "inconclusive"
    else:
        report["status"] = "pass"
    return report


def summarize_rule_reports(rules: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for rule in rules:
        summary[rule["status"]] = summary.get(rule["status"], 0) + 1
    summary["total"] = len(rules)
    return summary


def compare_paths(
    baseline: Path,
    candidate: Path,
    max_assignments: int = DEFAULT_MAX_ASSIGNMENTS,
) -> dict[str, Any]:
    """Compare two files or two directories containing ``.yar``/``.yara`` files."""
    if baseline.is_file() and candidate.is_file():
        report = compare_yara_texts(
            baseline.read_text(encoding="utf-8"),
            candidate.read_text(encoding="utf-8"),
            baseline_label=str(baseline),
            candidate_label=str(candidate),
            max_assignments=max_assignments,
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": "files",
            "status": report["status"],
            "files": [report],
        }

    if baseline.is_dir() and candidate.is_dir():
        left = yara_files(baseline)
        right = yara_files(candidate)
        file_reports = []
        for relative in sorted(set(left) | set(right)):
            if relative not in left or relative not in right:
                file_reports.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "baseline_label": relative,
                        "candidate_label": relative,
                        "status": "missing_file",
                        "missing_in_baseline": relative not in left,
                        "missing_in_candidate": relative not in right,
                        "rules": [],
                        "format_diff": "",
                        "has_text_differences": True,
                    }
                )
                continue
            left_path = left[relative]
            right_path = right[relative]
            file_reports.append(
                compare_yara_texts(
                    left_path.read_text(encoding="utf-8"),
                    right_path.read_text(encoding="utf-8"),
                    baseline_label=str(left_path),
                    candidate_label=str(right_path),
                    max_assignments=max_assignments,
                )
            )
        aggregate = {
            "schema_version": SCHEMA_VERSION,
            "mode": "directories",
            "baseline": str(baseline),
            "candidate": str(candidate),
            "files": file_reports,
        }
        aggregate["status"] = aggregate_status(file_reports)
        return aggregate

    raise ValueError("baseline and candidate must both be files or both be directories")


def yara_files(root: Path) -> dict[str, Path]:
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".yar", ".yara"}:
            files[path.relative_to(root).as_posix()] = path
    return files


def aggregate_status(file_reports: list[dict[str, Any]]) -> str:
    statuses = {item.get("status") for item in file_reports}
    if "parse_error" in statuses or "missing_file" in statuses or "fail" in statuses:
        return "fail"
    if "inconclusive" in statuses:
        return "inconclusive"
    return "pass"


def iter_rule_reports(multi_report: dict[str, Any]) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    for file_report in multi_report.get("files", [multi_report]):
        for rule_report in file_report.get("rules", []):
            yield file_report, rule_report


def format_difference_records(multi_report: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for file_report in multi_report.get("files", [multi_report]):
        diff = file_report.get("format_diff", "")
        if not file_report.get("has_text_differences"):
            continue
        rule_statuses = [rule.get("status") for rule in file_report.get("rules", [])]
        format_only = bool(diff) and rule_statuses and all(status == "equivalent" for status in rule_statuses)
        records.append(
            {
                "baseline_label": file_report.get("baseline_label"),
                "candidate_label": file_report.get("candidate_label"),
                "format_only": format_only,
                "whitespace_only": file_report.get("whitespace_only"),
                "classification": "format_only" if format_only else "also_has_semantic_or_gate_issue",
                "notification_color": "green" if format_only else "red",
                "changed_rules": [rule.get("rule") for rule in file_report.get("rules", [])],
                "diff": diff,
            }
        )
    return records


def condition_change_records(multi_report: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for file_report, rule_report in iter_rule_reports(multi_report):
        if rule_report.get("status") != "condition_change":
            continue
        records.append(
            {
                "rule": rule_report["rule"],
                "notification_color": "red",
                "baseline_label": file_report.get("baseline_label"),
                "candidate_label": file_report.get("candidate_label"),
                "condition_terms_equal": rule_report.get("condition_terms_equal"),
                "baseline_condition_terms": rule_report.get("baseline_condition_terms"),
                "candidate_condition_terms": rule_report.get("candidate_condition_terms"),
                "assignment_space": rule_report.get("assignment_space"),
                "counterexample": rule_report.get("counterexample"),
            }
        )
    return records


def uncertain_records(multi_report: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for file_report, rule_report in iter_rule_reports(multi_report):
        if rule_report.get("status") == "uncertain":
            records.append(
                {
                    "rule": rule_report["rule"],
                    "notification_color": "amber",
                    "baseline_label": file_report.get("baseline_label"),
                    "candidate_label": file_report.get("candidate_label"),
                    "limitations": rule_report.get("limitations", []),
                }
            )
    return records


def render_condition_changes_markdown(records: list[dict[str, Any]]) -> str:
    lines = ["# Condition changes with counterexamples", ""]
    if not records:
        lines.extend(["No supported condition changes with counterexamples were found.", ""])
        return "\n".join(lines)

    for record in records:
        witness = record["counterexample"]
        lines.append(f"## 🔴 {record['rule']}")
        lines.append("")
        lines.append(f"- Baseline: `{record['baseline_label']}`")
        lines.append(f"- Candidate: `{record['candidate_label']}`")
        baseline_terms = " ".join(record.get("baseline_condition_terms") or [])
        candidate_terms = " ".join(record.get("candidate_condition_terms") or [])
        lines.append(f"- Baseline condition: `{baseline_terms}`")
        lines.append(f"- Candidate condition: `{candidate_terms}`")
        lines.append(f"- Baseline result: `{witness['baseline_result']}`")
        lines.append(f"- Candidate result: `{witness['candidate_result']}`")
        lines.append("")
        lines.append("| Abstract atom | Occurrences | Match |")
        lines.append("| --- | ---: | --- |")
        for assignment in witness["assignments"]:
            lines.append(
                f"| `{assignment['atom']}` | {assignment['occurrences']} | {assignment['matches']} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_report_markdown(multi_report: dict[str, Any]) -> str:
    condition_changes = condition_change_records(multi_report)
    uncertain = uncertain_records(multi_report)
    format_differences = format_difference_records(multi_report)
    lines = ["# Plyara round-trip quality gate", ""]
    overall_status = multi_report.get("status", "unknown")
    lines.append(f"Overall status: **{status_color(overall_status)} {overall_status}**")
    lines.append("")
    lines.append(f"- 🟢 Format difference files: {len(format_differences)}")
    lines.append(f"- 🔴 Condition changes with counterexamples: {len(condition_changes)}")
    lines.append(f"- 🟡 Uncertain rules: {len(uncertain)}")
    lines.append("")

    for file_report in multi_report.get("files", [multi_report]):
        lines.append(f"## `{file_report.get('baseline_label')}` → `{file_report.get('candidate_label')}`")
        lines.append("")
        if file_report.get("parse_error") or file_report.get("candidate_parse_error"):
            parse_error = file_report.get("baseline_parse_error") or file_report.get(
                "candidate_parse_error"
            )
            lines.append(f"Parse error: `{parse_error}`")
            lines.append("")
            continue
        for rule in file_report.get("rules", []):
            color = status_color(rule["status"])
            lines.append(f"- {color} `{rule['rule']}`: `{rule['status']}`")
        lines.append("")

    lines.append("## Uncertain syntax boundary")
    lines.append("")
    for capability in UNCERTAIN_CAPABILITIES:
        lines.append(f"- {capability}")
    lines.append("")
    return "\n".join(lines)


def status_color(status: str) -> str:
    good = {"pass", "equivalent", "format_only"}
    bad = {
        "fail",
        "condition_change",
        "string_definition_change",
        "scope_change",
        "dependency_definition_change",
        "missing_rule",
        "parse_error",
    }
    if status in good:
        return "🟢"
    if status in bad:
        return "🔴"
    return "🟡"


def write_exports(multi_report: dict[str, Any], out_dir: Path) -> dict[str, str]:
    """Write separate format-difference and condition-change export files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    format_records = format_difference_records(multi_report)
    condition_records = condition_change_records(multi_report)
    uncertain = uncertain_records(multi_report)

    format_diff_path = out_dir / "format_differences.diff"
    format_json_path = out_dir / "format_differences.json"
    condition_json_path = out_dir / "condition_changes.json"
    condition_md_path = out_dir / "condition_changes.md"
    uncertain_path = out_dir / "uncertain_capabilities.json"
    report_json_path = out_dir / "gate_report.json"
    report_md_path = out_dir / "gate_report.md"

    diff_chunks = []
    for record in format_records:
        diff_chunks.append(record["diff"])
    format_diff_text = "\n".join(chunk for chunk in diff_chunks if chunk)
    if diff_chunks:
        format_diff_text += "\n"
    format_diff_path.write_text(format_diff_text, encoding="utf-8")
    format_json_path.write_text(json.dumps(format_records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    condition_json_path.write_text(json.dumps(condition_records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    condition_md_path.write_text(render_condition_changes_markdown(condition_records), encoding="utf-8")
    uncertain_path.write_text(
        json.dumps(
            {"capabilities": UNCERTAIN_CAPABILITIES, "rules": uncertain},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    report_json_path.write_text(json.dumps(multi_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_md_path.write_text(render_report_markdown(multi_report), encoding="utf-8")

    return {
        "format_diff": str(format_diff_path),
        "format_json": str(format_json_path),
        "condition_json": str(condition_json_path),
        "condition_markdown": str(condition_md_path),
        "uncertain_json": str(uncertain_path),
        "report_json": str(report_json_path),
        "report_markdown": str(report_md_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="Original YARA file or directory")
    parser.add_argument("candidate", type=Path, help="Formatted/candidate YARA file or directory")
    parser.add_argument("--out-dir", type=Path, help="Directory for all JSON/Markdown/diff exports")
    parser.add_argument("--format-diff-out", type=Path, help="Write unified format diff here")
    parser.add_argument("--counterexamples-out", type=Path, help="Write condition counterexamples JSON here")
    parser.add_argument("--report-json-out", type=Path, help="Write full JSON report here")
    parser.add_argument("--max-assignments", type=int, default=DEFAULT_MAX_ASSIGNMENTS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    multi_report = compare_paths(args.baseline, args.candidate, args.max_assignments)

    if args.out_dir:
        paths = write_exports(multi_report, args.out_dir)
        print(json.dumps({"status": multi_report.get("status"), "exports": paths}, ensure_ascii=False, indent=2))

    if args.format_diff_out:
        records = format_difference_records(multi_report)
        args.format_diff_out.parent.mkdir(parents=True, exist_ok=True)
        args.format_diff_out.write_text("\n".join(record["diff"] for record in records) + "\n", encoding="utf-8")

    if args.counterexamples_out:
        records = condition_change_records(multi_report)
        args.counterexamples_out.parent.mkdir(parents=True, exist_ok=True)
        args.counterexamples_out.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.report_json_out:
        args.report_json_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_json_out.write_text(json.dumps(multi_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if not args.out_dir and not any([args.format_diff_out, args.counterexamples_out, args.report_json_out]):
        print(json.dumps(multi_report, ensure_ascii=False, indent=2))

    status = multi_report.get("status")
    if status == "pass":
        return 0
    if status == "inconclusive":
        return 3
    return 2


if __name__ == "__main__":
    sys.exit(main())
