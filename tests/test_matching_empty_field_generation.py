from __future__ import annotations

import json
import os
import random
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import pytest

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.matching import Event, EventLogSource
from sigma.matching.compiler import MatchCompiler
from sigma.rule.rule import SigmaRule
from sigma.types import SigmaExists, SigmaNull, SigmaString

SEED = 20261122
GENERATED_CASE_COUNT = 24
MAX_TREE_DEPTH = 3
FIELD = "ProductName"
NONEMPTY_VALUE = "plain-label"
LOGSOURCE = EventLogSource(category="inventory", product="retail")
FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FieldState(Enum):
    """The three empty-forms plus a non-empty control, kept deliberately tiny."""

    MISSING = "missing"
    NULL = "null"
    EMPTY = "empty_text"
    VALUE = "nonempty_text"

    def as_data(self) -> dict[str, object]:
        if self is FieldState.MISSING:
            return {}
        if self is FieldState.NULL:
            return {FIELD: None}
        if self is FieldState.EMPTY:
            return {FIELD: ""}
        return {FIELD: NONEMPTY_VALUE}


STATES = tuple(FieldState)

class Atom(Enum):
    """Finite, explainable set of field-level operations used to build rules.

    Only four leaf predicates are needed to separate the three empty forms.
    All richer behaviour is produced by AND/OR/NOT over these leaves, so the
    operation surface stays auditable.
    """

    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    IS_NULL = "is_null"
    IS_EMPTY_TEXT = "is_empty_text"

    @property
    def selector_name(self) -> str:
        return f"sel_{self.value}"

    def selection_yaml(self) -> str:
        if self is Atom.EXISTS:
            return f"{FIELD}|exists: true"
        if self is Atom.NOT_EXISTS:
            return f"{FIELD}|exists: false"
        if self is Atom.IS_NULL:
            return f"{FIELD}: null"
        return f"{FIELD}: \x27\x27"

    def reference(self, state: FieldState) -> bool:
        """Independent first-principles truth table (no pySigma import here)."""
        present = state is not FieldState.MISSING
        if self is Atom.EXISTS:
            return present
        if self is Atom.NOT_EXISTS:
            return not present
        if self is Atom.IS_NULL:
            return state in (FieldState.MISSING, FieldState.NULL)
        return state in (FieldState.MISSING, FieldState.EMPTY)


ATOMS = tuple(Atom)

@dataclass(frozen=True)
class Expr: ...


@dataclass(frozen=True)
class Leaf(Expr):
    atom: Atom


@dataclass(frozen=True)
class Not(Expr):
    operand: Expr


@dataclass(frozen=True)
class And(Expr):
    operands: tuple[Expr, ...]


@dataclass(frozen=True)
class Or(Expr):
    operands: tuple[Expr, ...]


def reference_eval(expr: Expr, state: FieldState) -> bool:
    """Evaluate an expression purely against the independent truth table."""
    if isinstance(expr, Leaf):
        return expr.atom.reference(state)
    if isinstance(expr, Not):
        return not reference_eval(expr.operand, state)
    if isinstance(expr, And):
        return all(reference_eval(child, state) for child in expr.operands)
    return any(reference_eval(child, state) for child in expr.operands)

def generate_expressions(seed: int, count: int, max_depth: int) -> list[Expr]:
    """Deterministically build a small, deduplicated set of boolean expressions."""
    rng = random.Random(seed)
    seen: set[Expr] = set()
    ordered: list[Expr] = []

    def remember(expr: Expr) -> None:
        if expr not in seen:
            seen.add(expr)
            ordered.append(expr)

    for atom in ATOMS:
        remember(Leaf(atom))

    def grow(depth: int) -> Expr:
        if depth <= 1:
            return Leaf(rng.choice(ATOMS))
        choice = rng.randrange(4)
        if choice == 0:
            return Not(grow(depth - 1))
        if choice == 1:
            arity = rng.randint(2, 3)
            return And(tuple(grow(depth - 1) for _ in range(arity)))
        if choice == 2:
            arity = rng.randint(2, 3)
            return Or(tuple(grow(depth - 1) for _ in range(arity)))
        return Leaf(rng.choice(ATOMS))

    guard = 0
    while len(ordered) < count and guard < count * 20:
        guard += 1
        remember(grow(max_depth))
    return ordered[:count]

def collect_atoms(expr: Expr) -> set[Atom]:
    if isinstance(expr, Leaf):
        return {expr.atom}
    if isinstance(expr, Not):
        return collect_atoms(expr.operand)
    result: set[Atom] = set()
    for child in expr.operands:
        result.update(collect_atoms(child))
    return result


def condition_string(expr: Expr) -> str:
    if isinstance(expr, Leaf):
        return expr.atom.selector_name
    if isinstance(expr, Not):
        return f"not ({condition_string(expr.operand)})"
    joiner = " and " if isinstance(expr, And) else " or "
    parts = [f"({condition_string(child)})" for child in expr.operands]
    return joiner.join(parts)


def build_rule_yaml(expr: Expr, index: int) -> str:
    atoms = sorted(collect_atoms(expr), key=lambda item: item.value)
    lines = [
        "title: Empty Field Generation Case",
        f"name: empty_field_case_{index:03d}",
        "status: test",
        "logsource:",
        "    category: inventory",
        "    product: retail",
        "detection:",
    ]
    for atom in atoms:
        lines.append(f"    {atom.selector_name}:")
        lines.append(f"        {atom.selection_yaml()}")
    lines.append(f"    condition: {condition_string(expr)}")
    return "\n".join(lines) + "\n"

class ParseDivergence(Exception):
    """Raised when the Sigma parser cannot be mapped back to the finite op-set."""


def _translate_leaf(node: ConditionFieldEqualsValueExpression) -> Atom:
    if node.field != FIELD:
        raise ParseDivergence(f"unexpected field {node.field!r}")
    value = node.value
    if isinstance(value, SigmaExists):
        return Atom.EXISTS if value.exists else Atom.NOT_EXISTS
    if isinstance(value, SigmaNull):
        return Atom.IS_NULL
    if isinstance(value, SigmaString) and str(value) == "":
        return Atom.IS_EMPTY_TEXT
    raise ParseDivergence(f"unsupported value {type(value).__name__}: {value!r}")


def translate_node(node: object) -> Expr:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return Leaf(_translate_leaf(node))
    if isinstance(node, ConditionNOT):
        return Not(translate_node(node.args[0]))
    if isinstance(node, ConditionAND):
        return And(tuple(translate_node(arg) for arg in node.args))
    if isinstance(node, ConditionOR):
        return Or(tuple(translate_node(arg) for arg in node.args))
    raise ParseDivergence(f"unsupported condition node {type(node).__name__}")

@dataclass
class StateResult:
    state: FieldState
    expected: bool
    parsed_semantics: bool
    local_match: bool

    @property
    def parse_diverges(self) -> bool:
        return self.parsed_semantics != self.expected

    @property
    def local_diverges(self) -> bool:
        return self.local_match != self.expected


@dataclass
class CaseRecord:
    case_id: str
    expression: Expr
    condition: str
    rule_yaml: str
    parse_ok: bool
    parse_error: str | None
    translated: Expr | None
    state_results: list[StateResult] = field(default_factory=list)

    @property
    def has_divergence(self) -> bool:
        return (not self.parse_ok) or any(
            result.parse_diverges or result.local_diverges for result in self.state_results
        )

def _make_event(state: FieldState) -> Event:
    return Event(
        timestamp=FIXED_TIMESTAMP,
        logsource=LOGSOURCE,
        data=dict(state.as_data()),
    )


def evaluate_case(expr: Expr, index: int) -> CaseRecord:
    case_id = f"case_{index:03d}"
    rule_yaml = build_rule_yaml(expr, index)
    record = CaseRecord(
        case_id=case_id,
        expression=expr,
        condition=condition_string(expr),
        rule_yaml=rule_yaml,
        parse_ok=False,
        parse_error=None,
        translated=None,
    )

    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
        rule = collection.rules[0]
        assert isinstance(rule, SigmaRule)
        parsed_node = rule.detection.parsed_condition[0].parsed
        translated = translate_node(parsed_node)
        record.parse_ok = True
        record.translated = translated
    except Exception as exc:
        record.parse_error = f"{type(exc).__name__}: {exc}"
        return record

    compiled = MatchCompiler().compile_rule(rule)
    for state in STATES:
        event = _make_event(state)
        expected = reference_eval(expr, state)
        parsed_semantics = reference_eval(translated, state)
        local_match = bool(compiled(event.data, event.get_raw()))
        record.state_results.append(
            StateResult(state, expected, parsed_semantics, local_match)
        )
    return record

def classify(record: CaseRecord) -> str:
    if not record.parse_ok:
        return "condition-parse-divergence"
    parse_bad = [r.state.value for r in record.state_results if r.parse_diverges]
    local_bad = [r.state.value for r in record.state_results if r.local_diverges]
    if parse_bad:
        return "condition-parse-divergence:" + ",".join(parse_bad)
    if local_bad:
        return "local-match-divergence:" + ",".join(local_bad)
    return "consistent"


def record_to_dict(record: CaseRecord) -> dict[str, object]:
    return {
        "case_id": record.case_id,
        "condition": record.condition,
        "parse_ok": record.parse_ok,
        "parse_error": record.parse_error,
        "classification": classify(record),
        "rule_yaml": record.rule_yaml,
        "states": [
            {
                "state": result.state.value,
                "expected": result.expected,
                "parsed_semantics": result.parsed_semantics,
                "local_match": result.local_match,
            }
            for result in record.state_results
        ],
    }

def render_truth_table() -> str:
    header = "operation".ljust(14) + "".join(state.value.ljust(13) for state in STATES)
    rows = [header, "-" * len(header)]
    for atom in ATOMS:
        row = atom.value.ljust(14)
        for state in STATES:
            row += str(int(atom.reference(state))).ljust(13)
        rows.append(row)
    return "\n".join(rows)


def render_record(record: CaseRecord) -> str:
    lines = [
        f"[{record.case_id}] classification={classify(record)}",
        f"condition: {record.condition}",
    ]
    if not record.parse_ok:
        lines.append(f"parse error: {record.parse_error}")
    for result in record.state_results:
        marker = "OK" if not (result.parse_diverges or result.local_diverges) else "DIFF"
        lines.append(
            "    "
            + result.state.value.ljust(12)
            + f" expected={int(result.expected)} parsed={int(result.parsed_semantics)}"
            + f" local={int(result.local_match)} {marker}"
        )
    lines.append("rule yaml:")
    lines.extend("    " + line for line in record.rule_yaml.splitlines())
    return "\n".join(lines)

def run_suite(seed: int = SEED, count: int = GENERATED_CASE_COUNT) -> list[CaseRecord]:
    expressions = generate_expressions(seed, count, MAX_TREE_DEPTH)
    return [evaluate_case(expr, index) for index, expr in enumerate(expressions)]


def reduce_to_diverging(records: list[CaseRecord]) -> list[CaseRecord]:
    """Compress a failing run to only the diverging cases (delta-debug by case)."""
    bad = [record for record in records if record.has_divergence]
    if not bad:
        return []
    kept: list[CaseRecord] = []
    for record in bad:
        candidate = kept + [record]
        if any(item.has_divergence for item in candidate):
            kept.append(record)
    return kept


REPLAY_TEMPLATE = """#!/usr/bin/env python3
# One-command replay of the reduced empty-field divergence (no network, in-memory).
sys.path.insert(0, {repo!r})
from {module} import (
    evaluate_case, generate_expressions, reduce_to_diverging,
    render_record, render_truth_table, MAX_TREE_DEPTH,
)

seed = {seed}
count = {count}
depth = {depth}
reduced_indices = {indices!r}
print("Reference truth table (independent of the matcher):")
print(render_truth_table())
print()
expressions = generate_expressions(seed, count, depth)
all_records = [evaluate_case(expr, i) for i, expr in enumerate(expressions)]
reduced = [evaluate_case(expressions[i], i) for i in reduced_indices]
print(f"replaying {{len(reduced)}} reduced of {{len(all_records)}} generated cases")
still_bad = [record for record in reduced if record.has_divergence]
for record in reduced:
    print(render_record(record))
    print()
print(f"summary: {{len(still_bad)}} of the reduced cases still diverge")
sys.exit(1 if still_bad else 0)
"""


MODULE_NAME = "tests.test_matching_empty_field_generation"


def materialize_failure(records: list[CaseRecord]) -> dict[str, str]:
    reduced = reduce_to_diverging(records)
    artifact_dir = Path(tempfile.mkdtemp(prefix="sigma_empty_field_"))
    jsonl_path = artifact_dir / "reduced_cases.jsonl"
    replay_path = artifact_dir / "replay.py"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for record in reduced:
            handle.write(json.dumps(record_to_dict(record), ensure_ascii=False) + "\n")
    reduced_indices = [int(record.case_id.split("_")[1]) for record in reduced]
    repo_root = Path(__file__).resolve().parents[1]
    replay_path.write_text(
        REPLAY_TEMPLATE.format(
            repo=str(repo_root),
            module=MODULE_NAME,
            seed=SEED,
            count=GENERATED_CASE_COUNT,
            depth=MAX_TREE_DEPTH,
            indices=reduced_indices,
        ),
        encoding="utf-8",
    )
    os.chmod(replay_path, 0o755)
    return {
        "artifact_dir": str(artifact_dir),
        "jsonl": str(jsonl_path),
        "replay": str(replay_path),
        "replay_command": f"python {replay_path}",
    }

class TestEmptyFieldGeneration:
    def test_reference_table_separates_three_empty_forms(self):
        signatures = {
            state: tuple(int(atom.reference(state)) for atom in ATOMS) for state in STATES
        }
        assert len(set(signatures.values())) == len(STATES)
        assert signatures[FieldState.MISSING] != signatures[FieldState.NULL]
        assert signatures[FieldState.NULL] != signatures[FieldState.EMPTY]
        assert signatures[FieldState.MISSING] != signatures[FieldState.EMPTY]

    def test_generation_is_deterministic(self):
        first = generate_expressions(SEED, GENERATED_CASE_COUNT, MAX_TREE_DEPTH)
        second = generate_expressions(SEED, GENERATED_CASE_COUNT, MAX_TREE_DEPTH)
        assert first == second
        assert len(first) == GENERATED_CASE_COUNT

    def test_parser_and_local_matcher_match_reference_table(self):
        records = run_suite()
        material = materialize_failure(records)
        diverging = [record for record in records if record.has_divergence]
        if diverging:
            report = ["", render_truth_table(), ""]
            for record in reduce_to_diverging(records):
                report.append(render_record(record))
            report.append("Replay reduced case with: " + material["replay_command"])
            report.append("Reduced JSONL: " + material["jsonl"])
            pytest.fail("\n".join(report), pytrace=False)

    def test_every_case_keeps_parse_and_local_results(self):
        records = run_suite()
        for record in records:
            assert record.parse_ok, record.parse_error
            assert record.translated is not None
            assert {result.state for result in record.state_results} == set(STATES)
            for result in record.state_results:
                assert isinstance(result.expected, bool)
                assert isinstance(result.parsed_semantics, bool)
                assert isinstance(result.local_match, bool)
