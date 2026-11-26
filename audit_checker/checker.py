"""Path-sensitive audit credential checking with pycparser."""

from __future__ import annotations

import copy
import fnmatch
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pycparser import CParser, c_ast


class AuditCheckError(Exception):
    """Base error for backend calls."""


class AuditParseError(AuditCheckError):
    """Raised when preprocessed C cannot be parsed by pycparser."""


ROLE_ALIASES = {
    "change": "change",
    "mutate": "change",
    "write": "change",
    "protected_write": "change",
    "变更": "change",
    "写入": "change",
    "withdraw": "withdraw",
    "rollback": "withdraw",
    "undo": "withdraw",
    "撤回": "withdraw",
    "回滚": "withdraw",
    "credential": "credential",
    "commit": "credential",
    "audit": "credential",
    "voucher": "credential",
    "凭据": "credential",
    "提交凭据": "credential",
    "记账": "credential",
    "pure": "pure",
    "benign": "pure",
    "none": "pure",
}

DEFAULT_PURE = {
    "memcpy", "memmove", "memset", "strlen", "strcmp", "strncmp",
    "strcpy", "strncpy", "strchr", "strrchr", "snprintf", "sprintf",
    "printf", "fprintf", "puts", "fputs", "malloc", "calloc", "realloc",
    "free", "alloca", "abort", "exit",
}


@dataclass(frozen=True)
class Contract:
    role: str
    resource_arg: int | None = 0
    success: Any = 0
    pure: bool = False
    description: str = ""


def contracts_from_mapping(mapping: dict[str, Any] | None) -> dict[str, Contract]:
    result: dict[str, Contract] = {}
    for name, raw in (mapping or {}).items():
        data = {"role": raw} if isinstance(raw, str) else dict(raw)
        role_value = data.get("role", data.get("kind", data.get("type")))
        role_key = str(role_value).strip().lower()
        role = ROLE_ALIASES.get(role_key) or ROLE_ALIASES.get(str(role_value).strip())
        if role is None:
            raise AuditCheckError(f"unknown contract role for {name!r}: {role_value!r}")

        resource_arg = data.get("resource_arg", data.get("arg", 0))
        if resource_arg is not None:
            resource_arg = int(resource_arg)

        success = data.get("success_return", data.get("success", 0 if role == "change" else None))
        if success in ("nonzero", "non_zero", "truthy"):
            success = "nonzero"
        elif isinstance(success, dict):
            if "return" in success:
                success = success["return"]
        elif isinstance(success, str):
            try:
                success = int(success)
            except ValueError:
                pass

        result[name] = Contract(
            role=role,
            resource_arg=resource_arg,
            success=success,
            pure=bool(data.get("pure", role == "pure")),
            description=str(data.get("description", "")),
        )
    return result


def parse_preprocessed(source: str | Path, source_name: str = "<audit-input>"):
    if isinstance(source, Path):
        source_name = str(source)
        source = source.read_text(encoding="utf-8")
    if not isinstance(source, str):
        raise AuditCheckError("source must be preprocessed C source text or a Path")

    original_lines = source.splitlines()
    kept_lines: list[str] = []
    for line in original_lines:
        stripped = line.lstrip()
        if stripped.startswith("#") and _is_line_marker(stripped):
            kept_lines.append("")
        else:
            kept_lines.append(line)

    parse_text = _strip_comments_preserve_lines("\n".join(kept_lines))
    parser = CParser()
    try:
        ast = parser.parse(parse_text, filename=str(source_name))
    except Exception as exc:
        raise AuditParseError(f"pycparser could not parse {source_name}: {exc}") from exc
    return ast, original_lines


def _is_line_marker(directive: str) -> bool:
    body = directive[1:].strip()
    if body.startswith("line"):
        body = body[4:].strip()
    first = body.split(" ", 1)[0] if body else ""
    return first.isdigit()


def _strip_comments_preserve_lines(text: str) -> str:
    output: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        two = text[index:index + 2]
        char = text[index]
        if state == "code":
            if two == "/*":
                output.extend("  ")
                index += 2
                state = "block_comment"
                continue
            if two == "//":
                output.extend("  ")
                index += 2
                state = "line_comment"
                continue
            if char in {'"', "'"}:
                quote = char
                state = "string"
            output.append(char)
            index += 1
            continue
        if state == "block_comment":
            if two == "*/":
                output.extend("  ")
                index += 2
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                output.append(char)
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "string":
            output.append(char)
            if char == "\\" and index + 1 < len(text):
                output.append(text[index + 1])
                index += 2
                continue
            if char == quote:
                state = "code"
            index += 1
    return "".join(output)


@dataclass
class SValue:
    pass


@dataclass
class UnknownValue(SValue):
    reason: str = ""


@dataclass
class ConstValue(SValue):
    integer: int | None = None
    raw: str = ""


@dataclass
class KeyValue(SValue):
    key: str = ""


@dataclass
class ResultValue(SValue):
    uid: int = 0
    success: Any = 0


@dataclass
class BoundValue(SValue):
    value: SValue | None = None
    key: str | None = None


@dataclass
class Step:
    kind: str
    function: str
    line: int | None
    file: str
    code: str
    note: str = ""


@dataclass
class Boundary:
    function: str
    line: int | None
    callee: str
    reason: str


@dataclass
class ChangeEvent:
    uid: int
    key: str
    line: int | None
    function: str
    callee: str
    status: str = "unknown"
    withdrawn_uid: int | None = None


@dataclass
class CreditEvent:
    uid: int
    key: str
    line: int | None
    function: str
    callee: str


@dataclass
class WithdrawalEvent:
    uid: int
    key: str
    line: int | None
    function: str
    callee: str
    matched_change_uid: int | None = None


@dataclass
class State:
    scopes: list[dict[str, SValue]] = field(default_factory=lambda: [{}])
    function_stack: list[str] = field(default_factory=list)
    changes: list[ChangeEvent] = field(default_factory=list)
    credits: list[CreditEvent] = field(default_factory=list)
    withdrawals: list[WithdrawalEvent] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    boundaries: list[Boundary] = field(default_factory=list)
    values_by_node: dict[int, SValue] = field(default_factory=dict)
    loop_counts: dict[int, int] = field(default_factory=dict)
    loop_snapshots: dict[int, list[dict[str, tuple[int, ...]]]] = field(default_factory=dict)
    jump_count: int = 0
    next_uid: int = 1

    def clone(self) -> "State":
        return copy.deepcopy(self)

    @property
    def function(self) -> str:
        return self.function_stack[-1] if self.function_stack else "<unknown>"

    def lookup_binding(self, name: str) -> SValue | None:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def assign(self, name: str, value: SValue) -> None:
        for scope in reversed(self.scopes):
            if name in scope:
                scope[name] = value
                return
        self.scopes[-1][name] = value

    def declare(self, name: str | None, value: SValue | None = None) -> None:
        if name:
            self.scopes[-1][name] = value or UnknownValue()

    def trace(
        self,
        ctx: "Context",
        kind: str,
        *,
        node: c_ast.Node | None = None,
        line: int | None = None,
        note: str = "",
    ) -> None:
        if line is None and node is not None and getattr(node, "coord", None) is not None:
            line = node.coord.line
        self.steps.append(
            Step(
                kind=kind,
                function=self.function,
                line=line,
                file=ctx.source_name,
                code=ctx.source_line(line),
                note=note,
            )
        )

    def interrupt(self, ctx: "Context", callee: str, line: int | None, reason: str) -> None:
        boundary = Boundary(self.function, line, callee, reason)
        self.boundaries.append(boundary)
        self.trace(ctx, "boundary", line=line, note="proof interrupted: " + reason)


@dataclass
class Context:
    source_name: str
    source_lines: list[str]
    functions: dict[str, c_ast.FuncDef]
    contracts: dict[str, Contract]
    pure_functions: set[str]
    max_loop_unroll: int = 2
    max_jumps: int = 32
    max_helper_depth: int = 1

    def source_line(self, line: int | None) -> str:
        if line is None or line < 1 or line > len(self.source_lines):
            return ""
        return self.source_lines[line - 1].strip()

    def is_pure(self, name: str) -> bool:
        if name in self.contracts and self.contracts[name].role == "pure":
            return True
        if name in self.pure_functions:
            return True
        return any(fnmatch.fnmatch(name, pattern) for pattern in self.pure_functions if "*" in pattern or "?" in pattern)


@dataclass
class CallResult:
    state: State
    value: SValue


@dataclass
class Outcome:
    state: State
    kind: str = "fall"
    label: str | None = None
    value: SValue | None = None
    line: int | None = None


class _ForkedCall(Exception):
    def __init__(self, results: list[CallResult]):
        self.results = results


@dataclass
class ExitReport:
    exit_kind: str
    exit_line: int | None
    status: str
    message: str
    ledger: list[dict[str, Any]]
    problems: list[dict[str, Any]]
    boundaries: list[dict[str, Any]]
    path: list[dict[str, Any]]
    path_text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionReport:
    function: str
    verdict: str
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    exits: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def audit_source(
    source: str | Path,
    contracts: dict[str, Any] | None = None,
    *,
    function: str | None = None,
    source_name: str = "<audit-input>",
    pure_functions: list[str] | set[str] | None = None,
    max_loop_unroll: int = 2,
) -> dict[str, Any]:
    ast, lines = parse_preprocessed(source, source_name)
    functions = _collect_functions(ast)
    ctx = Context(
        source_name=str(source_name),
        source_lines=lines,
        functions=functions,
        contracts=contracts_from_mapping(contracts),
        pure_functions=set(DEFAULT_PURE) | set(pure_functions or []),
        max_loop_unroll=max_loop_unroll,
    )

    if function is not None:
        if function not in functions:
            raise AuditCheckError(f"function {function!r} was not found in preprocessed source")
        return analyze_function(function, ctx).to_dict()

    reports = {name: analyze_function(name, ctx).to_dict() for name in sorted(functions)}
    verdicts = [report["verdict"] for report in reports.values()]
    return {
        "source_name": str(source_name),
        "verdict": _aggregate_verdicts(verdicts),
        "functions": reports,
    }


def check_c_code(
    source: str | Path,
    contracts: dict[str, Any] | None = None,
    function: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Backend-friendly alias returning JSON-serializable dictionaries."""

    return audit_source(source, contracts, function=function, **kwargs)


def audit_file(
    path: str | Path,
    contracts: dict[str, Any] | None = None,
    function: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    path = Path(path)
    return audit_source(
        path.read_text(encoding="utf-8"),
        contracts,
        function=function,
        source_name=str(path),
        **kwargs,
    )


def _collect_functions(ast: c_ast.FileAST) -> dict[str, c_ast.FuncDef]:
    functions: dict[str, c_ast.FuncDef] = {}
    for node in ast.ext:
        if isinstance(node, c_ast.FuncDef) and node.decl and node.decl.name:
            functions[node.decl.name] = node
    return functions


def analyze_function(name: str, ctx: Context) -> FunctionReport:
    func = ctx.functions[name]
    state = State()
    state.function_stack = [name]
    for param in _parameter_decls(func):
        state.declare(param.name, KeyValue(f"{name}:param:{param.name}"))

    outcomes = exec_statement(func.body, state, ctx, 0)
    exits: list[ExitReport] = []
    for outcome in outcomes:
        st = outcome.state
        line = outcome.line or _last_line(st) or getattr(func.decl.coord, "line", None)
        if outcome.kind in ("return", "fall"):
            exits.append(_evaluate_exit(st, ctx, outcome.kind, line))
        elif outcome.kind == "goto":
            st.interrupt(ctx, "goto " + str(outcome.label), line, f"goto label {outcome.label!r} is outside the modeled blocks")
            exits.append(_evaluate_exit(st, ctx, outcome.kind, line))
        else:
            st.interrupt(ctx, outcome.kind, line, f"control flow {outcome.kind!r} is outside a loop/switch")
            exits.append(_evaluate_exit(st, ctx, outcome.kind, line))

    exits.sort(key=lambda item: (item.exit_line or 10**9, len(item.path_text), item.status))
    exit_dicts = [item.to_dict() for item in exits]
    verdict, findings = _build_findings(exit_dicts)
    summary = {
        "exit_count": len(exit_dicts),
        "status_counts": _count_by(exit_dicts, "status"),
        "boundary_count": sum(len(item.boundaries) for item in exits),
        "rollback_verified": any(
            row["withdrawn_changes"] > 0
            for item in exit_dicts
            for row in item["ledger"]
        ),
    }
    return FunctionReport(name, verdict, summary, findings, exit_dicts)


def _parameter_decls(func: c_ast.FuncDef) -> list[c_ast.Decl]:
    func_decl = func.decl.type
    args = getattr(func_decl, "args", None)
    if args is None:
        return []
    params = getattr(args, "params", args)
    result: list[c_ast.Decl] = []
    for param in params or []:
        if isinstance(param, c_ast.Decl) and param.name:
            result.append(param)
    return result


def _last_line(state: State) -> int | None:
    return state.steps[-1].line if state.steps else None


def exec_statement(stmt: c_ast.Node | None, state: State, ctx: Context, depth: int) -> list[Outcome]:
    if stmt is None:
        return [Outcome(state)]
    try:
        return _exec_statement(stmt, state, ctx, depth)
    except _ForkedCall as forked:
        return [Outcome(result.state, value=result.value) for result in forked.results]


def _exec_statement(stmt: c_ast.Node, state: State, ctx: Context, depth: int) -> list[Outcome]:
    if isinstance(stmt, c_ast.Compound):
        return _exec_block(stmt.block_items or [], state, ctx, depth)

    if isinstance(stmt, c_ast.DeclList):
        outcomes = [Outcome(state)]
        for decl in stmt.decls:
            next_outcomes: list[Outcome] = []
            for outcome in outcomes:
                if outcome.kind == "fall":
                    next_outcomes.extend(exec_statement(decl, outcome.state, ctx, depth))
                else:
                    next_outcomes.append(outcome)
            outcomes = next_outcomes
        return outcomes

    if isinstance(stmt, c_ast.Decl):
        if stmt.init is None:
            state.declare(stmt.name, UnknownValue("uninitialized local"))
            return [Outcome(state)]
        if isinstance(stmt.init, c_ast.FuncCall):
            results = invoke_call(stmt.init, state, ctx, depth)
            outcomes = []
            for result in results:
                result.state.declare(stmt.name, result.value)
                outcomes.append(Outcome(result.state, value=result.value))
            return outcomes
        value = eval_expr(stmt.init, state, ctx, depth)
        key = resource_key(stmt.init, state, ctx)
        if stmt.name:
            state.scopes[-1][stmt.name] = BoundValue(value=value, key=key) if key else value
        return [Outcome(state, value=value)]

    if isinstance(stmt, c_ast.Assignment):
        return _exec_assignment(stmt, state, ctx, depth)

    if isinstance(stmt, c_ast.FuncCall):
        results = invoke_call(stmt, state, ctx, depth)
        return [Outcome(result.state, value=result.value) for result in results]

    if hasattr(c_ast, "Expr") and isinstance(stmt, c_ast.Expr):
        return exec_statement(stmt.expr if hasattr(stmt, "expr") else stmt.name, state, ctx, depth)

    if isinstance(stmt, c_ast.Return):
        return _exec_return(stmt, state, ctx, depth)

    if isinstance(stmt, c_ast.If):
        return _exec_if(stmt, state, ctx, depth)

    if isinstance(stmt, c_ast.Goto):
        state.trace(ctx, "goto", node=stmt, note=f"jump to label {stmt.name}")
        return [Outcome(state, "goto", label=stmt.name, line=stmt.coord.line)]

    if isinstance(stmt, c_ast.Label):
        state.trace(ctx, "label", node=stmt, note=f"reached label {stmt.name}")
        return exec_statement(stmt.stmt, state, ctx, depth)

    if isinstance(stmt, c_ast.Break):
        state.trace(ctx, "break", node=stmt, note="break loop")
        return [Outcome(state, "break", line=stmt.coord.line)]

    if isinstance(stmt, c_ast.Continue):
        state.trace(ctx, "continue", node=stmt, note="continue next iteration")
        return [Outcome(state, "continue", line=stmt.coord.line)]

    if isinstance(stmt, c_ast.While):
        return _exec_while(stmt, state, ctx, depth)

    if isinstance(stmt, c_ast.DoWhile):
        return _exec_do_while(stmt, state, ctx, depth)

    if isinstance(stmt, c_ast.For):
        return _exec_for(stmt, state, ctx, depth)

    if isinstance(stmt, c_ast.EmptyStatement):
        return [Outcome(state)]

    state.interrupt(ctx, type(stmt).__name__, getattr(stmt.coord, "line", None), "unsupported C statement in checker")
    return [Outcome(state)]


def _exec_block(items: list[c_ast.Node], state: State, ctx: Context, depth: int) -> list[Outcome]:
    labels = {item.name: index for index, item in enumerate(items) if isinstance(item, c_ast.Label)}
    jobs: list[tuple[int, State]] = [(0, state)]
    terminal: list[Outcome] = []

    while jobs:
        pc, current = jobs.pop()
        if pc >= len(items):
            terminal.append(Outcome(current))
            continue

        for outcome in exec_statement(items[pc], current, ctx, depth):
            if outcome.kind == "fall":
                jobs.append((pc + 1, outcome.state))
            elif outcome.kind == "goto" and outcome.label in labels:
                outcome.state.jump_count += 1
                if outcome.state.jump_count > ctx.max_jumps:
                    outcome.state.interrupt(ctx, "goto " + str(outcome.label), outcome.line, "too many goto iterations")
                    terminal.append(Outcome(outcome.state, "return", line=outcome.line))
                else:
                    jobs.append((labels[outcome.label], outcome.state))
            else:
                terminal.append(outcome)

    return terminal


def _exec_assignment(stmt: c_ast.Assignment, state: State, ctx: Context, depth: int) -> list[Outcome]:
    if isinstance(stmt.rvalue, c_ast.FuncCall):
        results = invoke_call(stmt.rvalue, state, ctx, depth)
        outcomes = []
        for result in results:
            _assign_lvalue(stmt.lvalue, result.value, result.state, ctx, stmt.rvalue)
            outcomes.append(Outcome(result.state, value=result.value))
        return outcomes

    value = eval_expr(stmt.rvalue, state, ctx, depth)
    if stmt.op != "=":
        old_value = eval_expr(stmt.lvalue, state, ctx, depth)
        value = _compound_value(stmt.op, old_value, value)
    _assign_lvalue(stmt.lvalue, value, state, ctx, stmt.rvalue)
    return [Outcome(state, value=value)]


def _assign_lvalue(
    lvalue: c_ast.Node,
    value: SValue,
    state: State,
    ctx: Context,
    rvalue: c_ast.Node | None = None,
) -> None:
    if isinstance(lvalue, c_ast.ID):
        key = resource_key(rvalue, state, ctx) if rvalue is not None else None
        if key:
            state.assign(lvalue.name, BoundValue(value=value, key=key))
        else:
            state.assign(lvalue.name, value)


def _exec_return(stmt: c_ast.Return, state: State, ctx: Context, depth: int) -> list[Outcome]:
    if isinstance(stmt.expr, c_ast.FuncCall):
        results = invoke_call(stmt.expr, state, ctx, depth)
        outcomes = []
        for result in results:
            result.state.trace(ctx, "return", node=stmt, note="function exit")
            outcomes.append(Outcome(result.state, "return", value=result.value, line=stmt.coord.line))
        return outcomes

    value = eval_expr(stmt.expr, state, ctx, depth) if stmt.expr is not None else UnknownValue("void return")
    state.trace(ctx, "return", node=stmt, note="function exit")
    return [Outcome(state, "return", value=value, line=stmt.coord.line)]


def _exec_if(stmt: c_ast.If, state: State, ctx: Context, depth: int) -> list[Outcome]:
    branches = fork_condition(stmt.cond, state, ctx, depth)
    outcomes: list[Outcome] = []
    for truth, branch_state, note in branches:
        direction = "then" if truth else "else/skip-then"
        branch_state.trace(ctx, "branch", node=stmt, note=f"{direction}; {note}".rstrip("; "))
        body = stmt.iftrue if truth else stmt.iffalse
        if body is None:
            outcomes.append(Outcome(branch_state))
        else:
            outcomes.extend(exec_statement(body, branch_state, ctx, depth))
    return outcomes


def fork_condition(
    cond: c_ast.Node,
    state: State,
    ctx: Context,
    depth: int,
) -> list[tuple[bool, State, str]]:
    value = eval_expr(cond, state, ctx, depth)
    static_truth = truth_value(value)
    if static_truth is not None:
        note = apply_constraint(cond, static_truth, state, ctx)
        return [(static_truth, state, note)]

    true_state = state.clone()
    false_state = state.clone()
    true_note = apply_constraint(cond, True, true_state, ctx)
    false_note = apply_constraint(cond, False, false_state, ctx)
    return [(True, true_state, true_note), (False, false_state, false_note)]


def truth_value(value: SValue | None) -> bool | None:
    value = unwrap_value(value)
    if isinstance(value, ConstValue) and value.integer is not None:
        return value.integer != 0
    return None


def unwrap_value(value: SValue | None) -> SValue | None:
    while isinstance(value, BoundValue):
        value = value.value
    return value


def apply_constraint(cond: c_ast.Node, taken: bool, state: State, ctx: Context) -> str:
    atoms: list[tuple[c_ast.Node, bool]] = []
    _collect_atoms(cond, taken, atoms)
    notes: list[str] = []
    for atom, truth in atoms:
        note = _infer_atom(atom, truth, state, ctx)
        if note:
            notes.append(note)
    return "; ".join(notes)


def _collect_atoms(node: c_ast.Node, truth: bool, atoms: list[tuple[c_ast.Node, bool]]) -> None:
    unary_cls = getattr(c_ast, "Unary", c_ast.UnaryOp)
    if isinstance(node, unary_cls) and node.op == "!":
        _collect_atoms(node.expr, not truth, atoms)
        return
    if isinstance(node, c_ast.BinaryOp):
        if node.op == "&&" and truth:
            _collect_atoms(node.left, True, atoms)
            _collect_atoms(node.right, True, atoms)
            return
        if node.op == "||" and not truth:
            _collect_atoms(node.left, False, atoms)
            _collect_atoms(node.right, False, atoms)
            return
    atoms.append((node, truth))


def _infer_atom(atom: c_ast.Node, taken: bool, state: State, ctx: Context) -> str:
    target: c_ast.Node = atom
    op = "truthy"
    rhs: int | None = None

    if isinstance(atom, c_ast.BinaryOp) and atom.op in {"==", "!=", "<", "<=", ">", ">="}:
        left_value = unwrap_value(state.values_by_node.get(id(atom.left)))
        right_int = _static_int(atom.right, state)
        left_int = _static_int(atom.left, state)
        if right_int is not None and _is_result_expr(atom.left, state):
            target = atom.left
            op = atom.op
            rhs = right_int
        elif left_int is not None and _is_result_expr(atom.right, state):
            target = atom.right
            op = _flip_operator(atom.op)
            rhs = left_int
        else:
            return ""
    elif isinstance(atom, c_ast.ID):
        target = atom
    else:
        return ""

    value = unwrap_value(state.values_by_node.get(id(target)))
    if value is None and isinstance(target, c_ast.ID):
        value = unwrap_value(state.lookup_binding(target.name))
    if not isinstance(value, ResultValue):
        return ""

    fate = _fate_from_constraint(value.success, op, rhs, taken)
    if fate is None:
        return ""
    for change in state.changes:
        if change.uid == value.uid:
            change.status = fate
            return f"{change.callee} {change.key} inferred {fate}"
    return ""


def _is_result_expr(node: c_ast.Node, state: State) -> bool:
    value = unwrap_value(state.values_by_node.get(id(node)))
    if value is None and isinstance(node, c_ast.ID):
        value = unwrap_value(state.lookup_binding(node.name))
    return isinstance(value, ResultValue)


def _static_int(node: c_ast.Node, state: State) -> int | None:
    value = unwrap_value(state.values_by_node.get(id(node)))
    if isinstance(value, ConstValue) and value.integer is not None:
        return value.integer
    if isinstance(node, c_ast.Constant):
        return _constant_int(node)
    if isinstance(node, c_ast.ID):
        value = unwrap_value(state.lookup_binding(node.name))
        if isinstance(value, ConstValue):
            return value.integer
    return None


def _flip_operator(op: str) -> str:
    return {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}.get(op, op)


def _fate_from_constraint(success: Any, op: str, rhs: int | None, taken: bool) -> str | None:
    guarantees_zero = False
    guarantees_nonzero = False
    guarantees_nonnegative = False
    guarantees_negative = False

    if op == "truthy":
        guarantees_zero = not taken
        guarantees_nonzero = taken
    elif rhs == 0:
        if op == "==":
            guarantees_zero = taken
            guarantees_nonzero = not taken
        elif op == "!=":
            guarantees_nonzero = taken
            guarantees_zero = not taken
        elif op == "<":
            guarantees_negative = taken
            guarantees_nonzero = taken
            guarantees_nonnegative = not taken
        elif op == ">=":
            guarantees_nonnegative = taken
            guarantees_negative = not taken
        elif op == ">":
            guarantees_nonzero = taken
        elif op == "<=" and not taken:
            guarantees_nonzero = True

    if success == "nonzero":
        if guarantees_nonzero:
            return "succeeded"
        if guarantees_zero:
            return "failed"
        return None

    if success == ">=0":
        if guarantees_nonnegative:
            return "succeeded"
        if guarantees_negative:
            return "failed"
        if guarantees_zero:
            return "succeeded"
        return None

    if success in (0, "0", 0.0):
        if guarantees_zero:
            return "succeeded"
        if guarantees_nonzero:
            return "failed"
    return None


def _exec_while(node: c_ast.While, state: State, ctx: Context, depth: int) -> list[Outcome]:
    loop_id = id(node)
    state.loop_snapshots.setdefault(loop_id, []).append(_balance_signature(state))
    count = state.loop_counts.get(loop_id, 0)
    outcomes: list[Outcome] = []

    for truth, branch_state, note in fork_condition(node.cond, state, ctx, depth):
        branch_state.trace(
            ctx,
            "loop_condition",
            node=node,
            note=f"while after {count} iteration(s): {'exit loop' if not truth else 'enter/continue'}; {note}",
        )
        if not truth:
            outcomes.append(Outcome(branch_state))
        elif count >= ctx.max_loop_unroll:
            _widen_loop(branch_state, loop_id, ctx, node.coord.line)
            outcomes.append(Outcome(branch_state))
        else:
            branch_state.loop_counts[loop_id] = count + 1
            for body_outcome in exec_statement(node.stmt, branch_state, ctx, depth):
                if body_outcome.kind == "break":
                    outcomes.append(Outcome(body_outcome.state))
                elif body_outcome.kind in ("fall", "continue"):
                    outcomes.extend(_exec_while(node, body_outcome.state, ctx, depth))
                else:
                    outcomes.append(body_outcome)
    return outcomes


def _exec_for(node: c_ast.For, state: State, ctx: Context, depth: int) -> list[Outcome]:
    if node.init is None:
        init_outcomes = [Outcome(state)]
    else:
        init_outcomes = exec_statement(node.init, state, ctx, depth)

    outcomes: list[Outcome] = []
    for init_outcome in init_outcomes:
        if init_outcome.kind == "fall":
            outcomes.extend(_run_for(node, init_outcome.state, ctx, depth))
        else:
            outcomes.append(init_outcome)
    return outcomes


def _run_for(node: c_ast.For, state: State, ctx: Context, depth: int) -> list[Outcome]:
    loop_id = id(node)
    state.loop_snapshots.setdefault(loop_id, []).append(_balance_signature(state))
    count = state.loop_counts.get(loop_id, 0)

    if node.cond is None:
        branches = [(True, state, "omitted condition is always true")]
    else:
        branches = fork_condition(node.cond, state, ctx, depth)

    outcomes: list[Outcome] = []
    for truth, branch_state, note in branches:
        branch_state.trace(
            ctx,
            "loop_condition",
            node=node,
            note=f"for after {count} iteration(s): {'exit loop' if not truth else 'enter/continue'}; {note}",
        )
        if not truth:
            outcomes.append(Outcome(branch_state))
        elif count >= ctx.max_loop_unroll:
            _widen_loop(branch_state, loop_id, ctx, node.coord.line)
            outcomes.append(Outcome(branch_state))
        else:
            branch_state.loop_counts[loop_id] = count + 1
            body_outcomes = exec_statement(node.stmt, branch_state, ctx, depth)
            for body_outcome in body_outcomes:
                if body_outcome.kind == "break":
                    outcomes.append(Outcome(body_outcome.state))
                    continue
                if body_outcome.kind not in ("fall", "continue"):
                    outcomes.append(body_outcome)
                    continue

                next_states = [body_outcome.state]
                if node.next is not None:
                    try:
                        eval_expr(node.next, body_outcome.state, ctx, depth)
                    except _ForkedCall as forked:
                        next_states = [result.state for result in forked.results]
                for next_state in next_states:
                    outcomes.extend(_run_for(node, next_state, ctx, depth))
    return outcomes


def _exec_do_while(node: c_ast.DoWhile, state: State, ctx: Context, depth: int) -> list[Outcome]:
    outcomes: list[Outcome] = []
    loop_id = id(node)
    for body_outcome in exec_statement(node.stmt, state, ctx, depth):
        if body_outcome.kind == "break":
            outcomes.append(Outcome(body_outcome.state))
            continue
        if body_outcome.kind not in ("fall", "continue"):
            outcomes.append(body_outcome)
            continue

        current = body_outcome.state
        done = current.loop_counts.get(loop_id, 0) + 1
        current.loop_counts[loop_id] = done
        for truth, branch_state, note in fork_condition(node.cond, current, ctx, depth):
            branch_state.trace(ctx, "loop_condition", node=node, note=f"do-while after {done} iteration(s): {note}")
            if not truth:
                outcomes.append(Outcome(branch_state))
            elif done >= ctx.max_loop_unroll:
                branch_state.interrupt(ctx, "<loop>", node.coord.line, "do-while has more modeled iterations than the bounded witness set")
                outcomes.append(Outcome(branch_state))
            else:
                outcomes.extend(_exec_do_while(node, branch_state, ctx, depth))
    return outcomes


def _balance_signature(state: State) -> dict[str, tuple[int, ...]]:
    signature: dict[str, list[int]] = {}

    def row(key: str) -> list[int]:
        return signature.setdefault(key, [0, 0, 0, 0, 0])

    for change in state.changes:
        values = row(change.key)
        if change.status == "succeeded" and change.withdrawn_uid is None:
            values[0] += 1
        elif change.status == "withdrawn":
            values[3] += 1
        elif change.status == "failed":
            values[2] += 1
        else:
            values[4] += 1

    for credit in state.credits:
        row(credit.key)[1] += 1

    return {key: tuple(values) for key, values in signature.items()}


def _signature_delta(old: dict[str, tuple[int, ...]], new: dict[str, tuple[int, ...]]) -> dict[str, tuple[int, ...]]:
    delta: dict[str, tuple[int, ...]] = {}
    for key in set(old) | set(new):
        old_row = old.get(key, (0, 0, 0, 0, 0))
        new_row = new.get(key, (0, 0, 0, 0, 0))
        delta[key] = tuple(new_row[i] - old_row[i] for i in range(5))
    return delta


def _widen_loop(state: State, loop_id: int, ctx: Context, line: int | None) -> None:
    snapshots = state.loop_snapshots.get(loop_id, [])
    if len(snapshots) >= 3:
        first_delta = _signature_delta(snapshots[-2], snapshots[-3])
        second_delta = _signature_delta(snapshots[-1], snapshots[-2])
        stable = first_delta == second_delta
        balanced = all(delta[0] - delta[1] == 0 and delta[4] == 0 for delta in second_delta.values())
        if stable and balanced:
            state.trace(
                ctx,
                "loop_summary",
                line=line,
                note="zero/one/two iteration witnesses agree; repeated net change/credential effect is balanced",
            )
            return
        reason = f"loop multiplicity is not a stable balanced unit; delta={second_delta}"
    else:
        reason = "loop multiplicity exceeds bounded zero/one/two iteration witnesses"
    state.interrupt(ctx, "<loop>", line, reason)


def invoke_call(call: c_ast.FuncCall, state: State, ctx: Context, depth: int) -> list[CallResult]:
    arg_nodes = _call_args(call)
    arg_values = [eval_expr(arg, state, ctx, depth) for arg in arg_nodes]
    callee = call.name.name if isinstance(call.name, c_ast.ID) else None
    line = getattr(call.coord, "line", None)

    if callee is None:
        state.interrupt(ctx, "<indirect-call>", line, "function pointer call has no resource contract")
        return [CallResult(state, UnknownValue("indirect call"))]

    contract = ctx.contracts.get(callee)
    if contract is not None:
        if contract.role == "pure":
            return [CallResult(state, UnknownValue("pure contracted call"))]
        return [CallResult(state, _apply_contract(call, callee, contract, arg_nodes, state, ctx))]

    if callee in ctx.functions and depth < ctx.max_helper_depth:
        return _run_local_helper(call, callee, arg_nodes, arg_values, state, ctx, depth)

    if callee in ctx.functions:
        state.interrupt(ctx, callee, line, "local helper nesting exceeds one analyzed layer and has no contract")
    elif not ctx.is_pure(callee):
        state.interrupt(ctx, callee, line, "external function has no effect/audit contract")
    return [CallResult(state, UnknownValue(f"unmodeled call {callee}"))]


def _call_args(call: c_ast.FuncCall) -> list[c_ast.Node]:
    if call.args is None:
        return []
    if isinstance(call.args, c_ast.ExprList):
        return list(call.args.exprs or [])
    return [call.args]


def _apply_contract(
    call: c_ast.FuncCall,
    callee: str,
    contract: Contract,
    arg_nodes: list[c_ast.Node],
    state: State,
    ctx: Context,
) -> SValue:
    line = getattr(call.coord, "line", None)
    resource: str | None = None
    if contract.resource_arg is not None and contract.resource_arg < len(arg_nodes):
        resource = resource_key(arg_nodes[contract.resource_arg], state, ctx)
    if resource is None:
        resource = f"unresolved:{callee}@{line}"
        state.interrupt(ctx, callee, line, "resource parameter cannot be resolved for pairing")

    labels = {"change": "变更写入", "withdraw": "撤回", "credential": "提交凭据"}
    state.trace(
        ctx,
        "contract_" + contract.role,
        node=call,
        note=f"{callee}: {labels.get(contract.role, contract.role)}; resource={resource}",
    )

    if contract.role == "change":
        uid = state.next_uid
        state.next_uid += 1
        state.changes.append(ChangeEvent(uid, resource, line, state.function, callee))
        if contract.success is None:
            state.interrupt(ctx, callee, line, "change contract does not define its success return")
        return ResultValue(uid, contract.success if contract.success is not None else 0)

    if contract.role == "withdraw":
        uid = state.next_uid
        state.next_uid += 1
        candidates = [
            change
            for change in state.changes
            if change.key == resource and change.withdrawn_uid is None and change.status != "failed"
        ]
        matched = candidates[-1] if candidates else None
        if matched is not None:
            matched.status = "withdrawn"
            matched.withdrawn_uid = uid
        else:
            state.interrupt(ctx, callee, line, "withdrawal has no matching modeled successful change")
        state.withdrawals.append(
            WithdrawalEvent(uid, resource, line, state.function, callee, matched.uid if matched else None)
        )
        return UnknownValue("withdrawal return value not modeled")

    uid = state.next_uid
    state.next_uid += 1
    state.credits.append(CreditEvent(uid, resource, line, state.function, callee))
    return ConstValue(0, "0")


def _run_local_helper(
    call: c_ast.FuncCall,
    callee: str,
    arg_nodes: list[c_ast.Node],
    arg_values: list[SValue],
    caller_state: State,
    ctx: Context,
    depth: int,
) -> list[CallResult]:
    func = ctx.functions[callee]
    helper_state = caller_state.clone()
    scope: dict[str, SValue] = {}
    for index, param in enumerate(_parameter_decls(func)):
        argument = arg_nodes[index] if index < len(arg_nodes) else None
        value = arg_values[index] if index < len(arg_values) else UnknownValue("missing argument")
        key = resource_key(argument, caller_state, ctx) if argument is not None else None
        scope[param.name] = BoundValue(value=value, key=key) if key else value
    helper_state.scopes.append(scope)
    helper_state.function_stack.append(callee)
    helper_state.trace(ctx, "helper_enter", node=call, note=f"inline local helper layer {depth + 1}: {callee}")

    results: list[CallResult] = []
    for outcome in exec_statement(func.body, helper_state, ctx, depth + 1):
        st = outcome.state
        if st.function_stack and st.function_stack[-1] == callee:
            st.function_stack.pop()
        if len(st.scopes) > 1:
            st.scopes.pop()
        if outcome.kind in ("return", "fall"):
            results.append(CallResult(st, outcome.value or UnknownValue("helper fell through")))
        else:
            st.interrupt(ctx, callee, outcome.line, "helper has unsupported escaping control flow")
            results.append(CallResult(st, UnknownValue("helper control boundary")))
    return results


def resource_key(expr: c_ast.Node | None, state: State, ctx: Context | None = None) -> str | None:
    if expr is None:
        return None

    if isinstance(expr, c_ast.ID):
        binding = state.lookup_binding(expr.name)
        if isinstance(binding, BoundValue) and binding.key:
            return binding.key
        value = unwrap_value(binding)
        if isinstance(value, KeyValue):
            return value.key
        if isinstance(value, ConstValue) and value.integer is not None:
            return f"const:{value.integer}"
        return f"var:{expr.name}"

    if isinstance(expr, c_ast.Constant):
        raw = expr.value
        if getattr(expr, "type", "") == "string" or raw.startswith('"'):
            return "str:" + raw
        return "const:" + raw

    unary_cls = getattr(c_ast, "Unary", c_ast.UnaryOp)
    if isinstance(expr, unary_cls):
        if expr.op in ("&", "+"):
            return resource_key(expr.expr, state, ctx)
        return None

    if isinstance(expr, c_ast.Cast):
        return resource_key(expr.expr, state, ctx)

    if isinstance(expr, c_ast.StructRef):
        base = resource_key(expr.name, state, ctx)
        field = expr.field.name if isinstance(expr.field, c_ast.ID) else str(expr.field)
        separator = "->" if expr.type == "->" else "."
        return f"{base}{separator}{field}" if base else None

    if isinstance(expr, c_ast.ArrayRef):
        base = resource_key(expr.name, state, ctx)
        index = resource_key(expr.subscript, state, ctx)
        return f"{base}[{index}]" if base and index else None

    return None


def eval_expr(expr: c_ast.Node | None, state: State, ctx: Context, depth: int = 0) -> SValue:
    if expr is None:
        return UnknownValue("missing expression")
    value = _eval_expr(expr, state, ctx, depth)
    state.values_by_node[id(expr)] = value
    return value


def _eval_expr(expr: c_ast.Node, state: State, ctx: Context, depth: int) -> SValue:
    if isinstance(expr, c_ast.Constant):
        return ConstValue(_constant_int(expr), expr.value)

    if isinstance(expr, c_ast.ID):
        bound = state.lookup_binding(expr.name)
        if bound is None:
            return UnknownValue(f"unmodeled variable {expr.name}")
        return unwrap_value(bound) or UnknownValue(expr.name)

    unary_cls = getattr(c_ast, "Unary", c_ast.UnaryOp)
    if isinstance(expr, unary_cls):
        return _eval_unary(expr, state, ctx, depth)

    if isinstance(expr, c_ast.BinaryOp):
        left = eval_expr(expr.left, state, ctx, depth)
        if expr.op == "&&" and truth_value(left) is False:
            return ConstValue(0, "0")
        if expr.op == "||" and truth_value(left) is True:
            return ConstValue(1, "1")
        right = eval_expr(expr.right, state, ctx, depth)
        left = unwrap_value(left)
        right = unwrap_value(right)
        if isinstance(left, ConstValue) and isinstance(right, ConstValue):
            result = _binary_int(expr.op, left.integer, right.integer)
            if result is not None:
                return ConstValue(result, str(result))
        return UnknownValue(f"binary {expr.op}")

    if isinstance(expr, c_ast.Assignment):
        return _eval_assignment_expr(expr, state, ctx, depth)

    if isinstance(expr, c_ast.FuncCall):
        results = invoke_call(expr, state, ctx, depth)
        if len(results) != 1:
            raise _ForkedCall(results)
        result = results[0]
        if result.state is not state:
            state.__dict__.update(result.state.__dict__)
        return result.value

    if isinstance(expr, c_ast.Cast):
        return eval_expr(expr.expr, state, ctx, depth)

    if isinstance(expr, c_ast.TernaryOp):
        condition = truth_value(eval_expr(expr.cond, state, ctx, depth))
        if condition is True:
            return eval_expr(expr.iftrue, state, ctx, depth)
        if condition is False:
            return eval_expr(expr.iffalse, state, ctx, depth)
        eval_expr(expr.iftrue, state, ctx, depth)
        eval_expr(expr.iffalse, state, ctx, depth)
        return UnknownValue("ternary condition")

    if isinstance(expr, (c_ast.StructRef, c_ast.ArrayRef)):
        for child in expr.children():
            if isinstance(child[1], c_ast.Node):
                eval_expr(child[1], state, ctx, depth)
        return UnknownValue("memory reference")

    if isinstance(expr, c_ast.ExprList):
        value: SValue = UnknownValue("empty expression list")
        for subexpr in expr.exprs or []:
            value = eval_expr(subexpr, state, ctx, depth)
        return value

    return UnknownValue("unsupported expression " + type(expr).__name__)


def _eval_unary(expr: c_ast.UnaryOp, state: State, ctx: Context, depth: int) -> SValue:
    if expr.op == "&":
        key = resource_key(expr.expr, state, ctx)
        return KeyValue(key) if key else UnknownValue("address-of")
    if expr.op == "*":
        eval_expr(expr.expr, state, ctx, depth)
        return UnknownValue("dereference")
    if expr.op == "!":
        value = truth_value(eval_expr(expr.expr, state, ctx, depth))
        if value is None:
            return UnknownValue("logical not")
        return ConstValue(0 if value else 1, str(int(not value)))
    if expr.op in ("++", "--", "p++", "p--") and isinstance(expr.expr, c_ast.ID):
        old = unwrap_value(state.lookup_binding(expr.expr.name))
        old_int = old.integer if isinstance(old, ConstValue) else None
        if old_int is None:
            state.assign(expr.expr.name, UnknownValue("non-integer counter"))
            return UnknownValue("counter")
        delta = 1 if "++" in expr.op else -1
        new_value = ConstValue(old_int + delta, str(old_int + delta))
        state.assign(expr.expr.name, new_value)
        return new_value if expr.op in ("++", "--") else ConstValue(old_int, str(old_int))

    value = eval_expr(expr.expr, state, ctx, depth)
    integer = value.integer if isinstance(value, ConstValue) else None
    if integer is None:
        return UnknownValue("unary " + expr.op)
    if expr.op == "-":
        return ConstValue(-integer, str(-integer))
    if expr.op == "+":
        return ConstValue(integer, str(integer))
    if expr.op == "~":
        return ConstValue(~integer, str(~integer))
    return UnknownValue("unary " + expr.op)


def _eval_assignment_expr(expr: c_ast.Assignment, state: State, ctx: Context, depth: int) -> SValue:
    outcomes = _exec_assignment(expr, state, ctx, depth)
    if len(outcomes) != 1:
        raise _ForkedCall([CallResult(outcome.state, outcome.value or UnknownValue()) for outcome in outcomes])
    return outcomes[0].value or UnknownValue()


def _compound_value(op: str, old: SValue, new: SValue) -> SValue:
    old = unwrap_value(old)
    new = unwrap_value(new)
    operator = op[:-1] if op.endswith("=") else op
    if isinstance(old, ConstValue) and isinstance(new, ConstValue) and old.integer is not None and new.integer is not None:
        result = _binary_int(operator, old.integer, new.integer)
        if result is not None:
            return ConstValue(result, str(result))
    return UnknownValue("compound assignment")


def _binary_int(op: str, left: int | None, right: int | None) -> int | None:
    if left is None or right is None:
        return None
    operations = {
        "+": lambda a, b: a + b,
        "-": lambda a, b: a - b,
        "*": lambda a, b: a * b,
        "/": lambda a, b: int(a / b) if b else None,
        "%": lambda a, b: a % b if b else None,
        "<": lambda a, b: int(a < b),
        "<=": lambda a, b: int(a <= b),
        ">": lambda a, b: int(a > b),
        ">=": lambda a, b: int(a >= b),
        "==": lambda a, b: int(a == b),
        "!=": lambda a, b: int(a != b),
        "&": lambda a, b: a & b,
        "|": lambda a, b: a | b,
        "^": lambda a, b: a ^ b,
        "<<": lambda a, b: a << b,
        ">>": lambda a, b: a >> b,
    }
    operation = operations.get(op)
    if operation is None:
        return None
    try:
        return operation(left, right)
    except ZeroDivisionError:
        return None


def _constant_int(node: c_ast.Constant) -> int | None:
    raw = node.value
    try:
        return int(raw, 0)
    except ValueError:
        cleaned = raw.rstrip("uUlL")
        try:
            return int(cleaned, 0)
        except ValueError:
            return None


def _evaluate_exit(state: State, ctx: Context, exit_kind: str, line: int | None) -> ExitReport:
    ledger = _ledger_rows(state)
    boundaries = [asdict(boundary) for boundary in state.boundaries]
    problems: list[dict[str, Any]] = []
    unresolved = False

    for row in ledger:
        if row["unresolved_changes"]:
            unresolved = True
        if row["credentials"] < row["effective_changes"]:
            problems.append(
                {
                    "code": "missing_credential",
                    "resource": row["resource"],
                    "expected_credentials": row["effective_changes"],
                    "actual_credentials": row["credentials"],
                    "message_zh": (
                        f"资源 {row['resource']} 有 {row['effective_changes']} 个生效变更，"
                        f"但只有 {row['credentials']} 张凭据"
                    ),
                }
            )
        elif row["credentials"] > row["effective_changes"]:
            problems.append(
                {
                    "code": "duplicate_credential",
                    "resource": row["resource"],
                    "expected_credentials": row["effective_changes"],
                    "actual_credentials": row["credentials"],
                    "message_zh": (
                        f"资源 {row['resource']} 只需 {row['effective_changes']} 张凭据，"
                        f"实际有 {row['credentials']} 张（重复或多余记账）"
                    ),
                }
            )

    path = [asdict(step) for step in state.steps]
    path_text = render_path(state.steps)

    if boundaries or unresolved:
        status = "undecidable"
        reasons = [boundary["reason"] for boundary in boundaries]
        if unresolved:
            reasons.append("a change return/status is not constrained on this path")
        message = "证明中断：" + "；".join(dict.fromkeys(reasons))
    elif any(p["code"] == "missing_credential" for p in problems) and any(
        p["code"] == "duplicate_credential" for p in problems
    ):
        status = "missing_and_duplicate"
        message = "同时存在漏记和重复记账"
    elif any(p["code"] == "missing_credential" for p in problems):
        status = "missing_credential"
        message = "存在生效变更缺少凭据的出口"
    elif any(p["code"] == "duplicate_credential" for p in problems):
        status = "duplicate_credential"
        message = "存在重复或多余凭据的出口"
    elif any(row["withdrawn_changes"] for row in ledger):
        status = "rollback_clean"
        message = "撤回/回滚路径上生效变更和凭据均为零"
    else:
        status = "clean"
        message = "所有生效变更均恰好配对一张凭据"

    return ExitReport(exit_kind, line, status, message, ledger, problems, boundaries, path, path_text)


def _ledger_rows(state: State) -> list[dict[str, Any]]:
    keys = sorted(
        {change.key for change in state.changes}
        | {credit.key for credit in state.credits}
        | {withdrawal.key for withdrawal in state.withdrawals}
    )
    rows: list[dict[str, Any]] = []
    for key in keys:
        changes = [change for change in state.changes if change.key == key]
        credits = [credit for credit in state.credits if credit.key == key]
        effective = [c for c in changes if c.status == "succeeded" and c.withdrawn_uid is None]
        withdrawn = [c for c in changes if c.status == "withdrawn" or c.withdrawn_uid is not None]
        failed = [c for c in changes if c.status == "failed"]
        unresolved = [c for c in changes if c.status not in {"succeeded", "withdrawn", "failed"}]
        rows.append(
            {
                "resource": key,
                "effective_changes": len(effective),
                "credentials": len(credits),
                "failed_changes": len(failed),
                "withdrawn_changes": len(withdrawn),
                "unresolved_changes": len(unresolved),
                "change_lines": [change.line for change in changes],
                "credential_lines": [credit.line for credit in credits],
                "withdrawal_lines": [item.line for item in state.withdrawals if item.key == key],
            }
        )
    return rows


def render_path(steps: list[Step]) -> str:
    rendered: list[str] = []
    for step in steps:
        location = f"{step.file}:{step.line}" if step.line is not None else str(step.file)
        code = step.code or f"<{step.kind}>"
        line = f"  {location} [{step.function}] {code}"
        if step.note:
            line += f"    -- {step.note}"
        rendered.append(line)
    return "\n".join(rendered)


def _build_findings(exits: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    statuses = [exit_report["status"] for exit_report in exits]
    for exit_report in exits:
        if exit_report["status"] in {"missing_credential", "duplicate_credential", "missing_and_duplicate"}:
            for problem in exit_report["problems"]:
                finding = dict(problem)
                finding["exit_line"] = exit_report["exit_line"]
                finding["exit_kind"] = exit_report["exit_kind"]
                finding["path_text"] = exit_report["path_text"]
                finding["path"] = exit_report["path"]
                findings.append(finding)
        elif exit_report["status"] == "undecidable":
            findings.append(
                {
                    "code": "undecidable",
                    "exit_line": exit_report["exit_line"],
                    "exit_kind": exit_report["exit_kind"],
                    "message_zh": exit_report["message"],
                    "boundaries": exit_report["boundaries"],
                    "path_text": exit_report["path_text"],
                    "path": exit_report["path"],
                }
            )

    verdict = _aggregate_verdicts(statuses)
    return verdict, findings


def _aggregate_verdicts(statuses: list[str]) -> str:
    if "missing_and_duplicate" in statuses or ("missing_credential" in statuses and "duplicate_credential" in statuses):
        return "missing_and_duplicate"
    if "missing_credential" in statuses:
        return "missing_credential"
    if "duplicate_credential" in statuses:
        return "duplicate_credential"
    if "undecidable" in statuses:
        return "undecidable"
    if "rollback_clean" in statuses:
        return "rollback_clean"
    return "clean"


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key))
        counts[value] = counts.get(value, 0) + 1
    return counts


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Check protected-write audit credentials in preprocessed C.")
    parser.add_argument("--c-file", required=True, help="Preprocessed C source file")
    parser.add_argument("--function", required=True, help="Target function name")
    parser.add_argument("--contracts-json", help="JSON object mapping function names to contracts")
    parser.add_argument("--pure", nargs="*", default=[], help="Additional pure/benign function names or glob patterns")
    args = parser.parse_args()

    contracts = json.loads(args.contracts_json) if args.contracts_json else None
    report = audit_file(args.c_file, contracts, args.function, pure_functions=args.pure)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
