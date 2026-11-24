#
# SPDX-License-Identifier: Apache-2.0
r"""
==========================================================
B616: Field-set tracking for internal export interfaces
==========================================================

Internal export interfaces often copy a dict and then write restricted
fields back into the copied object. Plain taint rules cannot tell whether
the value that finally leaves through the export is clean, because the
restricted fields detour through shallow copies, aliases and conditionals.

This optional plugin performs a bounded, module-local field-set analysis.
For every function whose name matches one of the configured
`export_prefixes` it tracks which restricted keys may be present in the
returned mapping, following:

- shallow copies (`dict(x)`, `x.copy()`, `copy.copy(x)`, `{**x}`)
- aliases (`b = a`)
- conditional branches (field sets are merged at join points)
- updates with unknown keys (`d[k] = v`, `d.update(unknown)`)
- calls to other functions defined in the same module (depth limited)

The plugin reports the first position where the guarantee "no restricted
field reaches the export" is lost: a high confidence issue when a
restricted key provably flows back, and a low confidence issue when
unknown keys make the field set uninferable.

:Example:

.. code-block:: none

    >> Issue: [B616:internal_export_field_leak] Restricted field(s)
     'token' may reach export interface 'export_account()'; the field-set
     guarantee is first lost here (restricted field 'token' written back).
       Severity: High   Confidence: High
       CWE: CWE-200 (https://cwe.mitre.org/data/definitions/200.html)
       Location: examples/internal_export_fields_reflow.py:10:4

.. seealso::

 - https://cwe.mitre.org/data/definitions/200.html

.. versionadded:: 1.9.0

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

_DEFAULT_RESTRICTED_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "private_key",
    "ssn",
)
_DEFAULT_EXPORT_PREFIXES = ("export",)
_MAX_CALL_DEPTH = 4


def gen_config(name):
    if name == "internal_export_field_leak":
        return {
            "restricted_keys": list(_DEFAULT_RESTRICTED_KEYS),
            "export_prefixes": list(_DEFAULT_EXPORT_PREFIXES),
        }


class _Fields:
    """Abstract field set of a dict-shaped value.

    keys: restricted keys that may be present; unknown: True when the
    mapping may hold keys the analysis cannot see; lost: (lineno, col,
    reason) of the first position where the clean-fields guarantee was
    lost.
    """

    __slots__ = ("keys", "unknown", "lost")

    def __init__(self, keys=(), unknown=False, lost=None):
        self.keys = set(keys)
        self.unknown = unknown
        self.lost = lost

    def lose(self, node, reason):
        if self.lost is None:
            self.lost = (node.lineno, node.col_offset, reason)


def _earliest(left, right):
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


def _merge_fields(left, right):
    return _Fields(
        left.keys | right.keys,
        left.unknown or right.unknown,
        _earliest(left.lost, right.lost),
    )


def _params(func):
    args = func.args
    return [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]


class _ExportAnalyzer:
    def __init__(self, tree, restricted_keys, export_prefixes):
        self.restricted = set(restricted_keys)
        self.prefixes = tuple(export_prefixes)
        self.functions = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
        self._returns = []
        self._stack = []

    def run(self):
        findings = []
        for name in sorted(self.functions):
            if not self._is_export(name):
                continue
            func = self.functions[name]
            state = {param: _Fields() for param in _params(func)}
            result = self._analyze_function(func, state, 0)
            if result is None or result.lost is None:
                continue
            lineno, col, reason = result.lost
            if result.keys:
                text = (
                    "Restricted field(s) %s may reach export interface "
                    "'%s()'; the field-set guarantee is first lost here "
                    "(%s)." % (sorted(result.keys), name, reason)
                )
                findings.append((lineno, col, "leak", text))
            elif result.unknown:
                text = (
                    "Cannot prove export interface '%s()' withholds "
                    "restricted fields; unknown keys first enter here "
                    "(%s)." % (name, reason)
                )
                findings.append((lineno, col, "unknown", text))
        findings.sort()
        return findings[0] if findings else None

    def _is_export(self, name):
        return any(
            name == prefix or name.startswith(prefix + "_")
            for prefix in self.prefixes
        )

    def _analyze_function(self, func, state, depth):
        self._returns.append([])
        self._stack.append(func.name)
        try:
            self._exec_body(func.body, state, depth)
        finally:
            self._stack.pop()
        result = None
        for fields in self._returns.pop():
            if fields is None:
                continue
            result = (
                fields if result is None else _merge_fields(result, fields)
            )
        return result

    def _exec_body(self, body, state, depth):
        for stmt in body:
            self._exec_stmt(stmt, state, depth)

    def _exec_stmt(self, stmt, state, depth):
        if isinstance(stmt, ast.Assign):
            value = self._eval_expr(stmt.value, state, depth)
            for target in stmt.targets:
                self._assign_target(target, value, stmt, state, depth)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            value = self._eval_expr(stmt.value, state, depth)
            self._assign_target(stmt.target, value, stmt, state, depth)
        elif isinstance(stmt, ast.Delete):
            self._exec_delete(stmt, state)
        elif isinstance(stmt, ast.If):
            body_state = dict(state)
            self._exec_body(stmt.body, body_state, depth)
            else_state = dict(state)
            self._exec_body(stmt.orelse, else_state, depth)
            merged = self._merge_states(body_state, else_state)
            self._replace_state(state, merged)
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            for _ in range(2):
                inner = dict(state)
                self._exec_body(stmt.body, inner, depth)
                self._replace_state(state, self._merge_states(state, inner))
        elif isinstance(stmt, ast.Return):
            fields = None
            if stmt.value is not None:
                fields = self._eval_expr(stmt.value, state, depth)
            self._returns[-1].append(fields)
        elif isinstance(stmt, ast.Expr):
            self._eval_expr(stmt.value, state, depth)
        elif isinstance(stmt, ast.Try):
            self._exec_body(stmt.body, state, depth)
            for handler in stmt.handlers:
                self._exec_body(handler.body, state, depth)
            self._exec_body(stmt.orelse, state, depth)
            self._exec_body(stmt.finalbody, state, depth)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._exec_body(stmt.body, state, depth)

    @staticmethod
    def _replace_state(state, merged):
        state.clear()
        state.update(merged)

    def _merge_states(self, left, right):
        merged = {}
        for name in set(left) | set(right):
            a = left.get(name)
            b = right.get(name)
            if a is b:
                merged[name] = a
            elif a is None:
                merged[name] = b
            elif b is None:
                merged[name] = a
            else:
                merged[name] = _merge_fields(a, b)
        return merged

    def _exec_delete(self, stmt, state):
        for target in stmt.targets:
            if not isinstance(target, ast.Subscript):
                continue
            base = target.value
            key = target.slice
            if not isinstance(base, ast.Name):
                continue
            fields = state.get(base.id)
            if (
                fields is not None
                and isinstance(key, ast.Constant)
                and key.value in self.restricted
            ):
                fields.keys.discard(key.value)

    def _assign_target(self, target, value, stmt, state, depth):
        if isinstance(target, ast.Name):
            state[target.id] = value
        elif isinstance(target, ast.Subscript):
            base = target.value
            if not isinstance(base, ast.Name):
                return
            fields = state.get(base.id)
            if fields is None:
                return
            key = target.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if key.value in self.restricted:
                    fields.keys.add(key.value)
                    fields.lose(
                        stmt,
                        "restricted field '%s' written back" % key.value,
                    )
            else:
                fields.unknown = True
                fields.lose(stmt, "update with non-constant key")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign_target(elt, None, stmt, state, depth)

    def _eval_expr(self, node, state, depth):
        if isinstance(node, ast.Dict):
            return self._eval_dict(node, state, depth)
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, ast.Call):
            return self._eval_call(node, state, depth)
        if isinstance(node, ast.IfExp):
            body = self._eval_expr(node.body, state, depth)
            orelse = self._eval_expr(node.orelse, state, depth)
            if body is None:
                return orelse
            if orelse is None:
                return body
            return _merge_fields(body, orelse)
        return None

    def _eval_dict(self, node, state, depth):
        keys = set()
        unknown = False
        lost = None
        for key, value in zip(node.keys, node.values):
            if key is None:  # {**mapping} unpacking
                fields = self._eval_expr(value, state, depth)
                if fields is None:
                    unknown = True
                    lost = lost or (
                        node.lineno,
                        node.col_offset,
                        "unpacked unknown mapping",
                    )
                else:
                    keys |= fields.keys
                    unknown = unknown or fields.unknown
                    lost = _earliest(lost, fields.lost)
            elif (
                isinstance(key, ast.Constant)
                and key.value in self.restricted
            ):
                keys.add(key.value)
        if keys and lost is None:
            lost = (node.lineno, node.col_offset, "restricted field literal")
        return _Fields(keys, unknown, lost)

    def _eval_call(self, node, state, depth):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "dict":
            if not node.args:
                return _Fields()
            return self._shallow_copy(node.args[0], node, state, depth)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "copy"
            and isinstance(func.value, ast.Name)
            and func.value.id == "copy"
            and node.args
        ):
            return self._shallow_copy(node.args[0], node, state, depth)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "copy"
            and not node.args
        ):
            return self._shallow_copy(func.value, node, state, depth)
        if isinstance(func, ast.Attribute) and func.attr == "update":
            self._apply_update(func.value, node, state, depth)
            return None
        if isinstance(func, ast.Name) and func.id in self.functions:
            return self._call_local(func.id, node, state, depth)
        return None

    def _shallow_copy(self, expr, node, state, depth):
        src = self._eval_expr(expr, state, depth)
        if src is None:
            return None
        lost = src.lost
        if src.keys and not src.unknown:
            lost = (
                node.lineno,
                node.col_offset,
                "shallow copy carries restricted fields",
            )
        return _Fields(src.keys, src.unknown, lost)

    def _apply_update(self, target, node, state, depth):
        if not isinstance(target, ast.Name):
            return
        fields = state.get(target.id)
        if fields is None:
            return
        if node.args:
            src = self._eval_expr(node.args[0], state, depth)
            if src is None:
                fields.unknown = True
                fields.lose(node, "update from unknown mapping")
            else:
                fields.keys |= src.keys
                if src.keys:
                    fields.lose(node, "update with restricted fields")
                if src.unknown:
                    fields.unknown = True
                    fields.lost = fields.lost or src.lost
                    fields.lose(node, "update from unknown mapping")
        for keyword in node.keywords:
            if keyword.arg is None:
                fields.unknown = True
                fields.lose(node, "update from unknown mapping")
            elif keyword.arg in self.restricted:
                fields.keys.add(keyword.arg)
                fields.lose(
                    node,
                    "restricted field '%s' written back" % keyword.arg,
                )

    def _call_local(self, name, node, state, depth):
        if depth >= _MAX_CALL_DEPTH or name in self._stack:
            return _Fields(
                unknown=True,
                lost=(node.lineno, node.col_offset, "call depth limit"),
            )
        callee = self.functions[name]
        bindings = {}
        params = _params(callee)
        for param, arg in zip(params, node.args):
            fields = self._eval_expr(arg, state, depth)
            bindings[param] = fields or _Fields(
                unknown=True,
                lost=(node.lineno, node.col_offset, "opaque argument"),
            )
        for keyword in node.keywords:
            if keyword.arg in params:
                fields = self._eval_expr(keyword.value, state, depth)
                bindings[keyword.arg] = fields or _Fields(
                    unknown=True,
                    lost=(node.lineno, node.col_offset, "opaque argument"),
                )
        for param in params:
            bindings.setdefault(param, _Fields())
        return self._analyze_function(callee, bindings, depth + 1)


@test.test_id("B616")
@test.checks("File")
@test.takes_config("internal_export_field_leak")
def internal_export_field_leak(context, config):
    """Track restricted fields into internal export interfaces."""
    cfg = config or {}
    restricted = cfg.get("restricted_keys") or _DEFAULT_RESTRICTED_KEYS
    prefixes = cfg.get("export_prefixes") or _DEFAULT_EXPORT_PREFIXES
    src = context.file_data
    src.seek(0)
    try:
        tree = ast.parse(src.read())
    except SyntaxError:
        return None
    analyzer = _ExportAnalyzer(tree, restricted, prefixes)
    finding = analyzer.run()
    if finding is None:
        return None
    lineno, col, kind, text = finding
    if kind == "leak":
        severity = bandit.HIGH
        confidence = bandit.HIGH
    else:
        severity = bandit.MEDIUM
        confidence = bandit.LOW
    b_issue = bandit.Issue(
        severity=severity,
        confidence=confidence,
        cwe=issue.Cwe.EXPOSURE_OF_SENSITIVE_INFORMATION,
        text=text,
        lineno=lineno,
        col_offset=col,
    )
    b_issue.linerange = [lineno]
    return b_issue
