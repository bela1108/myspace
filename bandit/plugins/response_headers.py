#
# SPDX-License-Identifier: Apache-2.0
r"""
=====================================================
B705: Response header contract not guaranteed
=====================================================

This test tracks HTTP response values through a function and reports exits
that cannot prove the configured security response headers are present.  The
contract is intentionally conservative: when a response comes from an
external object, or when a loop makes the response state uncertain, the
header state is kept as unknown rather than guessed.

The test understands a deliberately small amount of Python: response aliases,
literal response dictionaries, header updates/overwrites, local helper and
wrapper summaries, decorators, and separate early returns.  It does not try
to be a general purpose data flow engine.

**Config Options:**

This plugin takes a config block named ``response_headers`` (the other
registered aliases use their own section names).  ``required_headers`` is the
set of headers that must be present at every response exit.  ``wrappers``
declares which wrapper/decorator guarantees which headers.  A value of
``all`` (or ``true``) means the wrapper guarantees the complete configured
contract.  Wrapper values may also be a list of header names:

.. code-block:: yaml

    response_headers:
        required_headers:
            - Content-Security-Policy
            - X-Content-Type-Options
            - X-Frame-Options
        wrappers:
            add_security_headers: all
            audit_only:
                headers:
                    - X-Content-Type-Options

When a wrapper creates a fresh response or rewrites the ``headers`` mapping,
the issue points at that rewrite line so it is easy to see where an inner
wrapper's guarantees were lost.

:Example:

.. code-block:: none

    >> Issue: [B705:response_headers] Missing security response headers:
       Content-Security-Policy. A new response object was created at line 24.
       Severity: Medium   Confidence: High
       Location: ./examples/response_headers.py:24:8

.. versionadded:: 1.9.0

"""  # noqa: E501

import ast
import hashlib
import json
from dataclasses import dataclass, field

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


DEFAULT_REQUIRED_HEADERS = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
)

_RESPONSE_KEYS = {
    "body",
    "content",
    "data",
    "employee",
    "employees",
    "error",
    "headers",
    "items",
    "json",
    "message",
    "report",
    "result",
    "status",
    "status_code",
}

_COMMON_HEADER_NAMES = {
    "cache-control",
    "content-encoding",
    "content-security-policy",
    "content-type",
    "etag",
    "expires",
    "location",
    "referrer-policy",
    "server",
    "set-cookie",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
}

_TRANSPARENT_DECORATORS = {"wraps", "functools.wraps"}
_MUTATING_METHODS = {"add", "clear", "extend", "pop", "setdefault", "update"}
_REQUIRED_KEYS = (
    "required_headers",
    "required_security_headers",
    "required",
    "contract",
    "security_headers",
    "headers",
)
_WRAPPER_KEYS = (
    "wrappers",
    "wrapper",
    "wrapper_guarantees",
    "wrapper_headers",
    "decorators",
    "guarantees",
    "wrapper_declarations",
)
_HANDLER_KEYS = ("handlers", "entry_points", "functions")
_ALL_WORDS = {"*", "all", "complete", "exactly", "full", "required"}


def _norm_header(name):
    return str(name).strip().lower()


def _looks_like_header(name):
    if not isinstance(name, str):
        return False
    return "-" in name or name.strip().lower() in _COMMON_HEADER_NAMES


def _dedupe_headers(values):
    result = []
    seen = set()
    for value in values:
        key = _norm_header(value)
        if key not in seen:
            seen.add(key)
            result.append(str(value))
    return result


@dataclass(frozen=True)
class WrapperSpec:
    headers: frozenset = frozenset()
    all_headers: bool = False


@dataclass
class HeaderContract:
    required: tuple = ()
    wrappers: dict = field(default_factory=dict)
    handlers: tuple = ()

    @property
    def required_norm(self):
        return {_norm_header(header): header for header in self.required}

    def missing(self, headers):
        present = {_norm_header(header) for header in headers or ()}
        required = self.required_norm
        return tuple(
            value for key, value in required.items() if key not in present
        )


def _coerce_wrapper_spec(value):
    headers = set()
    all_headers = False

    def add(item):
        nonlocal all_headers
        if item is None:
            return
        if isinstance(item, bool):
            all_headers = all_headers or item
        elif isinstance(item, str):
            if item.strip().lower() in _ALL_WORDS:
                all_headers = True
            else:
                headers.add(item)
        elif isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                add(child)
        elif isinstance(item, dict):
            recognised = False
            for key in (
                "all",
                "all_headers",
                "complete",
                "exactly",
                "full",
            ):
                if key in item:
                    recognised = True
                    if item[key]:
                        all_headers = True
            for key in (
                "add",
                "adds",
                "adds_headers",
                "ensures",
                "guaranteed_headers",
                "guarantees",
                "headers",
                "provides",
                "required",
                "required_headers",
            ):
                if key in item:
                    recognised = True
                    add(item[key])
            if not recognised:
                header_keys = [str(key) for key in item]
                if header_keys and all(
                    _looks_like_header(key) for key in header_keys
                ):
                    headers.update(header_keys)

    add(value)
    return WrapperSpec(frozenset(headers), all_headers)


def _first_config_value(config, keys):
    for key in keys:
        if key in config and config[key] is not None:
            return config[key]
    return None


def _normalise_required(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return _dedupe_headers(str(key) for key in value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return _dedupe_headers(value)
    return []


def normalise_config(config):
    """Return a normalized :class:`HeaderContract` for a plugin config."""
    if not isinstance(config, dict):
        config = {}

    raw_wrappers = _first_config_value(config, _WRAPPER_KEYS)
    raw_required = _first_config_value(config, _REQUIRED_KEYS)
    handlers = _first_config_value(config, _HANDLER_KEYS) or ()
    if isinstance(handlers, str):
        handlers = (handlers,)

    wrapper_specs = {}
    if isinstance(raw_wrappers, dict):
        items = raw_wrappers.items()
    elif isinstance(raw_wrappers, (list, tuple, set, frozenset)):
        items = []
        for entry in raw_wrappers:
            if isinstance(entry, dict) and "name" in entry:
                items.append((entry["name"], entry))
    else:
        items = []

    for name, value in items:
        if not isinstance(name, str):
            continue
        key = name.strip().lstrip("@")
        if key:
            wrapper_specs[key] = _coerce_wrapper_spec(value)

    required = _normalise_required(raw_required)
    if not required:
        declared = set()
        for spec in wrapper_specs.values():
            declared.update(spec.headers)
        required = _dedupe_headers(sorted(declared))
    if not required and any(
        spec.all_headers for spec in wrapper_specs.values()
    ):
        required = list(DEFAULT_REQUIRED_HEADERS)

    return HeaderContract(
        required=tuple(required),
        wrappers=wrapper_specs,
        handlers=tuple(str(name) for name in handlers),
    )


def gen_config(name):
    if name in {
        "response_headers",
        "http_response_headers",
        "security_headers",
        "response_header_contract",
        "missing_security_headers",
    }:
        return {
            "required_headers": [],
            "wrappers": {},
            "handlers": [],
        }
    return None


@dataclass
class Value:
    kind: str = "unknown"
    headers: set = None
    exact: bool = False
    origin: int = None
    origin_kind: str = None
    keys: set = None
    fn_node: ast.AST = None
    closure: dict = None
    call_states: list = None
    owner: "Value" = None
    literal: str = None

    def clone(self, headers=True):
        return Value(
            kind=self.kind,
            headers=set(self.headers)
            if headers and self.headers is not None
            else self.headers,
            exact=self.exact,
            origin=self.origin,
            origin_kind=self.origin_kind,
            keys=set(self.keys) if self.keys is not None else None,
            fn_node=self.fn_node,
            closure=self.closure,
            call_states=self.call_states,
            owner=self.owner,
            literal=self.literal,
        )


@dataclass
class ReturnState:
    value: Value
    return_node: ast.AST


@dataclass(frozen=True)
class Finding:
    missing: tuple
    line: int
    return_line: int
    function: str
    origin_kind: str
    message: str

    def as_issue(self):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
            text=self.message,
            lineno=self.line,
            col_offset=0,
        )


@dataclass
class FunctionInfo:
    name: str
    qualname: str
    node: ast.AST
    parent_fn: ast.AST = None
    parent_class: ast.AST = None


def _clone_env(env):
    memo = {}
    pairs = []

    def clone_value(value):
        if id(value) not in memo:
            cloned = value.clone()
            memo[id(value)] = cloned
            pairs.append((value, cloned))
        return memo[id(value)]

    cloned_env = {name: clone_value(value) for name, value in env.items()}
    for original, cloned in pairs:
        if original.owner is not None:
            cloned.owner = clone_value(original.owner)
    return cloned_env


def _unknown_value():
    return Value(kind="unknown")


def _unknown_response():
    return Value(kind="response", exact=False)


def _header_values(value):
    if value is None:
        return None
    if value.kind == "headers" and value.owner is not None:
        return value.owner.headers
    if value.kind in {"headers", "dict", "response"}:
        if value.headers is not None:
            return value.headers
        if value.kind == "dict" and value.keys is not None:
            return value.keys
    return None


def _merge_values(values):
    values = [value for value in values if value is not None]
    if not values:
        return _unknown_value()

    response_values = [
        value for value in values if value.kind in {"dict", "response"}
    ]
    if not response_values:
        if any(value.kind == "unknown" for value in values):
            return _unknown_value()
        return values[0].clone()

    exact = all(value.exact for value in response_values)
    header_sets = [
        _header_values(value)
        for value in response_values
        if _header_values(value) is not None
    ]
    if len(header_sets) != len(response_values):
        headers = None
        exact = False
    else:
        headers = set(header_sets[0])
        for other in header_sets[1:]:
            headers.intersection_update(other)

    origin = next(
        (
            value.origin
            for value in response_values
            if value.origin is not None
        ),
        None,
    )
    origin_kind = next(
        (
            value.origin_kind
            for value in response_values
            if value.origin is not None
        ),
        None,
    )
    return Value(
        kind="response",
        headers=headers,
        exact=exact,
        origin=origin,
        origin_kind=origin_kind,
    )


class Analyzer:
    def __init__(self, tree, contract, filename="<memory>"):
        self.tree = tree
        self.contract = contract
        self.filename = filename
        self.functions = []
        self.functions_by_name = {}
        self._collect_functions(tree, None, None)
        self.global_env = {}
        self._build_global_env()

    def _collect_functions(self, node, parent_fn, parent_class):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                prefix = self._class_prefix(parent_class)
                qualname = f"{prefix}{child.name}" if prefix else child.name
                info = FunctionInfo(
                    child.name,
                    qualname,
                    child,
                    parent_fn,
                    parent_class,
                )
                self.functions.append(info)
                self.functions_by_name.setdefault(child.name, []).append(info)
                self._collect_functions(child, child, None)
            elif isinstance(child, ast.ClassDef):
                self._collect_functions(child, parent_fn, child)
            else:
                self._collect_functions(child, parent_fn, parent_class)

    @staticmethod
    def _class_prefix(class_node):
        names = []
        current = class_node
        while isinstance(current, ast.ClassDef):
            names.append(current.name)
            current = getattr(current, "_rh_parent_class", None)
        return ".".join(reversed(names)) + "." if names else ""

    def _build_global_env(self):
        for info in self.functions:
            if info.parent_fn is None and info.parent_class is None:
                self.global_env[info.name] = Value(
                    kind="function",
                    fn_node=info.node,
                    closure=self.global_env,
                )

        for statement in self.tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.global_env[statement.name] = Value(
                    kind="function",
                    fn_node=statement,
                    closure=self.global_env,
                )
            elif isinstance(statement, ast.ClassDef):
                self.global_env[statement.name] = _unknown_value()
            elif isinstance(statement, ast.Assign):
                value = self._eval_expr(statement.value, self.global_env, 0)
                for target in statement.targets:
                    self._assign_target(
                        target,
                        value,
                        self.global_env,
                        statement.lineno,
                        0,
                    )
            elif isinstance(statement, ast.AnnAssign):
                if statement.value is not None:
                    value = self._eval_expr(
                        statement.value, self.global_env, 0
                    )
                    self._assign_target(
                        statement.target,
                        value,
                        self.global_env,
                        statement.lineno,
                        0,
                    )
            elif isinstance(statement, ast.If):
                self._exec_if(statement, self.global_env, 0)
            elif isinstance(statement, ast.Try):
                self._exec_try(statement, self.global_env, 0)

    def analyze(self):
        if not self.contract.required:
            return []
        states = []
        seen_entries = set()
        for info in self.functions:
            if info.parent_fn is not None:
                continue
            if id(info.node) in seen_entries:
                continue
            if not self._is_entry(info):
                continue
            seen_entries.add(id(info.node))
            closure = _clone_env(self.global_env)
            returns = self._exec_function_body(info.node, closure, 0)
            returns = self._apply_decorators(
                info.node.decorator_list,
                returns,
                closure,
                0,
            )
            states.extend(returns)
        return self._findings(states)

    def _is_entry(self, info):
        if info.name in self.contract.handlers:
            return True
        if info.qualname in self.contract.handlers:
            return True
        for decorator in info.node.decorator_list:
            names = _expr_names(decorator)
            if self._wrapper_spec(names) or self._local_function(names):
                return True
        return False

    def _wrapper_spec(self, names):
        for name in names:
            for key, spec in self.contract.wrappers.items():
                if _names_match(name, key):
                    return spec
        return None

    def _local_function(self, names):
        for name in names:
            candidates = self.functions_by_name.get(name.split(".")[-1])
            if candidates:
                return candidates[0]
        return None

    def _findings(self, states):
        findings = {}
        for state in states:
            value = state.value
            if value.kind != "response" or not value.exact:
                continue
            missing = self.contract.missing(value.headers or ())
            if not missing:
                continue
            line = value.origin or state.return_node.lineno
            key = (state.return_node.lineno, state.return_node.col_offset)
            function = self._enclosing_function_name(state.return_node)
            message = self._message(missing, line, state, value)
            finding = Finding(
                missing=missing,
                line=line,
                return_line=state.return_node.lineno,
                function=function,
                origin_kind=value.origin_kind or "returned",
                message=message,
            )
            previous = findings.get(key)
            if previous is None or finding.line <= previous.line:
                findings[key] = finding
        return list(findings.values())

    @staticmethod
    def _message(missing, line, state, value):
        missing_text = ", ".join(missing)
        parts = [f"Missing security response headers: {missing_text}."]
        if value.origin_kind == "headers rewritten":
            parts.append(
                f"Response headers were rewritten at line {line}, dropping "
                "an earlier header guarantee."
            )
        elif value.origin_kind == "created":
            parts.append(
                f"A new response object was created at line {line} "
                "(rewrite point) without the required headers."
            )
        if state.return_node.lineno != line:
            parts.append(
                f"The response is returned at line {state.return_node.lineno}."
            )
        parts.append("Ensure the wrapper contract is applied on every exit.")
        return " ".join(parts)

    def _enclosing_function_name(self, node):
        current = node
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current.name
            current = getattr(current, "_rh_parent", None)
        return "<module>"

    def _eval_expr(self, node, env, depth):
        if node is None:
            return _unknown_value()
        if isinstance(node, ast.Constant):
            literal = node.value if isinstance(node.value, str) else None
            return Value(kind="scalar", literal=literal)
        if isinstance(node, ast.Name):
            return env.get(node.id, _unknown_value())
        if isinstance(node, ast.Attribute):
            base = self._eval_expr(node.value, env, depth)
            if node.attr == "headers" and base.kind in {
                "dict",
                "response",
                "unknown",
            }:
                return Value(
                    kind="headers",
                    headers=base.headers,
                    exact=base.exact,
                    origin=base.origin,
                    origin_kind=base.origin_kind,
                    owner=base,
                )
            return _unknown_value()
        if isinstance(node, ast.Subscript):
            base = self._eval_expr(node.value, env, depth)
            key = _const_str(node.slice)
            if (
                key is not None
                and key.lower() == "headers"
                and base.kind
                in {
                    "dict",
                    "response",
                    "unknown",
                }
            ):
                return Value(
                    kind="headers",
                    headers=base.headers,
                    exact=base.exact,
                    origin=base.origin,
                    origin_kind=base.origin_kind,
                    owner=base,
                )
            if base.kind == "headers" and key is not None:
                return Value(kind="scalar")
            return _unknown_value()
        if isinstance(node, ast.Dict):
            return self._eval_dict(node, env, depth)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return Value(kind="scalar")
        if isinstance(node, ast.IfExp):
            return _merge_values(
                [
                    self._eval_expr(node.body, env, depth),
                    self._eval_expr(node.orelse, env, depth),
                ]
            )
        if isinstance(node, ast.BoolOp):
            return _merge_values(
                [self._eval_expr(value, env, depth) for value in node.values]
            )
        if isinstance(node, ast.Await):
            return self._eval_expr(node.value, env, depth)
        if isinstance(node, ast.Call):
            return self._eval_call(node, env, depth)
        if isinstance(node, ast.NamedExpr):
            value = self._eval_expr(node.value, env, depth)
            self._assign_target(node.target, value, env, node.lineno, depth)
            return value
        if isinstance(node, ast.Lambda):
            return Value(kind="function", fn_node=node, closure=env)
        return Value(kind="scalar")

    def _eval_dict(self, node, env, depth):
        keys = set()
        headers = None
        exact = True
        has_headers = False
        response_like = False
        origin = node.lineno

        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                value = self._eval_expr(value_node, env, depth)
                response_like = True
                if value.kind in {"dict", "headers", "response"}:
                    if value.kind == "dict" and value.keys is not None:
                        keys.update(value.keys)
                    else:
                        keys.update(value.headers or ())
                        if value.headers is not None:
                            headers = set(headers or ()) | set(value.headers)
                        else:
                            exact = False
                    if not value.exact:
                        exact = False
                else:
                    exact = False
                continue

            key = _const_str(key_node)
            if key is None:
                exact = False
                continue
            keys.add(key)
            if key.lower() == "headers":
                has_headers = True
                response_like = True
                value = self._eval_expr(value_node, env, depth)
                header_set = _header_values(value)
                if header_set is None:
                    exact = False
                else:
                    headers = set(header_set)
                if value is not None and not value.exact:
                    exact = False
            elif key in _RESPONSE_KEYS:
                response_like = True

        if has_headers or response_like:
            if headers is None and exact:
                headers = set()
            return Value(
                kind="response",
                headers=headers,
                exact=exact,
                origin=origin,
                origin_kind="created",
                keys=keys,
            )
        if keys and all(_looks_like_header(key) for key in keys):
            return Value(
                kind="headers",
                headers=set(keys),
                exact=True,
                origin=origin,
                keys=keys,
            )
        return Value(
            kind="dict",
            headers=None,
            exact=exact,
            origin=origin,
            origin_kind="created",
            keys=keys,
        )

    def _eval_call(self, node, env, depth):
        names = _expr_names(node.func)
        spec = self._wrapper_spec(names)

        if isinstance(node.func, ast.Name):
            callee = env.get(node.func.id)
            if callee is not None and callee.kind == "provider":
                return _merge_values(
                    [state.value for state in callee.call_states or []]
                )
            if callee is not None and callee.kind == "function":
                args = [self._eval_expr(arg, env, depth) for arg in node.args]
                kwargs = {
                    keyword.arg: self._eval_expr(keyword.value, env, depth)
                    for keyword in node.keywords
                    if keyword.arg is not None
                }
                result = self._call_local(
                    callee,
                    args,
                    kwargs,
                    node,
                    depth,
                )
                if spec is not None and result.kind in {
                    "dict",
                    "response",
                    "unknown",
                }:
                    result = self._apply_spec(result, spec)
                return result

        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            base = self._eval_expr(node.func.value, env, depth)
            if attr == "copy":
                return base.clone()
            if attr in _MUTATING_METHODS:
                self._apply_method_effect(base, attr, node, env, depth)
                return _unknown_value()
            if attr in {"json", "jsonify"} and base.kind == "response":
                return base.clone()

        if isinstance(node.func, ast.Name) and node.func.id == "dict":
            return self._eval_dict_call(node, env, depth)

        for arg_node in node.args:
            if isinstance(arg_node, ast.Call):
                self._eval_call(arg_node, env, depth)

        if spec is not None and node.args:
            first = self._eval_expr(node.args[0], env, depth)
            if first.kind in {"dict", "response", "unknown"}:
                return self._apply_spec(first, spec)

        return _unknown_value()

    def _eval_dict_call(self, node, env, depth):
        values = [self._eval_expr(arg, env, depth) for arg in node.args[:1]]
        base = values[0] if values else None
        keys = set()
        headers = None
        exact = True
        if base is not None:
            if base.kind in {"dict", "headers", "response"}:
                keys.update(base.keys or base.headers or ())
                headers = _header_values(base)
                exact = base.exact
            elif isinstance(node.args[0], (ast.List, ast.Tuple)):
                for element in node.args[0].elts:
                    if (
                        isinstance(element, (ast.Tuple, ast.List))
                        and element.elts
                    ):
                        key = _const_str(element.elts[0])
                        if key is not None:
                            keys.add(key)

        keyword_values = {
            keyword.arg: self._eval_expr(keyword.value, env, depth)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        keys.update(keyword_values)
        if "headers" in keyword_values:
            headers = _header_values(keyword_values["headers"])
            if headers is None:
                exact = False
            return Value(
                kind="response",
                headers=set(headers) if headers is not None else None,
                exact=exact,
                origin=node.lineno,
                origin_kind="created",
                keys=keys,
            )
        return Value(
            kind="dict",
            headers=headers,
            exact=exact,
            origin=node.lineno,
            origin_kind="created",
            keys=keys,
        )

    def _call_local(self, callee, args, kwargs, call_node, depth):
        if depth > 8:
            return _unknown_response()
        fn_node = callee.fn_node
        if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return _unknown_value()
        closure = _clone_env(callee.closure or self.global_env)
        self._bind_arguments(fn_node, args, kwargs, closure)
        returns = self._exec_function_body(fn_node, closure, depth + 1)
        if not returns:
            return _unknown_value()
        result = _merge_values([state.value for state in returns])
        if result.kind == "dict":
            result = self._as_response(result, call_node)
        return result

    def _bind_arguments(self, fn_node, args, kwargs, env):
        parameters = list(getattr(fn_node.args, "posonlyargs", [])) + list(
            fn_node.args.args
        )
        for index, param in enumerate(parameters):
            value = args[index] if index < len(args) else _unknown_value()
            env[param.arg] = value
        if fn_node.args.vararg is not None:
            env[fn_node.args.vararg.arg] = _unknown_value()
        if fn_node.args.kwarg is not None:
            env[fn_node.args.kwarg.arg] = _unknown_value()
        for name, value in kwargs.items():
            env[name] = value

    def _exec_function_body(self, fn_node, closure, depth):
        env = _clone_env(closure or {})
        for param in list(getattr(fn_node.args, "posonlyargs", [])) + list(
            fn_node.args.args
        ):
            env.setdefault(param.arg, _unknown_value())
        for param in fn_node.args.kwonlyargs:
            env.setdefault(param.arg, _unknown_value())
        if fn_node.args.vararg is not None:
            env.setdefault(fn_node.args.vararg.arg, _unknown_value())
        if fn_node.args.kwarg is not None:
            env.setdefault(fn_node.args.kwarg.arg, _unknown_value())
        returns, _ = self._exec_block(fn_node.body, env, depth, 0)
        return returns

    def _apply_decorators(self, decorators, states, env, depth):
        for decorator in reversed(decorators):
            names = _expr_names(decorator)
            if any(name in _TRANSPARENT_DECORATORS for name in names):
                continue
            spec = self._wrapper_spec(names)
            local = self._local_function(names)
            if local is not None and isinstance(
                local.node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                wrapped = self._apply_local_decorator(
                    local.node,
                    states,
                    env,
                    depth + 1,
                )
                if wrapped:
                    states = wrapped
            if spec is not None:
                states = [
                    ReturnState(
                        self._apply_spec(state.value, spec),
                        state.return_node,
                    )
                    if state.value.kind in {"dict", "response", "unknown"}
                    else state
                    for state in states
                ]
        return states

    def _apply_local_decorator(self, fn_node, states, caller_env, depth):
        if depth > 8:
            return states
        env = _clone_env(fn_node_closure := caller_env or self.global_env)
        parameters = list(getattr(fn_node.args, "posonlyargs", [])) + list(
            fn_node.args.args
        )
        if parameters:
            env[parameters[0].arg] = Value(
                kind="provider",
                call_states=states,
            )
            for param in parameters[1:]:
                env[param.arg] = _unknown_value()

        returns, _ = self._exec_block(fn_node.body, env, depth, 0)
        output = []
        for state in returns:
            value = state.value
            if value.kind == "function" and isinstance(
                value.fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                wrapper_closure = _clone_env(value.closure or fn_node_closure)
                wrapper_returns = self._exec_function_body(
                    value.fn_node,
                    wrapper_closure,
                    depth + 1,
                )
                wrapper_returns = self._apply_decorators(
                    value.fn_node.decorator_list,
                    wrapper_returns,
                    wrapper_closure,
                    depth + 1,
                )
                output.extend(wrapper_returns)
            elif value.kind in {"dict", "response", "unknown"}:
                output.append(state)
        return output or states

    def _apply_spec(self, value, spec):
        if value.kind not in {"dict", "response", "unknown"}:
            return value
        if value.kind != "response":
            value = self._as_response(value, None)
        if spec.all_headers:
            value.headers = set(value.headers or ()) | set(
                self.contract.required
            )
            value.exact = True
        else:
            if value.headers is None:
                value.headers = set(spec.headers)
            else:
                value.headers.update(spec.headers)
        return value

    def _exec_block(self, statements, env, depth, loop_depth):
        returns = []
        for statement in statements:
            if isinstance(statement, ast.Return):
                value = self._eval_expr(statement.value, env, depth)
                response = self._as_response(value, statement)
                if response is not None and loop_depth:
                    response = response.clone()
                    response.headers = None
                    response.exact = False
                returns.append(
                    ReturnState(
                        response if response is not None else value,
                        statement,
                    )
                )
                return returns, False
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                if isinstance(statement, ast.Assign):
                    value = self._eval_expr(statement.value, env, depth)
                    for target in statement.targets:
                        self._assign_target(
                            target,
                            value,
                            env,
                            statement.lineno,
                            depth,
                        )
                elif statement.value is not None:
                    value = self._eval_expr(statement.value, env, depth)
                    self._assign_target(
                        statement.target,
                        value,
                        env,
                        statement.lineno,
                        depth,
                    )
            elif isinstance(statement, ast.AugAssign):
                self._exec_augassign(statement, env, depth)
            elif isinstance(statement, ast.Expr):
                self._eval_expr(statement.value, env, depth)
            elif isinstance(statement, ast.If):
                returns.extend(
                    self._exec_if(statement, env, depth, loop_depth)
                )
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                returns.extend(
                    self._exec_loop(statement, env, depth, loop_depth + 1)
                )
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                returns.extend(
                    self._exec_with(statement, env, depth, loop_depth)
                )
            elif isinstance(statement, ast.Try):
                returns.extend(
                    self._exec_try(statement, env, depth, loop_depth)
                )
            elif isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                env[statement.name] = Value(
                    kind="function",
                    fn_node=statement,
                    closure=env.copy(),
                )
            elif isinstance(statement, ast.ClassDef):
                env[statement.name] = _unknown_value()
            elif isinstance(statement, ast.Raise):
                return returns, False
        return returns, True

    def _exec_if(self, statement, env, depth, loop_depth=0):
        body_env = _clone_env(env)
        body_returns, body_falls = self._exec_block(
            statement.body,
            body_env,
            depth,
            loop_depth,
        )
        else_env = _clone_env(env)
        if statement.orelse:
            else_returns, else_falls = self._exec_block(
                statement.orelse,
                else_env,
                depth,
                loop_depth,
            )
        else:
            else_returns, else_falls = [], True

        returns = body_returns + else_returns
        if body_falls and else_falls:
            self._replace_env(env, self._merge_envs(body_env, else_env))
        elif body_falls:
            self._replace_env(env, body_env)
        elif else_falls:
            self._replace_env(env, else_env)
        return returns

    def _exec_loop(self, statement, env, depth, loop_depth):
        body_env = _clone_env(env)
        body_returns, _ = self._exec_block(
            statement.body,
            body_env,
            depth,
            loop_depth,
        )
        for state in body_returns:
            state.value.headers = None
            state.value.exact = False

        for name, value in body_env.items():
            if value.kind in {"dict", "headers", "response", "unknown"}:
                if name not in env or env[name] is not value:
                    env[name] = Value(
                        kind="response"
                        if value.kind != "headers"
                        else "headers",
                        exact=False,
                    )
        for value in env.values():
            if value.kind in {"dict", "headers", "response"}:
                value.headers = None
                value.exact = False
                value.origin = None
                value.origin_kind = None
        return body_returns

    def _exec_with(self, statement, env, depth, loop_depth):
        body_env = _clone_env(env)
        returns, falls = self._exec_block(
            statement.body,
            body_env,
            depth,
            loop_depth,
        )
        if falls:
            self._replace_env(env, body_env)
        return returns

    def _exec_try(self, statement, env, depth, loop_depth=0):
        body_env = _clone_env(env)
        returns, body_falls = self._exec_block(
            statement.body,
            body_env,
            depth,
            loop_depth,
        )
        fall_envs = [body_env] if body_falls else []
        for handler in statement.handlers:
            handler_env = _clone_env(env)
            handler_returns, handler_falls = self._exec_block(
                handler.body,
                handler_env,
                depth,
                loop_depth,
            )
            returns.extend(handler_returns)
            if handler_falls:
                fall_envs.append(handler_env)

        if statement.orelse:
            else_returns, else_falls = self._exec_block(
                statement.orelse,
                body_env,
                depth,
                loop_depth,
            )
            returns.extend(else_returns)
            if not else_falls and body_env in fall_envs:
                fall_envs.remove(body_env)

        if fall_envs:
            merged = fall_envs[0]
            for other in fall_envs[1:]:
                merged = self._merge_envs(merged, other)
            self._replace_env(env, merged)
        if statement.finalbody:
            final_returns, _ = self._exec_block(
                statement.finalbody,
                env,
                depth,
                loop_depth,
            )
            returns.extend(final_returns)
        return returns

    @staticmethod
    def _replace_env(env, replacement):
        env.clear()
        env.update(replacement)

    def _merge_envs(self, left, right):
        merged = {}
        for name in set(left) | set(right):
            if name not in left or name not in right:
                value = left.get(name) or right.get(name)
                if value is None:
                    continue
                if value.kind in {"dict", "headers", "response"}:
                    merged[name] = Value(kind=value.kind, exact=False)
                else:
                    merged[name] = value.clone()
                continue
            a, b = left[name], right[name]
            if a is b:
                merged[name] = a
                continue
            headers_a = _header_values(a)
            headers_b = _header_values(b)
            if a.kind in {"dict", "headers", "response"} or b.kind in {
                "dict",
                "headers",
                "response",
                "unknown",
            }:
                if headers_a is None or headers_b is None:
                    headers = None
                    exact = False
                else:
                    headers = set(headers_a) & set(headers_b)
                    exact = a.exact and b.exact
                merged[name] = Value(
                    kind="response",
                    headers=headers,
                    exact=exact,
                    origin=a.origin or b.origin,
                    origin_kind=a.origin_kind or b.origin_kind,
                )
            else:
                merged[name] = a.clone()
        return merged

    def _assign_target(self, target, value, env, lineno, depth):
        if isinstance(target, ast.Name):
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(
                    element,
                    _unknown_value(),
                    env,
                    lineno,
                    depth,
                )
            return
        if isinstance(target, ast.Attribute):
            if target.attr == "headers":
                base = self._eval_expr(target.value, env, depth)
                self._set_headers(base, value, lineno)
            return
        if isinstance(target, ast.Subscript):
            self._assign_subscript(target, value, env, lineno, depth)

    def _assign_subscript(self, target, value, env, lineno, depth):
        key = _const_str(target.slice)
        container = target.value
        if key is None:
            return
        if key.lower() == "headers":
            base = self._eval_expr(container, env, depth)
            self._set_headers(base, value, lineno)
            return
        base = self._eval_expr(container, env, depth)
        if (
            isinstance(container, ast.Attribute)
            and container.attr == "headers"
        ):
            self._add_header(base, key)
        elif isinstance(container, ast.Subscript):
            inner_key = _const_str(container.slice)
            if inner_key is not None and inner_key.lower() == "headers":
                inner = self._eval_expr(container, env, depth)
                self._add_header(inner, key)
        elif base.kind == "headers":
            self._add_header(base, key)

    def _set_headers(self, value, header_value, lineno):
        if value.kind == "headers" and value.owner is not None:
            value = value.owner
        if value.kind not in {"dict", "response", "unknown"}:
            return
        if value.kind != "response":
            value.kind = "response"
        headers = _header_values(header_value)
        if headers is None:
            value.headers = None
            value.exact = False
        else:
            value.headers = set(headers)
            value.exact = True
        value.origin = lineno
        value.origin_kind = "headers rewritten"

    def _add_header(self, value, header):
        if value.kind == "headers" and value.owner is not None:
            value = value.owner
        if value.kind not in {"dict", "headers", "response", "unknown"}:
            return
        if value.headers is None:
            value.headers = {header}
        else:
            value.headers.add(header)

    def _apply_method_effect(self, base, attr, call_node, env, depth):
        owner = base.owner if base.kind == "headers" and base.owner else base
        args = [self._eval_expr(arg, env, depth) for arg in call_node.args]
        if attr == "update":
            if base.kind == "headers" or owner.kind == "headers":
                for value in args:
                    headers = _header_values(value)
                    if headers is None:
                        owner.exact = False
                        owner.headers = None
                    elif owner.headers is None:
                        owner.headers = set(headers)
                    else:
                        owner.headers.update(headers)
                for keyword in call_node.keywords:
                    if keyword.arg is None:
                        owner.exact = False
                        continue
                    value = self._eval_expr(keyword.value, env, depth)
                    if keyword.arg.lower() == "headers":
                        self._set_headers(owner, value, call_node.lineno)
                    else:
                        self._add_header(owner, keyword.arg)
                return
            if owner.kind in {"dict", "response"}:
                for value in args:
                    if value.kind == "dict" and value.keys is not None:
                        if "headers" in value.keys:
                            headers = value.headers or set()
                            self._set_headers(
                                owner,
                                Value(
                                    kind="headers",
                                    headers=set(headers),
                                    exact=value.exact,
                                ),
                                call_node.lineno,
                            )
                for keyword in call_node.keywords:
                    if keyword.arg == "headers":
                        value = self._eval_expr(keyword.value, env, depth)
                        self._set_headers(owner, value, call_node.lineno)
            return
        if attr in {"add", "setdefault", "extend"}:
            for value in args[:1]:
                header = _const_str_value(value)
                if header is not None:
                    self._add_header(owner, header)
            return
        if attr == "pop":
            if args:
                header = _const_str_value(args[0])
                if header is not None and owner.headers is not None:
                    owner.headers = {
                        item
                        for item in owner.headers
                        if _norm_header(item) != _norm_header(header)
                    }
            return
        if attr == "clear":
            owner.headers = set()
            owner.exact = True
            owner.origin = call_node.lineno
            owner.origin_kind = "headers rewritten"

    def _exec_augassign(self, statement, env, depth):
        value = self._eval_expr(statement.value, env, depth)
        target = statement.target
        if isinstance(target, ast.Subscript):
            key = _const_str(target.slice)
            if key is not None and key.lower() == "headers":
                base = self._eval_expr(target.value, env, depth)
                headers = _header_values(value)
                if headers is not None:
                    for header in headers:
                        self._add_header(base, header)
                else:
                    if base.kind == "headers" and base.owner is not None:
                        base = base.owner
                    base.exact = False
            elif key is not None:
                base = self._eval_expr(target.value, env, depth)
                if base.kind == "headers":
                    self._add_header(base, key)
        elif isinstance(target, ast.Name):
            current = env.get(target.id)
            if current is not None and current.kind in {"response", "headers"}:
                headers = _header_values(value)
                if headers is not None:
                    for header in headers:
                        self._add_header(current, header)
                else:
                    current.exact = False

    def _as_response(self, value, return_node):
        if value is None:
            return None
        if value.kind == "response":
            return value
        if value.kind == "dict":
            headers = value.headers
            if headers is None:
                headers = set() if value.exact else None
            return Value(
                kind="response",
                headers=headers,
                exact=value.exact,
                origin=value.origin
                or (return_node.lineno if return_node is not None else None),
                origin_kind=value.origin_kind or "created",
                keys=value.keys,
            )
        if value.kind == "unknown":
            return Value(
                kind="response",
                exact=False,
                origin=return_node.lineno if return_node is not None else None,
                origin_kind="external",
            )
        return None


def _const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _const_str_value(value):
    if value is None:
        return None
    return value.literal


def _names_match(name, key):
    name = str(name).strip().lstrip("@")
    key = str(key).strip().lstrip("@")
    if name == key:
        return True
    return name.split(".")[-1] == key.split(".")[-1]


def _expr_names(node):
    if isinstance(node, ast.Call):
        return _expr_names(node.func)
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return [f"{base}.{node.attr}" if base else node.attr, node.attr]
    return []


def _dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _mark_parents(tree):
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._rh_parent = parent
            if isinstance(parent, ast.ClassDef):
                child._rh_parent_class = parent


def analyze_source(source, config=None, filename="<memory>"):
    """Analyze ``source`` and return a list of response-header findings."""
    if isinstance(source, bytes):
        source = source.decode("utf-8")
    tree = ast.parse(source)
    _mark_parents(tree)
    contract = normalise_config(config or {})
    return Analyzer(tree, contract, filename).analyze()


def analyze_file(path, config=None):
    with open(path, "r", encoding="utf-8") as source_file:
        return analyze_source(source_file.read(), config, path)


_CACHE = {}


def _source_bytes(context):
    data = context.file_data or b""
    if hasattr(data, "read"):
        try:
            position = data.tell()
        except (AttributeError, OSError):
            position = None
        data.seek(0)
        data = data.read()
        if position is not None:
            data_file = context.file_data
            data_file.seek(position)
    if isinstance(data, str):
        data = data.encode("utf-8")
    return data


def _cache_key(context, config):
    source = _source_bytes(context)
    digest = hashlib.sha256(source).hexdigest()
    try:
        config_key = json.dumps(config, sort_keys=True, default=str)
    except TypeError:
        config_key = repr(config)
    return (context.filename, digest, config_key)


def _plugin(context, config):
    key = _cache_key(context, config)
    if key not in _CACHE:
        source = _source_bytes(context)
        _CACHE[key] = analyze_source(source, config, context.filename)
    if not isinstance(context.node, ast.Return):
        if (
            isinstance(context.node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _CACHE[key]
        ):
            return _CACHE[key][0].as_issue()
        return None
    for finding in _CACHE[key]:
        if finding.return_line == context.node.lineno:
            return finding.as_issue()
    return None


@test.takes_config("response_headers")
@test.checks("Return")
@test.test_id("B705")
def response_headers(context, config):
    return _plugin(context, config)


@test.takes_config("http_response_headers")
@test.checks("Return")
@test.test_id("B705")
def http_response_headers(context, config):
    return _plugin(context, config)


@test.takes_config("security_headers")
@test.checks("Return")
@test.test_id("B705")
def security_headers(context, config):
    return _plugin(context, config)


@test.takes_config("response_header_contract")
@test.checks("Return")
@test.test_id("B705")
def response_header_contract(context, config):
    return _plugin(context, config)


@test.takes_config("missing_security_headers")
@test.checks("Return")
@test.test_id("B705")
def missing_security_headers(context, config):
    return _plugin(context, config)
