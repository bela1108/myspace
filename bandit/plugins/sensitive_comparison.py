# SPDX-License-Identifier: Apache-2.0
r"""\
================================================
B616: Test for ordinary comparison of secrets
================================================

Sensitive values, such as passwords and authentication tokens, should be
compared with a constant-time comparison function.  Ordinary equality
operators short-circuit as soon as a difference is found, which can leak
information through timing side channels.

This plugin follows local assignments and tuple/list unpacking, examines
every equality in a chained comparison, and visits comparisons embedded in
short-circuit boolean expressions.  It is deliberately enabled through
configuration so that projects can name their own sensitive formal
parameters and their own constant-time comparison helpers.

**Config Options:**

.. code-block:: yaml

    sensitive_comparison:
        sensitive_parameters:
            - password
            - token
            - api_key
        allowed_comparison_functions:
            - hmac.compare_digest
            - secrets.compare_digest

The plugin reports the definite sensitive source and any source whose
provenance cannot be established separately in the issue text.

:Example:

.. code-block:: none

        >> Issue: Ordinary equality comparison involving a sensitive value
           Severity: Medium   Confidence: High
           CWE: CWE-208 (https://cwe.mitre.org/data/definitions/208.html)
           Location: examples/sensitive-comparison.py:8
        7    def authenticate(password, candidate, ready):
        8        if ready and password == candidate:
        9            return True

.. seealso::

    - https://cwe.mitre.org/data/definitions/208.html
    - https://docs.python.org/3/library/hmac.html#hmac.compare_digest

.. versionadded:: 1.8.7

"""

import ast
import fnmatch

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

_DEFAULT_SENSITIVE_PARAMETERS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "session_token",
    "csrf_token",
    "private_key",
    "signing_key",
)

_DEFAULT_ALLOWED_COMPARISON_FUNCTIONS = (
    "hmac.compare_digest",
    "secrets.compare_digest",
    "django.utils.crypto.constant_time_compare",
    "cryptography.hazmat.primitives.constant_time.bytes_eq",
)

_SENSITIVE_KEYS = (
    "sensitive_parameters",
    "sensitive_params",
    "sensitive_formal_parameters",
    "sensitive_formals",
    "sensitive_arguments",
    "sensitive_args",
    "sensitive_parameter_names",
    "sensitive_names",
    "sensitive_values",
    "sensitive_variables",
    "secret_parameters",
    "secret_params",
    "secret_names",
    "protected_parameters",
    "parameter_names",
)

_ALLOWED_KEYS = (
    "allowed_comparison_functions",
    "allowed_comparisons",
    "allowed_compare_functions",
    "allowed_comparison_funcs",
    "allowed_comparison_function_names",
    "allowed_funcs",
    "allowed_functions",
    "allowed_methods",
    "safe_comparison_functions",
    "safe_functions",
    "safe_funcs",
    "constant_time_functions",
    "constant_time_comparison_functions",
    "permitted_comparison_functions",
    "comparison_functions",
)


class _Sources:
    """Provenance of an expression for one side of a comparison."""

    __slots__ = ("definite", "unknown", "safe")

    def __init__(self, definite=None, unknown=None, safe=False):
        self.definite = set(definite or ())
        self.unknown = set(unknown or ())
        self.safe = safe

    def clone(self):
        return _Sources(self.definite, self.unknown, self.safe)

    def merge(self, other):
        if other is None:
            return self
        self.definite.update(other.definite)
        self.unknown.update(other.unknown)
        self.safe = self.safe or other.safe
        return self


def _coerce_values(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        for key in ("parameters", "names", "values", "arguments", "args"):
            if key in value:
                return _coerce_values(value[key])
        result = list(value)
        for nested in value.values():
            if isinstance(nested, (list, tuple, set, str)):
                result.extend(_coerce_values(nested))
        return result
    result = []
    for item in value:
        if isinstance(item, dict):
            name = (
                item.get("name")
                or item.get("parameter")
                or item.get("identifier")
            )
            if name:
                result.append(name)
            else:
                result.extend(item)
        else:
            result.append(item)
    return result


def _options(config, keys, default):
    if isinstance(config, (list, tuple, set, frozenset)):
        return list(config)
    if not isinstance(config, dict):
        return list(default)
    for key in keys:
        if key in config:
            return _coerce_values(config[key])
    return list(default)


def _config_values(config):
    if config is None:
        sensitive = list(_DEFAULT_SENSITIVE_PARAMETERS)
        allowed = list(_DEFAULT_ALLOWED_COMPARISON_FUNCTIONS)
    else:
        sensitive = _options(config, _SENSITIVE_KEYS, ())
        allowed = _options(
            config,
            _ALLOWED_KEYS,
            _DEFAULT_ALLOWED_COMPARISON_FUNCTIONS,
        )
    return sensitive, allowed


def _normalise_entry(value):
    return str(value).strip().casefold()


def _sensitive_names(values):
    return {_normalise_entry(value) for value in values if value}


def _allowed_names(values):
    return {_normalise_entry(value) for value in values if value}


def _matches_allowed(name, allowed):
    if not name:
        return False
    name = _normalise_entry(name)
    for entry in allowed:
        if fnmatch.fnmatchcase(name, entry):
            return True
        if "." in entry:
            if name == entry or name.endswith("." + entry):
                return True
        elif name.split(".")[-1] == entry:
            return True
    return False


def _is_sensitive(name, sensitive):
    if not name:
        return False
    name = _normalise_entry(name)
    if name in sensitive:
        return True
    if any("*" in entry or "?" in entry for entry in sensitive) and any(
        fnmatch.fnmatchcase(name, entry)
        for entry in sensitive
        if "*" in entry or "?" in entry
    ):
        return True
    return any(
        entry.endswith("." + name) for entry in sensitive if "." in entry
    )


def _node_text(node):
    try:
        text = ast.unparse(node)
    except (AttributeError, TypeError, ValueError):
        text = type(node).__name__
    text = " ".join(text.split())
    if len(text) > 90:
        text = text[:87] + "..."
    return text


def _expr_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        if base:
            return base + "." + node.attr
        return node.attr
    return None


def _call_name(node):
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    return None


def _parent(node):
    return getattr(node, "_bandit_parent", None)


def _enclosing_scope(node):
    parent = _parent(node)
    while parent is not None:
        if isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            return parent
        parent = _parent(parent)
    return None


def _function_name(function):
    if isinstance(function, ast.Lambda):
        return "<lambda>"
    return getattr(function, "name", None)


def _function_qualname(function):
    parts = []
    parent = function
    while parent is not None:
        name = _function_name(parent)
        if name and name != "<lambda>":
            parts.append(name)
        parent = _parent(parent)
    return ".".join(reversed(parts))


def _inside_allowed_call(node, allowed):
    parent = _parent(node)
    while parent is not None:
        if isinstance(parent, ast.Call):
            if _matches_allowed(_call_name(parent), allowed):
                return True
        parent = _parent(parent)
    return False


def _inside_allowed_function(scope, allowed):
    if scope is None:
        return False
    name = _function_name(scope)
    if _matches_allowed(name, allowed):
        return True
    if _matches_allowed(_function_qualname(scope), allowed):
        return True
    final = _normalise_entry(name)
    return any(
        entry.split(".")[-1] == final
        for entry in allowed
        if "." in entry and final
    )


def _walk_scope(root):
    """Yield nodes in the current lexical scope, not nested scopes."""
    for child in ast.iter_child_nodes(root):
        if isinstance(
            child,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        yield child
        yield from _walk_scope(child)


def _iter_comparisons(node):
    """Yield every comparison node below *node* in deterministic order."""
    if isinstance(node, ast.Compare):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_comparisons(child)


def collect_compare_nodes(node):
    """Return all comparison nodes, independent of statement ordering."""
    return list(_iter_comparisons(node))


def _merge_sources(env, name, sources):
    if not name:
        return
    current = env.get(name)
    if current is None:
        env[name] = sources.clone()
    else:
        current.merge(sources)


class _ScopeAnalyzer:
    """Flow-insensitive local source tracker for a function or module."""

    def __init__(self, scope, sensitive, allowed):
        self.scope = scope
        self.sensitive = sensitive
        self.allowed = allowed
        self.bindings = []
        self.env = {}
        if scope is not None:
            self._collect_bindings()
            self._solve_bindings()

    def _collect_bindings(self):
        for node in _walk_scope(self.scope):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self.bindings.append((target, node.value))
            elif isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    self.bindings.append((node.target, node.value))
            elif isinstance(node, ast.AugAssign):
                self.bindings.append((node.target, node.value))
            elif isinstance(node, ast.NamedExpr):
                self.bindings.append((node.target, node.value))
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self.bindings.append((node.target, node.iter))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        self.bindings.append(
                            (item.optional_vars, item.context_expr)
                        )
            elif isinstance(node, ast.comprehension):
                self.bindings.append((node.target, node.iter))
            elif isinstance(node, ast.ExceptHandler):
                if node.name:
                    self.bindings.append((ast.Name(id=node.name), None))

    def _solve_bindings(self):
        passes = min(max(len(self.bindings) + 1, 2), 10)
        for _ in range(passes):
            env = {}
            for target, value in self.bindings:
                if value is None:
                    sources = _Sources(unknown={_node_text(target)})
                else:
                    sources = self._resolve(value, env)
                self._bind_target(env, target, value, sources)
            self.env = env

    def _bind_target(self, env, target, value, sources):
        if isinstance(target, ast.Name):
            _merge_sources(env, target.id, sources)
        elif isinstance(target, ast.Starred):
            self._bind_target(env, target.value, value, sources)
        elif isinstance(target, (ast.Tuple, ast.List)):
            elements = getattr(value, "elts", None)
            if isinstance(value, (ast.Tuple, ast.List)) and elements:
                values = list(elements)
                targets = list(target.elts)
                for index, element in enumerate(targets):
                    if isinstance(element, ast.Starred):
                        remaining = values[index:]
                    else:
                        remaining = values[index : index + 1]
                    if remaining:
                        child = self._resolve_many(remaining, env)
                    else:
                        child = sources
                    self._bind_target(env, element, None, child)
            else:
                for element in target.elts:
                    self._bind_target(env, element, None, sources)
        elif isinstance(target, ast.Attribute):
            _merge_sources(env, _expr_name(target), sources)
        elif isinstance(target, ast.Subscript):
            _merge_sources(env, _node_text(target), sources)

    def _resolve_many(self, nodes, env):
        sources = _Sources()
        for node in nodes:
            sources.merge(self._resolve(node, env, set(), 0))
        return sources

    def _resolve(self, node, env=None, seen=None, depth=0):
        if node is None:
            return _Sources(safe=True)
        if env is None:
            env = self.env
        if seen is None:
            seen = set()
        if depth > 8:
            return _Sources(unknown={_node_text(node)})

        if isinstance(node, ast.Constant):
            return _Sources(safe=True)

        if isinstance(node, ast.Name):
            if _is_sensitive(node.id, self.sensitive):
                return _Sources(definite={node.id})
            if node.id in env and node.id not in seen:
                seen = seen | {node.id}
                return env[node.id].clone()
            return _Sources(unknown={node.id})

        if isinstance(node, ast.Attribute):
            label = _expr_name(node)
            if label in env:
                return env[label].clone()
            if _is_sensitive(label, self.sensitive):
                return _Sources(definite={label})
            base = self._resolve(node.value, env, seen, depth + 1)
            if base.definite:
                return _Sources(definite={label}, safe=base.safe)
            if base.unknown:
                return _Sources(unknown={label})
            return _Sources(safe=base.safe)

        if isinstance(node, ast.Subscript):
            base = self._resolve(node.value, env, seen, depth + 1)
            if base.definite:
                return base
            if base.unknown:
                return _Sources(unknown={_node_text(node)})
            return _Sources(safe=True)

        if isinstance(node, ast.Call):
            if _matches_allowed(_call_name(node), self.allowed):
                return _Sources(safe=True)
            return _Sources(unknown={_node_text(node)})

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return self._resolve_many(node.elts, env)

        if isinstance(node, ast.Dict):
            sources = _Sources()
            for key in node.keys:
                sources.merge(self._resolve(key, env, seen, depth + 1))
            for value in node.values:
                sources.merge(self._resolve(value, env, seen, depth + 1))
            return sources

        if isinstance(node, ast.BoolOp):
            return self._resolve_many(node.values, env)

        if isinstance(node, ast.BinOp):
            sources = self._resolve(node.left, env, seen, depth + 1)
            sources.merge(self._resolve(node.right, env, seen, depth + 1))
            return sources

        if isinstance(node, ast.UnaryOp):
            return self._resolve(node.operand, env, seen, depth + 1)

        if isinstance(node, ast.IfExp):
            sources = self._resolve(node.test, env, seen, depth + 1)
            sources.merge(self._resolve(node.body, env, seen, depth + 1))
            sources.merge(self._resolve(node.orelse, env, seen, depth + 1))
            return sources

        if isinstance(node, ast.Compare):
            sources = self._resolve(node.left, env, seen, depth + 1)
            for comparator in node.comparators:
                sources.merge(self._resolve(comparator, env, seen, depth + 1))
            return sources

        if isinstance(node, ast.JoinedStr):
            return self._resolve_many(node.values, env)

        if isinstance(node, ast.FormattedValue):
            return self._resolve(node.value, env, seen, depth + 1)

        if isinstance(node, ast.Starred):
            return self._resolve(node.value, env, seen, depth + 1)

        if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
            return self._resolve(node.value, env, seen, depth + 1)

        if isinstance(node, ast.NamedExpr):
            return self._resolve(node.value, env, seen, depth + 1)

        return _Sources(unknown={_node_text(node)})

    def find_equalities(self, node, include_inequalities=False):
        findings = []
        left = node.left
        for op, right in zip(node.ops, node.comparators):
            is_equality = isinstance(op, ast.Eq)
            is_inequality = isinstance(op, ast.NotEq)
            if not (is_equality or (include_inequalities and is_inequality)):
                left = right
                continue
            left_sources = self._resolve(left)
            right_sources = self._resolve(right)
            definite = left_sources.definite | right_sources.definite
            if definite:
                unknown = set()
                if not left_sources.definite:
                    unknown.update(left_sources.unknown)
                if not right_sources.definite:
                    unknown.update(right_sources.unknown)
                findings.append(
                    (
                        _node_text(left)
                        + " "
                        + _op_text(op)
                        + " "
                        + _node_text(right),
                        definite,
                        unknown,
                    )
                )
            left = right
        return findings


def _op_text(op):
    if isinstance(op, ast.Eq):
        return "=="
    if isinstance(op, ast.NotEq):
        return "!="
    return type(op).__name__


def _format_names(values):
    if not values:
        return "none"
    return ", ".join(sorted(values))


def _run_check(context, config):
    node = context.node
    if not isinstance(node, ast.Compare):
        return None

    config = config or {}
    sensitive_values, allowed_values = _config_values(config)
    sensitive = _sensitive_names(sensitive_values)
    allowed = _allowed_names(allowed_values)
    include_inequalities = bool(
        config.get("check_not_equal", config.get("include_inequalities"))
        if isinstance(config, dict)
        else False
    )

    scope = _enclosing_scope(node)
    if scope is None:
        scope = context._context.get("function")
    if _inside_allowed_function(scope, allowed):
        return None
    if _inside_allowed_call(node, allowed):
        return None

    analyzer = _ScopeAnalyzer(scope, sensitive, allowed)
    findings = analyzer.find_equalities(
        node, include_inequalities=include_inequalities
    )
    if not findings:
        return None

    definite = set()
    unknown = set()
    for _, defs, unks in findings:
        definite.update(defs)
        unknown.update(unks)

    text = (
        "Ordinary equality comparison involving sensitive data "
        "(possible timing attack): "
        f"definite source(s): {_format_names(definite)}; "
        f"unknown source(s): {_format_names(unknown)}. "
        "Use a constant-time comparison function instead. "
        f"Comparison: {_node_text(node)}"
    )
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.HIGH,
        cwe=issue.Cwe.TIMING_ATTACK,
        text=text,
        lineno=node.lineno,
    )


def gen_config(name):
    return {
        "sensitive_parameters": [],
        "allowed_comparison_functions": list(
            _DEFAULT_ALLOWED_COMPARISON_FUNCTIONS
        ),
    }


@test.checks("Compare")
@test.test_id("B616")
@test.takes_config("sensitive_comparison")
def sensitive_comparison(context, config=None):
    """Detect ordinary equality checks against configured secrets."""
    return _run_check(context, config)


@test.checks("Compare")
@test.test_id("B616")
@test.takes_config("insecure_comparison")
def insecure_comparison(context, config=None):
    """Alias entry point for projects using the insecure_comparison name."""
    return _run_check(context, config)


@test.checks("Compare")
@test.test_id("B616")
@test.takes_config("sensitive_compare")
def sensitive_compare(context, config=None):
    """Alias entry point for projects using the sensitive_compare name."""
    return _run_check(context, config)


@test.checks("Compare")
@test.test_id("B616")
@test.takes_config("unsafe_comparison")
def unsafe_comparison(context, config=None):
    """Alias entry point for projects using the unsafe_comparison name."""
    return _run_check(context, config)


@test.checks("Compare")
@test.test_id("B616")
@test.takes_config("sensitive_data_comparison")
def sensitive_data_comparison(context, config=None):
    """Alias entry point for the sensitive_data_comparison name."""
    return _run_check(context, config)


@test.checks("Compare")
@test.test_id("B616")
@test.takes_config("timing_attack")
def timing_attack(context, config=None):
    """Alias entry point for projects using the timing_attack name."""
    return _run_check(context, config)


find_comparisons = collect_compare_nodes
constant_time_compare = sensitive_comparison
sensitive_equality = sensitive_comparison
