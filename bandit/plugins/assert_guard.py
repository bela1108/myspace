#
# SPDX-License-Identifier: Apache-2.0
r"""
==============================================
B114: Test for validation guards that use assert
==============================================

Python removes ``assert`` statements when it compiles optimized byte code
(``python -O``).  A gateway that uses an assertion as its only validation
check therefore changes its security behaviour in an optimized build.

This plugin looks at assertions whose condition calls a configured validation
function.  It then follows the rest of the enclosing function (and bounded
local helper calls) to find configured sensitive operations.

Each operation is classified as one of:

``independent-rejection``
    An explicit ``if``/``raise``/``return`` rejection still rejects invalid
    input when the assertion is removed.  The assertion is redundant for this
    operation.

``sole-check``
    No independent rejection protects the operation.  Removing the assertion
    lets invalid input reach the operation.

``unproven``
    The bounded analysis found a conditional rejection, or reached a
    configured analysis bound, but cannot prove that every invalid path is
    rejected.

The analysis deliberately stays local.  It only inspects conditionals in the
enclosing function and functions defined in the same module, up to the
configured nesting and helper-call bounds.  It does not attempt whole-program
data-flow analysis.

**Config Options:**

The caller declares which calls are validation calls and which calls are
sensitive operations.  Patterns are matched against both the qualified name
and the final call name, using shell-style wildcards.

.. code-block:: yaml

    assert_guard:
      validators:
        - validate_request
        - authorize
      sensitive_calls:
        - db.execute
        - write_audit
      max_if_depth: 3
      max_helper_depth: 1
      report_independent: true

``report_independent`` controls whether the safe ``independent-rejection``
classification is emitted.  It is enabled by default so that an audit shows
all three outcomes.

:Example:

.. code-block:: none

    >> Issue: Assert guard analysis (classification=sole-check; assert at
       line 26: 'assert validate_request(request), "invalid request"'):
       operation at line 27
       ('write_audit(request)') is reached when python -O removes the only
       validation check.
       Severity: High   Confidence: High
       CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
       Location: ./examples/assert_guard_assert_only.py:26

.. seealso::

 - https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement
 - https://cwe.mitre.org/data/definitions/703.html

.. versionadded:: 1.8.0
"""

import ast
import fnmatch

import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core import utils

INDEPENDENT = "independent-rejection"
SOLE = "sole-check"
UNKNOWN = "unproven"

DEFAULT_VALIDATORS = (
    "validate*",
    "check_*",
    "verify*",
    "authorize*",
    "authenticate*",
    "is_valid",
    "has_access",
)

DEFAULT_SENSITIVE_CALLS = (
    "os.system",
    "os.popen",
    "subprocess.*",
    "*.execute",
    "*.executemany",
    "*.executescript",
    "*.query",
    "*.raw",
    "*.send",
    "*.sendall",
    "*.publish",
    "*.write",
    "*.writelines",
    "*.delete",
    "*.unlink",
    "*.remove",
    "*.commit",
    "*.transfer",
    "*.charge",
    "*.refund",
)

DEFAULT_REJECT_CALLS = (
    "abort*",
    "deny*",
    "reject*",
    "forbid*",
    "unauthori*",
    "send_error",
    "fail*",
    "exit",
    "quit",
    "os._exit",
    "sys.exit",
)

_MAX_EXPR_DEPTH = 10
_MAX_STATEMENTS = 500


def gen_config(name):
    if name == "assert_guard":
        return {
            "validators": list(DEFAULT_VALIDATORS),
            "sensitive_calls": list(DEFAULT_SENSITIVE_CALLS),
            "max_if_depth": 3,
            "max_helper_depth": 1,
            "report_independent": True,
        }


def _list_option(config, *names):
    for name in names:
        if name in config:
            value = config.get(name)
            if value is None:
                return []
            if isinstance(value, str):
                return [value]
            return [str(item) for item in value]
    return None


def _bool_option(config, name, default):
    value = config.get(name, default)
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "off")
    return bool(value)


def _int_option(config, name, default):
    try:
        value = int(config.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _matches(name, patterns):
    if not name:
        return False
    short_name = name.rsplit(".", 1)[-1]
    for pattern in patterns:
        short_pattern = pattern[2:] if pattern.startswith("*.") else pattern
        if fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(
            short_name, short_pattern
        ):
            return True
        if "." in name and name.endswith("." + pattern):
            return True
    return False


def _source_line(file_data, lineno):
    if not file_data or not lineno:
        return ""
    if hasattr(file_data, "read"):
        handle = file_data
        position = handle.tell() if hasattr(handle, "tell") else None
        if hasattr(handle, "seek"):
            handle.seek(0)
        file_data = handle.read()
        if position is not None and hasattr(handle, "seek"):
            try:
                handle.seek(position)
            except (OSError, ValueError):
                pass
    if isinstance(file_data, bytes):
        file_data = file_data.decode("utf-8", "replace")
    lines = file_data.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _call_name(node, import_aliases):
    try:
        return utils.get_call_name(node, import_aliases)
    except (AttributeError, TypeError):
        return ""


def _simple_key(node, aliases=None, renames=None, depth=0):
    """Return a small, stable spelling for an expression.

    The key is used only to decide whether two validation calls refer to the
    same value.  Aliases and helper parameter renames are resolved here; more
    complicated expressions fall back to their AST spelling.
    """
    aliases = aliases or {}
    renames = renames or {}
    if depth > _MAX_EXPR_DEPTH:
        return "deep:" + ast.dump(
            node, annotate_fields=False, include_attributes=False
        )

    if isinstance(node, ast.Name):
        if node.id in renames:
            return renames[node.id]
        target = aliases.get(node.id)
        if target is not None:
            return _simple_key(target, aliases, renames, depth + 1)
        return "name:" + node.id

    if isinstance(node, ast.Attribute):
        return "{}.{}".format(
            _simple_key(node.value, aliases, renames, depth + 1), node.attr
        )

    if isinstance(node, ast.Subscript):
        return "{}[{}]".format(
            _simple_key(node.value, aliases, renames, depth + 1),
            _simple_key(node.slice, aliases, renames, depth + 1),
        )

    if isinstance(node, ast.Call):
        args = [
            _simple_key(arg, aliases, renames, depth + 1) for arg in node.args
        ]
        keywords = [
            "{}={}".format(
                keyword.arg or "**",
                _simple_key(keyword.value, aliases, renames, depth + 1),
            )
            for keyword in node.keywords
        ]
        return "{}({})".format(
            _simple_key(node.func, aliases, renames, depth + 1),
            ", ".join(args + keywords),
        )

    if isinstance(node, ast.Constant):
        return "const:" + repr(node.value)

    if isinstance(node, ast.Starred):
        return "*" + _simple_key(node.value, aliases, renames, depth + 1)

    return "ast:" + ast.dump(
        node, annotate_fields=False, include_attributes=False
    )


def _fingerprint(call, aliases, renames, import_aliases):
    args = tuple(_simple_key(arg, aliases, renames) for arg in call.args)
    keywords = tuple(
        sorted(
            (
                keyword.arg or "**",
                _simple_key(keyword.value, aliases, renames),
            )
            for keyword in call.keywords
        )
    )
    return (_call_name(call, import_aliases), args, keywords)


def _validation_fingerprints(
    node, validators, aliases, renames, import_aliases
):
    found = []
    seen = set()

    def visit(current, depth=0):
        if current is None or depth > _MAX_EXPR_DEPTH:
            return
        marker = id(current)
        if marker in seen:
            return
        seen.add(marker)

        if isinstance(current, ast.Name) and current.id in aliases:
            visit(aliases[current.id], depth + 1)
            return

        if isinstance(current, ast.Call):
            name = _call_name(current, import_aliases)
            if _matches(name, validators):
                found.append(
                    _fingerprint(current, aliases, renames, import_aliases)
                )

        for child in ast.iter_child_nodes(current):
            visit(child, depth + 1)

    visit(node)
    return tuple(dict.fromkeys(found))


def _resolve_alias(node, aliases):
    seen = set()
    while isinstance(node, ast.Name) and node.id in aliases:
        if node.id in seen:
            break
        seen.add(node.id)
        node = aliases[node.id]
    return node


def _is_negative_assert(test, aliases=None):
    aliases = aliases or {}
    test = _resolve_alias(test, aliases)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return True

    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        comparator = test.comparators[0]
        if not isinstance(comparator, ast.Constant):
            return False
        left = _resolve_alias(test.left, aliases)
        op = test.ops[0]
        value = comparator.value
        if isinstance(left, ast.UnaryOp) and isinstance(left.op, ast.Not):
            if value is True and isinstance(op, (ast.Is, ast.Eq)):
                return True
            if value is False and isinstance(op, (ast.IsNot, ast.NotEq)):
                return True
            return False
        if value is False and isinstance(op, (ast.Is, ast.Eq)):
            return True
        if value is None and isinstance(op, ast.Is):
            return True
        if value is True and isinstance(op, (ast.IsNot, ast.NotEq)):
            return True

    return False


def _invalid_fingerprints(test, validators, aliases, renames, import_aliases):
    """Return fingerprints rejected by a condition.

    The result is ``(body_fingerprints, covers_all_invalid,
    else_valid_fingerprints)``.  ``body_fingerprints`` are known false when
    the condition is true, while ``else_valid_fingerprints`` are known true
    when the condition is false.
    """

    def fp(node):
        return _validation_fingerprints(
            node, validators, aliases, renames, import_aliases
        )

    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        operand = test.operand
        body_fps = fp(operand)
        if isinstance(operand, ast.BoolOp):
            if isinstance(operand.op, ast.And):
                return body_fps, True, body_fps
            return body_fps, False, ()
        return body_fps, True, body_fps

    if isinstance(test, ast.BoolOp):
        children = []
        else_valid = []
        all_invalid = True
        for value in test.values:
            child_fps, child_full, child_else = _invalid_fingerprints(
                value, validators, aliases, renames, import_aliases
            )
            children.extend(child_fps)
            all_invalid = all_invalid and child_full
            else_valid.extend(child_else)
        if not children:
            return (), False, ()
        if isinstance(test.op, ast.Or):
            return (
                tuple(dict.fromkeys(children)),
                all_invalid,
                tuple(dict.fromkeys(else_valid)),
            )
        return tuple(dict.fromkeys(children)), False, ()

    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        comparator = test.comparators[0]
        if isinstance(comparator, ast.Constant):
            op = test.ops[0]
            value = comparator.value
            if value is False and isinstance(op, (ast.Is, ast.Eq)):
                return fp(test.left), True, fp(test.left)
            if value is None and isinstance(op, ast.Is):
                return fp(test.left), True, fp(test.left)
            if value is True and isinstance(op, (ast.IsNot, ast.NotEq)):
                return fp(test.left), True, fp(test.left)

    return (), False, ()


def _valid_fingerprints(test, validators, aliases, renames, import_aliases):
    """Return fingerprints that are known true in the true branch."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return ()

    if isinstance(test, ast.BoolOp):
        if isinstance(test.op, ast.And):
            found = []
            for value in test.values:
                found.extend(
                    _valid_fingerprints(
                        value,
                        validators,
                        aliases,
                        renames,
                        import_aliases,
                    )
                )
            return tuple(dict.fromkeys(found))
        return ()

    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        comparator = test.comparators[0]
        if isinstance(comparator, ast.Constant):
            op = test.ops[0]
            value = comparator.value
            if value is False and isinstance(op, (ast.Is, ast.Eq)):
                return ()
            if value is True and isinstance(op, (ast.IsNot, ast.NotEq)):
                return ()

    return _validation_fingerprints(
        test, validators, aliases, renames, import_aliases
    )


def _aliases_before(body, lineno):
    aliases = {}
    for statement in body:
        if getattr(statement, "lineno", 0) >= lineno:
            break
        target = None
        value = None
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            target = statement.targets[0].id
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target, ast.Name
        ):
            target = statement.target.id
            value = statement.value
        if target is not None and value is not None:
            aliases[target] = value
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for item in targets:
                if isinstance(item, ast.Name):
                    aliases.pop(item.id, None)
    return aliases


def _scope_for(node):
    parent = getattr(node, "_bandit_parent", None)
    while parent is not None:
        if isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
        ):
            return parent
        parent = getattr(parent, "_bandit_parent", None)
    return None


def _module_for(scope):
    current = scope
    while current is not None:
        if isinstance(current, ast.Module):
            return current
        current = getattr(current, "_bandit_parent", None)
    return scope


def _collect_local_functions(scope):
    functions = {}
    module = _module_for(scope)

    def collect(body):
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.setdefault(statement.name, statement)

    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        collect(scope.body)
    if isinstance(module, ast.Module):
        collect(module.body)
    return functions


def _statements_after(node, scope):
    following = []
    current = node
    while current is not None and current is not scope:
        parent = getattr(current, "_bandit_parent", None)
        if parent is None:
            break
        for _, value in ast.iter_fields(parent):
            if isinstance(value, list) and current in value:
                index = value.index(current)
                following = list(value[index + 1 :]) + following
                break
        current = parent
    return following


class _PathState:
    def __init__(self, aliases=None):
        self.protected = {}
        self.saw_rejection = False
        self.rejection_line = None
        self.rejection_source = ""
        self.opaque = False
        self.terminated = False
        self.aliases = dict(aliases or {})

    def clone(self):
        state = _PathState(self.aliases)
        state.protected = dict(self.protected)
        state.saw_rejection = self.saw_rejection
        state.rejection_line = self.rejection_line
        state.rejection_source = self.rejection_source
        state.opaque = self.opaque
        state.terminated = self.terminated
        return state


def _merge_states(first, second):
    state = first.clone()
    state.protected = {
        key: value
        for key, value in first.protected.items()
        if key in second.protected
    }
    state.saw_rejection = first.saw_rejection or second.saw_rejection
    state.opaque = first.opaque or second.opaque
    state.terminated = first.terminated and second.terminated
    state.rejection_line = first.rejection_line or second.rejection_line
    state.rejection_source = first.rejection_source or second.rejection_source
    state.aliases = {
        name: first.aliases[name]
        for name in first.aliases.keys() & second.aliases.keys()
        if _simple_key(first.aliases[name])
        == _simple_key(second.aliases[name])
    }
    return state


class _Finding:
    def __init__(self, classification, call, state, reason=""):
        self.classification = classification
        self.call = call
        self.state = state.clone()
        self.reason = reason


class _GuardAnalysis:
    def __init__(
        self,
        context,
        assert_node,
        scope,
        required,
        validators,
        sensitive_calls,
        reject_calls,
        max_if_depth,
        max_helper_depth,
        ambiguous,
    ):
        self.context = context
        self.assert_node = assert_node
        self.scope = scope
        self.required = required
        self.validators = validators
        self.sensitive_calls = sensitive_calls
        self.reject_calls = reject_calls
        self.max_if_depth = max_if_depth
        self.max_helper_depth = max_helper_depth
        self.ambiguous = ambiguous
        self.helpers = _collect_local_functions(scope)
        self.findings = []
        self.statements_seen = 0

    def run(self):
        body = _statements_after(self.assert_node, self.scope)
        aliases = _aliases_before(self.scope.body, self.assert_node.lineno)
        state = _PathState(aliases)
        if self.ambiguous:
            state.opaque = True
        self._analyze_block(body, state, 0, (), {})
        return self.findings

    def _call_name(self, call):
        return _call_name(
            call, self.context._context.get("import_aliases", {})
        )

    def _is_reject_call(self, call):
        return _matches(self._call_name(call), self.reject_calls)

    def _is_sensitive_call(self, call):
        return _matches(self._call_name(call), self.sensitive_calls)

    def _helper_for(self, call):
        if not isinstance(call.func, ast.Name):
            return None
        return self.helpers.get(call.func.id)

    def _protect(self, state, fingerprints, line):
        source = _source_line(self.context._context.get("file_data"), line)
        for fingerprint in fingerprints:
            state.protected.setdefault(fingerprint, (line, source))

    def _covered(self, state):
        return all(item in state.protected for item in self.required)

    def _record(self, call, state):
        if self._covered(state):
            classification = INDEPENDENT
        elif state.opaque or state.saw_rejection:
            classification = UNKNOWN
        else:
            classification = SOLE

        reason = ""
        if classification == UNKNOWN:
            if state.opaque:
                reason = "a configured analysis bound was reached"
            else:
                reason = "a rejection exists only on a conditional path"
        self.findings.append(_Finding(classification, call, state, reason))

    def _block_always_exits(self, statements, ctx):
        if not statements:
            return False
        for statement in statements:
            if isinstance(statement, (ast.Return, ast.Raise)):
                return True
            if isinstance(statement, ast.Expr) and isinstance(
                statement.value, ast.Call
            ):
                if self._is_reject_call(statement.value):
                    return True
            if isinstance(statement, ast.If):
                if (
                    statement.orelse
                    and self._block_always_exits(statement.body, ctx)
                    and self._block_always_exits(statement.orelse, ctx)
                ):
                    return True
            if isinstance(statement, ast.Try):
                if self._block_always_exits(statement.body, ctx) and all(
                    self._block_always_exits(handler.body, ctx)
                    for handler in statement.handlers
                ):
                    return True
        return False

    def _rejection_line(self, statements):
        for statement in statements:
            if isinstance(statement, (ast.Return, ast.Raise)):
                return statement.lineno
            if isinstance(statement, ast.Expr) and isinstance(
                statement.value, ast.Call
            ):
                if self._is_reject_call(statement.value):
                    return statement.lineno
        return None

    def _rejection_in_helper(self, helper, renames):
        aliases = _aliases_before(helper.body, 10**9)
        for statement in helper.body:
            if not isinstance(statement, ast.If):
                continue
            invalid, full, _ = _invalid_fingerprints(
                statement.test,
                self.validators,
                aliases,
                renames,
                self.context._context.get("import_aliases", {}),
            )
            if (
                full
                and set(self.required).issubset(invalid)
                and self._block_always_exits(statement.body, {})
            ):
                return statement.lineno
        return None

    def _helper_renames(self, helper, call, aliases):
        renames = {}
        positional = list(helper.args.posonlyargs) + list(helper.args.args)
        for argument, value in zip(positional, call.args):
            renames[argument.arg] = _simple_key(value, aliases)
        keywords = {
            keyword.arg: keyword.value
            for keyword in call.keywords
            if keyword.arg is not None
        }
        for argument in helper.args.kwonlyargs:
            value = keywords.get(argument.arg)
            if value is not None:
                renames[argument.arg] = _simple_key(value, aliases)
        return renames

    def _analyze_helper(self, call, helper, state, depth, stack):
        if len(stack) >= self.max_helper_depth or helper.name in stack:
            state.opaque = True
            state.saw_rejection = True
            return

        renames = self._helper_renames(helper, call, state.aliases)
        helper_state = state.clone()
        helper_state = self._analyze_block(
            helper.body,
            helper_state,
            depth + 1,
            stack + (helper.name,),
            renames,
        )
        state.saw_rejection = state.saw_rejection or helper_state.saw_rejection
        state.opaque = state.opaque or helper_state.opaque

        line = self._rejection_in_helper(helper, renames)
        if line is not None:
            self._protect(state, self.required, line)
            state.saw_rejection = True
            state.rejection_line = line
            state.rejection_source = _source_line(
                self.context._context.get("file_data"), line
            )

    def _visit_expr(self, expr, state, depth, stack, renames):
        if expr is None or state.terminated:
            return
        if isinstance(expr, ast.Lambda):
            return

        if isinstance(expr, ast.Call):
            for argument in expr.args:
                self._visit_expr(argument, state, depth, stack, renames)
            for keyword in expr.keywords:
                self._visit_expr(keyword.value, state, depth, stack, renames)
            helper = None
            if not _matches(self._call_name(expr), self.validators):
                helper = self._helper_for(expr)
            if helper is not None:
                self._analyze_helper(expr, helper, state, depth, stack)
            if self._is_sensitive_call(expr):
                self._record(expr, state)
            if self._is_reject_call(expr):
                state.terminated = True
            return

        for child in ast.iter_child_nodes(expr):
            self._visit_expr(child, state, depth, stack, renames)

    def _analyze_if(self, statement, state, depth, stack, renames):
        import_aliases = self.context._context.get("import_aliases", {})
        invalid, full, else_valid = _invalid_fingerprints(
            statement.test,
            self.validators,
            state.aliases,
            renames,
            import_aliases,
        )
        valid = _valid_fingerprints(
            statement.test,
            self.validators,
            state.aliases,
            renames,
            import_aliases,
        )
        invalid = tuple(item for item in invalid if item in self.required)
        valid = tuple(item for item in valid if item in self.required)

        body_exits = self._block_always_exits(statement.body, {})
        else_exits = self._block_always_exits(statement.orelse, {})

        body_state = state.clone()
        if valid:
            self._protect(body_state, valid, statement.lineno)
        if depth >= self.max_if_depth:
            body_state.opaque = True
            if invalid:
                body_state.saw_rejection = True
        body_state = self._analyze_block(
            statement.body,
            body_state,
            depth + 1,
            stack,
            renames,
        )
        if invalid and body_exits:
            body_state.saw_rejection = True
            body_state.rejection_line = statement.lineno
            body_state.rejection_source = _source_line(
                self.context._context.get("file_data"),
                statement.lineno,
            )

        else_state = state.clone()
        if else_valid:
            self._protect(else_state, else_valid, statement.lineno)
        if depth >= self.max_if_depth:
            else_state.opaque = True
        else_state = self._analyze_block(
            statement.orelse,
            else_state,
            depth + 1,
            stack,
            renames,
        )

        if body_exits and not else_exits:
            return else_state
        if else_exits and not body_exits:
            return body_state
        return _merge_states(body_state, else_state)

    def _analyze_loop(self, statement, state, depth, stack, renames):
        test = getattr(statement, "test", None)
        if test is not None:
            self._visit_expr(test, state, depth, stack, renames)
        iterator = getattr(statement, "iter", None)
        if iterator is not None:
            self._visit_expr(iterator, state, depth, stack, renames)

        body_state = state.clone()
        body_state = self._analyze_block(
            statement.body, body_state, depth + 1, stack, renames
        )
        result = state.clone()
        result.saw_rejection = result.saw_rejection or body_state.saw_rejection
        result.opaque = result.opaque or body_state.opaque
        if statement.orelse:
            else_state = self._analyze_block(
                statement.orelse,
                state.clone(),
                depth + 1,
                stack,
                renames,
            )
            result = _merge_states(result, else_state)
        return result

    def _analyze_block(self, statements, state, depth, stack, renames):
        state = state.clone()
        for statement in statements:
            if state.terminated:
                break
            self.statements_seen += 1
            if self.statements_seen > _MAX_STATEMENTS:
                state.opaque = True
                break

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(statement, ast.ClassDef):
                continue
            if isinstance(statement, ast.Assert):
                continue

            if isinstance(statement, ast.If):
                self._visit_expr(statement.test, state, depth, stack, renames)
                state = self._analyze_if(
                    statement, state, depth, stack, renames
                )
                continue

            if isinstance(
                statement,
                (ast.For, ast.AsyncFor, ast.While),
            ):
                state = self._analyze_loop(
                    statement, state, depth, stack, renames
                )
                continue

            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._visit_expr(
                        item.context_expr,
                        state,
                        depth,
                        stack,
                        renames,
                    )
                state = self._analyze_block(
                    statement.body,
                    state,
                    depth + 1,
                    stack,
                    renames,
                )
                continue

            if isinstance(statement, ast.Try):
                branch_states = []
                branch_states.append(
                    self._analyze_block(
                        statement.body,
                        state.clone(),
                        depth + 1,
                        stack,
                        renames,
                    )
                )
                for handler in statement.handlers:
                    branch_states.append(
                        self._analyze_block(
                            handler.body,
                            state.clone(),
                            depth + 1,
                            stack,
                            renames,
                        )
                    )
                if statement.orelse:
                    branch_states.append(
                        self._analyze_block(
                            statement.orelse,
                            state.clone(),
                            depth + 1,
                            stack,
                            renames,
                        )
                    )
                merged = branch_states[0]
                for branch in branch_states[1:]:
                    merged = _merge_states(merged, branch)
                if statement.finalbody:
                    merged = self._analyze_block(
                        statement.finalbody,
                        merged,
                        depth + 1,
                        stack,
                        renames,
                    )
                state = merged
                continue

            if isinstance(statement, (ast.Return, ast.Raise)):
                value = getattr(statement, "value", None)
                self._visit_expr(value, state, depth, stack, renames)
                break

            if isinstance(statement, ast.Expr):
                self._visit_expr(statement.value, state, depth, stack, renames)
                if state.terminated:
                    break
                continue

            if isinstance(statement, ast.Assign):
                self._visit_expr(statement.value, state, depth, stack, renames)
                if len(statement.targets) == 1 and isinstance(
                    statement.targets[0], ast.Name
                ):
                    state.aliases[statement.targets[0].id] = statement.value
                else:
                    for target in statement.targets:
                        if isinstance(target, ast.Name):
                            state.aliases.pop(target.id, None)
                continue

            if isinstance(statement, ast.AnnAssign):
                self._visit_expr(statement.value, state, depth, stack, renames)
                if isinstance(statement.target, ast.Name):
                    if statement.value is None:
                        state.aliases.pop(statement.target.id, None)
                    else:
                        state.aliases[statement.target.id] = statement.value
                continue

            if isinstance(statement, ast.AugAssign):
                self._visit_expr(statement.value, state, depth, stack, renames)
                if isinstance(statement.target, ast.Name):
                    state.aliases.pop(statement.target.id, None)
                continue

            for _, value in ast.iter_fields(statement):
                if isinstance(value, ast.AST):
                    self._visit_expr(value, state, depth, stack, renames)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST):
                            self._visit_expr(
                                item, state, depth, stack, renames
                            )

        return state


def _severity_and_confidence(classes):
    if SOLE in classes:
        return bandit.HIGH, bandit.HIGH
    if UNKNOWN in classes:
        return bandit.MEDIUM, bandit.LOW
    return bandit.LOW, bandit.HIGH


def _format_findings(findings, assert_node, file_data):
    assert_source = _source_line(file_data, assert_node.lineno)
    classes = sorted({finding.classification for finding in findings})
    pieces = [
        "Assert guard analysis (classification={}; assert at line {}: "
        "'{}'):".format(
            ", ".join(classes),
            assert_node.lineno,
            assert_source,
        )
    ]

    for finding in findings:
        operation = _source_line(file_data, finding.call.lineno)
        piece = "operation at line {} ('{}') -> {}".format(
            finding.call.lineno, operation, finding.classification
        )
        if finding.classification == INDEPENDENT:
            protections = {
                line: source
                for line, source in finding.state.protected.values()
            }
            if protections:
                details = ", ".join(
                    "line {} ('{}')".format(line, protections[line])
                    for line in sorted(protections)
                )
                piece += "; independent rejection at {}".format(details)
            piece += "; the operation stays rejected with python -O"
        elif finding.classification == SOLE:
            piece += (
                "; python -O removes the only validation check before "
                "this operation"
            )
        else:
            if finding.state.rejection_line:
                rejection_source = _source_line(
                    file_data, finding.state.rejection_line
                )
                piece += (
                    "; rejection at line {} ('{}') only covers "
                    "part of the path"
                ).format(finding.state.rejection_line, rejection_source)
            detail = finding.reason or "coverage could not be proven"
            piece += "; {} and python -O removes the assertion".format(detail)
        pieces.append(piece)

    if len(pieces) == 1:
        return pieces[0] + "."
    return pieces[0] + " " + "; ".join(pieces[1:]) + "."


@test.takes_config
@test.checks("Assert")
@test.test_id("B114")
def assert_guard(context, config):
    node = context.node
    scope = _scope_for(node)
    if scope is None:
        return None

    validators = _list_option(
        config,
        "validators",
        "validation_calls",
        "validate_calls",
        "validation_functions",
    )
    if validators is None:
        validators = list(DEFAULT_VALIDATORS)

    sensitive_calls = _list_option(
        config,
        "sensitive_calls",
        "sensitive_operations",
        "sensitive_functions",
        "operations",
    )
    if sensitive_calls is None:
        sensitive_calls = list(DEFAULT_SENSITIVE_CALLS)

    reject_calls = _list_option(config, "reject_calls", "rejection_calls")
    if reject_calls is None:
        reject_calls = list(DEFAULT_REJECT_CALLS)

    import_aliases = context._context.get("import_aliases", {})
    aliases = _aliases_before(scope.body, node.lineno)
    required = _validation_fingerprints(
        node.test,
        validators,
        aliases,
        {},
        import_aliases,
    )
    if not required or _is_negative_assert(node.test, aliases):
        return None

    ambiguous = isinstance(node.test, ast.BoolOp) and isinstance(
        node.test.op, ast.Or
    )
    analysis = _GuardAnalysis(
        context=context,
        assert_node=node,
        scope=scope,
        required=required,
        validators=validators,
        sensitive_calls=sensitive_calls,
        reject_calls=reject_calls,
        max_if_depth=_int_option(config, "max_if_depth", 3),
        max_helper_depth=_int_option(config, "max_helper_depth", 1),
        ambiguous=ambiguous,
    )
    findings = analysis.run()
    if not findings:
        return None

    if not _bool_option(config, "report_independent", True):
        findings = [
            finding
            for finding in findings
            if finding.classification != INDEPENDENT
        ]
    if not findings:
        return None

    severity, confidence = _severity_and_confidence(
        {finding.classification for finding in findings}
    )
    return bandit.Issue(
        severity=severity,
        confidence=confidence,
        cwe=issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND,
        text=_format_findings(
            findings,
            node,
            context._context.get("file_data"),
        ),
        lineno=node.lineno,
        col_offset=node.col_offset,
    )
