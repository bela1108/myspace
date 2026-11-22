#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base

CHECKED = 'checked'
PENDING = 'pending'
UNCERTAIN = 'uncertain'
OTHER = 'other'


def _call_name(call):
    if isinstance(call.func, ast.Name):
        return call.func.id
    elif isinstance(call.func, ast.Attribute):
        return call.func.attr
    else:
        return None


class BadAsyncSecurityCheckLinter(base.BaseLinter):
    """This linter looks for security check calls whose results are misused
    when synchronous and asynchronous check factories are mixed. Only the
    declared set of check APIs is analyzed. Local "async def" definitions,
    "await" usage, and limited assignment/return relationships are used to
    distinguish proven checks from retained asynchronous objects. External
    functions and inconsistent branch results are flagged for manual review.
    A plain "await" of a non-check function never counts as a security check.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 async security check used without "await"'
    _unused_result_tmpl = 'DUO139 awaited security check result is not used'
    _uncertain_tmpl = 'DUO139 unable to confirm security check result, manual review required'

    check_apis = frozenset([
        'verify_token',
        'check_permission',
        'is_authorized',
    ])

    def __init__(self, *args, **kwargs):
        self._reported = set()

        super(BadAsyncSecurityCheckLinter, self).__init__(*args, **kwargs)

    def visit_Module(self, node):
        self.local_async = set()
        self.return_kinds = {}

        for child in ast.walk(node):
            if isinstance(child, ast.AsyncFunctionDef):
                self.local_async.add(child.name)

        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.return_kinds[child.name] = self._return_kind(child)

        self._analyze_body(node.body, {})

    def _return_kind(self, function):
        kinds = set()

        for child in self._walk_same_scope(function):
            if isinstance(child, ast.Return) and child.value is not None:
                kinds.add(self._classify_return_value(child.value))

        if not kinds:
            return OTHER
        if kinds == set([CHECKED]):
            return CHECKED
        if kinds == set([PENDING]):
            return PENDING
        if CHECKED in kinds or PENDING in kinds:
            return UNCERTAIN
        return OTHER

    def _walk_same_scope(self, node):
        scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        todo = list(ast.iter_child_nodes(node))
        while todo:
            child = todo.pop()
            if isinstance(child, scopes):
                continue
            yield child
            todo.extend(ast.iter_child_nodes(child))

    def _classify_return_value(self, value):
        if isinstance(value, ast.Await) and self._is_check_call(value.value):
            return CHECKED
        if self._is_check_call(value):
            return PENDING
        return OTHER

    def _is_check_call(self, node):
        return (
            isinstance(node, ast.Call)
            and _call_name(node) in self.check_apis
        )

    def _classify_value(self, node, env):
        if isinstance(node, ast.Await):
            inner = node.value
            if self._is_check_call(inner):
                return CHECKED
            if isinstance(inner, ast.Name) and env.get(inner.id) == PENDING:
                return CHECKED
            return OTHER

        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in self.check_apis:
                if name in self.local_async:
                    return PENDING
                return UNCERTAIN
            if name in self.local_async:
                return OTHER
            return self.return_kinds.get(name, OTHER)

        if isinstance(node, ast.Name):
            return env.get(node.id, OTHER)

        return OTHER

    def _report(self, node, message):
        key = (node.lineno, node.col_offset, message)
        if key in self._reported:
            return
        self._reported.add(key)
        self.results.append(
            base.Flake8Result(
                lineno=node.lineno,
                col_offset=node.col_offset,
                message=message
            )
        )

    def _check_test(self, test, env):
        if isinstance(test, ast.Await):
            return

        if isinstance(test, ast.BoolOp):
            for value in test.values:
                self._check_test(value, env)
            return

        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            self._check_test(test.operand, env)
            return

        if isinstance(test, ast.IfExp):
            self._check_test(test.test, env)
            return

        if isinstance(test, ast.Name):
            state = env.get(test.id)
            if state == PENDING:
                self._report(test, self._error_tmpl)
            elif state == UNCERTAIN:
                self._report(test, self._uncertain_tmpl)
            return

        self._check_calls_in_expression(test)

    def _check_calls_in_expression(self, node):
        if isinstance(node, ast.Await):
            return

        if self._is_check_call(node):
            if _call_name(node) in self.local_async:
                self._report(node, self._error_tmpl)
            else:
                self._report(node, self._uncertain_tmpl)

        for child in ast.iter_child_nodes(node):
            self._check_calls_in_expression(child)

    def _merge_state(self, left, right):
        if left == right:
            return left
        return UNCERTAIN

    def _analyze_body(self, body, env):
        for statement in body:
            self._analyze_statement(statement, env)

    def _analyze_statement(self, statement, env):
        if isinstance(statement, ast.Assign):
            if len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                env[statement.targets[0].id] = self._classify_value(statement.value, env)

        elif isinstance(statement, ast.AnnAssign):
            if isinstance(statement.target, ast.Name) and statement.value is not None:
                env[statement.target.id] = self._classify_value(statement.value, env)

        elif isinstance(statement, ast.Expr):
            value = statement.value
            if isinstance(value, ast.Await):
                inner = value.value
                if self._is_check_call(inner):
                    self._report(statement, self._unused_result_tmpl)
                elif isinstance(inner, ast.Name) and env.get(inner.id) == PENDING:
                    self._report(statement, self._unused_result_tmpl)
            elif self._is_check_call(value):
                if _call_name(value) in self.local_async:
                    self._report(statement, self._error_tmpl)
                else:
                    self._report(statement, self._uncertain_tmpl)

        elif isinstance(statement, ast.If):
            self._check_test(statement.test, env)
            body_env = dict(env)
            orelse_env = dict(env)
            self._analyze_body(statement.body, body_env)
            self._analyze_body(statement.orelse, orelse_env)
            for name in set(body_env) | set(orelse_env):
                env[name] = self._merge_state(
                    body_env.get(name, OTHER),
                    orelse_env.get(name, OTHER)
                )

        elif isinstance(statement, ast.While):
            self._check_test(statement.test, env)
            body_env = dict(env)
            self._analyze_body(statement.body, body_env)
            for name, state in body_env.items():
                if env.get(name) != state:
                    env[name] = self._merge_state(env.get(name, OTHER), state)

        elif isinstance(statement, ast.Assert):
            self._check_test(statement.test, env)

        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._analyze_body(statement.body, {})

        elif isinstance(statement, ast.ClassDef):
            self._analyze_body(statement.body, env)

        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            self._analyze_body(statement.body, env)

        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            self._analyze_body(statement.body, dict(env))
            self._analyze_body(statement.orelse, env)

        elif isinstance(statement, ast.Try):
            self._analyze_body(statement.body, env)
            for handler in statement.handlers:
                self._analyze_body(handler.body, dict(env))
            self._analyze_body(statement.orelse, env)
            self._analyze_body(statement.finalbody, env)
