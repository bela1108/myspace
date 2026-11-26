#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base


class BadDigestUseLinter(base.BaseLinter):
    """This linter looks for digests passed to a purpose they are not
    permitted for. Digests are classified by the function that produced
    them (e.g. an archive digest may be used for integrity checks, while
    external deduplication requires a recipient-facing digest).

    The linter is driven entirely by configuration:

    * "digest_sources" maps a digest-producing function name to the kind
      of digest it returns, e.g. {"archive_digest": "archive"}.
    * "entry_points" maps a checked function name to a mapping of
      parameter (positional index or keyword name) to the purpose that
      parameter serves, e.g. {"publish": {0: "integrity", 1: "external"}}.
    * "usage_policy" maps a purpose to the digest kinds permitted for it.

    Within a function the linter tracks assignments, tuple unpacking,
    simple conditional merges, and direct-return helper functions. A
    proven misuse is reported at the offending argument. Arguments whose
    provenance cannot be determined (e.g. produced by an unknown call)
    are reported as uncertain rather than assumed compliant.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 digest used for a purpose it is not permitted for'
    _uncertain_tmpl = 'DUO139 unable to confirm digest is used for a permitted purpose'

    UNKNOWN_KIND = 'unknown'

    DEFAULT_USAGE_POLICY = {
        'integrity': frozenset(['archive', 'recipient']),
        'external': frozenset(['recipient']),
    }

    def __init__(self, digest_sources=None, entry_points=None, usage_policy=None):
        self.digest_sources = digest_sources if digest_sources is not None else {}
        self.entry_points = entry_points if entry_points is not None else {}
        self.usage_policy = (
            usage_policy if usage_policy is not None else self.DEFAULT_USAGE_POLICY
        )

        self._helpers = {}

        super(BadDigestUseLinter, self).__init__()

    def visit_Module(self, node):
        self._process_body(node.body, {})

    def _unknown_value(self):
        return frozenset([self.UNKNOWN_KIND])

    def _process_body(self, body, env):
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._register_helper(statement)

        for statement in body:
            self._process_statement(statement, env)

    def _register_helper(self, node):
        body = node.body
        if body and self._is_docstring(body[0]):
            body = body[1:]

        if (
                len(body) == 1
                and isinstance(body[0], ast.Return)
                and body[0].value is not None
        ):
            self._helpers[node.name] = body[0].value
        else:
            self._helpers.pop(node.name, None)

    @staticmethod
    def _is_docstring(statement):
        if not isinstance(statement, ast.Expr):
            return False

        value = statement.value
        if isinstance(value, ast.Str):
            return True

        constant = getattr(ast, 'Constant', None)
        return (
            constant is not None
            and isinstance(value, constant)
            and isinstance(value.value, str)
        )

    def _process_statement(self, statement, env):
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._check_calls([statement.args] + list(statement.decorator_list), env)
            outer_helpers = dict(self._helpers)
            self._process_body(statement.body, {})
            self._helpers = outer_helpers
        elif isinstance(statement, ast.ClassDef):
            self._check_calls(
                list(statement.decorator_list)
                + list(statement.bases)
                + [keyword.value for keyword in statement.keywords],
                env
            )
            outer_helpers = dict(self._helpers)
            self._process_body(statement.body, {})
            self._helpers = outer_helpers
        elif isinstance(statement, ast.Assign):
            value = self._resolve_expression(statement.value, env)
            for target in statement.targets:
                self._assign_target(target, value, env)
            self._check_calls([statement], env)
        elif isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                value = self._resolve_expression(statement.value, env)
                self._assign_target(statement.target, value, env)
            self._check_calls([statement], env)
        elif isinstance(statement, ast.AugAssign):
            if isinstance(statement.target, ast.Name):
                env[statement.target.id] = self._unknown_value()
            self._check_calls([statement], env)
        elif isinstance(statement, ast.If):
            self._check_calls([statement.test], env)
            self._process_branches(env, statement.body, statement.orelse)
        elif isinstance(statement, ast.While):
            self._check_calls([statement.test], env)
            self._process_branches(env, statement.body)
            self._process_body(statement.orelse, env)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            self._check_calls([statement.iter], env)
            iter_value = self._resolve_expression(statement.iter, env)
            self._assign_target(statement.target, self._element_value(iter_value), env)
            self._process_branches(env, statement.body)
            self._process_body(statement.orelse, env)
        elif isinstance(statement, ast.Try):
            bodies = [statement.body, statement.orelse]
            bodies += [handler.body for handler in statement.handlers]
            self._process_branches(env, *bodies)
            self._process_body(statement.finalbody, env)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                self._check_calls([item.context_expr], env)
                if item.optional_vars is not None:
                    self._assign_target(item.optional_vars, self._unknown_value(), env)
            self._process_body(statement.body, env)
        else:
            self._check_calls([statement], env)

    def _process_branches(self, env, *bodies):
        merged = {}
        for body in bodies:
            branch_env = dict(env)
            self._process_body(body, branch_env)
            for name, value in branch_env.items():
                merged[name] = self._union_values(merged.get(name), value)

        env.clear()
        env.update(merged)

    def _union_values(self, value1, value2):
        if value1 is None:
            return value2

        if isinstance(value1, frozenset) and isinstance(value2, frozenset):
            return value1 | value2

        if (
                isinstance(value1, tuple)
                and isinstance(value2, tuple)
                and len(value1) == len(value2)
        ):
            return tuple(
                self._union_values(element1, element2)
                for element1, element2 in zip(value1, value2)
            )

        return self._unknown_value()

    def _element_value(self, iter_value):
        if (
                isinstance(iter_value, tuple)
                and iter_value
                and all(isinstance(element, frozenset) for element in iter_value)
        ):
            return frozenset().union(*iter_value)

        return self._unknown_value()

    def _assign_target(self, target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            starred = getattr(ast, 'Starred', None)
            has_starred = any(
                starred is not None and isinstance(element, starred)
                for element in target.elts
            )

            if (
                    not has_starred
                    and isinstance(value, tuple)
                    and len(value) == len(target.elts)
            ):
                for element, element_value in zip(target.elts, value):
                    self._assign_target(element, element_value, env)
            else:
                for element in target.elts:
                    self._assign_target(element, self._unknown_value(), env)

    def _resolve_expression(self, node, env, seen=None):
        if isinstance(node, ast.Call):
            return self._resolve_call(node, seen)

        if isinstance(node, ast.Name):
            return env.get(node.id, self._unknown_value())

        if isinstance(node, (ast.Tuple, ast.List)):
            return tuple(
                self._resolve_expression(element, env, seen)
                for element in node.elts
            )

        return self._unknown_value()

    def _resolve_call(self, node, seen):
        if not isinstance(node.func, ast.Name):
            return self._unknown_value()

        name = node.func.id
        if name in self.digest_sources:
            return frozenset([self.digest_sources[name]])

        if name in self._helpers:
            return self._resolve_helper(name, seen)

        return self._unknown_value()

    def _resolve_helper(self, name, seen):
        seen = seen if seen is not None else frozenset()
        if name in seen:
            return self._unknown_value()

        return self._resolve_expression(self._helpers[name], {}, seen | {name})

    def _check_calls(self, nodes, env):
        for node in nodes:
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    self._check_entry_call(child, env)

    def _check_entry_call(self, node, env):
        if not isinstance(node.func, ast.Name):
            return

        parameters = self.entry_points.get(node.func.id)
        if parameters is None:
            return

        for parameter, usage in parameters.items():
            allowed = self.usage_policy.get(usage)
            if not allowed:
                continue

            argument = self._find_argument(node, parameter)
            if argument is None:
                continue

            value = self._resolve_expression(argument, env)
            if not isinstance(value, frozenset):
                value = self._unknown_value()

            self._evaluate_argument(argument, value, allowed)

    @staticmethod
    def _find_argument(node, parameter):
        if isinstance(parameter, int):
            starred = getattr(ast, 'Starred', None)
            if parameter >= len(node.args):
                return None
            argument = node.args[parameter]
            if starred is not None and isinstance(argument, starred):
                return None
            return argument

        for keyword in node.keywords:
            if keyword.arg == parameter:
                return keyword.value

        return None

    def _evaluate_argument(self, node, value, allowed):
        known_kinds = value - frozenset([self.UNKNOWN_KIND])

        if known_kinds - allowed:
            self.results.append(
                base.Flake8Result(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    message=self._error_tmpl
                )
            )
        elif self.UNKNOWN_KIND in value:
            self.results.append(
                base.Flake8Result(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    message=self._uncertain_tmpl
                )
            )
