#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base


class _Summary(object):
    """Base class for the limited value summaries tracked by the linter."""


class _Unknown(_Summary):
    """A value we cannot statically say anything about."""


class _NotMarker(_Summary):
    """A value we know cannot be a review policy marker."""


class _Marker(_Summary):
    """A decorator object that stamps a function with a review policy.

    'identity' is the policy identity string, or None when the value is
    definitely a review marker but its policy cannot be determined.
    """

    def __init__(self, identity):
        self.identity = identity


class _Factory(_Summary):
    """A callable that produces a review marker when called.

    'evaluate' maps a list of literal call arguments (None for
    non-literals) to a policy identity string, or None when the identity
    cannot be determined.
    """

    def __init__(self, evaluate):
        self.evaluate = evaluate


class _ClassNamespace(_Summary):
    """A locally defined class, summarized by its own namespace."""

    def __init__(self, names):
        self.names = names


UNKNOWN = _Unknown()
NOT_MARKER = _NotMarker()

FUNCTION_DEF_NODES = (ast.FunctionDef,) + (
    (ast.AsyncFunctionDef,) if hasattr(ast, 'AsyncFunctionDef') else ()
)

if hasattr(ast, 'Constant'):
    # Python 3.8+: all literals are ast.Constant, and isinstance checks
    # against the legacy literal classes emit DeprecationWarnings
    LITERAL_NODES = (ast.Lambda, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.Constant)
else:
    LITERAL_NODES = (
        ast.Lambda, ast.List, ast.Tuple, ast.Dict, ast.Set,
        ast.Num, ast.Str, ast.Bytes, ast.NameConstant,
    )


def _review_policy_evaluate(args):
    """Return summary of 'review.policy(name)': the policy identity is the
    first positional argument when it's a string literal.
    """
    return args[0] if args and isinstance(args[0], str) else None


def _const_str(node):
    constant = getattr(ast, 'Constant', None)
    if constant is not None:
        if isinstance(node, constant) and isinstance(node.value, str):
            return node.value
        return None
    if isinstance(node, ast.Str):
        return node.s
    return None


def _attribute_path(node):
    """Return ('foo', 'bar', 'baz') for 'foo.bar.baz', else None."""
    path = []
    while isinstance(node, ast.Attribute):
        path.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        path.append(node.id)
        return tuple(reversed(path))
    return None


def _terminal_name(decorator):
    """Return the terminal name a decorator expression refers to."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _parameter_names(function_def):
    names = []
    for arg in function_def.args.args:
        name = getattr(arg, 'arg', None) or getattr(arg, 'id', None)
        names.append(name)
    return names


class BadReviewMarkerUseLinter(base.BaseLinter):
    """This linter checks the "internal review" decorator convention used by
    the export review process. The export review only checks decorator
    *names*, so a same-named impostor or a marker carrying the wrong review
    policy would pass undetected. This linter instead traces each decorator
    through the AST to the policy identity it evaluates to, and requires the
    effective policy to be "internal".

    The analysis is order-sensitive: a rebinding that happens after a
    function definition does not retroactively change that function's
    attribution. It supports module aliases, definitions nested in class
    bodies, and local factories through a limited return summary. When
    stacked markers disagree, the topmost (last applied) marker wins and
    the diagnostic explains the ordering.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 function does not carry the "internal" review policy'

    @property
    def review_module(self):
        return 'review'

    @property
    def internal_marker(self):
        return 'internal_review'

    @property
    def policy_factory(self):
        return 'policy'

    @property
    def required_policy(self):
        return 'internal'

    def visit_Module(self, node):
        self._process_statements(node.body, [{}])

    def _process_statements(self, statements, scopes):
        """Process a module or class body in order. 'scopes' is a list of
        binding dictionaries, innermost last; new bindings land in the
        innermost scope.
        """
        for statement in statements:
            if isinstance(statement, FUNCTION_DEF_NODES):
                self._check_decorators(statement, scopes)
                scopes[-1][statement.name] = self._summarize_function(statement, scopes)
                self._check_nested(statement, scopes)
            elif isinstance(statement, ast.ClassDef):
                inner_names = {}
                self._process_statements(statement.body, scopes + [inner_names])
                scopes[-1][statement.name] = _ClassNamespace(inner_names)
            elif isinstance(statement, ast.Assign):
                summary = self._resolve_value(statement.value, scopes)
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        scopes[-1][target.id] = summary
            elif (hasattr(ast, 'AnnAssign')
                    and isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                    and statement.value is not None):
                scopes[-1][statement.target.id] = self._resolve_value(statement.value, scopes)

    def _check_nested(self, node, scopes):
        """Check functions nested inside a function body. Function-local
        bindings are not tracked (limited analysis), so nested decorators
        resolve against the scopes visible at the outer definition.
        """
        for child in ast.iter_child_nodes(node):
            if isinstance(child, FUNCTION_DEF_NODES):
                self._check_decorators(child, scopes)
                self._check_nested(child, scopes)
            elif isinstance(child, ast.ClassDef):
                self._process_statements(child.body, scopes + [{}])
            else:
                self._check_nested(child, scopes)

    def _check_decorators(self, function_def, scopes):
        markers = []
        for decorator in function_def.decorator_list:
            summary = self._resolve_value(decorator, scopes)

            if isinstance(summary, _Marker):
                markers.append((summary.identity, decorator))
            elif isinstance(summary, _Factory):
                # A marker factory used directly as a decorator
                markers.append((None, decorator))
            elif summary is NOT_MARKER and self._is_marker_name(decorator):
                self.results.append(
                    base.Flake8Result(
                        lineno=decorator.lineno,
                        col_offset=decorator.col_offset,
                        message=self._impostor_message(function_def, decorator)
                    )
                )

        if not markers:
            return

        # The topmost marker is applied last, so it determines the
        # effective review policy of the function
        identity, effective = markers[0]

        if identity == self.required_policy:
            return

        if identity is None:
            message = self._unconfirmed_message(function_def)
        else:
            overridden = [marker for marker in markers[1:] if marker[0] != identity]
            if overridden:
                message = self._override_message(function_def, identity, effective, overridden[0])
            else:
                message = self._wrong_policy_message(function_def, identity)

        self.results.append(
            base.Flake8Result(
                lineno=effective.lineno,
                col_offset=effective.col_offset,
                message=message
            )
        )

    def _is_marker_name(self, decorator):
        return _terminal_name(decorator) in (self.internal_marker, self.policy_factory)

    def _resolve_value(self, node, scopes):
        if isinstance(node, ast.Name):
            return self._lookup_path((node.id,), scopes)

        if isinstance(node, ast.Attribute):
            path = _attribute_path(node)
            if path is None:
                return UNKNOWN
            return self._lookup_path(path, scopes)

        if isinstance(node, ast.Call):
            factory = self._resolve_value(node.func, scopes)
            if isinstance(factory, _Factory):
                args = [_const_str(arg) for arg in node.args]
                return _Marker(factory.evaluate(args))
            return UNKNOWN

        if isinstance(node, LITERAL_NODES):
            return NOT_MARKER

        return UNKNOWN

    def _lookup_path(self, path, scopes):
        for scope in reversed(scopes):
            if path[0] not in scope:
                continue
            summary = scope[path[0]]
            for segment in path[1:]:
                if isinstance(summary, _ClassNamespace) and segment in summary.names:
                    summary = summary.names[segment]
                else:
                    return UNKNOWN
            return summary

        return self._from_import(path)

    def _from_import(self, path):
        dotted = '.'.join(path)

        if self.namespace.illegal_module_imported(
                dotted, self.review_module + '.' + self.internal_marker):
            return _Marker(self.required_policy)

        if self.namespace.illegal_module_imported(
                dotted, self.review_module + '.' + self.policy_factory):
            return _Factory(_review_policy_evaluate)

        return UNKNOWN

    def _summarize_function(self, function_def, scopes):
        """Limited return summary: a function whose body is a single
        'return <known factory>(...)' statement is itself a marker factory.
        Anything else is a plain function, i.e. not a review marker.
        """
        body = function_def.body
        if (len(body) == 1
                and isinstance(body[0], ast.Return)
                and isinstance(body[0].value, ast.Call)):
            call = body[0].value
            target = self._resolve_value(call.func, scopes)

            if isinstance(target, _Factory):
                parameters = _parameter_names(function_def)

                templates = []
                for arg in call.args:
                    if isinstance(arg, ast.Name) and arg.id in parameters:
                        templates.append(('param', parameters.index(arg.id)))
                    else:
                        const = _const_str(arg)
                        templates.append(('const', const) if const is not None else ('unknown', None))

                def evaluate(args, target=target, templates=templates):
                    forwarded = []
                    for kind, value in templates:
                        if kind == 'param':
                            forwarded.append(args[value] if value < len(args) else None)
                        elif kind == 'const':
                            forwarded.append(value)
                        else:
                            forwarded.append(None)
                    return target.evaluate(forwarded)

                return _Factory(evaluate)

        return NOT_MARKER

    def _wrong_policy_message(self, function_def, identity):
        return (
            '{code} function "{name}" carries the "{identity}" review policy, '
            'not the required "{required}" policy'
        ).format(
            code=self._code,
            name=function_def.name,
            identity=identity,
            required=self.required_policy,
        )

    def _override_message(self, function_def, identity, effective, overridden):
        overridden_identity, overridden_node = overridden
        return (
            '{code} function "{name}" carries the "{identity}" review policy '
            'from the marker on line {effective_line}, overriding the '
            '"{overridden_identity}" marker on line {overridden_line}'
        ).format(
            code=self._code,
            name=function_def.name,
            identity=identity,
            effective_line=effective.lineno,
            overridden_identity=overridden_identity,
            overridden_line=overridden_node.lineno,
        )

    def _unconfirmed_message(self, function_def):
        return (
            '{code} unable to confirm that function "{name}" carries the '
            'required "{required}" review policy'
        ).format(
            code=self._code,
            name=function_def.name,
            required=self.required_policy,
        )

    def _impostor_message(self, function_def, decorator):
        return (
            '{code} decorator "{name}" on function "{function}" does not '
            'resolve to the internal review marker'
        ).format(
            code=self._code,
            name=_terminal_name(decorator),
            function=function_def.name,
        )
