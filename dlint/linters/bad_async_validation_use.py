#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base


_ASYNC_FUNCTION_TYPES = tuple(
    node_type
    for node_type in (getattr(ast, 'AsyncFunctionDef', None),)
    if node_type is not None
)

_ASYNC_FOR_TYPES = tuple(
    node_type
    for node_type in (getattr(ast, 'AsyncFor', None),)
    if node_type is not None
)

_ASYNC_WITH_TYPES = tuple(
    node_type
    for node_type in (getattr(ast, 'AsyncWith', None),)
    if node_type is not None
)

_NAMED_EXPRESSION_TYPES = tuple(
    node_type
    for node_type in (getattr(ast, 'NamedExpr', None),)
    if node_type is not None
)

_FORMATTED_STRING_TYPES = tuple(
    node_type
    for node_type in (
        getattr(ast, 'JoinedStr', None),
        getattr(ast, 'FormattedValue', None),
    )
    if node_type is not None
)


class _Value(object):
    """Abstract value used by the limited validation data-flow analysis."""

    NONE = 'none'
    ASYNC = 'async'
    CHECK = 'check'
    PENDING = 'pending'
    ALIAS = 'alias'

    def __init__(
            self,
            kind,
            security=False,
            certain=True,
            node=None,
            resolved=None,
            records=None,
            target=None,
            reason=None):
        self.kind = kind
        self.security = security
        self.certain = certain
        self.node = node
        self.resolved = resolved
        self.records = list(records or [])
        self.target = target
        self.reason = reason

    def clone(self, **kwargs):
        value = _Value(
            kind=kwargs.pop('kind', self.kind),
            security=kwargs.pop('security', self.security),
            certain=kwargs.pop('certain', self.certain),
            node=kwargs.pop('node', self.node),
            resolved=kwargs.pop('resolved', self.resolved),
            records=kwargs.pop('records', self.records),
            target=kwargs.pop('target', self.target),
            reason=kwargs.pop('reason', self.reason),
        )
        return value

    def with_record(self, record):
        return self.clone(records=self.records + [record])


def _none():
    return _Value(_Value.NONE)


class _AwaitRecord(object):
    """Tracks whether the result of an awaited validation call was used."""

    def __init__(self, node):
        self.node = node
        self.used = False

    def mark_used(self):
        self.used = True


class _AsyncRecord(object):
    """Tracks a retained coroutine object."""

    def __init__(self, node):
        self.node = node
        self.consumed = False
        self.escaped = False
        self.reported = False
        self.inconclusive = False

    def mark_consumed(self):
        self.consumed = True

    def mark_escaped(self):
        self.escaped = True

    def mark_reported(self):
        self.reported = True

    def mark_inconclusive(self):
        self.inconclusive = True


class _Scope(object):
    def __init__(self, env=None, quiet=False, collect_returns=False):
        self.env = dict(env or {})
        self.await_records = []
        self.async_records = []
        self.quiet = quiet
        self.return_values = [] if collect_returns else None

    def copy(self):
        scope = _Scope(self.env, quiet=self.quiet)
        scope.await_records = self.await_records
        scope.async_records = self.async_records
        scope.return_values = self.return_values
        return scope

    def with_env(self, env):
        scope = self.copy()
        scope.env = dict(env)
        return scope

    def add_await_record(self, node):
        record = _AwaitRecord(node)
        self.await_records.append(record)
        return record

    def add_async_record(self, node):
        record = _AsyncRecord(node)
        self.async_records.append(record)
        return record


class BadAsyncValidationUseLinter(base.BaseLinter):
    """Looks for validation APIs whose asynchronous result is not a check.

    Only APIs declared by the caller are considered. A local ``async def``
    proves that an unawaited call produces a coroutine. ``await`` consumes
    that coroutine, and a limited amount of assignment and return analysis is
    used to follow wrappers around declared APIs. External APIs and branch
    results that disagree are reported as needing confirmation rather than as
    definite failures.
    """
    off_by_default = False

    _code = 'DUO139'
    _missing_await_tmpl = (
        'DUO139 async validation call is missing "await"; '
        'a coroutine object is used instead of a check result'
    )
    _ignored_result_tmpl = (
        'DUO139 awaited validation result is unused; '
        'the check does not protect any statement'
    )
    _pending_tmpl = (
        'DUO139 validation result needs confirmation; '
        'an external function or inconsistent branch prevents proof'
    )
    _error_tmpl = _missing_await_tmpl

    # Callers can set the class attribute, pass ``validation_apis`` to the
    # constructor, or use the ``--dlint-validation-api`` flake8 option.
    validation_apis = ()
    guard_apis = ()
    check_apis = ()

    @classmethod
    def set_validation_apis(cls, apis):
        cls.validation_apis = tuple(_normalize_apis(apis))

    def __init__(
            self,
            validation_apis=None,
            guard_apis=None,
            check_apis=None,
            *args,
            **kwargs):
        apis = []

        if validation_apis is None:
            apis.extend(_normalize_apis(self.validation_apis))
        else:
            apis.extend(_normalize_apis(validation_apis))

        if guard_apis is None:
            apis.extend(_normalize_apis(self.guard_apis))
        else:
            apis.extend(_normalize_apis(guard_apis))

        if check_apis is None:
            apis.extend(_normalize_apis(self.check_apis))
        else:
            apis.extend(_normalize_apis(check_apis))

        self._declared_apis = tuple(_unique(apis))
        self._issues = []
        self._issue_keys = set()
        self._local_functions = {}
        self._ambiguous_functions = set()
        self._import_aliases = {}
        self._module_aliases = {}
        self._summaries = {}
        self._summary_stack = set()
        self._analyzed_functions = set()
        self._module_node = None

        super(BadAsyncValidationUseLinter, self).__init__(*args, **kwargs)

    def visit_Module(self, node):
        self._module_node = node
        self._collect_local_functions(node.body)
        self._collect_import_aliases(node.body)
        self._collect_module_aliases(node.body)

        scope = _Scope()
        self._analyze_block(node.body, scope)
        self._finalize_scope(scope)

        self.results.extend(self._issues)

        # The full module was analyzed above. Do not ask the multi-visitor to
        # walk child nodes for this linter a second time.
        return None

    def _add_issue(self, kind, node, scope):
        if scope.quiet or node is None:
            return

        if kind == 'missing-await':
            message = self._missing_await_tmpl
        elif kind == 'ignored-result':
            message = self._ignored_result_tmpl
        else:
            message = self._pending_tmpl

        key = (kind, node.lineno, node.col_offset)
        if key in self._issue_keys:
            return

        self._issue_keys.add(key)
        self._issues.append(
            base.Flake8Result(
                lineno=node.lineno,
                col_offset=node.col_offset,
                message=message,
            )
        )

    def _collect_local_functions(self, statements):
        for statement in statements:
            if isinstance(
                    statement,
                    (ast.FunctionDef,) + _ASYNC_FUNCTION_TYPES):
                name = statement.name
                if name in self._local_functions:
                    self._ambiguous_functions.add(name)
                else:
                    self._local_functions[name] = statement

                self._collect_local_functions(statement.body)
            elif isinstance(statement, ast.ClassDef):
                self._collect_local_functions(statement.body)
            else:
                self._collect_local_functions(_compound_statement_bodies(statement))

    def _collect_import_aliases(self, statements):
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    if alias.asname:
                        local_name = alias.asname
                        canonical = alias.name
                    else:
                        local_name = alias.name.split('.')[0]
                        canonical = local_name
                    self._import_aliases[local_name] = canonical
            elif isinstance(statement, ast.ImportFrom):
                module = statement.module or ''
                module = module.lstrip('.')
                for alias in statement.names:
                    if alias.name == '*':
                        continue
                    local_name = alias.asname or alias.name
                    canonical = '.'.join(
                        part for part in (module, alias.name) if part
                    )
                    self._import_aliases[local_name] = canonical
            elif not isinstance(
                    statement,
                    (ast.ClassDef,) + (ast.FunctionDef,) + _ASYNC_FUNCTION_TYPES):
                self._collect_import_aliases(
                    _compound_statement_bodies(statement)
                )

    def _collect_module_aliases(self, statements):
        for statement in statements:
            if isinstance(statement, ast.Assign):
                value = statement.value
                targets = statement.targets
            elif isinstance(statement, ast.AnnAssign):
                value = statement.value
                targets = [statement.target]
            else:
                continue

            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            if not isinstance(value, (ast.Name, ast.Attribute)):
                continue

            target_name = self._alias_target(value, {})
            if target_name:
                self._module_aliases[targets[0].id] = target_name

    def _function_scope(self, function):
        scope = _Scope()
        for name, target in self._module_aliases.items():
            scope.env[name] = _Value(_Value.ALIAS, target=target)
        for argument in _function_arguments(function):
            scope.env[argument] = _none()
        return scope

    def _matches_declared(self, canonical_name):
        if not canonical_name:
            return False

        for declared in self._declared_apis:
            if canonical_name == declared:
                return True

            if declared.startswith('.'):
                if canonical_name.endswith(declared):
                    return True
                continue

            if '.' not in declared:
                if canonical_name.split('.')[-1] == declared:
                    return True
            elif canonical_name.endswith('.' + declared):
                return True

            if declared.endswith('.' + canonical_name):
                return True

        return False

    def _canonical_name(self, node, env):
        if isinstance(node, ast.Name):
            value = env.get(node.id)
            if value is not None and value.kind == _Value.ALIAS:
                return value.target
            if node.id in self._local_functions:
                return node.id
            return self._import_aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            base = self._canonical_name(node.value, env)
            if base:
                return base + '.' + node.attr
            return node.attr

        return None

    def _local_function(self, canonical_name, env):
        if not canonical_name:
            return None

        if canonical_name in self._local_functions:
            return self._local_functions.get(canonical_name)

        short_name = canonical_name.split('.')[-1]
        if short_name in self._ambiguous_functions:
            return None
        if '.' not in canonical_name:
            return self._local_functions.get(short_name)

        return None

    def _function_is_declared(self, function):
        return self._matches_declared(function.name)

    def _function_summary(self, function):
        key = id(function)
        if key in self._summaries:
            return self._summaries[key].clone(records=[])

        if key in self._summary_stack:
            return _Value(
                _Value.PENDING,
                security=True,
                certain=False,
                node=function,
                reason='recursive',
            )

        self._summary_stack.add(key)
        try:
            scope = self._function_scope(function)
            scope.quiet = True
            scope.return_values = []

            self._analyze_block(function.body, scope)
            values = [
                value
                for value in scope.return_values
                if value is not None
            ]

            if not values:
                summary = _none()
            else:
                summary = values[0]
                for value in values[1:]:
                    summary = _merge_values(summary, value)
                    if summary.kind == _Value.PENDING:
                        break

            summary = summary.clone(records=[], node=None)
        finally:
            self._summary_stack.discard(key)

        self._summaries[key] = summary
        return summary.clone(records=[])

    def _call_value(self, call, scope):
        canonical_name = self._canonical_name(call.func, scope.env)
        declared = self._matches_declared(canonical_name)
        function = self._local_function(canonical_name, scope.env)

        if function is None:
            if declared:
                return _Value(
                    _Value.PENDING,
                    security=True,
                    certain=False,
                    node=call,
                    reason='external',
                )
            return None

        function_declared = declared or self._function_is_declared(function)
        is_async = isinstance(function, _ASYNC_FUNCTION_TYPES)
        summary = self._function_summary(function)

        if is_async:
            if summary.security:
                resolved = summary.clone(node=call)
            elif function_declared:
                resolved = _Value(
                    _Value.CHECK,
                    security=True,
                    certain=True,
                    node=call,
                    reason='declared-async',
                )
            else:
                resolved = _none()

            if not resolved.security:
                return _Value(
                    _Value.ASYNC,
                    security=False,
                    certain=True,
                    node=call,
                    resolved=resolved,
                )

            return _Value(
                _Value.ASYNC,
                security=True,
                certain=True,
                node=call,
                resolved=resolved,
            )

        if summary.security:
            return summary.clone(node=call)

        if function_declared:
            return _Value(
                _Value.CHECK,
                security=True,
                certain=True,
                node=call,
                reason='declared-sync',
            )

        return None

    def _alias_target(self, node, env):
        if isinstance(node, ast.Name):
            value = env.get(node.id)
            if value is not None:
                if value.kind == _Value.ALIAS:
                    return value.target
                return None
            return self._import_aliases.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            return self._canonical_name(node, env)

        return None

    def _eval_expr(self, node, scope, usage='load'):
        if node is None:
            return _none()

        if isinstance(node, ast.Name):
            value = scope.env.get(node.id)
            if value is None:
                return _none()
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Call):
            argument_values = [
                self._eval_expr(argument, scope, usage='escape')
                for argument in node.args
            ]
            argument_values.extend(
                self._eval_expr(keyword.value, scope, usage='escape')
                for keyword in node.keywords
            )

            value = self._call_value(node, scope)
            if value is None:
                if any(value.security for value in argument_values):
                    value = _Value(
                        _Value.PENDING,
                        security=True,
                        certain=False,
                        node=node,
                        reason='external-consumer',
                    )
                else:
                    value = _none()

            if (value.kind == _Value.ASYNC
                    and value.security
                    and value.certain
                    and usage != 'await'):
                value = value.with_record(scope.add_async_record(node))

            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Await):
            inner = self._eval_expr(node.value, scope, usage='await')
            value = self._await_value(inner, node, scope)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Attribute):
            base = self._eval_expr(node.value, scope, usage='escape')
            if base.security:
                value = _Value(
                    _Value.PENDING,
                    security=True,
                    certain=False,
                    node=node,
                    reason='external-attribute',
                )
            else:
                value = _none()
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, _NAMED_EXPRESSION_TYPES):
            value = self._eval_expr(node.value, scope, usage='load')
            self._assign_target(node.target, value, scope)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.BoolOp):
            values = [
                self._eval_expr(value, scope, usage='escape')
                for value in node.values
            ]
            value = self._boolean_value(values, node)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.UnaryOp):
            operand = self._eval_expr(node.operand, scope, usage='escape')
            if isinstance(node.op, ast.Not) and operand.security:
                value = operand.clone(node=node)
            else:
                value = _none()
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Compare):
            values = [self._eval_expr(node.left, scope, usage='escape')]
            values.extend(
                self._eval_expr(comparator, scope, usage='escape')
                for comparator in node.comparators
            )
            value = self._boolean_value(values, node)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.IfExp):
            self._eval_expr(node.test, scope, usage='escape')
            body_value = self._eval_expr(node.body, scope, usage='escape')
            else_value = self._eval_expr(node.orelse, scope, usage='escape')
            value = _merge_values(body_value, else_value, node=node)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.BinOp):
            left = self._eval_expr(node.left, scope, usage='escape')
            right = self._eval_expr(node.right, scope, usage='escape')
            if left.security or right.security:
                value = _Value(
                    _Value.PENDING,
                    security=True,
                    certain=False,
                    node=node,
                    reason='operator',
                    records=left.records + right.records,
                )
            else:
                value = _none()
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            values = [
                self._eval_expr(element, scope, usage='escape')
                for element in node.elts
            ]
            value = self._boolean_value(values, node)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Dict):
            values = []
            for key, item in zip(node.keys, node.values):
                if key is not None:
                    values.append(
                        self._eval_expr(key, scope, usage='escape')
                    )
                values.append(self._eval_expr(item, scope, usage='escape'))
            value = self._boolean_value(values, node)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Subscript):
            base = self._eval_expr(node.value, scope, usage='escape')
            self._eval_expr(node.slice, scope, usage='escape')
            if base.security:
                value = _Value(
                    _Value.PENDING,
                    security=True,
                    certain=False,
                    node=node,
                    reason='subscript',
                )
            else:
                value = _none()
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, _FORMATTED_STRING_TYPES) and isinstance(
                node, getattr(ast, 'JoinedStr', ())):
            values = [
                self._eval_expr(value, scope, usage='escape')
                for value in node.values
            ]
            value = self._boolean_value(values, node)
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, _FORMATTED_STRING_TYPES) and isinstance(
                node, getattr(ast, 'FormattedValue', ())):
            value = self._eval_expr(node.value, scope, usage='escape')
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Starred):
            value = self._eval_expr(node.value, scope, usage='escape')
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if isinstance(node, ast.Yield):
            value = self._eval_expr(node.value, scope, usage='escape')
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        if hasattr(ast, 'YieldFrom') and isinstance(node, ast.YieldFrom):
            value = self._eval_expr(node.value, scope, usage='escape')
            self._apply_usage(value, usage)
            return value.clone(records=value.records)

        return _none()

    def _await_value(self, inner, node, scope):
        if inner.kind == _Value.ASYNC and inner.security:
            if inner.records:
                for record in inner.records:
                    if isinstance(record, _AsyncRecord):
                        record.mark_consumed()

            resolved = inner.resolved
            if resolved is None:
                resolved = _Value(
                    _Value.CHECK,
                    security=True,
                    certain=inner.certain,
                    node=node,
                )

            if resolved.kind == _Value.ASYNC and resolved.security:
                async_record = scope.add_async_record(node)
                return resolved.clone(
                    node=node,
                    records=resolved.records + [async_record],
                )

            if resolved.security:
                await_record = scope.add_await_record(node)
                return resolved.clone(
                    node=node,
                    records=resolved.records + [await_record],
                )

            return resolved.clone(node=node)

        if inner.kind == _Value.PENDING and inner.security:
            await_record = scope.add_await_record(node)
            return inner.clone(
                node=node,
                records=inner.records + [await_record],
            )

        if inner.kind == _Value.CHECK and inner.security:
            return inner.clone(node=node)

        return _none()

    def _boolean_value(self, values, node):
        security_values = [
            value for value in values if value.security
        ]
        if not security_values:
            return _none()

        value = security_values[0]
        for other in security_values[1:]:
            value = _merge_values(value, other, node=node)
        return value.clone(node=node)

    def _apply_usage(self, value, usage):
        if value is None:
            return

        for record in value.records:
            if isinstance(record, _AwaitRecord):
                if usage in ('escape', 'guard'):
                    record.mark_used()
            elif isinstance(record, _AsyncRecord):
                if usage == 'escape':
                    record.mark_escaped()

    def _assign_target(self, target, value, scope):
        if isinstance(target, ast.Name):
            previous = scope.env.get(target.id)
            if previous is not None:
                self._discard_retained_value(previous, scope)
            scope.env[target.id] = value
            return

        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(element, _none(), scope)
            return

        if isinstance(target, ast.Starred):
            self._assign_target(target.value, _none(), scope)

    def _assign_alias(self, target, value_node, scope):
        if not isinstance(target, ast.Name):
            return False

        target_name = self._alias_target(value_node, scope.env)
        if not target_name:
            return False

        previous = scope.env.get(target.id)
        if previous is not None:
            self._discard_retained_value(previous, scope)

        scope.env[target.id] = _Value(
            _Value.ALIAS,
            target=target_name,
            node=value_node,
        )
        return True

    def _discard_retained_value(self, value, scope):
        for record in value.records:
            if isinstance(record, _AsyncRecord):
                if (not record.consumed
                        and not record.escaped
                        and not record.reported
                        and not record.inconclusive):
                    record.mark_reported()
                    self._add_issue('missing-await', record.node, scope)

    def _guard_expr(self, node, scope):
        if node is None:
            return

        if isinstance(node, ast.BoolOp):
            for value in node.values:
                self._guard_expr(value, scope)
            return

        if isinstance(node, ast.UnaryOp):
            self._guard_expr(node.operand, scope)
            return

        if isinstance(node, _NAMED_EXPRESSION_TYPES):
            value = self._eval_expr(node.value, scope, usage='guard')
            self._assign_target(node.target, value, scope)
            self._report_guard_value(value, node, scope)
            return

        if isinstance(node, ast.IfExp):
            self._guard_expr(node.test, scope)
            body_value = self._eval_expr(node.body, scope, usage='guard')
            else_value = self._eval_expr(node.orelse, scope, usage='guard')
            self._report_guard_value(
                _merge_values(body_value, else_value, node=node),
                node,
                scope,
            )
            return

        if isinstance(node, ast.Compare):
            values = [
                self._eval_expr(node.left, scope, usage='guard'),
            ]
            values.extend(
                self._eval_expr(comparator, scope, usage='guard')
                for comparator in node.comparators
            )
            for value in values:
                self._report_guard_value(value, node, scope)
            return

        value = self._eval_expr(node, scope, usage='guard')
        self._report_guard_value(value, node, scope)

    def _report_guard_value(self, value, node, scope):
        if value is None or not value.security:
            return

        if value.kind == _Value.CHECK:
            if not value.certain:
                self._add_issue('pending', node, scope)
            return

        if value.kind == _Value.PENDING:
            self._add_issue('pending', node, scope)
            return

        if value.kind == _Value.ASYNC:
            if value.certain:
                self._add_issue('missing-await', value.node or node, scope)
                for record in value.records:
                    if isinstance(record, _AsyncRecord):
                        record.mark_reported()
            else:
                self._add_issue('pending', value.node or node, scope)

    def _analyze_block(self, statements, scope):
        current = scope
        terminated = False

        for statement in statements:
            current, statement_terminated = self._analyze_statement(
                statement, current
            )
            if statement_terminated:
                terminated = True
                break

        return current, terminated

    def _analyze_statement(self, statement, scope):
        if isinstance(statement, ast.Expr):
            value = self._eval_expr(statement.value, scope, usage='discard')
            if (value.kind == _Value.PENDING
                    and value.security
                    and not isinstance(statement.value, ast.Await)):
                # A discarded external result is not proof of either a
                # coroutine or a completed check. Keep it pending rather than
                # claiming a missing ``await``.
                self._add_issue('pending', statement.value, scope)
            return scope, False

        if isinstance(statement, ast.Assign):
            value = self._eval_expr(statement.value, scope, usage='load')
            for target in statement.targets:
                if not self._assign_alias(target, statement.value, scope):
                    self._assign_target(target, value, scope)
            return scope, False

        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                value = self._eval_expr(statement.value, scope, usage='load')
                if not self._assign_alias(
                        statement.target, statement.value, scope):
                    self._assign_target(statement.target, value, scope)
            return scope, False

        if isinstance(statement, ast.AugAssign):
            self._eval_expr(statement.target, scope, usage='escape')
            self._eval_expr(statement.value, scope, usage='escape')
            return scope, False

        if isinstance(statement, ast.If):
            self._guard_expr(statement.test, scope)
            body_scope, body_terminated = self._analyze_block(
                statement.body, scope.copy()
            )
            else_scope, else_terminated = self._analyze_block(
                statement.orelse, scope.copy()
            )
            merged = _merge_envs(scope.env, body_scope.env, else_scope.env)
            return scope.with_env(merged), body_terminated and else_terminated

        if isinstance(statement, ast.While):
            self._guard_expr(statement.test, scope)
            body_scope, _ = self._analyze_block(
                statement.body, scope.copy()
            )
            else_scope, _ = self._analyze_block(
                statement.orelse, scope.copy()
            )
            merged = _merge_envs(
                scope.env,
                body_scope.env,
                else_scope.env,
            )
            return scope.with_env(merged), False

        if isinstance(statement, (ast.For,) + _ASYNC_FOR_TYPES):
            self._eval_expr(statement.iter, scope, usage='escape')
            self._assign_target(statement.target, _none(), scope)
            body_scope, _ = self._analyze_block(
                statement.body, scope.copy()
            )
            else_scope, _ = self._analyze_block(
                statement.orelse, scope.copy()
            )
            merged = _merge_envs(
                scope.env,
                body_scope.env,
                else_scope.env,
            )
            return scope.with_env(merged), False

        if isinstance(statement, ast.Try):
            branch_envs = []
            body_scope, _ = self._analyze_block(
                statement.body, scope.copy()
            )
            branch_envs.append(body_scope.env)

            for handler in statement.handlers:
                handler_scope, _ = self._analyze_block(
                    handler.body, scope.copy()
                )
                branch_envs.append(handler_scope.env)

            else_scope, _ = self._analyze_block(
                statement.orelse, scope.copy()
            )
            branch_envs.append(else_scope.env)

            merged = _merge_many_envs(scope.env, branch_envs)
            final_scope = scope.with_env(merged)
            final_scope, _ = self._analyze_block(
                statement.finalbody, final_scope
            )
            return scope.with_env(final_scope.env), False

        if isinstance(statement, (ast.With,) + _ASYNC_WITH_TYPES):
            for item in statement.items:
                self._eval_expr(item.context_expr, scope, usage='escape')
                if item.optional_vars is not None:
                    self._assign_target(item.optional_vars, _none(), scope)
            body_scope, terminated = self._analyze_block(
                statement.body, scope.copy()
            )
            return scope.with_env(body_scope.env), terminated

        if isinstance(statement, ast.Return):
            value = self._eval_expr(statement.value, scope, usage='escape')
            if scope.return_values is not None:
                scope.return_values.append(value.clone(records=[]))
            for record in value.records:
                if isinstance(record, _AwaitRecord):
                    record.mark_used()
            return scope, True

        if isinstance(statement, ast.Raise):
            self._eval_expr(statement.exc, scope, usage='escape')
            self._eval_expr(statement.cause, scope, usage='escape')
            return scope, True

        if isinstance(statement, ast.Assert):
            self._guard_expr(statement.test, scope)
            self._eval_expr(statement.msg, scope, usage='escape')
            return scope, False

        if isinstance(
                statement,
                (ast.FunctionDef,) + _ASYNC_FUNCTION_TYPES):
            for decorator in statement.decorator_list:
                self._eval_expr(decorator, scope, usage='escape')
            for default in _function_defaults(statement):
                self._eval_expr(default, scope, usage='escape')
            self._analyze_function(statement)
            self._assign_target(
                _name_target(statement.name),
                _none(),
                scope,
            )
            return scope, False

        if isinstance(statement, ast.ClassDef):
            for decorator in statement.decorator_list:
                self._eval_expr(decorator, scope, usage='escape')
            for base in statement.bases:
                self._eval_expr(base, scope, usage='escape')
            class_scope = _Scope()
            self._analyze_block(statement.body, class_scope)
            self._finalize_scope(class_scope)
            return scope, False

        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    previous = scope.env.pop(target.id, None)
                    if previous is not None:
                        self._discard_retained_value(previous, scope)
            return scope, False

        if isinstance(statement, (ast.Break, ast.Continue)):
            return scope, True

        return scope, False

    def _analyze_function(self, function):
        key = id(function)
        if key in self._analyzed_functions:
            return
        self._analyzed_functions.add(key)

        scope = self._function_scope(function)

        self._analyze_block(function.body, scope)
        self._finalize_scope(scope)

    def _finalize_scope(self, scope):
        for record in scope.await_records:
            if not record.used:
                self._add_issue('ignored-result', record.node, scope)

        for record in scope.async_records:
            if (not record.consumed
                    and not record.escaped
                    and not record.reported
                    and not record.inconclusive):
                self._add_issue('missing-await', record.node, scope)


def _normalize_apis(apis):
    if apis is None:
        return []

    if isinstance(apis, str):
        apis = [apis]

    normalized = []
    for api in apis:
        if api is None:
            continue
        for part in str(api).split(','):
            part = part.strip()
            if part:
                normalized.append(part)
    return normalized


def _unique(values):
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _name_target(name):
    return ast.Name(id=name, ctx=ast.Store())


def _function_arguments(function):
    arguments = function.args
    names = []
    names.extend(argument.arg for argument in arguments.args)
    names.extend(
        argument.arg
        for argument in getattr(arguments, 'kwonlyargs', [])
    )
    if arguments.vararg is not None:
        if hasattr(arguments.vararg, 'arg'):
            names.append(arguments.vararg.arg)
        else:
            names.append(arguments.vararg)
    if arguments.kwarg is not None:
        if hasattr(arguments.kwarg, 'arg'):
            names.append(arguments.kwarg.arg)
        else:
            names.append(arguments.kwarg)
    return names


def _function_defaults(function):
    defaults = list(function.args.defaults)
    defaults.extend(getattr(function.args, 'kw_defaults', []))
    return [default for default in defaults if default is not None]


def _compound_statement_bodies(statement):
    bodies = []
    for attribute in ('body', 'orelse', 'finalbody', 'handlers'):
        body = getattr(statement, attribute, None)
        if not body:
            continue
        if attribute == 'handlers':
            for handler in body:
                bodies.extend(handler.body)
        else:
            bodies.extend(body)
    return bodies


def _merge_values(first, second, node=None):
    if first is None:
        first = _none()
    if second is None:
        second = _none()

    records = first.records + second.records

    if first.kind == _Value.NONE and second.kind == _Value.NONE:
        return _none()

    if first.kind == second.kind:
        if first.kind == _Value.ASYNC:
            if first.security and second.security:
                resolved = _merge_values(
                    first.resolved, second.resolved, node=node
                )
                value = first.clone(
                    node=first.node or second.node or node,
                    resolved=resolved,
                    records=records,
                    certain=first.certain and second.certain,
                )
                if resolved.kind == _Value.PENDING:
                    value.kind = _Value.PENDING
                    value.certain = False
                    value.reason = 'branch'
                if records:
                    _mark_records_inconclusive(
                        records,
                        value.kind == _Value.PENDING,
                    )
                return value
            if not first.security and not second.security:
                return first.clone(records=records)

        if first.security == second.security:
            value = first.clone(
                node=first.node or second.node or node,
                records=records,
                certain=first.certain and second.certain,
            )
            if records:
                _mark_records_inconclusive(
                    records,
                    value.kind == _Value.PENDING,
                )
            return value

    security = first.security or second.security
    if not security:
        return _none()

    value = _Value(
        _Value.PENDING,
        security=True,
        certain=False,
        node=first.node or second.node or node,
        records=records,
        reason='branch',
    )
    _mark_records_inconclusive(records, True)
    return value


def _mark_records_inconclusive(records, inconclusive):
    if not inconclusive:
        return

    for record in records:
        if isinstance(record, _AsyncRecord):
            record.mark_inconclusive()


def _merge_envs(base, first, second):
    names = set(base)
    names.update(first)
    names.update(second)

    merged = {}
    for name in names:
        merged[name] = _merge_values(
            first.get(name, _none()),
            second.get(name, _none()),
        )
    return merged


def _merge_many_envs(base, envs):
    result = dict(base)
    for env in envs:
        result = _merge_envs(base, result, env)
    return result
