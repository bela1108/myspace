#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base
from .. import tree


_UNPROVABLE = object()

_DEF_NODES = (ast.FunctionDef,)
_LOOP_NODES = (ast.For, ast.While)
if hasattr(ast, 'AsyncFunctionDef'):
    _DEF_NODES += (ast.AsyncFunctionDef,)
if hasattr(ast, 'AsyncFor'):
    _LOOP_NODES += (ast.AsyncFor,)

_NONLOCAL_NODE = getattr(ast, 'Nonlocal', None)
_ANN_ASSIGN_NODE = getattr(ast, 'AnnAssign', None)


def _literal_value(node):
    """Return the value of a literal node, or _UNPROVABLE."""
    if node is None:
        return _UNPROVABLE
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Num):
        return node.n
    name_constant = getattr(ast, 'NameConstant', None)
    if name_constant is not None and isinstance(node, name_constant):
        return node.value
    constant = getattr(ast, 'Constant', None)
    if constant is not None and isinstance(node, constant):
        return node.value
    return _UNPROVABLE


def _arg_name(arg):
    # Python 3 uses ast.arg, Python 2 uses ast.Name
    return getattr(arg, 'arg', None) or arg.id


def _parameter_names(function):
    args = function.args
    names = [_arg_name(arg) for arg in args.args]
    names += [_arg_name(arg) for arg in getattr(args, 'kwonlyargs', [])]
    names += [_arg_name(arg) for arg in getattr(args, 'posonlyargs', [])]
    return set(names)


def _loop_target_names(loop):
    return set(
        node.id
        for node in ast.walk(loop.target)
        if isinstance(node, ast.Name)
    )


def _literal_iterable_values(node):
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_literal_value(element) for element in node.elts]
    return [_UNPROVABLE]


def _name_assignments(statements, name):
    """Collect (node, value_node) assignments to 'name' in the same scope."""
    assignments = []

    def visitor(node):
        if isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets
            ):
                assignments.append((node, node.value))
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                assignments.append((node, None))
        elif _ANN_ASSIGN_NODE is not None and isinstance(node, _ANN_ASSIGN_NODE):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                assignments.append((node, node.value))

    for statement in statements:
        visitor(statement)
        tree.walk_callback_same_scope(statement, visitor)

    return assignments


def _nonlocal_reassigners(function_node, name):
    """Find nested functions that declare 'name' nonlocal and reassign it."""
    reassigners = []

    if _NONLOCAL_NODE is None:
        return reassigners

    for node in ast.walk(function_node):
        if node is function_node or not isinstance(node, _DEF_NODES):
            continue

        declared = set()

        def visitor(inner_node, declared=declared):
            if isinstance(inner_node, _NONLOCAL_NODE):
                declared.update(inner_node.names)

        for statement in node.body:
            visitor(statement)
            tree.walk_callback_same_scope(statement, visitor)

        if name in declared and _name_assignments(node.body, name):
            reassigners.append(node)

    return reassigners


class BadDeferredDesensitizeUseLinter(base.BaseLinter):
    """This linter looks for desensitization jobs registered with the local
    queue scheduler whose data level is selected through a captured variable.
    Python closures are late-binding: a deferred callback reads the variable
    when the queue drains, not when the job is registered, so the level that
    static review sees at the registration site may not be the level applied
    at execution time.

    Three capture patterns are modeled separately:

    * closure reads of a variable that is rebound in the enclosing batch
      (loop target, in-loop assignment, or assignment after registration)
    * default-value captures, which bind at registration time and are safe
    * nonlocal reassignments from sibling callbacks, which mutate the shared
      binding between registration and execution

    Only source is examined. A deferred callable produced by an unknown
    higher-order wrapper cannot be resolved and is reported for manual
    review. Each enclosing loop forms an independent queue batch, so capture
    results from separate batches are never merged.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 deferred desensitization data level not fixed at registration'
    _manual_review_tmpl = (
        'DUO139 deferred callable cannot be resolved from source '
        '(unknown higher-order wrapper), manual review required'
    )

    def __init__(self, *args, **kwargs):
        self._parents = {}

        super(BadDeferredDesensitizeUseLinter, self).__init__(*args, **kwargs)

    @property
    def schedule_module_paths(self):
        """Module paths of the in-house queue scheduling API."""
        return (
            'scheduler.defer',
            'scheduler.enqueue',
        )

    @property
    def desensitize_module_path(self):
        """Module path of the desensitization call to constrain against."""
        return 'desensitize.apply'

    @property
    def level_kwarg(self):
        return 'level'

    def visit_Module(self, node):
        # Build a parent map once so capture analysis can walk from a
        # registration site up to its enclosing batch and scopes. This works
        # in both single-linter and MultiNodeVisitor runs.
        self._parents = {}
        for parent in ast.walk(node):
            for child in ast.iter_child_nodes(parent):
                self._parents[id(child)] = parent

        self.generic_visit(node)

    def visit_Call(self, node):
        self.generic_visit(node)

        if not self._is_schedule_call(node):
            return

        callback = self._callback_argument(node)
        if callback is None:
            return

        resolved = self._resolve_callback(node, callback)
        if resolved is None:
            self.results.append(
                base.Flake8Result(
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    message=self._manual_review_tmpl
                )
            )
            return

        self._check_callback(node, resolved)

    def _is_schedule_call(self, node):
        if not isinstance(node.func, (ast.Attribute, ast.Name)):
            return False

        module_path = tree.module_path_str(node.func)

        return any(
            self.namespace.illegal_module_imported(module_path, schedule_module_path)
            for schedule_module_path in self.schedule_module_paths
        )

    def _is_desensitize_call(self, node):
        if not isinstance(node.func, (ast.Attribute, ast.Name)):
            return False

        return self.namespace.illegal_module_imported(
            tree.module_path_str(node.func),
            self.desensitize_module_path
        )

    @staticmethod
    def _callback_argument(node):
        if node.args:
            return node.args[0]

        for keyword in node.keywords:
            if keyword.arg in ('callback', 'func'):
                return keyword.value

        return None

    def _resolve_callback(self, schedule_call, node):
        if isinstance(node, ast.Lambda):
            return node

        if isinstance(node, ast.Name):
            return self._resolve_name(schedule_call, node.id)

        # A Call, Attribute, or anything else is an unknown higher-order
        # wrapper whose return value source-only analysis cannot see
        return None

    def _resolve_name(self, schedule_call, name):
        for ancestor in self._ancestors(schedule_call):
            body = getattr(ancestor, 'body', None)
            if not isinstance(body, list):
                continue

            for statement in body:
                if isinstance(statement, _DEF_NODES) and statement.name == name:
                    return statement
                if (isinstance(statement, ast.Assign)
                        and len(statement.targets) == 1
                        and isinstance(statement.targets[0], ast.Name)
                        and statement.targets[0].id == name
                        and isinstance(statement.value, ast.Lambda)):
                    return statement.value

        return None

    def _ancestors(self, node):
        current = node
        while id(current) in self._parents:
            current = self._parents[id(current)]
            yield current

    def _enclosing_function(self, node):
        for ancestor in self._ancestors(node):
            if isinstance(ancestor, _DEF_NODES):
                return ancestor
            if isinstance(ancestor, ast.Module):
                return None

        return None

    def _batch_context(self, node):
        """Return (statements, loop) of the nearest enclosing queue batch.

        Each loop forms an independent batch so that capture results from
        separate batches are never merged.
        """
        for ancestor in self._ancestors(node):
            if isinstance(ancestor, _LOOP_NODES):
                return ancestor.body, ancestor
            if isinstance(ancestor, _DEF_NODES + (ast.Module,)):
                return ancestor.body, None
            if isinstance(ancestor, ast.Lambda):
                return [], None

        return [], None

    def _check_callback(self, schedule_call, callback):
        calls = []

        def visitor(node):
            if isinstance(node, ast.Call):
                calls.append(node)

        tree.walk_callback_same_scope(callback, visitor)

        parameter_names = _parameter_names(callback)

        for call in calls:
            if not self._is_desensitize_call(call):
                continue

            level_node = self._level_argument(call)
            if level_node is None:
                continue

            self._check_level_node(schedule_call, call, level_node, parameter_names)

    def _level_argument(self, call):
        for keyword in call.keywords:
            if keyword.arg == self.level_kwarg:
                return keyword.value

        return None

    def _check_level_node(self, schedule_call, call, level_node, parameter_names):
        if _literal_value(level_node) is not _UNPROVABLE:
            # A literal level is fixed at registration time
            return

        if not isinstance(level_node, ast.Name):
            # Expressions other than plain names are outside this rule's
            # capture model
            return

        if level_node.id in parameter_names:
            # A parameter is supplied by the invoker, and a default-value
            # capture binds at registration time: both are safe
            return

        self._check_closure_capture(schedule_call, call, level_node.id)

    def _check_closure_capture(self, schedule_call, call, name):
        enclosing_function = self._enclosing_function(schedule_call)

        if enclosing_function is not None:
            reassigners = _nonlocal_reassigners(enclosing_function, name)
            if reassigners:
                names = ', '.join(
                    sorted('"{}"'.format(reassigner.name) for reassigner in reassigners)
                )
                self.results.append(
                    base.Flake8Result(
                        lineno=call.lineno,
                        col_offset=call.col_offset,
                        message=(
                            '{}: nonlocal variable "{}" reassigned by '
                            'nested callback(s) {}'.format(self._error_tmpl, name, names)
                        )
                    )
                )
                return

        batch_statements, batch_loop = self._batch_context(schedule_call)
        assignments = _name_assignments(batch_statements, name)

        late_bound = (
            (batch_loop is not None and name in _loop_target_names(batch_loop))
            or (batch_loop is not None and len(assignments) > 0)
            or any(node.lineno > schedule_call.lineno for node, _ in assignments)
        )

        if not late_bound:
            # The binding cannot change between registration and execution
            return

        level = self._provable_level(name, batch_loop, assignments)

        if level is _UNPROVABLE:
            detail = (
                'closure variable "{}" cannot be statically resolved '
                'when the queue drains'.format(name)
            )
        else:
            detail = (
                'closure variable "{}" provably resolves to {!r} '
                'when the queue drains'.format(name, level)
            )

        self.results.append(
            base.Flake8Result(
                lineno=call.lineno,
                col_offset=call.col_offset,
                message='{}: {}'.format(self._error_tmpl, detail)
            )
        )

    @staticmethod
    def _provable_level(name, batch_loop, assignments):
        values = []

        if batch_loop is not None and name in _loop_target_names(batch_loop):
            values.extend(_literal_iterable_values(batch_loop.iter))

        values.extend(_literal_value(value_node) for _, value_node in assignments)

        if not values or any(value is _UNPROVABLE for value in values):
            return _UNPROVABLE

        # Late binding means the deferred callback observes the last value
        # assigned in the batch
        return values[-1]
