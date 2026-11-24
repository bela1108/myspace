#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import sys

from .. import base
from ... import tree


IS_PYTHON_3 = sys.version_info >= (3,)


class FunctionScope(object):
    def __init__(self, node):
        self.node = node
        self.parent = None
        self.arguments = set()
        self.default_literals = {}
        self.assigned = set()
        self.assignment_nodes = []
        self.global_names = set()
        self.nonlocal_names = set()


def make_scope(node):
    return FunctionScope(node)


class ScopeCollector(ast.NodeVisitor):
    """Collect lexical binding information for every function scope in the
    module without following imports or executing anything, i.e. this is a
    source-only analysis.
    """

    def __init__(self):
        self.scopes = {}
        self._stack = []

    def _visit_function(self, node):
        scope = make_scope(node)
        self.scopes[id(node)] = scope
        if self._stack:
            scope.parent = self._stack[-1]

        arguments = node.args
        arg_nodes = list(arguments.args)
        if arguments.vararg is not None:
            arg_nodes.append(arguments.vararg)
        if arguments.kwarg is not None:
            arg_nodes.append(arguments.kwarg)

        positional_defaults = arguments.defaults
        default_offset = len(arg_nodes) - len(positional_defaults)
        for index, arg in enumerate(arg_nodes):
            name = tree.argument_name(arg)
            scope.arguments.add(name)
            default_index = index - default_offset
            if default_index >= 0:
                default = positional_defaults[default_index]
                if tree.is_constant_literal(default):
                    scope.default_literals[name] = tree.literal_value(default)

        if IS_PYTHON_3:
            for index, default in enumerate(arguments.kw_defaults):
                if default is not None and tree.is_constant_literal(default):
                    kwarg = arguments.kwonlyargs[index]
                    scope.default_literals[
                        tree.argument_name(kwarg)
                    ] = tree.literal_value(default)

        self._stack.append(scope)
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node):
        self._bind_name(node.name)
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        self._bind_name(node.name)
        self._visit_function(node)

    def visit_Lambda(self, node):
        self._visit_function(node)

    def _bind_name(self, name):
        if self._stack:
            scope = self._stack[-1]
            scope.assigned.add(name)
            scope.assignment_nodes.append((name, None))

    def _visit_binding(self, node):
        if not self._stack:
            return
        scope = self._stack[-1]
        for name in tree.assignment_names(node):
            scope.assigned.add(name)
            scope.assignment_nodes.append((name, node))

    def visit_Assign(self, node):
        self._visit_binding(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._visit_binding(node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._visit_binding(node)
        self.generic_visit(node)

    def visit_For(self, node):
        self._visit_binding(node)
        self.generic_visit(node)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None:
                self._visit_binding(item.optional_vars)
        self.generic_visit(node)

    def visit_Global(self, node):
        if self._stack:
            self._stack[-1].global_names.update(node.names)
        self.generic_visit(node)

    def visit_Nonlocal(self, node):
        if self._stack:
            self._stack[-1].nonlocal_names.update(node.names)
        self.generic_visit(node)


class DeferredMaskingLevelLinter(base.BaseLinter):
    """This linter inspects callbacks registered with the in-house masking
    queue scheduling API. The data-classification level passed to the masking
    call inside a deferred callback is not fixed at registration time when it
    is read through a closure, rebound via ``nonlocal``, or otherwise resolved
    dynamically. The linter models each capture kind separately, keeps every
    scheduling batch independent, and reports only what can be proven from the
    source itself.

    Unknown higher-order wrapper results cannot be resolved from source alone,
    so they are flagged for manual review rather than guessed at.
    """

    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 deferred masking callback "{}" at scheduling call line {}: {}'

    SCHEDULE_FUNCTION_NAMES = frozenset((
        'submit_masking_job',
    ))
    SCHEDULE_METHOD_NAMES = frozenset((
        'submit',
        'defer',
        'enqueue',
    ))
    MASKING_FUNCTION_NAMES = frozenset((
        'mask',
        'mask_field',
    ))
    MASKING_METHOD_NAMES = frozenset((
        'mask',
        'mask_field',
    ))
    LEVEL_KEYWORD = 'level'
    LEVEL_POSITION = 1

    MODEL_CONSTANT = 'constant'
    MODEL_DEFAULT_CAPTURE = 'default-capture'
    MODEL_CLOSURE_READ = 'closure-read'
    MODEL_NONLOCAL_REASSIGNMENT = 'nonlocal-reassignment'
    MODEL_DYNAMIC = 'dynamic'

    def __init__(self, *args, **kwargs):
        super(DeferredMaskingLevelLinter, self).__init__(*args, **kwargs)
        self._function_scopes = {}
        self._parents = {}
        self._module_node = None
        self._module_scope = None
        self._module_assignments = {}

    def visit_Module(self, node):
        collector = ScopeCollector()
        collector.visit(node)
        self._function_scopes = collector.scopes
        self._parents = tree.node_parent_map(node)
        self._module_node = node
        self._module_scope = self._build_module_scope(node)
        self._module_assignments = self._module_scope.default_literals

        self.generic_visit(node)

    def _build_module_scope(self, module_node):
        scope = make_scope(module_node)
        for statement in module_node.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign,
                                      ast.AugAssign, ast.For)):
                for name in tree.assignment_names(statement):
                    scope.assigned.add(name)
                    scope.assignment_nodes.append((name, statement))
                    if isinstance(statement, ast.Assign) and \
                            len(statement.targets) == 1 and \
                            tree.is_constant_literal(statement.value):
                        scope.default_literals[name] = \
                            tree.literal_value(statement.value)
        return scope

    def visit_Call(self, node):
        self.generic_visit(node)

        if not self._is_scheduling_call(node):
            return

        callback = self._scheduling_callback(node)
        if callback is None:
            return

        if isinstance(callback, (ast.Lambda, ast.FunctionDef)):
            if hasattr(ast, 'AsyncFunctionDef') and isinstance(
                callback, ast.AsyncFunctionDef
            ):
                self._manual_result(node, 'async callback')
                return
            self._analyze_callback(callback, node)
            return

        if isinstance(callback, ast.Name):
            resolved = self._resolve_local_function(callback)
            if resolved is not None:
                self._analyze_callback(resolved, node)
                return

        self._manual_result(
            node,
            'callback originates from an unknown higher-order wrapper'
        )

    def _is_scheduling_call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in self.SCHEDULE_METHOD_NAMES
        if isinstance(func, ast.Name):
            return func.id in self.SCHEDULE_FUNCTION_NAMES
        return False

    def _is_masking_call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in self.MASKING_METHOD_NAMES
        if isinstance(func, ast.Name):
            return func.id in self.MASKING_FUNCTION_NAMES
        return False

    def _scheduling_callback(self, node):
        if node.args:
            return node.args[0]
        return None

    def _masking_level_node(self, node):
        for keyword in node.keywords:
            if keyword.arg == self.LEVEL_KEYWORD:
                return keyword.value
        if len(node.args) > self.LEVEL_POSITION:
            return node.args[self.LEVEL_POSITION]
        return None

    def _resolve_local_function(self, name_node):
        target_id = name_node.id

        enclosing = self._enclosing_scopes(name_node)
        for scope in enclosing:
            if target_id in scope.arguments:
                return None
            if self._has_value_binding(scope, target_id):
                return None

        enclosing_ids = set(id(scope.node) for scope in enclosing)
        for scope in self._function_scopes.values():
            function_node = scope.node
            if not isinstance(function_node, ast.FunctionDef):
                continue
            if function_node.name != target_id:
                continue
            if not self._is_lexically_enclosed(function_node, enclosing_ids):
                continue
            return function_node
        return None

    def _is_lexically_enclosed(self, node, enclosing_ids):
        if not enclosing_ids:
            # References at module scope may resolve to module-level defs.
            return self._parents.get(node) is self._module_node

        current = node
        while current in self._parents:
            current = self._parents[current]
            if id(current) in enclosing_ids:
                return True
        return False

    def _has_value_binding(self, scope, name):
        return any(
            assignment_name == name and assignment_node is not None
            for assignment_name, assignment_node in scope.assignment_nodes
        )

    def _enclosing_scopes(self, node):
        current = node
        scopes = []
        while current in self._parents:
            current = self._parents[current]
            scope = self._function_scopes.get(id(current))
            if scope is not None:
                scopes.append(scope)
        return scopes

    def _manual_result(self, scheduling_call, reason):
        message = self._error_tmpl.format(
            tree.call_name(scheduling_call),
            scheduling_call.lineno,
            'manual review required - ' + reason
        )
        self.results.append(
            base.Flake8Result(
                lineno=scheduling_call.lineno,
                col_offset=scheduling_call.col_offset,
                message=message
            )
        )

    def _analyze_callback(self, callback_node, scheduling_call):
        masking_calls = []

        def collect_masking_call(inner_node):
            if isinstance(inner_node, ast.Call) and \
                    self._is_masking_call(inner_node):
                masking_calls.append(inner_node)

        tree.walk_callback(callback_node, collect_masking_call)

        if not masking_calls:
            return

        callback_name = tree.function_name(callback_node)
        for masking_call in masking_calls:
            level_node = self._masking_level_node(masking_call)
            model, level = self._classify_level(level_node, callback_node)
            self._emit_result(
                scheduling_call,
                masking_call,
                callback_name,
                model,
                level
            )

    def _classify_level(self, level_node, callback_node):
        if level_node is None:
            return self.MODEL_DYNAMIC, None

        if tree.is_constant_literal(level_node):
            return self.MODEL_CONSTANT, tree.literal_value(level_node)

        names = tree.collect_nodes(level_node, (ast.Name,))
        if isinstance(level_node, ast.Name):
            names = [level_node] + names
        if not names:
            return self.MODEL_DYNAMIC, None

        models = set()
        provable_levels = set()
        for name_node in names:
            model, level = self._classify_name(name_node, callback_node)
            models.add(model)
            if level is not None:
                provable_levels.add(level)

        if models == set((self.MODEL_CONSTANT,)):
            if len(provable_levels) == 1:
                return self.MODEL_CONSTANT, next(iter(provable_levels))
            return self.MODEL_CONSTANT, None

        if len(models) == 1:
            model = next(iter(models))
            level = next(iter(provable_levels)) \
                if len(provable_levels) == 1 else None
            return model, level

        return self.MODEL_DYNAMIC, None

    def _classify_name(self, name_node, callback_node):
        name = name_node.id
        callback_scope = self._function_scopes.get(id(callback_node))
        if callback_scope is None:
            return self.MODEL_DYNAMIC, None

        if name in callback_scope.nonlocal_names:
            return self.MODEL_NONLOCAL_REASSIGNMENT, None

        if name in callback_scope.global_names:
            return self.MODEL_DYNAMIC, None

        if name in callback_scope.assigned:
            return self.MODEL_DYNAMIC, None

        if name in callback_scope.arguments:
            if name in callback_scope.default_literals:
                return (
                    self.MODEL_DEFAULT_CAPTURE,
                    callback_scope.default_literals[name]
                )
            return self.MODEL_DYNAMIC, None

        scope = callback_scope.parent
        if scope is None:
            scope = self._module_scope
        while scope is not None:
            if name in scope.nonlocal_names or name in scope.global_names:
                break

            if name in scope.assigned:
                for assigned_name, assignment_node in scope.assignment_nodes:
                    if assigned_name == name and \
                            tree.binding_is_loop_binding(
                                assignment_node, scope.node
                            ):
                        return self.MODEL_CLOSURE_READ, None

                literal = self._single_constant_binding(name, scope)
                if literal is not None:
                    return self.MODEL_CONSTANT, literal

                if scope is self._module_scope:
                    return self.MODEL_DYNAMIC, None

                return self.MODEL_CLOSURE_READ, None

            if name in scope.arguments:
                if name in scope.default_literals:
                    return (
                        self.MODEL_DEFAULT_CAPTURE,
                        scope.default_literals[name]
                    )
                return self.MODEL_CLOSURE_READ, None

            scope = scope.parent

        return self.MODEL_DYNAMIC, None

    def _single_constant_binding(self, name, scope):
        bindings = [
            assignment_node
            for assigned_name, assignment_node in scope.assignment_nodes
            if assigned_name == name
        ]
        if len(bindings) != 1:
            return None

        node = bindings[0]
        if node is None:
            return None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            value = node.value
        elif hasattr(ast, 'AnnAssign') and isinstance(node, ast.AnnAssign):
            value = node.value
        else:
            return None

        if value is not None and tree.is_constant_literal(value):
            return tree.literal_value(value)
        return None

    def _emit_result(self, scheduling_call, masking_call, callback_name,
                     model, level):
        if level is not None:
            level_text = 'provable level {}'.format(level)
        else:
            level_text = 'no provable level'

        detail = '{} at masking call line {} ({})'.format(
            model,
            masking_call.lineno,
            level_text
        )
        message = self._error_tmpl.format(
            callback_name,
            scheduling_call.lineno,
            detail
        )
        self.results.append(
            base.Flake8Result(
                lineno=masking_call.lineno,
                col_offset=masking_call.col_offset,
                message=message
            )
        )
