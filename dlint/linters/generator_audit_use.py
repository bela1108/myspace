#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from .. import tree
from . import base


class GeneratorAuditUseLinter(base.BaseLinter):
    """Track internal audit bookkeeping on data-export generators.

    An ending audit written at the bottom of a generator only runs when
    the generator is fully consumed. This linter identifies in-house
    audit_start/audit_end calls and classifies every in-file consumer by
    the consumption stage it guarantees: first consumption, early break,
    explicit close, or full exhaustion. Consumers whose contract cannot
    be determined are flagged for manual review.
    """

    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = (
        'DUO139 generator "{name}" is never consumed, '
        'ending audit is never confirmed'
    )
    review_tmpl = (
        'DUO140 consumer contract unknown for generator "{name}", '
        'review whether ending audit is confirmed'
    )
    missing_end_tmpl = (
        'DUO140 {stage} of generator "{name}" cannot confirm ending audit'
    )

    audit_functions = ("audit_start", "audit_end")

    known_exhausting_consumers = (
        "list",
        "tuple",
        "set",
        "frozenset",
        "sorted",
        "sum",
        "max",
        "min",
        "any",
        "all",
        "enumerate",
    )

    def visit_Module(self, node):
        self.results = []
        self.parent_map = tree.build_parent_map(node)

        functions = self._collect_functions(node)
        self.generators = self._generator_infos(functions)
        self.wrappers = self._wrapper_infos(functions)

        if not self.generators:
            return

        consumed = set()
        reviews = set()

        for function in functions:
            self._visit_consumers(function, consumed, reviews)

        for name in sorted(self.generators):
            if name in consumed:
                continue

            info = self.generators[name]
            self.results.append(
                base.Flake8Result(
                    lineno=info["node"].lineno,
                    col_offset=info["node"].col_offset,
                    message=self._error_tmpl.format(name=name)
                )
            )

    def _collect_functions(self, module_node):
        functions = []

        def collect(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(child)
                collect(child)

        collect(module_node)
        return functions

    def _generator_infos(self, functions):
        generators = {}

        for function in functions:
            if not tree.function_is_generator(function):
                continue

            start_audits = []
            end_audits = []

            def audit_callback(inner_node):
                if not isinstance(inner_node, ast.Call):
                    return

                call_name = tree.call_name(inner_node)
                if call_name == "audit_start":
                    start_audits.append(inner_node)
                elif call_name == "audit_end":
                    end_audits.append(inner_node)

            tree.walk_callback_same_scope(function, audit_callback)

            generators[function.name] = {
                "node": function,
                "has_start": bool(start_audits),
                "has_end": bool(end_audits),
                "has_guaranteed_end": any(
                    tree.node_is_in_finally(audit, self.parent_map)
                    for audit in end_audits
                ),
            }

        return generators

    def _wrapper_infos(self, functions):
        wrappers = {}

        for function in functions:
            if tree.function_is_generator(function):
                continue

            returned_names = []

            def return_callback(inner_node):
                if (
                    not isinstance(inner_node, ast.Return)
                    or not inner_node.value
                ):
                    return

                call_name = self._bare_call_name(inner_node.value)
                if call_name is not None:
                    returned_names.append(call_name)

            tree.walk_callback_same_scope(function, return_callback)

            if len(returned_names) == 1:
                wrappers[function.name] = returned_names[0]

        return wrappers

    def _bare_call_name(self, node):
        if not isinstance(node, ast.Call):
            return None

        name = tree.call_name(node)
        if not name or name in self.audit_functions:
            return None

        return name

    def _resolve(self, call_name):
        if call_name in self.generators:
            return call_name

        wrapped = self.wrappers.get(call_name)
        if wrapped is not None and wrapped in self.generators:
            return wrapped

        return None

    def _visit_consumers(self, function, consumed, reviews):
        tracked = {}

        def bind(node):
            if not isinstance(node, ast.Assign):
                return

            call_name = self._bare_call_name(node.value)
            if call_name is None:
                return

            for target in node.targets:
                if isinstance(target, ast.Name):
                    tracked[target.id] = call_name

        tree.walk_callback_same_scope(function, bind)

        def check(node):
            if isinstance(node, ast.Call):
                self._check_call(node, consumed, reviews)
            elif (
                isinstance(node, ast.Name)
                and node.id in tracked
                and isinstance(node.ctx, ast.Load)
            ):
                self._check_name(node, tracked[node.id], consumed, reviews)

        self._walk_same_scope(function, check)

    def _walk_same_scope(self, node, callback):
        for child in ast.iter_child_nodes(node):
            callback(child)
            self._walk_same_scope(child, callback)

    def _check_call(self, node, consumed, reviews):
        call_name = self._bare_call_name(node)
        if call_name is None:
            return

        if call_name not in self.generators and call_name not in self.wrappers:
            return

        generator_name = self._resolve(call_name)
        stage = self._stage_for_call(node, call_name)

        if stage in ("local binding only", "returned without consumption"):
            return

        if generator_name is None:
            self._emit_review(node, call_name, reviews)
            return

        consumed.add(generator_name)
        self._emit(node, generator_name, stage, reviews)

    def _emit_review(self, node, generator_name, reviews):
        key = (generator_name, node.lineno, node.col_offset)
        if key in reviews:
            return
        reviews.add(key)

        self.results.append(
            base.Flake8Result(
                lineno=node.lineno,
                col_offset=node.col_offset,
                message=self.review_tmpl.format(name=generator_name)
            )
        )

    def _stage_for_call(self, node, call_name):
        parent = self.parent_map.get(node)

        if isinstance(parent, ast.Assign):
            return "local binding only"

        if isinstance(parent, ast.Return):
            return "returned without consumption"
        if isinstance(parent, ast.For):
            return self._for_stage(parent)
        if isinstance(parent, (ast.While, ast.If, ast.With)):
            return "first consumption"
        if isinstance(parent, (ast.List, ast.Tuple, ast.Set, ast.ListComp)):
            return "full exhaustion"
        if isinstance(parent, ast.Call):
            func_name = tree.call_name(parent)
            if func_name in ("next", "iter"):
                return "first consumption"
            if func_name in self.known_exhausting_consumers:
                return "full exhaustion"
            return "unknown consumer"

        return self._builtin_stage(call_name)

    def _builtin_stage(self, call_name):
        if call_name in ("next", "iter"):
            return "first consumption"
        if call_name in self.known_exhausting_consumers:
            return "full exhaustion"
        return "unknown consumer"

    def _check_name(self, node, call_name, consumed, reviews):
        generator_name = self._resolve(call_name)
        if generator_name is None:
            return

        stage = self._stage_for_name(node)
        if stage != "returned without consumption":
            consumed.add(generator_name)
        self._emit(node, generator_name, stage, reviews)

    def _stage_for_name(self, node):
        parent = self.parent_map.get(node)

        if isinstance(parent, ast.Call):
            func_name = tree.call_name(parent)
            if func_name in ("next", "iter"):
                return "first consumption"
            if func_name in self.known_exhausting_consumers:
                return "full exhaustion"
            return "unknown consumer"
        if isinstance(parent, ast.Attribute) and parent.attr == "close":
            attr_parent = self.parent_map.get(parent)
            if isinstance(attr_parent, ast.Call):
                return "explicit close"
            return "unknown consumer"
        if isinstance(parent, ast.Return):
            return "returned without consumption"
        if isinstance(parent, ast.For):
            return self._for_stage(parent)
        if isinstance(parent, (ast.While, ast.If, ast.With)):
            return "first consumption"
        return "unknown consumer"

    def _for_stage(self, for_node):
        if any(isinstance(n, ast.Break) for n in ast.walk(for_node)):
            return "early break"
        return "full exhaustion"

    def _emit(self, node, generator_name, stage, reviews):
        info = self.generators[generator_name]

        if info["has_guaranteed_end"]:
            return

        if stage in ("explicit close", "full exhaustion") and info["has_end"]:
            return

        if stage == "unknown consumer":
            key = (generator_name, node.lineno, node.col_offset)
            if key in reviews:
                return
            reviews.add(key)
            message = self.review_tmpl.format(name=generator_name)
        elif stage in ("returned without consumption", "local binding only"):
            return
        else:
            message = self.missing_end_tmpl.format(
                stage=stage, name=generator_name
            )

        self.results.append(
            base.Flake8Result(
                lineno=node.lineno,
                col_offset=node.col_offset,
                message=message
            )
        )
