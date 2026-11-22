#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadDeferredDesensitizeUse(dlint.test.base.BaseTest):

    def test_two_deferred_cleanup_jobs_and_list_callback(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batches, items):
                for batch in batches:
                    level = "internal"
                    scheduler.defer(lambda: desensitize.apply(batch, level=level))

                for batch in batches:
                    level = "secret"
                    scheduler.defer(lambda: desensitize.apply(batch, level=level))

                cleaned = list(map(lambda item: desensitize.apply(item, level=level), items))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=32,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': closure variable "level" provably resolves to '
                    "'internal' when the queue drains"
                )
            ),
            dlint.linters.base.Flake8Result(
                lineno=12,
                col_offset=32,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': closure variable "level" provably resolves to '
                    "'secret' when the queue drains"
                )
            ),
        ]

        assert result == expected

    def test_default_value_capture_safe(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batches):
                for batch in batches:
                    level = "internal"
                    scheduler.defer(lambda level=level: desensitize.apply(batch, level=level))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_nonlocal_reassignment(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(records):
                level = "public"

                def escalate():
                    nonlocal level
                    level = "secret"

                scheduler.defer(escalate)
                scheduler.defer(lambda: desensitize.apply(records, level=level))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=13,
                col_offset=28,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': nonlocal variable "level" reassigned by nested '
                    'callback(s) "escalate"'
                )
            ),
        ]

        assert result == expected

    def test_unknown_higher_order_wrapper_manual_review(self):
        python_node = self.get_ast_node(
            """
            import scheduler

            def run_cleanup(records, level):
                scheduler.defer(make_cleanup(records, level))
                scheduler.defer(cleanup)
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=4,
                message=dlint.linters.BadDeferredDesensitizeUseLinter._manual_review_tmpl
            ),
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=4,
                message=dlint.linters.BadDeferredDesensitizeUseLinter._manual_review_tmpl
            ),
        ]

        assert result == expected

    def test_literal_level_safe(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batch):
                scheduler.defer(lambda: desensitize.apply(batch, level="public"))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_fixed_closure_level_safe(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batch):
                level = "public"
                scheduler.defer(lambda: desensitize.apply(batch, level=level))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_unprovable_level(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batches, config):
                for batch in batches:
                    level = config.level_for(batch)
                    scheduler.defer(lambda: desensitize.apply(batch, level=level))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=32,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': closure variable "level" cannot be statically '
                    'resolved when the queue drains'
                )
            ),
        ]

        assert result == expected

    def test_loop_variable_capture(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batch):
                for level in ["public", "internal"]:
                    scheduler.defer(lambda: desensitize.apply(batch, level=level))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=7,
                col_offset=32,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': closure variable "level" provably resolves to '
                    "'internal' when the queue drains"
                )
            ),
        ]

        assert result == expected

    def test_assignment_after_registration(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batch):
                level = "public"
                scheduler.defer(lambda: desensitize.apply(batch, level=level))
                level = "secret"
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=7,
                col_offset=28,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': closure variable "level" provably resolves to '
                    "'secret' when the queue drains"
                )
            ),
        ]

        assert result == expected

    def test_named_callback(self):
        python_node = self.get_ast_node(
            """
            import scheduler
            import desensitize

            def run_cleanup(batches):
                for batch in batches:
                    level = "internal"

                    def cleanup():
                        desensitize.apply(batch, level=level)

                    scheduler.defer(cleanup)
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=10,
                col_offset=12,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': closure variable "level" provably resolves to '
                    "'internal' when the queue drains"
                )
            ),
        ]

        assert result == expected

    def test_from_import(self):
        python_node = self.get_ast_node(
            """
            from scheduler import defer
            from desensitize import apply

            def run_cleanup(batches):
                for batch in batches:
                    level = "internal"
                    defer(lambda: apply(batch, level=level))
            """
        )

        linter = dlint.linters.BadDeferredDesensitizeUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=22,
                message=(
                    dlint.linters.BadDeferredDesensitizeUseLinter._error_tmpl
                    + ': closure variable "level" provably resolves to '
                    "'internal' when the queue drains"
                )
            ),
        ]

        assert result == expected


if __name__ == "__main__":
    unittest.main()
