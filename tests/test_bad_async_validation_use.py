#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import os

import dlint


FIXTURE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "async_validation",
)


class TestBadAsyncValidationUse(dlint.test.base.BaseTest):

    def lint(self, source, apis=("verify",)):
        python_node = self.get_ast_node(source)
        linter = dlint.linters.BadAsyncValidationUseLinter(
            validation_apis=apis
        )
        linter.visit(python_node)
        return linter.get_results()

    def lint_fixture(self, name):
        path = os.path.join(FIXTURE_DIR, name)
        with open(path) as fixture:
            source = fixture.read()
        return self.lint(source, apis=("verify_payload",))

    def test_missing_await_fixture(self):
        results = self.lint_fixture("missing_await.py")

        assert len(results) == 1
        assert results[0].lineno == 6
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._missing_await_tmpl
        )

    def test_unused_await_fixture(self):
        results = self.lint_fixture("unused_await.py")

        assert len(results) == 1
        assert results[0].lineno == 6
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._ignored_result_tmpl
        )

    def test_protected_fixture(self):
        results = self.lint_fixture("protected.py")

        assert results == []

    def test_no_declared_apis(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            def handle(payload):
                if verify(payload):
                    return "allowed"
            """,
            apis=(),
        )

        assert results == []

    def test_synchronous_local_validation_is_safe(self):
        results = self.lint(
            """
            def verify(payload):
                return payload == "trusted"

            def handle(payload):
                if verify(payload):
                    return "allowed"
            """
        )

        assert results == []

    def test_assignment_then_condition_is_safe(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            async def handle(payload):
                allowed = await verify(payload)
                if allowed:
                    return "allowed"
            """
        )

        assert results == []

    def test_assigned_awaited_result_is_unused(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            async def handle(payload):
                allowed = await verify(payload)
                return "allowed"
            """
        )

        assert len(results) == 1
        assert results[0].lineno == 6
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._ignored_result_tmpl
        )

    def test_external_validation_needs_confirmation(self):
        results = self.lint(
            """
            def handle(payload):
                if verify(payload):
                    return "allowed"
            """
        )

        assert len(results) == 1
        assert results[0].lineno == 3
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._pending_tmpl
        )

    def test_awaited_external_validation_needs_confirmation(self):
        results = self.lint(
            """
            async def handle(payload):
                if await verify(payload):
                    return "allowed"
            """
        )

        assert len(results) == 1
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._pending_tmpl
        )

    def test_inconsistent_branch_results_need_confirmation(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            async def handle(flag, payload):
                if flag:
                    allowed = await verify(payload)
                else:
                    allowed = verify(payload)
                if allowed:
                    return "allowed"
            """
        )

        assert len(results) == 1
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._pending_tmpl
        )

    def test_async_wrapper_return_relation_is_safe(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            async def guard(payload):
                return await verify(payload)

            async def handle(payload):
                if await guard(payload):
                    return "allowed"
            """
        )

        assert results == []

    def test_wrapper_returning_coroutine_is_missing_await(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            def guard(payload):
                return verify(payload)

            def handle(payload):
                if guard(payload):
                    return "allowed"
            """
        )

        assert len(results) == 1
        assert results[0].lineno == 9
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._missing_await_tmpl
        )

    def test_unrelated_await_is_not_a_security_check(self):
        results = self.lint(
            """
            async def transport(payload):
                return payload

            async def handle(payload):
                if await transport(payload):
                    return "allowed"
            """
        )

        assert results == []

    def test_await_comparison_is_safe(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            async def handle(payload):
                if await verify(payload) is True:
                    return "allowed"
            """
        )

        assert results == []

    def test_assert_is_a_guard(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            async def handle(payload):
                assert await verify(payload)
                return "allowed"
            """
        )

        assert results == []


    def test_unawaited_assignment_is_retained(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            def handle(payload):
                pending = verify(payload)
                return "allowed"
            """
        )

        assert len(results) == 1
        assert results[0].message == (
            dlint.linters.BadAsyncValidationUseLinter._missing_await_tmpl
        )

    def test_consistent_branch_results_are_safe(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            async def handle(flag, payload):
                if flag:
                    allowed = await verify(payload)
                else:
                    allowed = await verify(payload)
                if allowed:
                    return "allowed"
            """
        )

        assert results == []

    def test_comma_separated_api_configuration(self):
        results = self.lint(
            """
            async def verify(payload):
                return payload == "trusted"

            def handle(payload):
                if verify(payload):
                    return "allowed"
            """,
            apis=("other_verify, verify",),
        )

        assert len(results) == 1


if __name__ == "__main__":
    import unittest
    unittest.main()
