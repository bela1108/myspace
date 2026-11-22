#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadAsyncSecurityCheck(dlint.test.base.BaseTest):

    def test_missing_await_direct_call(self):
        python_node = self.get_ast_node(
            """
            async def verify_token(token):
                return token == "secret"

            async def handler(token):
                if verify_token(token):
                    grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=7,
                message=dlint.linters.BadAsyncSecurityCheckLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_missing_await_assigned_result(self):
        python_node = self.get_ast_node(
            """
            async def check_permission(user):
                return True

            def handler(user):
                allowed = check_permission(user)
                if allowed:
                    grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=7,
                col_offset=7,
                message=dlint.linters.BadAsyncSecurityCheckLinter._error_tmpl
            )
        ]

        assert result == expected

    def test_awaited_but_result_unused(self):
        python_node = self.get_ast_node(
            """
            async def verify_token(token):
                return True

            async def handler(token):
                await verify_token(token)
                grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=4,
                message=dlint.linters.BadAsyncSecurityCheckLinter._unused_result_tmpl
            )
        ]

        assert result == expected

    def test_properly_protected(self):
        python_node = self.get_ast_node(
            """
            async def is_authorized(user):
                return True

            async def handler(user):
                allowed = await is_authorized(user)
                if allowed:
                    grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_awaited_directly_in_condition(self):
        python_node = self.get_ast_node(
            """
            async def verify_token(token):
                return True

            async def handler(token):
                if await verify_token(token):
                    grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_external_check_needs_review(self):
        python_node = self.get_ast_node(
            """
            def handler(user):
                if verify_token(user):
                    grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=3,
                col_offset=7,
                message=dlint.linters.BadAsyncSecurityCheckLinter._uncertain_tmpl
            )
        ]

        assert result == expected

    def test_inconsistent_branch_result_needs_review(self):
        python_node = self.get_ast_node(
            """
            async def check_permission(user):
                return True

            async def handler(user, flag):
                if flag:
                    allowed = await check_permission(user)
                else:
                    allowed = check_permission(user)
                if allowed:
                    grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=10,
                col_offset=7,
                message=dlint.linters.BadAsyncSecurityCheckLinter._uncertain_tmpl
            )
        ]

        assert result == expected

    def test_plain_await_is_not_a_check(self):
        python_node = self.get_ast_node(
            """
            async def notify(user):
                return True

            async def handler(user):
                await notify(user)
                grant_access()
            """
        )

        linter = dlint.linters.BadAsyncSecurityCheckLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected


if __name__ == "__main__":
    unittest.main()
