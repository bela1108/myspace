#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadReviewMarkerUse(dlint.test.base.BaseTest):

    def lint(self, source):
        python_node = self.get_ast_node(source)

        linter = dlint.linters.BadReviewMarkerUseLinter()
        linter.visit(python_node)

        return linter.get_results()

    def test_internal_marker_import(self):
        result = self.lint(
            """
            from review import internal_review

            @internal_review
            def func():
                pass
            """
        )

        assert result == []

    def test_internal_policy_factory_call(self):
        result = self.lint(
            """
            from review import policy

            @policy("internal")
            def func():
                pass
            """
        )

        assert result == []

    def test_module_alias(self):
        result = self.lint(
            """
            import review as rv

            @rv.internal_review
            def good():
                pass

            @rv.policy("public")
            def bad():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=1,
                message='DUO139 function "bad" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_from_import_alias(self):
        result = self.lint(
            """
            from review import policy as make_policy

            @make_policy("public")
            def func():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=4,
                col_offset=1,
                message='DUO139 function "func" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_class_nested_method(self):
        result = self.lint(
            """
            import review

            class Exporter(object):
                @review.policy("public")
                def dump(self):
                    pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=5,
                message='DUO139 function "dump" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_class_attribute_marker(self):
        result = self.lint(
            """
            import review

            class Policies(object):
                public = review.policy("public")
                internal = review.policy("internal")

            @Policies.public
            def bad():
                pass

            @Policies.internal
            def good():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=1,
                message='DUO139 function "bad" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_local_factory_return_summary(self):
        result = self.lint(
            """
            import review

            def make_marker(name):
                return review.policy(name)

            @make_marker("public")
            def bad():
                pass

            @make_marker("internal")
            def good():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=7,
                col_offset=1,
                message='DUO139 function "bad" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_rebinding_after_definition_does_not_change_attribution(self):
        result = self.lint(
            """
            import review

            marker = review.policy("public")

            @marker
            def bad():
                pass

            marker = review.internal_review
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=1,
                message='DUO139 function "bad" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_rebinding_between_definitions(self):
        result = self.lint(
            """
            import review

            marker = review.internal_review

            @marker
            def good():
                pass

            marker = review.policy("public")

            @marker
            def bad():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=12,
                col_offset=1,
                message='DUO139 function "bad" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_same_name_two_definition_sites(self):
        result = self.lint(
            """
            from review import internal_review

            @internal_review
            def good():
                pass

            def internal_review(func):
                return func

            @internal_review
            def bad():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=11,
                col_offset=1,
                message='DUO139 decorator "internal_review" on function "bad" '
                        'does not resolve to the internal review marker'
            )
        ]

        assert result == expected

    def test_stacked_markers_order_explained(self):
        result = self.lint(
            """
            import review

            @review.policy("public")
            @review.policy("internal")
            def bad():
                pass

            @review.policy("internal")
            @review.policy("public")
            def good():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=4,
                col_offset=1,
                message='DUO139 function "bad" carries the "public" review '
                        'policy from the marker on line 4, overriding the '
                        '"internal" marker on line 5'
            )
        ]

        assert result == expected

    def test_logging_decorator_no_diagnostic(self):
        result = self.lint(
            """
            import logging

            def log_calls(func):
                return func

            @logging.getLogger
            def one():
                pass

            @log_calls
            def two():
                pass
            """
        )

        assert result == []

    def test_unconfirmed_policy(self):
        result = self.lint(
            """
            import review

            POLICY = "internal"

            @review.policy(POLICY)
            def func():
                pass
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=1,
                message='DUO139 unable to confirm that function "func" carries '
                        'the required "internal" review policy'
            )
        ]

        assert result == expected

    def test_nested_function(self):
        result = self.lint(
            """
            import review

            def outer():
                @review.policy("public")
                def inner():
                    pass
                return inner
            """
        )

        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=5,
                message='DUO139 function "inner" carries the "public" review '
                        'policy, not the required "internal" policy'
            )
        ]

        assert result == expected

    def test_no_marker_no_diagnostic(self):
        result = self.lint(
            """
            def func():
                pass
            """
        )

        assert result == []

    def test_flake8_line_col_output(self):
        python_node = self.get_ast_node(
            """
            import review

            @review.policy("public")
            def bad():
                pass
            """
        )

        linter = dlint.linters.BadReviewMarkerUseLinter()
        linter.visit(python_node)

        # flake8's default output format is
        # 'path:row:col: CODE message' with a 1-based column
        output = [
            "test.py:{row}:{col}: {message}".format(
                row=result.lineno,
                col=result.col_offset + 1,
                message=result.message
            )
            for result in linter.get_results()
        ]

        expected = [
            'test.py:4:2: DUO139 function "bad" carries the "public" review '
            'policy, not the required "internal" policy'
        ]

        assert output == expected


if __name__ == "__main__":
    unittest.main()
