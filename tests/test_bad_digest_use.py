#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadDigestUse(dlint.test.base.BaseTest):

    @staticmethod
    def get_linter(**kwargs):
        kwargs.setdefault(
            'digest_sources',
            {
                'archive_digest': 'archive',
                'recipient_digest': 'recipient',
            }
        )
        kwargs.setdefault(
            'entry_points',
            {
                'publish': {0: 'integrity', 1: 'external'},
            }
        )

        return dlint.linters.BadDigestUseLinter(**kwargs)

    def test_empty(self):
        python_node = self.get_ast_node(
            """
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_no_entry_points_configured(self):
        python_node = self.get_ast_node(
            """
            publish(archive_digest(), archive_digest())
            """
        )

        linter = dlint.linters.BadDigestUseLinter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_compliant_direct_call(self):
        python_node = self.get_ast_node(
            """
            publish(archive_digest(), recipient_digest())
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_misuse_direct_call(self):
        python_node = self.get_ast_node(
            """
            publish(recipient_digest(), archive_digest())
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=28,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_assignment_compliant(self):
        python_node = self.get_ast_node(
            """
            digest = archive_digest()
            publish(digest, recipient_digest())
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_assignment_misuse(self):
        python_node = self.get_ast_node(
            """
            digest = archive_digest()
            publish(archive_digest(), digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=3,
                col_offset=26,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_reassignment(self):
        python_node = self.get_ast_node(
            """
            digest = archive_digest()
            digest = recipient_digest()
            publish(archive_digest(), digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_tuple_unpacking_compliant(self):
        python_node = self.get_ast_node(
            """
            integrity, external = archive_digest(), recipient_digest()
            publish(integrity, external)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_tuple_unpacking_misuse(self):
        python_node = self.get_ast_node(
            """
            integrity, external = recipient_digest(), archive_digest()
            publish(integrity, external)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=3,
                col_offset=19,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_conditional_merge_compliant(self):
        python_node = self.get_ast_node(
            """
            if condition:
                digest = recipient_digest()
            else:
                digest = recipient_digest()
            publish(archive_digest(), digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_conditional_merge_misuse(self):
        python_node = self.get_ast_node(
            """
            if condition:
                digest = recipient_digest()
            else:
                digest = archive_digest()
            publish(archive_digest(), digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=26,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_conditional_merge_uncertain(self):
        python_node = self.get_ast_node(
            """
            if condition:
                digest = recipient_digest()
            else:
                digest = external_service_digest()
            publish(archive_digest(), digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=6,
                col_offset=26,
                message=dlint.linters.BadDigestUseLinter._uncertain_tmpl
            ),
        ]

        assert result == expected

    def test_direct_return_helper_misuse(self):
        python_node = self.get_ast_node(
            """
            def make_digest():
                return archive_digest()

            publish(archive_digest(), make_digest())
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=26,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_direct_return_helper_chain_compliant(self):
        python_node = self.get_ast_node(
            """
            def make_pair():
                return archive_digest(), recipient_digest()

            def make_digests():
                return make_pair()

            integrity, external = make_digests()
            publish(integrity, external)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = []

        assert result == expected

    def test_unresolvable_helper_uncertain(self):
        python_node = self.get_ast_node(
            """
            def make_digest():
                return request_digest()

            publish(archive_digest(), make_digest())
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=26,
                message=dlint.linters.BadDigestUseLinter._uncertain_tmpl
            ),
        ]

        assert result == expected

    def test_unknown_call_uncertain(self):
        python_node = self.get_ast_node(
            """
            digest = request_digest()
            publish(archive_digest(), digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=3,
                col_offset=26,
                message=dlint.linters.BadDigestUseLinter._uncertain_tmpl
            ),
        ]

        assert result == expected

    def test_branch_merge_only_flags_misused_position(self):
        python_node = self.get_ast_node(
            """
            if condition:
                integrity = archive_digest()
                external = recipient_digest()
            else:
                integrity = archive_digest()
                external = archive_digest()
            publish(integrity, external)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=19,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_nested_function_misuse(self):
        python_node = self.get_ast_node(
            """
            def handler():
                digest = archive_digest()
                publish(archive_digest(), digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=4,
                col_offset=30,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_keyword_argument_misuse(self):
        python_node = self.get_ast_node(
            """
            publish(digest=archive_digest())
            """
        )

        linter = self.get_linter(entry_points={'publish': {'digest': 'external'}})
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=15,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_configured_entry_point_name(self):
        python_node = self.get_ast_node(
            """
            send_report(archive_digest())
            """
        )

        linter = self.get_linter(entry_points={'send_report': {0: 'external'}})
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=2,
                col_offset=12,
                message=dlint.linters.BadDigestUseLinter._error_tmpl
            ),
        ]

        assert result == expected


if __name__ == "__main__":
    unittest.main()
