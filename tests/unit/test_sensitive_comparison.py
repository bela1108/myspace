# SPDX-License-Identifier: Apache-2.0
import ast
import textwrap
import unittest

from bandit.core import context as b_context
from bandit.plugins import sensitive_comparison as plugin

CONFIG = {
    "sensitive_parameters": ["secret", "token"],
    "allowed_comparison_functions": [
        "hmac.compare_digest",
        "secrets.compare_digest",
    ],
}


def parse(source):
    tree = ast.parse(textwrap.dedent(source))
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._bandit_parent = parent
    return tree


def run_plugin(source, config=None):
    tree = parse(source)
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            ctx = b_context.Context(
                {
                    "node": node,
                    "filename": "placeholder.py",
                    "lineno": node.lineno,
                    "linerange": [node.lineno],
                    "file_data": "",
                }
            )
            issue = plugin.sensitive_comparison(
                ctx, CONFIG if config is None else config
            )
            if issue is not None:
                issues.append(issue)
    return issues


class SensitiveComparisonTest(unittest.TestCase):
    def test_plugin_is_opt_in(self):
        issues = run_plugin(
            """
            def authenticate(secret, candidate):
                if secret == candidate:
                    return True
            """,
            {},
        )
        self.assertEqual([], issues)

    def test_direct_comparison_in_short_circuit(self):
        issues = run_plugin("""
            def authenticate(secret, candidate, ready):
                if ready and secret == candidate:
                    return True
            """)
        self.assertEqual(1, len(issues))
        self.assertIn("definite source(s): secret", issues[0].text)
        self.assertIn("unknown source(s): candidate", issues[0].text)

    def test_local_tuple_unpacking(self):
        issues = run_plugin("""
            def authenticate(secret, candidate, ready):
                left, right = secret, candidate
                if ready and left == right:
                    return True
            """)
        self.assertEqual(1, len(issues))
        self.assertIn("definite source(s): secret", issues[0].text)
        self.assertIn("unknown source(s): candidate", issues[0].text)

    def test_chained_comparison_checks_each_equality(self):
        issues = run_plugin("""
            def authenticate(secret, candidate, ready):
                if secret == candidate == "placeholder-value":
                    return True
            """)
        self.assertEqual(1, len(issues))
        self.assertIn("secret == candidate", issues[0].text)
        self.assertIn("candidate == 'placeholder-value'", issues[0].text)
        self.assertIn("unknown source(s): candidate", issues[0].text)

    def test_tuple_comparison(self):
        issues = run_plugin("""
            def authenticate(secret, candidate):
                if (secret, "placeholder") == (candidate, "placeholder"):
                    return True
            """)
        self.assertEqual(1, len(issues))
        self.assertIn("definite source(s): secret", issues[0].text)

    def test_allowed_comparison_function_is_ignored(self):
        issues = run_plugin("""
            import hmac

            def authenticate(secret, candidate):
                if hmac.compare_digest(secret, candidate) == True:
                    return hmac.compare_digest(secret, candidate)
                return False
            """)
        self.assertEqual([], issues)

    def test_allowed_function_body_is_ignored(self):
        issues = run_plugin(
            """
            def safe_compare(secret, candidate):
                return secret == candidate
            """,
            {
                "sensitive_parameters": ["secret"],
                "allowed_comparison_functions": ["safe_compare"],
            },
        )
        self.assertEqual([], issues)

    def test_allowed_dotted_wrapper_body_is_ignored(self):
        issues = run_plugin(
            """
            def safe_compare(secret, candidate):
                return secret == candidate
            """,
            {
                "sensitive_params": {"secret": True},
                "allowed_funcs": ["custom.utils.safe_compare"],
            },
        )
        self.assertEqual([], issues)

    def test_attribute_assignment_tracks_source(self):
        issues = run_plugin("""
            class Holder:
                pass

            def authenticate(secret, candidate, holder):
                holder.value = secret
                if holder.value == candidate:
                    return True
            """)
        self.assertEqual(1, len(issues))
        self.assertIn("definite source(s): secret", issues[0].text)

    def test_non_sensitive_comparison_is_not_reported(self):
        issues = run_plugin("""
            def choose(first, second):
                if first == second:
                    return True
            """)
        self.assertEqual([], issues)

    def test_reversing_branches_keeps_the_same_compare_nodes(self):
        first = parse("""
            def authenticate(secret, candidate, ready):
                if ready:
                    if secret == candidate:
                        return True
                else:
                    if secret == candidate:
                        return False
            """)
        second = parse("""
            def authenticate(secret, candidate, ready):
                if ready:
                    if secret == candidate:
                        return False
                else:
                    if secret == candidate:
                        return True
            """)
        compare_nodes = {
            ast.dump(node) for node in plugin.collect_compare_nodes(first)
        }
        self.assertEqual(
            compare_nodes,
            {ast.dump(node) for node in plugin.collect_compare_nodes(second)},
        )
        self.assertEqual(
            compare_nodes,
            {ast.dump(node) for node in plugin.find_comparisons(first)},
        )

    def test_reversing_branches_reports_the_same_issues(self):
        first = """
            def authenticate(secret, candidate, ready):
                if ready:
                    if secret == candidate:
                        return True
                else:
                    if secret == candidate:
                        return False
        """
        second = """
            def authenticate(secret, candidate, ready):
                if ready:
                    if secret == candidate:
                        return False
                else:
                    if secret == candidate:
                        return True
        """
        first_issues = run_plugin(first)
        second_issues = run_plugin(second)
        self.assertEqual(
            {issue.text for issue in first_issues},
            {issue.text for issue in second_issues},
        )


if __name__ == "__main__":
    unittest.main()
