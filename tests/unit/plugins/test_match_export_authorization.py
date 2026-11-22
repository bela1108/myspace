# SPDX-License-Identifier: Apache-2.0
import ast

import testtools

from bandit.core import context as b_context
from bandit.plugins import match_export_authorization as plugin


CONFIG = plugin.gen_config("match_export_authorization")


def _match_node(source):
    tree = ast.parse(source)
    return next(
        node for node in ast.walk(tree) if isinstance(node, ast.Match)
    )


def _run(source, config=None):
    node = _match_node(source)
    ctx = b_context.Context(
        {
            "node": node,
            "lineno": node.lineno,
            "linerange": [node.lineno],
            "col_offset": node.col_offset,
            "end_col_offset": 0,
            "filename": "example.py",
            "file_data": b"",
        }
    )
    issue = plugin.match_export_authorization(
        ctx, config or CONFIG
    )
    return issue.text if issue is not None else ""


class MatchExportAuthorizationTests(testtools.TestCase):
    def test_earlier_case_shadowing_authorization_is_named(self):
        text = _run(
            """
def export(department, action, user):
    match (department, action):
        case ("dept_a", "export"):
            export_customer_pii()
        case ("dept_a", "export") if is_admin(user):
            log_attempt()
"""
        )
        self.assertIn("department='dept_a', action='export'", text)
        self.assertIn("case on line 4", text)
        self.assertIn("shadows the later authorization condition", text)
        self.assertIn("export_customer_pii", text)

    def test_or_pattern_witnesses_both_actions(self):
        text = _run(
            """
def export(department, action):
    match (department, action):
        case ("dept_a", "export" | "bulk_export"):
            export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertIn("action='export'", text)
        self.assertIn("action='bulk_export'", text)
        self.assertIn("'export' | 'bulk_export'", text)

    def test_capture_pattern_enumerates_both_departments(self):
        text = _run(
            """
def export(department, action):
    match (department, action):
        case (dept, "export"):
            export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertIn("department='dept_a', action='export'", text)
        self.assertIn("department='dept_b', action='export'", text)

    def test_satisfied_guard_authorizes_the_export(self):
        text = _run(
            """
def export(department, action):
    match (department, action):
        case (dept, "export") if has_export_grant(dept):
            export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertEqual("", text)

    def test_guard_failure_falls_through_to_unauthorized_case(self):
        text = _run(
            """
def export(department, action):
    match (department, action):
        case ("dept_a", "export") if has_export_grant("dept_a"):
            export_customer_pii()
        case ("dept_b", "export"):
            export_customer_pii()
"""
        )
        self.assertIn("department='dept_b'", text)
        self.assertNotIn("department='dept_a'", text)

    def test_unknown_guard_is_reported_as_analysis_gap(self):
        text = _run(
            """
def export(department, action, user):
    match (department, action):
        case ("dept_a", "export") if runtime_policy(user):
            export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertIn("Analysis gap", text)
        self.assertIn("guard on line 4", text)

    def test_unknown_nested_if_is_reported_as_analysis_gap(self):
        text = _run(
            """
def export(department, action, user):
    match (department, action):
        case ("dept_a", "export"):
            if runtime_policy(user):
                export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertIn("Analysis gap", text)
        self.assertIn("guard on line 5", text)

    def test_match_without_restricted_call_is_clean(self):
        text = _run(
            """
def dispatch(department, action):
    match (department, action):
        case ("dept_a", "view"):
            render_dashboard()
        case _:
            deny()
"""
        )
        self.assertEqual("", text)

    def test_unconfigured_match_subject_is_ignored(self):
        text = _run(
            """
def export(region, action):
    match (region, action):
        case ("dept_a", "export"):
            export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertEqual("", text)

    def test_legacy_if_chain_source_is_untouched(self):
        legacy_source = """
def export(department, action):
    if department == 'dept_a' and action == 'export':
        export_customer_pii()
"""
        tree = ast.parse(legacy_source)
        self.assertFalse(
            any(isinstance(node, ast.Match) for node in ast.walk(tree))
        )

    def test_nested_authorized_if_is_clean(self):
        text = _run(
            """
def export(department, action):
    match (department, action):
        case ("dept_a", "export"):
            if has_export_grant("dept_a"):
                export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertEqual("", text)


    def test_singleton_pattern_match_is_evaluated(self):
        text = _run(
            """
def export(department, action):
    match (department, action):
        case ("dept_a", None):
            deny()
        case ("dept_a", "export"):
            export_customer_pii()
        case _:
            deny()
"""
        )
        self.assertIn("department='dept_a', action='export'", text)

    def test_single_subject_match_is_supported(self):
        config = {
            "subjects": ["action"],
            "domains": {"action": ["view", "export"]},
            "restricted_calls": ["export_customer_pii"],
            "authorization_calls": ["has_export_grant"],
        }
        text = _run(
            """
def export(action):
    match action:
        case "export":
            export_customer_pii()
        case _:
            deny()
""",
            config,
        )
        self.assertIn("action='export'", text)
