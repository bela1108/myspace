# SPDX-License-Identifier: Apache-2.0
import ast
import os
import textwrap

import testtools

from bandit.core.context import Context
from bandit.plugins import assert_guard as plugin


def _attach_parents(tree):
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._bandit_parent = node


def _config(**overrides):
    config = plugin.gen_config("assert_guard")
    config.update(
        {
            "validators": ["validate_request"],
            "sensitive_calls": ["write_audit"],
        }
    )
    config.update(overrides)
    return config


def _run(source, config=None):
    source = textwrap.dedent(source).lstrip()
    tree = ast.parse(source)
    _attach_parents(tree)
    assertion = next(
        node for node in ast.walk(tree) if isinstance(node, ast.Assert)
    )
    context = Context(
        {
            "node": assertion,
            "filename": "fixture.py",
            "file_data": source,
            "lineno": assertion.lineno,
            "col_offset": assertion.col_offset,
            "linerange": [assertion.lineno, assertion.lineno],
            "import_aliases": {},
        }
    )
    return plugin.assert_guard(context, config or _config())


class AssertGuardTests(testtools.TestCase):
    def test_sole_check_points_to_assert_and_operation(self):
        source = """
 def validate_request(request):
     return True

 def write_audit(request):
     return request

 def handle(request):
     assert validate_request(request), "invalid"
     write_audit(request)
 """
        issue = _run(source)

        self.assertIsNotNone(issue)
        self.assertIn("classification=sole-check", issue.text)
        self.assertIn("assert at line 8", issue.text)
        self.assertIn("operation at line 9", issue.text)
        self.assertIn(
            "python -O removes the only validation check", issue.text
        )

    def test_independent_rejection_is_reported(self):
        source = """
 def validate_request(request):
     return True

 def write_audit(request):
     return request

 def handle(request):
     assert validate_request(request)
     if not validate_request(request):
         return "rejected"
     write_audit(request)
 """
        issue = _run(source)

        self.assertIsNotNone(issue)
        self.assertIn("classification=independent-rejection", issue.text)
        self.assertIn("independent rejection at line 9", issue.text)
        self.assertIn("operation at line 11", issue.text)

    def test_unproven_when_rejection_is_conditional(self):
        source = """
 def validate_request(request):
     return True

 def write_audit(request):
     return request

 def _reject_if_invalid(request):
     if not validate_request(request):
         raise PermissionError("invalid")

 def handle(request):
     assert validate_request(request)
     if request.enforce:
         _reject_if_invalid(request)
     write_audit(request)
 """
        issue = _run(source)

        self.assertIsNotNone(issue)
        self.assertIn("classification=unproven", issue.text)
        self.assertIn("conditional path", issue.text)
        self.assertIn("operation at line 15", issue.text)

    def test_alias_of_validation_result_is_followed(self):
        source = """
 def validate_request(request):
     return True

 def write_audit(request):
     return request

 def handle(request):
     ok = validate_request(request)
     assert ok
     if not ok:
         return "rejected"
     write_audit(request)
 """
        issue = _run(source)

        self.assertIsNotNone(issue)
        self.assertIn("classification=independent-rejection", issue.text)

    def test_negative_assertion_is_not_a_validation_guard(self):
        source = """
 def validate_request(request):
     return True

 def write_audit(request):
     return request

 def handle(request):
     assert not validate_request(request)
     write_audit(request)
 """
        self.assertIsNone(_run(source))

    def test_unrelated_assertion_is_ignored(self):
        source = """
 def write_audit(request):
     return request

 def handle(request):
     assert request
     write_audit(request)
 """
        self.assertIsNone(_run(source))

    def test_report_independent_can_be_disabled(self):
        source = """
 def validate_request(request):
     return True

 def write_audit(request):
     return request

 def handle(request):
     assert validate_request(request)
     if not validate_request(request):
         return "rejected"
     write_audit(request)
 """
        issue = _run(
            source,
            _config(
                validators=["validate_request"],
                sensitive_calls=["write_audit"],
                report_independent=False,
            ),
        )
        self.assertIsNone(issue)

    def test_bound_marks_operation_unproven(self):
        source = """
 def validate_request(request):
     return True

 def write_audit(request):
     return request

 def handle(request):
     assert validate_request(request)
     if request.a:
         if request.b:
             write_audit(request)
 """
        issue = _run(
            source,
            _config(
                validators=["validate_request"],
                sensitive_calls=["write_audit"],
                max_if_depth=1,
            ),
        )
        self.assertIsNotNone(issue)
        self.assertIn("classification=unproven", issue.text)
        self.assertIn("analysis bound", issue.text)

    def test_configured_sensitive_call_is_used(self):
        source = """
 def validate_request(request):
     return True

 def commit_ledger(request):
     return request

 def handle(request):
     assert validate_request(request)
     commit_ledger(request)
 """
        issue = _run(
            source,
            _config(
                validators=["validate_request"],
                sensitive_calls=["commit_ledger"],
            ),
        )
        self.assertIsNotNone(issue)
        self.assertIn("commit_ledger(request)", issue.text)

    def test_fixture_messages_point_at_real_source_lines(self):
        fixtures = {
            "assert_guard_independent.py": "independent-rejection",
            "assert_guard_assert_only.py": "sole-check",
            "assert_guard_unprovable.py": "unproven",
        }
        for name, classification in fixtures.items():
            with open(os.path.join("examples", name)) as fixture:
                source = fixture.read()
            issue = _run(source)
            lines = source.splitlines()
            guard_line = next(
                index
                for index, line in enumerate(lines, 1)
                if "assert validate_request" in line
            )
            operation_line = next(
                index
                for index, line in enumerate(lines, 1)
                if index > guard_line and "write_audit(request)" in line
            )

            self.assertIsNotNone(issue)
            self.assertIn("classification=" + classification, issue.text)
            self.assertIn("assert at line {}".format(guard_line), issue.text)
            self.assertIn(
                "operation at line {}".format(operation_line), issue.text
            )
