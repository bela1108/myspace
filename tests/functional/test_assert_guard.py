# SPDX-License-Identifier: Apache-2.0
import json
import os
import subprocess
import sys

import testtools

from bandit.core import config as b_config
from bandit.core import manager


class AssertGuardRuntimeTests(testtools.TestCase):
    def _run_fixture(self, name, optimized=False, extra_args=None):
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(os.path.join("examples", name))
        command.extend(extra_args or [])
        result = subprocess.run(
            command,
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = result.stdout.strip().splitlines()[-1]
        return json.loads(payload)

    def test_independent_fixture_is_safe_in_both_modes(self):
        normal = self._run_fixture("assert_guard_independent.py")
        optimized = self._run_fixture(
            "assert_guard_independent.py", optimized=True
        )

        self.assertEqual("assertion-rejected", normal["outcome"])
        self.assertFalse(normal["reached"])
        self.assertEqual("rejected", optimized["outcome"])
        self.assertFalse(optimized["reached"])

    def test_assert_only_fixture_reaches_operation_when_optimized(self):
        normal = self._run_fixture("assert_guard_assert_only.py")
        optimized = self._run_fixture(
            "assert_guard_assert_only.py", optimized=True
        )

        self.assertEqual("assertion-rejected", normal["outcome"])
        self.assertFalse(normal["reached"])
        self.assertEqual("accepted", optimized["outcome"])
        self.assertTrue(optimized["reached"])

    def test_unproven_fixture_depends_on_runtime_path(self):
        normal = self._run_fixture("assert_guard_unprovable.py")
        optimized = self._run_fixture(
            "assert_guard_unprovable.py", optimized=True
        )
        enforced_normal = self._run_fixture(
            "assert_guard_unprovable.py", extra_args=["--enforce"]
        )
        enforced_optimized = self._run_fixture(
            "assert_guard_unprovable.py",
            optimized=True,
            extra_args=["--enforce"],
        )

        self.assertEqual("assertion-rejected", normal["outcome"])
        self.assertFalse(normal["reached"])
        self.assertEqual("accepted", optimized["outcome"])
        self.assertTrue(optimized["reached"])

        self.assertEqual("assertion-rejected", enforced_normal["outcome"])
        self.assertFalse(enforced_normal["reached"])
        self.assertEqual("helper-rejected", enforced_optimized["outcome"])
        self.assertFalse(enforced_optimized["reached"])

    def test_b114_is_registered_and_classifies_all_three_fixtures(self):
        b_conf = b_config.BanditConfig()
        b_conf._config["assert_guard"] = {
            "validators": ["validate_request"],
            "sensitive_calls": ["write_audit"],
            "max_if_depth": 3,
            "max_helper_depth": 1,
            "report_independent": True,
        }
        b_mgr = manager.BanditManager(
            b_conf, "file", profile={"include": ["B114"]}
        )
        fixture_names = [
            "assert_guard_independent.py",
            "assert_guard_assert_only.py",
            "assert_guard_unprovable.py",
        ]
        b_mgr.discover_files(
            [os.path.join("examples", name) for name in fixture_names],
            True,
        )
        b_mgr.run_tests()
        issues = b_mgr.get_issue_list()

        self.assertEqual(3, len(issues))
        texts = {os.path.basename(issue.fname): issue.text for issue in issues}
        self.assertIn(
            "classification=independent-rejection",
            texts["assert_guard_independent.py"],
        )
        self.assertIn(
            "classification=sole-check",
            texts["assert_guard_assert_only.py"],
        )
        self.assertIn(
            "classification=unproven",
            texts["assert_guard_unprovable.py"],
        )
        self.assertEqual(
            "assert_guard_assert_only.py",
            os.path.basename(
                next(
                    issue.fname
                    for issue in issues
                    if "classification=sole-check" in issue.text
                )
            ),
        )
