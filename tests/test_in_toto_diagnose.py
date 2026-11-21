# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Test the in-toto-diagnose command line tool."""

import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from in_toto.in_toto_diagnose import main
from tests.common import TmpDirMixin

SHA = {"sha256": "a" * 64}


class TestInTotoDiagnose(unittest.TestCase, TmpDirMixin):
    """Test offline scenario input and report output."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()
        cls.scenario_path = os.path.join(cls.test_dir, "scenario.json")
        scenario = {
            "steps": [
                {
                    "name": "build",
                    "expected_products": [
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "source",
                        ],
                        ["ALLOW", "bar"],
                        ["ALLOW", "*"],
                        ["DISALLOW", "*"],
                    ],
                    "materials": {},
                    "products": {"foo": SHA, "bar": SHA},
                },
                {"name": "source", "products": {"foo": SHA}},
            ]
        }
        with open(cls.scenario_path, "w", encoding="utf8") as file:
            json.dump(scenario, file)

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def _run(self, extra_args):
        args = ["in-toto-diagnose", "--scenario", self.scenario_path]
        args.extend(extra_args)
        stdout = io.StringIO()
        with (
            patch("in_toto.in_toto_diagnose.sys.argv", args),
            redirect_stdout(stdout),
            self.assertRaises(SystemExit) as exit_ctx,
        ):
            main()
        return exit_ctx.exception.code, stdout.getvalue()

    def test_json_report_and_failure_exit(self):
        """A hollowed MATCH produces JSON and a non-zero exit."""
        code, output = self._run(["--json"])
        report = json.loads(output)

        self.assertEqual(code, 1)
        self.assertEqual(report["hollowed_constraints"][0]["name"], "build")
        self.assertEqual(
            report["hollowed_constraints"][0]["source_type"], "products"
        )

    def test_no_fail_and_source_type_filter(self):
        """--no-fail overrides the exit code and filters artifact sides."""
        code, output = self._run(
            ["--json", "--no-fail", "--source-type", "products"]
        )
        report = json.loads(output)

        self.assertEqual(code, 0)
        self.assertIn("products", report["items"][0])
        self.assertNotIn("materials", report["items"][0])

    def test_text_report_names_shadowing_experiment(self):
        """The text report points at the shadowing experiment finding."""
        _, output = self._run(["--no-fail"])

        self.assertIn("Hollowed constraints (shadowing experiment)", output)
        self.assertIn("MATCH foo WITH PRODUCTS FROM source", output)
        self.assertIn("mandatory_shadowed", output)


if __name__ == "__main__":
    unittest.main()
