# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for offline artifact-rule order diagnostics."""

import unittest
from pathlib import Path

from in_toto.models.metadata import Metadata
from in_toto.rule_diagnostics import (
    diagnose_item_rules,
    diagnose_steps,
    run_order_experiments,
)

SHA = {"sha256": "a" * 64}


class TestRuleDiagnostics(unittest.TestCase):
    """Test per-rule consumption, shadowing and order experiments."""

    def setUp(self):
        self.links = {
            "build": {
                "name": "build",
                "materials": {"foo": SHA, "bar": SHA},
                "products": {"foo": SHA, "bar": SHA},
            },
            "source": {
                "name": "source",
                "materials": {},
                "products": {"foo": SHA},
            },
        }

    def test_match_is_effective_in_declared_order(self):
        """A preceding consumer does not shadow an effective MATCH."""
        rules = [
            ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "source"],
            ["ALLOW", "*"],
            ["DISALLOW", "*"],
        ]

        report = diagnose_item_rules("build", "products", rules, self.links)

        match = report["rules"][0]
        self.assertEqual(match["consumed"], ["foo"])
        self.assertEqual(match["shadowed"], [])
        self.assertEqual(report["declared_hollow_rules"], [])
        self.assertEqual(report["detected_in"], ["mandatory_shadowed"])
        self.assertTrue(report["conclusion"]["only_shadowing_order_detected"])

        finding = report["hollowed_constraints"][0]
        self.assertEqual(finding["index"], 0)
        self.assertEqual(finding["original_index"], 0)
        self.assertEqual(finding["rule"][0], "MATCH")
        self.assertEqual(finding["shadowed"], ["foo"])

    def test_broad_allow_hollows_later_match(self):
        """A broad ALLOW first makes a later MATCH consume nothing."""
        rules = [
            ["ALLOW", "*"],
            ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "source"],
            ["DISALLOW", "*"],
        ]

        report = diagnose_item_rules("build", "products", rules, self.links)

        match = report["rules"][1]
        self.assertEqual(match["potential"], ["foo"])
        self.assertEqual(match["consumed"], [])
        self.assertEqual(match["shadowed"], ["foo"])
        self.assertEqual(match["shadowed_by"], {0: ["foo"]})
        self.assertIn("original", report["detected_in"])
        self.assertEqual(report["hollowed_constraints"][0]["index"], 1)
        self.assertEqual(report["minimum_ordering"][0]["before"], 1)
        self.assertEqual(report["minimum_ordering"][0]["after"], 0)

    def test_independent_swap_preserves_verdict(self):
        """Swapping disjoint rules has no effect on the verdict."""
        rules = [
            ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "source"],
            ["ALLOW", "bar"],
            ["DISALLOW", "*"],
        ]

        experiments = run_order_experiments(
            "build", "products", rules, self.links
        )

        self.assertEqual(experiments["original"]["verdict"], "pass")
        self.assertEqual(experiments["independent_swap"]["order"], [1, 0, 2])
        self.assertEqual(experiments["independent_swap"]["verdict"], "pass")

    def test_shadow_order_is_the_only_hollow_detector(self):
        """Only the shadowing permutation exposes an otherwise hidden hole."""
        rules = [
            ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "source"],
            ["ALLOW", "bar"],
            ["ALLOW", "*"],
            ["DISALLOW", "*"],
        ]

        report = diagnose_item_rules("build", "products", rules, self.links)
        detected = {
            name: bool(experiment["hollow_rules"])
            for name, experiment in report["experiments"].items()
        }

        self.assertFalse(detected["original"])
        self.assertFalse(detected["independent_swap"])
        self.assertTrue(detected["mandatory_shadowed"])
        self.assertEqual(
            report["experiments"]["independent_swap"]["order"],
            [1, 0, 2, 3],
        )
        self.assertEqual(report["detected_in"], ["mandatory_shadowed"])

    def test_missing_destination_does_not_report_shadowing(self):
        """A MATCH with no destination is inert for a different reason."""
        rules = [
            ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "missing"],
            ["ALLOW", "*"],
            ["DISALLOW", "*"],
        ]

        report = diagnose_item_rules("build", "products", rules, self.links)

        self.assertEqual(report["rules"][0]["potential"], [])
        self.assertEqual(report["hollowed_constraints"], [])

    def test_nested_metadata_links(self):
        """Accept the functionary-keyed mapping returned by link loading."""
        demo = Path(__file__).parent / "demo_files"
        links = {
            "package": {"keyid": Metadata.load(demo / "package.2f89b927.link")},
            "write-code": {
                "keyid": Metadata.load(demo / "write-code.776a00e2.link")
            },
        }
        rules = [
            [
                "MATCH",
                "foo.py",
                "WITH",
                "PRODUCTS",
                "FROM",
                "write-code",
            ]
        ]

        report = diagnose_item_rules("package", "materials", rules, links)

        self.assertEqual(report["rules"][0]["consumed"], ["foo.py"])

    def test_diagnose_steps_reports_product_rules(self):
        """Step-level diagnosis finds the hollowed product constraint."""
        steps = [
            {
                "name": "build",
                "expected_products": [
                    ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "source"],
                    ["ALLOW", "*"],
                    ["DISALLOW", "*"],
                ],
            },
            {"name": "source"},
        ]

        report = diagnose_steps(steps, self.links)

        self.assertFalse(report["passed"])
        self.assertEqual(len(report["hollowed_constraints"]), 1)
        finding = report["hollowed_constraints"][0]
        self.assertEqual(finding["name"], "build")
        self.assertEqual(finding["source_type"], "products")
        self.assertEqual(finding["detected_in"], ["mandatory_shadowed"])


if __name__ == "__main__":
    unittest.main()
