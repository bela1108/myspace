# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the offline material naming migration review."""

import unittest

from in_toto.material_migration import (
    first_deciding_rule,
    review_material_migration,
)
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock
from tests.common import SignerStore


def _decision(rules, name):
    return first_deciding_rule(
        name, [{"item": "package", "kind": "step", "rules": rules}]
    )


class TestFirstDecidingRule(unittest.TestCase):
    def test_order_matters(self):
        """A leading DISALLOW rejects before a later ALLOW can consume."""
        rules = [["DISALLOW", "*"], ["ALLOW", "src/foo.py"]]
        decision = _decision(rules, "src/foo.py")
        self.assertEqual(decision["outcome"], "reject")
        self.assertEqual(decision["rule_index"], 0)
        self.assertEqual(decision["rule"], ["DISALLOW", "*"])

        rules = [["ALLOW", "src/foo.py"], ["DISALLOW", "*"]]
        decision = _decision(rules, "src/foo.py")
        self.assertEqual(decision["outcome"], "accept")
        self.assertEqual(decision["rule_index"], 0)
        self.assertEqual(decision["rule"], ["ALLOW", "src/foo.py"])

    def test_match_prefix_is_stripped_before_globbing(self):
        rules = [
            [
                "MATCH",
                "foo.py",
                "IN",
                "src",
                "WITH",
                "PRODUCTS",
                "IN",
                "src",
                "FROM",
                "write-code",
            ]
        ]
        self.assertEqual(_decision(rules, "src/foo.py")["outcome"], "accept")
        self.assertEqual(
            _decision(rules, "other/foo.py")["outcome"], "uncovered"
        )

    def test_no_rule_is_uncovered_not_accepted(self):
        rules = [
            ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
        ]
        decision = _decision(rules, "src/foo.py")
        self.assertEqual(decision["outcome"], "uncovered")
        self.assertIsNone(decision["rule_index"])


def _layout(material_rules):
    return Layout.read(
        {
            "_type": "layout",
            "steps": [
                {
                    "_type": "step",
                    "name": "write-code",
                    "expected_command": [],
                    "expected_materials": [],
                    "expected_products": [["CREATE", "foo.py"]],
                },
                {
                    "_type": "step",
                    "name": "package",
                    "expected_command": [],
                    "expected_materials": material_rules,
                    "expected_products": [
                        ["CREATE", "foo.tar.gz"],
                        ["ALLOW", "foo.py"],
                    ],
                },
            ],
            "inspect": [],
        }
    )


OLD_MATCH = ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
NEW_MATCH = [
    "MATCH",
    "foo.py",
    "IN",
    "src",
    "WITH",
    "PRODUCTS",
    "IN",
    "src",
    "FROM",
    "write-code",
]


class TestMigrationReview(unittest.TestCase):
    def setUp(self):
        self.verification_keys = {
            SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub
        }

        self.old_layout = _layout([OLD_MATCH, ["DISALLOW", "*"]])
        self.new_layout = _layout([NEW_MATCH, ["DISALLOW", "*"]])

        self.old_metadata = Metablock(signed=self.old_layout)
        self.old_metadata.create_signature(SignerStore.rsa)
        self.new_metadata = Metablock(signed=self.new_layout)
        self.new_metadata.create_signature(SignerStore.rsa)

    def _review(self, **kwargs):
        return review_material_migration(
            self.old_metadata,
            self.new_metadata,
            ["src/foo.py"],
            path_mappings={"src/": ""},
            verification_keys=self.verification_keys,
            **kwargs,
        )

    def test_signed_flip_reports_both_deciding_rules(self):
        report = self._review()

        self.assertEqual(report["signatures"], {"old": True, "new": True})
        self.assertTrue(report["migration_allowed"])
        self.assertEqual(report["expansion"], [])
        self.assertEqual(report["lost"], [])

        # The renamed material maps back to the approved old spelling.
        entry = report["materials"]["src/foo.py"]
        self.assertEqual(entry["old_name"], "foo.py")
        self.assertTrue(entry["approved_by_old"])
        self.assertTrue(entry["accepted_by_new"])

        # Feeding the new spelling to the old rules is what flips.
        self.assertTrue(entry["flip"])
        self.assertEqual(entry["legacy"]["outcome"], "reject")
        self.assertEqual(entry["legacy"]["item"], "package")
        self.assertEqual(entry["legacy"]["rule_index"], 1)
        self.assertEqual(entry["new"]["outcome"], "accept")
        self.assertEqual(entry["new"]["item"], "package")
        self.assertEqual(entry["new"]["rule_index"], 0)

        self.assertEqual(len(report["flips"]), 1)
        flip = report["flips"][0]
        self.assertEqual(flip["material"], "src/foo.py")
        self.assertEqual(flip["old_side"]["rule"], ["DISALLOW", "*"])
        self.assertEqual(flip["new_side"]["rule"], NEW_MATCH)

    def test_observed_name_outside_vocabulary_is_a_gap(self):
        observed_layout = _layout(
            [["ALLOW", "src/*"], ["DISALLOW", "*"]]
        )
        observed_metadata = Metablock(signed=observed_layout)
        observed_metadata.create_signature(SignerStore.rsa)

        report = review_material_migration(
            self.old_metadata,
            observed_metadata,
            ["src/foo.py"],
            path_mappings={"src/": ""},
            observed_materials=["src/secret.py"],
            verification_keys=self.verification_keys,
        )

        self.assertFalse(report["migration_allowed"])
        self.assertTrue(report["unbounded_accept"])
        self.assertIn("src/secret.py", report["expansion"])
        gap_names = {gap.get("material") for gap in report["coverage_gaps"]}
        self.assertIn("src/secret.py", gap_names)

    def test_passing_samples_do_not_expand_permission(self):
        """Known samples passing is not proof that the set did not widen."""
        wildcard_layout = _layout([["ALLOW", "src/*"], ["DISALLOW", "*"]])
        wildcard_metadata = Metablock(signed=wildcard_layout)
        wildcard_metadata.create_signature(SignerStore.rsa)

        report = review_material_migration(
            self.old_metadata,
            wildcard_metadata,
            ["src/foo.py"],
            path_mappings={"src/": ""},
            # Every known sample is accepted ...
            observed_materials=["src/foo.py"],
            verification_keys=self.verification_keys,
        )

        self.assertTrue(report["materials"]["src/foo.py"]["accepted_by_new"])
        # ... but the wildcard still prevents a migration approval.
        self.assertTrue(report["unbounded_accept"])
        self.assertFalse(report["migration_allowed"])

    def test_explicit_rule_steps_can_be_substituted(self):
        report = review_material_migration(
            self.old_metadata,
            self.new_metadata,
            ["src/foo.py"],
            rule_steps={
                "old": [("package", [OLD_MATCH, ["DISALLOW", "*"]])],
                "new": [("package", [NEW_MATCH, ["DISALLOW", "*"]])],
            },
            path_mappings={"src/": ""},
        )
        self.assertTrue(report["materials"]["src/foo.py"]["flip"])
        self.assertTrue(report["migration_allowed"])


if __name__ == "__main__":
    unittest.main()
