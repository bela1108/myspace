# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the offline layout material compatibility review."""

import unittest

import attr

from in_toto.layout_compat import (
    ArtifactFacts,
    PathMapping,
    evaluate_material_rules,
    review_layout_compatibility,
)
from in_toto.models.layout import Layout, Step
from in_toto.models.metadata import Metablock


def make_layout(rules, step_name="build"):
    """Return a layout with one step carrying the passed material rules."""
    step = Step(
        name=step_name,
        expected_materials=rules,
        expected_products=[],
    )
    return Layout(steps=[step], inspect=[], keys={})


class TestEvaluateMaterialRules(unittest.TestCase):
    """Test ordered single-material evaluation."""

    def test_first_matching_rule_decides(self):
        allow_first = [["ALLOW", "src/a"], ["DISALLOW", "*"]]
        deny_first = [["DISALLOW", "*"], ["ALLOW", "src/a"]]

        decision = evaluate_material_rules("src/a", allow_first)
        self.assertEqual(decision.outcome, "accepted")
        self.assertEqual(decision.rule_index, 0)

        decision = evaluate_material_rules("src/a", deny_first)
        self.assertEqual(decision.outcome, "rejected")
        self.assertEqual(decision.rule_index, 0)

    def test_consumption_removes_artifact_from_later_rules(self):
        rules = [["ALLOW", "src/a"], ["DISALLOW", "src/a"]]
        decision = evaluate_material_rules("src/a", rules)
        self.assertEqual(decision.outcome, "accepted")
        self.assertEqual(decision.rule_index, 0)

    def test_require_after_consumption_rejects(self):
        rules = [
            ["ALLOW", "src/a"],
            ["REQUIRE", "src/a"],
            ["DISALLOW", "*"],
        ]
        decision = evaluate_material_rules("src/a", rules)
        self.assertEqual(decision.outcome, "rejected")
        self.assertEqual(decision.rule_index, 1)

    def test_missing_evidence_leaves_unknown(self):
        rules = [["DELETE", "src/a"], ["DISALLOW", "*"]]
        decision = evaluate_material_rules("src/a", rules)
        self.assertEqual(decision.outcome, "unknown")

    def test_evidence_resolves_delete_rule(self):
        rules = [["DELETE", "src/a"], ["DISALLOW", "*"]]
        facts = ArtifactFacts(
            materials=frozenset({"src/a"}),
            products=frozenset(),
        )
        decision = evaluate_material_rules("src/a", rules, facts)
        self.assertEqual(decision.outcome, "accepted")
        self.assertEqual(decision.rule_index, 0)


class TestReviewLayoutCompatibility(unittest.TestCase):
    """Test the two-layout material compatibility review."""

    def test_newly_allowed_reports_both_first_decisions(self):
        vocabulary = ["src/main.c", "src/generated/foo.c"]
        old_layout = make_layout([["ALLOW", "src/main.c"], ["DISALLOW", "*"]])
        new_layout = make_layout(
            [
                ["ALLOW", "src/generated/foo.c"],
                ["ALLOW", "src/main.c"],
                ["DISALLOW", "*"],
            ]
        )

        report = review_layout_compatibility(old_layout, new_layout, vocabulary)
        review = report["src/generated/foo.c"]

        self.assertTrue(review.in_vocabulary)
        self.assertEqual(review.status, "newly_allowed")
        self.assertEqual(review.old.outcome, "rejected")
        self.assertEqual(review.old.rule_index, 1)
        self.assertEqual(review.old.decision_point, "build[1]")
        self.assertEqual(review.new.outcome, "accepted")
        self.assertEqual(review.new.rule_index, 0)
        self.assertEqual(review.new.decision_point, "build[0]")
        self.assertTrue(review.migration_allowed)
        self.assertTrue(report.approved_for_migration)
        self.assertTrue(report.compatible)

    def test_reordered_layout_accepts_previously_rejected_name(self):
        vocabulary = ["src/main.c", "src/generated/foo.c"]
        old_layout = make_layout(
            [
                ["ALLOW", "src/main.c"],
                ["DISALLOW", "*"],
                ["ALLOW", "src/generated/foo.c"],
            ]
        )
        new_layout = make_layout(
            [
                ["ALLOW", "src/generated/foo.c"],
                ["ALLOW", "src/main.c"],
                ["DISALLOW", "*"],
            ]
        )

        report = review_layout_compatibility(old_layout, new_layout, vocabulary)
        review = report["src/generated/foo.c"]

        self.assertEqual(review.status, "newly_allowed")
        self.assertEqual(review.old.outcome, "rejected")
        self.assertEqual(review.old.rule_index, 1)
        self.assertEqual(review.old.decision_point, "build[1]")
        self.assertEqual(review.new.outcome, "accepted")
        self.assertEqual(review.new.rule_index, 0)
        self.assertEqual(review.new.decision_point, "build[0]")
        self.assertEqual(review.first_deciding_steps, ("build", "build"))
        self.assertTrue(report.approved_for_migration)

    def test_rule_reordering_changes_compatibility(self):
        vocabulary = ["src/a"]
        old_layout = make_layout([["ALLOW", "src/a"], ["DISALLOW", "*"]])
        new_layout = make_layout([["DISALLOW", "*"], ["ALLOW", "src/a"]])

        report = review_layout_compatibility(old_layout, new_layout, vocabulary)
        review = report["src/a"]

        self.assertEqual(review.status, "regression")
        self.assertEqual(review.new.rule_index, 0)
        self.assertFalse(review.migration_allowed)
        self.assertFalse(report.compatible)

    def test_outside_vocabulary_is_coverage_gap_even_when_allowed(self):
        vocabulary = ["src/main.c"]
        layout = make_layout(
            [
                ["ALLOW", "src/extra.c"],
                ["ALLOW", "src/main.c"],
                ["DISALLOW", "*"],
            ]
        )

        report = review_layout_compatibility(layout, layout, vocabulary)
        review = report["src/extra.c"]

        self.assertFalse(review.in_vocabulary)
        self.assertEqual(review.status, "coverage_gap")
        self.assertEqual(review.old.outcome, "accepted")
        self.assertEqual(review.new.outcome, "accepted")
        self.assertFalse(review.migration_allowed)
        self.assertFalse(report.approved_for_migration)
        self.assertTrue(
            any(
                gap.name == "src/extra.c" and gap.may_accept_outside_vocabulary
                for gap in report.gaps
            )
        )

    def test_passing_known_sample_does_not_expand_permission(self):
        vocabulary = ["src/main.c"]
        old_layout = make_layout([["ALLOW", "src/main.c"], ["DISALLOW", "*"]])
        new_layout = make_layout([["ALLOW", "src/*.c"], ["DISALLOW", "*"]])

        report = review_layout_compatibility(old_layout, new_layout, vocabulary)
        review = report["src/main.c"]

        self.assertEqual(review.status, "unchanged_allowed")
        self.assertTrue(review.migration_allowed)
        self.assertFalse(report.approved_for_migration)
        self.assertTrue(
            any(
                gap.side == "new"
                and gap.pattern == "src/*.c"
                and gap.introduced
                and gap.may_accept_outside_vocabulary
                for gap in report.gaps
            )
        )

    def test_path_mapping_aligns_old_and_new_names(self):
        vocabulary = ["lib/foo"]
        old_layout = make_layout([["ALLOW", "lib/foo"], ["DISALLOW", "*"]])
        new_layout = make_layout([["ALLOW", "pkg/foo"], ["DISALLOW", "*"]])

        report = review_layout_compatibility(
            old_layout,
            new_layout,
            vocabulary,
            path_mappings={"lib": "pkg"},
        )
        review = report["lib/foo"]

        self.assertEqual(review.old_name, "lib/foo")
        self.assertEqual(review.new_name, "pkg/foo")
        self.assertEqual(review.status, "unchanged_allowed")
        self.assertTrue(review.migration_allowed)
        self.assertTrue(report.approved_for_migration)
        mapping = PathMapping({"lib": "pkg", "lib/vendor": "vendor"})
        self.assertEqual(mapping.map("lib/foo"), "pkg/foo")
        self.assertEqual(mapping.map("lib/vendor/foo"), "vendor/foo")
        self.assertEqual(mapping.unmap("vendor/foo"), "lib/vendor/foo")

    def test_match_rule_uses_artifact_evidence(self):
        layout = make_layout(
            [
                ["MATCH", "foo", "WITH", "MATERIALS", "FROM", "build"],
                ["DISALLOW", "*"],
            ]
        )
        facts = ArtifactFacts(
            materials=frozenset({"foo"}),
            material_hashes={"foo": {"sha256": "a" * 64}},
        )

        report = review_layout_compatibility(
            layout, layout, ["foo"], artifacts={"build": facts}
        )
        review = report["foo"]

        self.assertEqual(review.old.outcome, "accepted")
        self.assertEqual(review.old.rule_index, 0)
        self.assertEqual(review.new.outcome, "accepted")
        self.assertTrue(report.approved_for_migration)

    def test_per_side_rule_specs_are_supported(self):
        empty = Layout(steps=[], inspect=[], keys={})
        report = review_layout_compatibility(
            empty,
            empty,
            ["legacy/x"],
            rule_steps={
                "old": [["ALLOW", "legacy/x"], ["DISALLOW", "*"]],
                "new": [["ALLOW", "modern/x"], ["DISALLOW", "*"]],
            },
            path_mappings={"legacy": "modern"},
        )
        review = report["legacy/x"]

        self.assertEqual(
            (review.old_name, review.new_name), ("legacy/x", "modern/x")
        )
        self.assertEqual(review.status, "unchanged_allowed")
        self.assertTrue(report.approved_for_migration)

    def test_caller_supplied_rule_steps_replace_layout_rules(self):
        empty = Layout(steps=[], inspect=[], keys={})
        report = review_layout_compatibility(
            empty,
            empty,
            ["src/a"],
            rule_steps={
                "caller-step": [
                    ["ALLOW", "src/a"],
                    ["DISALLOW", "*"],
                ]
            },
        )
        review = report["src/a"]

        self.assertEqual(review.old.step, "caller-step")
        self.assertEqual(review.new.step, "caller-step")
        self.assertTrue(report.approved_for_migration)

    def test_metadata_and_dict_inputs_are_accepted(self):
        vocabulary = ["src/a"]
        layout = make_layout([["ALLOW", "src/a"], ["DISALLOW", "*"]])
        metadata = Metablock(signed=layout, signatures=[])
        as_dict = {
            "signed": attr.asdict(layout),
            "signatures": [],
        }

        report = review_layout_compatibility(layout, metadata, vocabulary)
        self.assertTrue(report.approved_for_migration)
        self.assertEqual(report.old_signature_count, None)
        self.assertEqual(report.new_signature_count, 0)

        report = review_layout_compatibility(as_dict, layout, vocabulary)
        self.assertTrue(report.approved_for_migration)

    def test_review_does_not_mutate_layouts(self):
        vocabulary = ["src/a"]
        old_layout = make_layout([["ALLOW", "src/a"], ["DISALLOW", "*"]])
        new_layout = make_layout([["ALLOW", "src/a"], ["DISALLOW", "*"]])
        old_repr = repr(old_layout)
        new_repr = repr(new_layout)

        review_layout_compatibility(old_layout, new_layout, vocabulary)

        self.assertEqual(repr(old_layout), old_repr)
        self.assertEqual(repr(new_layout), new_repr)

    def test_report_is_json_serializable(self):
        layout = make_layout([["ALLOW", "src/a"], ["DISALLOW", "*"]])
        report = review_layout_compatibility(layout, layout, ["src/a"])
        data = report.to_dict()

        self.assertEqual(data["materials"][0]["material"], "src/a")
        self.assertEqual(data["materials"][0]["old_decision_point"], "build[0]")
        self.assertTrue(data["approved_for_migration"])


if __name__ == "__main__":
    unittest.main()
