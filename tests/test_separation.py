# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_separation.py

<Purpose>
  Test the offline separation-of-duties audit.
"""

import unittest

from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.separation import (
    SeparationConstraint,
    SeparationReport,
    verify_separation_of_duties,
    verify_separation_policy,
)

ALICE = "a" * 64
BOB = "b" * 64
CAROL = "c" * 64
DAVE = "d" * 64


def _layout(*steps):
    return Layout(
        steps=[
            Step(
                name=name,
                pubkeys=list(pubkeys),
                threshold=threshold,
            )
            for name, pubkeys, threshold in steps
        ]
    )


def _links(steps):
    return {
        step_name: {keyid: Link(name=step_name) for keyid in keyids}
        for step_name, keyids in steps.items()
    }


class TestSeparationOfDuties(unittest.TestCase):
    """Test role assignment, evidence alternatives, and conflict reports."""

    def test_clean_pipeline_gives_role_assignment_basis(self):
        """A build team and an acceptance team satisfy the same threshold."""
        layout = _layout(
            ("build", [ALICE], 1),
            ("accept", [BOB], 1),
        )
        links = _links({"build": [ALICE], "accept": [BOB]})
        report = verify_separation_of_duties(
            layout,
            links,
            {ALICE: "build-team", BOB: "accept-team"},
            [SeparationConstraint(("build", "accept"))],
        )

        self.assertTrue(report.satisfied)
        build = report.solutions[0]["build"]
        accept = report.solutions[0]["accept"]
        self.assertEqual(build["control_domain"], "build-team")
        self.assertEqual(accept["control_domain"], "accept-team")
        self.assertIn(ALICE, build["basis"])
        self.assertIn("build-team", build["basis"])
        self.assertIn(BOB, accept["basis"])
        self.assertIn("accept-team", accept["basis"])
        self.assertIn("Role assignment 1", report.explain())
        self.assertIn("build->build-team", report.explain())
        self.assertIn("accept->accept-team", report.explain())

    def test_same_threshold_pipeline_blocked_by_shared_domain(self):
        """The contrast pipeline has the same thresholds but one control team."""
        clean = _layout(
            ("build", [ALICE, BOB], 2),
            ("accept", [CAROL, DAVE], 2),
        )
        shared = _layout(
            ("build", [ALICE, BOB], 2),
            ("accept", [ALICE, BOB], 2),
        )

        self.assertEqual(
            [step.threshold for step in clean.steps],
            [step.threshold for step in shared.steps],
        )

        report = verify_separation_of_duties(
            shared,
            _links(
                {
                    "build": [ALICE, BOB],
                    "accept": [ALICE, BOB],
                }
            ),
            {
                ALICE: "platform-team",
                BOB: "platform-team",
            },
            [["build", "accept"]],
        )

        self.assertFalse(report.satisfied)
        conflict = report.conflicts[0]
        self.assertEqual(conflict["steps"], ["build", "accept"])
        self.assertEqual(conflict["shared_domains"], ["platform-team"])
        self.assertIn("'build'", conflict["message"])
        self.assertIn("'accept'", conflict["message"])
        self.assertIn("platform-team", conflict["message"])

    def test_multiple_evidence_is_retained_when_solutions_are_capped(self):
        """Multiple qualified links stay visible even with a solution cap."""
        layout = _layout(
            ("build", [ALICE, BOB], 1),
            ("accept", [CAROL], 1),
        )
        links = _links({"build": [ALICE, BOB], "accept": [CAROL]})
        report = verify_separation_of_duties(
            layout,
            links,
            {
                ALICE: "build-team",
                BOB: "build-team",
                CAROL: "accept-team",
            },
            [("build", "accept")],
            max_solutions=1,
        )

        self.assertTrue(report.satisfied)
        self.assertTrue(report.truncated)
        evidence = {
            row["keyid"]: row for row in report.steps["build"]["evidence"]
        }
        self.assertEqual(len(evidence), 2)
        self.assertEqual(evidence[ALICE]["status"], "selected")
        self.assertEqual(evidence[BOB]["status"], "eligible")
        self.assertIn(
            "alternatives are listed",
            " ".join(report.explanations),
        )

    def test_same_signer_with_two_affiliations_cannot_bridge_steps(self):
        """A dual-affiliation signer is explained, but still bridges control."""
        layout = _layout(
            ("build", [ALICE], 1),
            ("accept", [ALICE], 1),
        )
        report = verify_separation_of_duties(
            layout,
            _links({"build": [ALICE], "accept": [ALICE]}),
            {
                ALICE: {
                    "affiliations": ["build-team", "accept-team"],
                    "identity": "alice",
                    "note": "holds two organizational identities",
                }
            },
            [
                {
                    "steps": ["build", "accept"],
                    "reason": "build and acceptance must not share a person",
                }
            ],
        )

        self.assertFalse(report.satisfied)
        conflict = report.conflicts[0]
        self.assertEqual(conflict["shared_identities"], ["alice"])
        self.assertIn("alice", report.explain())
        self.assertIn("holds two organizational identities", report.explain())
        self.assertIn("must not share a person", report.explain())

    def test_report_helpers_without_conflicts(self):
        """Report helpers handle empty explanations and missing conflicts."""
        self.assertEqual(SeparationReport(satisfied=True).explain(), "")
        self.assertEqual(
            SeparationReport(satisfied=False).message(),
            "Separation-of-duties check failed: no compatible role"
            " assignment was found",
        )

    def test_affiliation_records_list_and_unknown_step(self):
        """List-style affiliation records are accepted and stray steps noted."""
        layout = _layout(("build", [ALICE], 1))
        report = verify_separation_of_duties(
            layout,
            {
                "build": {ALICE: Link(name="build")},
                "unused": {BOB: Link(name="unused")},
            },
            [
                {
                    "keyid": ALICE,
                    "teams": ["build-team"],
                    "person": "alice",
                }
            ],
        )

        self.assertTrue(report.satisfied)
        self.assertIn("unknown step 'unused'", report.explain())

    def test_no_common_domain_and_step_conflict_diagnostics(self):
        """Threshold evidence must share a domain; direct pair is still noted."""
        layout = _layout(
            ("build", [ALICE, BOB], 2),
            ("accept", [CAROL], 1),
        )
        report = verify_separation_of_duties(
            layout,
            _links(
                {
                    "build": [ALICE, BOB],
                    "accept": [CAROL],
                }
            ),
            {
                ALICE: "build-team",
                BOB: "accept-team",
                CAROL: "accept-team",
            },
            [("build", "accept")],
        )

        self.assertFalse(report.satisfied)
        self.assertIn("no common control domain", report.explain())
        self.assertEqual(report.conflicts[0]["type"], "step")

    def test_redundant_constraint_shrinks_unsat_core(self):
        """A duplicate constraint is removed from the minimal conflict core."""
        layout = _layout(
            ("build", [ALICE], 1),
            ("accept", [BOB], 1),
        )
        report = verify_separation_of_duties(
            layout,
            _links({"build": [ALICE], "accept": [BOB]}),
            {ALICE: "shared-team", BOB: "shared-team"},
            [
                ("build", "accept"),
                ("build", "accept"),
            ],
        )

        self.assertFalse(report.satisfied)
        core_conflicts = [
            conflict
            for conflict in report.conflicts
            if conflict["type"] == "constraint_set"
        ]
        self.assertEqual(core_conflicts, [])
        self.assertEqual(len(report.conflicts), 2)

    def test_affiliation_only_constraint_allows_label_change(self):
        """Callers can explicitly request team-level separation only."""
        layout = _layout(
            ("build", [ALICE], 1),
            ("accept", [ALICE], 1),
        )
        report = verify_separation_of_duties(
            layout,
            _links({"build": [ALICE], "accept": [ALICE]}),
            {ALICE: ["build-team", "accept-team"]},
            [
                {
                    "steps": ["build", "accept"],
                    "kind": "affiliation",
                    "reason": "teams only",
                }
            ],
        )

        self.assertTrue(report.satisfied)
        assignment = report.solutions[0]
        self.assertNotEqual(
            assignment["build"]["control_domain"],
            assignment["accept"]["control_domain"],
        )
        self.assertIn(
            "multiple affiliations",
            report.explanations[0],
        )

    def test_temporary_substitution_note_is_retained(self):
        """A substitute can fill either side and the caller note survives."""
        layout = _layout(
            ("build", [ALICE, CAROL], 1),
            ("accept", [BOB, CAROL], 1),
        )
        report = verify_separation_of_duties(
            layout,
            _links({"build": [ALICE, CAROL], "accept": [BOB, CAROL]}),
            {
                ALICE: "build-team",
                BOB: "accept-team",
                CAROL: {
                    "affiliations": ["accept-team", "build-team"],
                    "identity": "carol",
                    "note": "temporarily covering acceptance",
                },
            },
            [("build", "accept")],
        )

        self.assertTrue(report.satisfied)
        self.assertEqual(len(report.solutions), 3)
        domains = {
            (
                solution["build"]["control_domain"],
                solution["accept"]["control_domain"],
            )
            for solution in report.solutions
        }
        self.assertEqual(domains, {("build-team", "accept-team")})
        self.assertTrue(
            any(
                CAROL in solution["build"]["keyids"]
                for solution in report.solutions
            )
        )
        self.assertTrue(
            any(
                CAROL in solution["accept"]["keyids"]
                for solution in report.solutions
            )
        )
        self.assertIn("temporarily covering acceptance", report.explain())

    def test_two_keys_for_one_person_do_not_meet_threshold(self):
        """Caller-provided identities deduplicate keys within a step."""
        layout = _layout(("build", [ALICE, BOB], 2))
        report = verify_separation_of_duties(
            layout,
            _links({"build": [ALICE, BOB]}),
            {ALICE: "build-team", BOB: "build-team"},
            signer_identities={ALICE: "alice", BOB: "alice"},
        )

        self.assertFalse(report.satisfied)
        self.assertIn(
            "fewer distinct people",
            " ".join(report.explanations),
        )

    def test_unclassified_evidence_is_explained(self):
        """Links without caller-provided affiliation cannot be assigned."""
        layout = _layout(("build", [ALICE], 1))
        report = verify_separation_of_duties(
            layout,
            _links({"build": [ALICE]}),
            {},
            [],
        )

        self.assertFalse(report.satisfied)
        self.assertEqual(
            report.steps["build"]["evidence"][0]["status"],
            "unclassified",
        )
        self.assertIn(
            "no caller-provided affiliation",
            report.explain(),
        )

    def test_constraint_cycle_reports_constraint_set(self):
        """Three pairwise constraints over two domains have no global solution."""
        layout = _layout(
            ("build", [ALICE], 1),
            ("accept", [BOB], 1),
            ("release", [CAROL], 1),
        )
        report = verify_separation_of_duties(
            layout,
            _links(
                {
                    "build": [ALICE],
                    "accept": [BOB],
                    "release": [CAROL],
                }
            ),
            {
                ALICE: ["build-team", "accept-team"],
                BOB: ["build-team", "accept-team"],
                CAROL: ["build-team", "accept-team"],
            },
            [
                ("build", "accept"),
                ("accept", "release"),
                ("build", "release"),
            ],
        )

        self.assertFalse(report.satisfied)
        types = [conflict["type"] for conflict in report.conflicts]
        self.assertIn("constraint_set", types)
        constraint_set = next(
            conflict
            for conflict in report.conflicts
            if conflict["type"] == "constraint_set"
        )
        self.assertEqual(len(constraint_set["constraints"]), 3)

    def test_policy_aliases_and_report_serialization(self):
        """Dictionary policies and the JSON-safe report shape are supported."""
        layout = _layout(("build", [ALICE], 1))
        report = verify_separation_policy(
            layout,
            _links({"build": [ALICE]}),
            {
                "signer_affiliations": {
                    ALICE: {
                        "teams": ["build-team"],
                        "person": "alice",
                    }
                },
                "constraints": [],
            },
        )

        self.assertTrue(report.satisfied)
        serialized = report.to_dict()
        self.assertTrue(serialized["satisfied"])
        self.assertEqual(
            serialized["solutions"][0]["build"]["identities"],
            ["alice"],
        )
        self.assertIn("passed", report.message())

        direct = verify_separation_policy(
            layout,
            _links({"build": [ALICE]}),
            {
                "affiliations": {ALICE: "build-team"},
                "separation_constraints": [],
                "identities": {ALICE: "alice"},
            },
        )
        self.assertTrue(direct.satisfied)
        self.assertEqual(direct.solutions[0]["build"]["identities"], ["alice"])

    def test_invalid_policy_inputs(self):
        """Malformed policies fail loudly instead of silently passing."""
        layout = _layout(("build", [ALICE], 1))
        links = _links({"build": [ALICE]})

        with self.assertRaises(ValueError):
            verify_separation_policy(layout, links, [])
        with self.assertRaises(ValueError):
            verify_separation_of_duties(object(), links, {ALICE: "team"})
        with self.assertRaises(ValueError):
            verify_separation_of_duties(layout, [], {ALICE: "team"})

        with self.assertRaises(ValueError):
            verify_separation_of_duties(
                layout, links, {ALICE: "build-team"}, [("build", "missing")]
            )
        with self.assertRaises(ValueError):
            verify_separation_of_duties(
                layout,
                links,
                {ALICE: "build-team"},
                [{"steps": ["build", "build"]}],
            )
        with self.assertRaises(ValueError):
            verify_separation_of_duties(
                layout,
                links,
                {ALICE: "build-team"},
                [{"steps": ["build", "accept"], "kind": "unknown"}],
            )
        with self.assertRaises(ValueError):
            verify_separation_of_duties(
                layout,
                links,
                {ALICE: "build-team"},
                [{"steps": ["build", "accept"], "kind": 1}],
            )
        with self.assertRaises(ValueError):
            verify_separation_of_duties(
                layout, links, {ALICE: "build-team"}, max_solutions=0
            )
        with self.assertRaises(ValueError):
            verify_separation_policy(layout, links, {"constraints": []})

    def test_validation_errors(self):
        """All malformed affiliation and constraint records are rejected."""
        layout = _layout(
            ("build", [ALICE], 1),
            ("accept", [BOB], 1),
        )
        links = _links({"build": [ALICE], "accept": [BOB]})

        cases = [
            {"signer_affiliations": 42},
            {"signer_affiliations": [{"teams": ["build-team"]}]},
            {"signer_affiliations": {1: "build-team"}},
            {
                "signer_affiliations": [
                    {"keyid": ALICE, "teams": ["build-team"]},
                    {"keyid": ALICE, "teams": ["other-team"]},
                ]
            },
            {"signer_identities": []},
            {"signer_identities": {1: "alice"}},
            {"signer_identities": {ALICE: 1}},
            {"signer_affiliations": {ALICE: {}}},
            {
                "signer_affiliations": {
                    ALICE: {"affiliations": "build-team", "identity": 1}
                }
            },
            {
                "signer_affiliations": {
                    ALICE: {"affiliations": "build-team", "note": 1}
                }
            },
            {"signer_affiliations": {ALICE: 1}},
            {"signer_affiliations": {ALICE: [""]}},
            {"constraints": [{"steps": "build"}]},
            {"constraints": [["build", 1]]},
            {
                "constraints": [
                    {
                        "steps": ["build", "accept"],
                        "reason": 1,
                    }
                ]
            },
            {"links": {"build": []}},
            {"links": {"build": {1: Link(name="build")}}},
        ]

        for index, raw_case in enumerate(cases):
            case = dict(raw_case)
            affiliations = case.pop("signer_affiliations", {ALICE: "team"})
            identities = case.pop("signer_identities", None)
            constraints = case.pop("constraints", [])
            case_links = case.pop("links", links)
            with (
                self.subTest(case=index),
                self.assertRaises(ValueError),
            ):
                verify_separation_of_duties(
                    layout,
                    case_links,
                    affiliations,
                    constraints,
                    signer_identities=identities,
                )

    def test_identity_only_signer_is_unclassified(self):
        """An identity without affiliation is retained but not assignable."""
        layout = _layout(("build", [ALICE], 1))
        report = verify_separation_of_duties(
            layout,
            _links({"build": [ALICE]}),
            {},
            signer_identities={ALICE: "alice"},
        )

        self.assertFalse(report.satisfied)
        evidence = report.steps["build"]["evidence"][0]
        self.assertEqual(evidence["identity"], "alice")
        self.assertEqual(evidence["affiliations"], [])


if __name__ == "__main__":
    unittest.main()
