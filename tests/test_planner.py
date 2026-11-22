import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import CVSS4, CVSS4Action, CVSS4Planner, plan_cvss4_remediations
from cvss.exceptions import CVSS4PlanningError

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"


def four_actions():
    return [
        CVSS4Action("network", {"AV": "A"}, cost=3, conflicts=["crypto"]),
        CVSS4Action("mfa", {"PR": "H"}, cost=2),
        CVSS4Action("crypto", {"VC": "L"}, cost=4),
        CVSS4Action("integrity", {"VI": "L"}, cost=3),
    ]


class TestCVSS4Planner(unittest.TestCase):
    def make_planner(self, **kwargs):
        options = {
            "max_actions": 2,
            "fixed_metrics": {"SC": "H", "SI": "H", "SA": "H"},
            "release_threshold": 9.0,
        }
        options.update(kwargs)
        return CVSS4Planner(BASE, four_actions(), **options)

    def test_four_actions_are_exhaustively_enumerated(self):
        planner = self.make_planner()

        # Four singles plus C(4, 2) pairs, less the mutually-exclusive network/crypto pair.
        self.assertEqual(10 - 1, len(planner.all_plans))
        self.assertEqual(4, len(planner.single_action_plans))
        self.assertEqual(["network", "crypto"], planner.infeasible_combinations[0]["actions"])

        for plan in planner.all_plans:
            self.assertEqual(CVSS4(plan["vector"]).base_score, plan["score"])
            self.assertEqual((plan["score"], plan["cost"]), plan.recompute_objectives())
            self.assertTrue(plan.objectives_match())

    def test_pareto_front_uses_score_and_cost(self):
        planner = self.make_planner()

        self.assertEqual(
            {"mfa", "integrity", "mfa+integrity"},
            set(plan["id"] for plan in planner.pareto_front),
        )
        self.assertEqual("mfa+integrity", planner.best()["id"])
        self.assertEqual("mfa+integrity", planner.cheapest_compliant()["id"])

        # The cheaper mfa plan and the lower-scoring integrity plan are a genuine trade-off.
        self.assertTrue(
            all(
                not (
                    left["score"] <= right["score"]
                    and left["cost"] <= right["cost"]
                    and (left["score"], left["cost"]) != (right["score"], right["cost"])
                )
                for left in planner.pareto_front
                for right in planner.pareto_front
                if left is not right
            )
        )

    def test_combinations_are_scored_whole_not_by_single_deltas(self):
        planner = self.make_planner()
        cancellation = planner.evaluate(["crypto", "integrity"])

        self.assertEqual(9.3, cancellation["score"])
        self.assertEqual(0.7, cancellation["score_delta"])
        self.assertEqual(-0.7, cancellation["interaction"])
        self.assertIn("interaction", cancellation["rationale"].lower())
        self.assertFalse(cancellation["compliant"])

    def test_fixed_metrics_are_immutable(self):
        actions = [
            CVSS4Action("allowed", {"VI": "L"}, cost=1),
            CVSS4Action("vendor_scope", {"SC": "L"}, cost=1),
        ]
        planner = CVSS4Planner(
            BASE,
            actions,
            max_actions=2,
            fixed_metrics={"SC": "H", "SI": "H", "SA": "H"},
        )

        self.assertEqual(["vendor_scope"], [item["id"] for item in planner.rejected_actions])
        self.assertEqual(["allowed"], [plan["id"] for plan in planner.all_plans])

    def test_fixed_base_metric_blocks_modified_override(self):
        planner = CVSS4Planner(
            BASE,
            [CVSS4Action("override", {"MVC": "L"}, cost=1)],
            max_actions=1,
            fixed_metrics={"VC": "H"},
        )

        self.assertEqual([], list(planner.all_plans))
        self.assertEqual(["override"], [item["id"] for item in planner.rejected_actions])

    def test_mutual_exclusion_is_symmetric_and_reported(self):
        planner = CVSS4Planner(
            BASE,
            [
                CVSS4Action("a", {"VI": "L"}, cost=1),
                CVSS4Action("b", {"VA": "L"}, cost=1),
            ],
            max_actions=2,
            exclusions=[("a", "b")],
        )

        self.assertEqual(2, len(planner.all_plans))
        self.assertEqual(["a", "b"], planner.infeasible_combinations[0]["actions"])
        with self.assertRaises(CVSS4PlanningError):
            planner.evaluate(["b", "a"])

    def test_cost_is_exact_and_budget_is_enforced(self):
        planner = CVSS4Planner(
            BASE,
            [
                CVSS4Action("a", {"VI": "L"}, cost=0.75),
                CVSS4Action("b", {"PR": "H"}, cost=0.5),
            ],
            max_actions=2,
            cost_budget=1.0,
        )

        self.assertEqual(1.25, planner.evaluate(["a", "b"])["cost"])
        self.assertEqual({"a", "b"}, set(plan["id"] for plan in planner.pareto()))
        self.assertEqual(1, len(planner.infeasible_combinations))

    def test_standalone_and_cvss4_wrappers_match_planner(self):
        direct = self.make_planner()
        standalone = plan_cvss4_remediations(
            BASE,
            four_actions(),
            max_actions=2,
            fixed_metrics={"SC": "H", "SI": "H", "SA": "H"},
            release_threshold=9.0,
        )
        from_object = CVSS4(BASE).plan_remediations(
            four_actions(),
            max_actions=2,
            fixed_metrics={"SC": "H", "SI": "H", "SA": "H"},
            release_threshold=9.0,
        )

        self.assertEqual(
            [plan["id"] for plan in direct.pareto_front],
            [plan["id"] for plan in standalone],
        )
        self.assertEqual(
            [plan["id"] for plan in direct.pareto_front],
            [plan["id"] for plan in from_object],
        )

    def test_analyze_report_contains_recomputable_plans(self):
        report = self.make_planner().analyze()

        self.assertEqual(BASE, report["base_vector"])
        self.assertEqual(10.0, report["base_score"])
        for plan in report["plans"]:
            self.assertEqual(CVSS4(plan["vector"]).base_score, plan["score"])
            self.assertEqual((plan["score"], plan["cost"]), plan["objective_vector"])


if __name__ == "__main__":
    unittest.main()
