import json
import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.inquiry import (
    InquiryError,
    InquiryQuestion,
    enumerate_scenarios,
    plan_inquiries,
)

HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
HIGH_2 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
LOW = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
LOW_2 = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"


def scenario_map(vectors):
    return dict(("s{0}".format(index), vector) for index, vector in enumerate(vectors, 1))


def brute_force_best(scenarios, questions, budget):
    """
    Independent exhaustive policy search used to check the planner.

    This deliberately has no memoization or pruning.  It enumerates every
    affordable first question at every reachable subset and returns the
    lexicographic worst-branch optimum (unresolved mass, inquiry cost).
    """
    by_id = scenarios

    def partition(question, state):
        groups = {}
        for scenario_id in sorted(state):
            for label, members in question["partition"].items():
                if scenario_id in members:
                    groups.setdefault(label, set()).add(scenario_id)
                    break
        return groups

    def visit(state, remaining, spent):
        outcomes = {by_id[scenario_id]["outcome"] for scenario_id in state}
        if len(outcomes) <= 1:
            return (0, spent)

        best = None
        for question in questions:
            if question["cost"] > remaining:
                continue
            groups = partition(question, state)
            if len(groups) < 2:
                continue
            children = [
                visit(group, remaining - question["cost"], spent + question["cost"])
                for group in groups.values()
            ]
            candidate = (
                max(child[0] for child in children),
                max(child[1] for child in children),
            )
            if best is None or candidate < best:
                best = candidate

        if best is not None:
            return best
        return (len(state), spent)

    return visit(set(by_id), budget, 0)


class TestInquiryPlanning(unittest.TestCase):
    def setUp(self):
        self.scenarios = {
            "s1": HIGH,
            "s2": LOW,
            "s3": HIGH_2,
            "s4": LOW_2,
        }

    def test_minimax_does_not_let_average_hide_worst_branch(self):
        # s1/s2 are hold, s3/s4 are normal; the cheap split is 3/1.
        scenarios = {"s1": HIGH, "s2": HIGH_2, "s3": LOW, "s4": LOW_2}
        questions = [
            # Cheap and good on average: spend 1, then 3/4 of scenarios need
            # another 10.  Expected cost is 8.5, but the worst path is 11.
            InquiryQuestion(
                "q_cheap_imbalanced",
                "cheap 3/1 split",
                1,
                answers={"mixed": ["s1", "s2", "s3"], "s4": ["s4"]},
            ),
            InquiryQuestion(
                "q_finish_big",
                "finish the mixed branch",
                10,
                answers={"hold": ["s1", "s2"], "normal": ["s3"]},
            ),
            # Expensive but balanced, and decisive on every path.
            InquiryQuestion(
                "q_balanced",
                "balanced 2/2 split",
                9,
                answers={"hold": ["s1", "s2"], "normal": ["s3", "s4"]},
            ),
        ]

        # Budget 11 leaves both complete strategies affordable.  The cheap
        # strategy has expected cost 8.5 but worst cost 11; minimax picks the
        # balanced strategy with worst cost 9.
        plan = plan_inquiries(scenarios, questions, 7.0, budget=11)

        self.assertEqual("q_balanced", plan.first_question.id)
        self.assertTrue(plan.complete)
        self.assertEqual(9, plan.worst_case_cost)

    def test_budget_exhaustion_reports_remaining_disagreement(self):
        questions = [
            InquiryQuestion(
                "q_half",
                "split into two mixed halves",
                4,
                answers={"a": ["s1", "s2"], "b": ["s3", "s4"]},
            ),
            InquiryQuestion(
                "q_cross",
                "cross the halves",
                5,
                answers={"a": ["s1", "s4"], "b": ["s2", "s3"]},
            ),
        ]

        plan = plan_inquiries(self.scenarios, questions, 7.0, budget=4)
        data = plan.as_dict()

        self.assertFalse(plan.complete)
        self.assertEqual(4, plan.worst_case_cost)
        self.assertEqual(2, plan.worst_unresolved_mass)
        self.assertEqual(2, len(data["unresolved_disagreements"]))

        for leaf in plan.leaves():
            self.assertTrue(leaf["unresolved"])
            self.assertEqual(4, leaf["worst_cost"])
            self.assertEqual({"hold": 1, "normal": 1}, dict(leaf["outcomes"]))
            self.assertEqual("budget_exhausted", leaf["missing"]["reason"])
            self.assertEqual(5, leaf["missing"]["minimum_extra_budget"])
            self.assertEqual(5, leaf["missing"]["missing_budget"])
            self.assertIn("AV", leaf["missing"]["remaining_metrics"])
            self.assertEqual("q_cross", leaf["missing"]["candidate_questions"][0]["question_id"])
            self.assertFalse(leaf["missing"]["candidate_questions"][0]["affordable"])

    def test_budget_shortfall_can_be_partial(self):
        questions = [
            InquiryQuestion(
                "q_half",
                "split into two mixed halves",
                4,
                answers={"a": ["s1", "s2"], "b": ["s3", "s4"]},
            ),
            InquiryQuestion(
                "q_cross",
                "cross the halves",
                5,
                answers={"a": ["s1", "s4"], "b": ["s2", "s3"]},
            ),
        ]

        plan = plan_inquiries(self.scenarios, questions, 7.0, budget=7)

        self.assertFalse(plan.complete)
        for leaf in plan.leaves():
            self.assertEqual(5, leaf["missing"]["minimum_extra_budget"])
            self.assertEqual(2, leaf["missing"]["missing_budget"])

    def test_metric_questions_and_enumeration(self):
        scenarios = enumerate_scenarios(
            fixed_metrics={
                "AC": "L",
                "UI": "N",
                "S": "U",
                "C": "H",
                "I": "H",
                "A": "H",
            },
            uncertain_metrics={"AV": ["N", "L"], "PR": ["N", "H"]},
            version="3.1",
        )
        self.assertEqual(4, len(scenarios))
        self.assertIn("AV:N", scenarios["s1"])
        self.assertIn("PR:H", scenarios["s2"])

        questions = [
            InquiryQuestion.from_metric(
                "ask_av",
                "Ask the vendor about attack vector",
                1,
                "AV",
                {"network": ["N"], "local": ["L"]},
            ),
            InquiryQuestion.from_metric(
                "ask_pr",
                "Ask the maintainer about privileges",
                2,
                "PR",
                {"none": ["N"], "privileged": ["H"]},
            ),
        ]
        plan = plan_inquiries(scenarios, questions, 7.0)

        self.assertTrue(plan.complete)
        self.assertEqual("ask_av", plan.first_question.id)
        self.assertEqual(3, plan.worst_case_cost)
        json.dumps(plan.as_dict())

    def test_cvss4_enumeration_and_severity_threshold(self):
        fixed = {
            "AC": "L",
            "AT": "N",
            "PR": "N",
            "UI": "N",
            "VC": "H",
            "VI": "H",
            "VA": "H",
            "SC": "H",
            "SI": "H",
            "SA": "N",
        }
        scenarios = enumerate_scenarios(
            fixed_metrics=fixed,
            uncertain_metrics={"AV": ["N", "P"]},
            version="4.0",
        )
        self.assertEqual(2, len(scenarios))
        question = InquiryQuestion.from_metric(
            "ask_av", "Ask about attack vector", 1, "AV", {"n": ["N"], "p": ["P"]}
        )
        plan = plan_inquiries(scenarios, question, "High")
        self.assertTrue(plan.complete)

    def test_invalid_metric_question_is_rejected(self):
        question = InquiryQuestion.from_metric(
            "ask_av", "incomplete answer map", 1, "AV", {"network": ["N"]}
        )
        with self.assertRaises(InquiryError):
            plan_inquiries(self.scenarios, [question], 7.0)

    def test_exhaustive_small_vectors_are_optimal(self):
        vectors = [HIGH, LOW, HIGH_2, LOW_2, HIGH, LOW]

        for case in range(12):
            scenarios = scenario_map(vectors[:5])
            # Give each scenario a deterministic but non-trivial outcome.
            for index, scenario_id in enumerate(sorted(scenarios), 1):
                if index % 2:
                    scenarios[scenario_id] = HIGH if index < 4 else HIGH_2
                else:
                    scenarios[scenario_id] = LOW if index < 4 else LOW_2

            questions = []
            question_specs = []
            for question_index in range(3):
                labels = ["a", "b", "c"][: 2 + (question_index % 2)]
                assignment = {}
                for offset, scenario_id in enumerate(sorted(scenarios)):
                    assignment[scenario_id] = labels[(offset + case + question_index) % len(labels)]
                if len(set(assignment.values())) < 2:
                    assignment[sorted(scenarios)[0]] = labels[0]
                    assignment[sorted(scenarios)[1]] = labels[1]
                partition = {}
                for scenario_id, label in assignment.items():
                    partition.setdefault(label, []).append(scenario_id)
                cost = (case + question_index) % 4
                question_specs.append({"cost": cost, "partition": partition})
                questions.append(
                    InquiryQuestion(
                        "q{0}".format(question_index),
                        "random split",
                        cost,
                        answers=partition,
                    )
                )

            # The brute-force helper needs the realised outcomes, not vectors.
            scored = plan_inquiries(scenarios, questions, 7.0).as_dict()
            outcome_by_id = dict(
                (item["id"], item["outcome"]) for item in scored["audit"]["scenarios"]
            )
            brute_input = {
                scenario_id: {
                    "outcome": outcome_by_id[scenario_id],
                }
                for scenario_id in scenarios
            }

            for budget in [0, 1, 2, 3, 4, 5, 6, 7, 8, None]:
                plan = plan_inquiries(scenarios, questions, 7.0, budget=budget)
                expected = brute_force_best(
                    brute_input, question_specs, budget if budget is not None else 10**9
                )
                with self.subTest(case=case, budget=budget):
                    self.assertEqual(expected[0], plan.worst_unresolved_mass)
                    self.assertEqual(expected[1], plan.worst_case_cost)


if __name__ == "__main__":
    unittest.main()
