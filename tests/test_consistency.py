# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_consistency.py

<Purpose>
  Test the post-verification ordering consistency check against
  exhaustive permutation on samples of at most six steps, including a
  pair of steps that each read the other's old value: every link is
  well signed and every digest well formed, yet no single execution
  order explains them.
"""

import unittest

from in_toto.consistency import (
    ReplayError,
    brute_force_orders,
    check_consistency,
    find_orders,
    format_report,
    load_problem,
    replay,
)

# Three parallel build steps read the same release history "rel";
# the release step bumps it, so it must run last.
PARALLEL_RELEASE_SPEC = {
    "initial": {"rel": "r0", "a": "a0", "b": "b0", "c": "c0"},
    "steps": [
        {
            "name": "build-a",
            "materials": {"rel": "r0", "a": "a0"},
            "products": {"a": "a1"},
        },
        {
            "name": "build-b",
            "materials": {"rel": "r0", "b": "b0"},
            "products": {"b": "b1"},
        },
        {
            "name": "release",
            "materials": {"rel": "r0", "c": "c0"},
            "products": {"c": "c1", "rel": "r1"},
        },
    ],
    "constraints": [],
    "final": {"rel": "r1", "a": "a1", "b": "b1", "c": "c1"},
}

# A path may return to an older digest; only step boundaries matter.
REVERT_SPEC = {
    "initial": {"p": "p0", "q": "q0"},
    "steps": [
        {
            "name": "mutate",
            "materials": {"p": "p0"},
            "products": {"p": "p1"},
        },
        {
            "name": "revert",
            "materials": {"p": "p1"},
            "products": {"p": "p0", "q": "q1"},
        },
    ],
    "constraints": [],
    "final": {"p": "p0", "q": "q1"},
}

# Two steps each read the other's old value.  Both links verify: the
# signatures are genuine and the recorded digests are well formed
# in-toto hash dicts.  No sequential order can satisfy both.
SWAP_SPEC = {
    "initial": {
        "x": {"sha256": "x0"},
        "y": {"sha256": "y0"},
    },
    "steps": [
        {
            "name": "step-a",
            "materials": {"y": {"sha256": "y0"}},
            "products": {"x": {"sha256": "x1"}},
        },
        {
            "name": "step-b",
            "materials": {"x": {"sha256": "x0"}},
            "products": {"y": {"sha256": "y1"}},
        },
    ],
    "constraints": [],
    "final": {
        "x": {"sha256": "x1"},
        "y": {"sha256": "y1"},
    },
}

# Six steps: the parallel trio, a revert, and the mutual-old-value
# pair, tied by known ordering constraints.  Unsatisfiable as a whole.
SIX_STEP_SPEC = {
    "initial": {
        "rel": "r0",
        "a": "a0",
        "b": "b0",
        "x": "x0",
        "y": "y0",
        "doc": "d0",
    },
    "steps": [
        {
            "name": "build-a",
            "materials": {"rel": "r0", "a": "a0"},
            "products": {"a": "a1"},
        },
        {
            "name": "build-b",
            "materials": {"rel": "r0", "b": "b0"},
            "products": {"b": "b1", "rel": "r1"},
        },
        {
            "name": "revert-a",
            "materials": {"a": "a1"},
            "products": {"a": "a0"},
        },
        {
            "name": "swap-x",
            "materials": {"y": "y0"},
            "products": {"x": "x1"},
        },
        {
            "name": "swap-y",
            "materials": {"x": "x0"},
            "products": {"y": "y1"},
        },
        {
            "name": "docs",
            "materials": {"rel": "r1", "doc": "d0"},
            "products": {"doc": "d1"},
        },
    ],
    "constraints": [["build-a", "revert-a"], ["build-b", "docs"]],
    "final": {
        "rel": "r1",
        "a": "a0",
        "b": "b1",
        "x": "x1",
        "y": "y1",
        "doc": "d1",
    },
}


class TestCheckConsistency(unittest.TestCase):
    """Test the satisfiable cases of check_consistency."""

    def test_parallel_release_has_multiple_orders(self):
        """The release step must be last; the two builds may swap."""
        result = check_consistency(PARALLEL_RELEASE_SPEC)
        self.assertTrue(result.satisfiable)
        self.assertTrue(result.multiple)
        self.assertEqual(
            sorted(result.orders),
            [
                ["build-a", "build-b", "release"],
                ["build-b", "build-a", "release"],
            ],
        )
        problem = load_problem(PARALLEL_RELEASE_SPEC)
        for order in result.orders:
            state = replay(problem, order)
            self.assertEqual(state, problem.final)

    def test_revert_to_old_digest(self):
        """A path may return to an older digest; order stays unique."""
        result = check_consistency(REVERT_SPEC)
        self.assertTrue(result.satisfiable)
        self.assertFalse(result.multiple)
        self.assertEqual(result.orders, [["mutate", "revert"]])

    def test_constraint_can_eliminate_every_order(self):
        """A known ordering constraint can make a layout unsat."""
        spec = dict(PARALLEL_RELEASE_SPEC, constraints=[["release", "build-a"]])
        result = check_consistency(spec)
        self.assertFalse(result.satisfiable)
        text = format_report(load_problem(spec), result.report)
        self.assertIn("waits for release", text)


class TestUnsatReports(unittest.TestCase):
    """Test the replayable explanations for unsatisfiable layouts."""

    def test_mutual_old_value_pair_is_unsat(self):
        """Each step reads the other's old value: no order exists."""
        result = check_consistency(SWAP_SPEC)
        self.assertFalse(result.satisfiable)
        self.assertEqual(result.orders, [])
        dead_ends = {
            tuple(entry.prefix): entry
            for entry in result.report
            if not entry.next_steps
        }
        self.assertEqual(set(dead_ends), {("step-a",), ("step-b",)})
        blocker = dead_ends[("step-a",)].blockers[0]
        self.assertEqual(blocker.step, "step-b")
        path, expected, actual = blocker.failing_materials[0]
        self.assertEqual(path, "x")
        self.assertEqual(expected, (("sha256", "x0"),))
        self.assertEqual(actual, (("sha256", "x1"),))
        blocker = dead_ends[("step-b",)].blockers[0]
        self.assertEqual(blocker.step, "step-a")
        self.assertEqual(blocker.failing_materials[0][0], "y")

    def test_final_summary_mismatch_is_reported(self):
        """All steps run, yet the final summary disagrees."""
        spec = dict(REVERT_SPEC, final={"p": "p0", "q": "q2"})
        problem = load_problem(spec)
        result = check_consistency(problem)
        self.assertFalse(result.satisfiable)
        complete = [
            entry
            for entry in result.report
            if len(entry.prefix) == len(problem.steps)
        ]
        self.assertEqual(len(complete), 1)
        self.assertEqual(complete[0].prefix, ["mutate", "revert"])
        path, expected, actual = complete[0].final_mismatches[0]
        self.assertEqual((path, expected, actual), ("q", "q2", "q1"))

    def test_every_reported_prefix_replays(self):
        """Each prefix in the six-step report replays; blockers bite."""
        problem = load_problem(SIX_STEP_SPEC)
        result = check_consistency(problem)
        self.assertFalse(result.satisfiable)
        all_names = {step.name for step in problem.steps}
        for entry in result.report:
            replay(problem, entry.prefix)
            blocked = {b.step for b in entry.blockers}
            remaining = all_names - set(entry.prefix)
            self.assertEqual(remaining, blocked | set(entry.next_steps))
            for blocker in entry.blockers:
                if not blocker.failing_materials:
                    continue
                with self.assertRaises(ReplayError) as ctx:
                    replay(problem, entry.prefix + [blocker.step])
                for path, _, _ in blocker.failing_materials:
                    self.assertIn(path, str(ctx.exception))
            for name in entry.next_steps:
                replay(problem, entry.prefix + [name])
        text = format_report(problem, result.report)
        self.assertIn("stuck", text)
        self.assertIn("swap-y: material x expected x0, found x1", text)


class TestBruteForceCrossCheck(unittest.TestCase):
    """Cross-check the solver against full permutation enumeration."""

    def test_solver_matches_brute_force(self):
        """find_orders(limit=None) equals brute_force_orders."""
        specs = [
            PARALLEL_RELEASE_SPEC,
            REVERT_SPEC,
            SWAP_SPEC,
            SIX_STEP_SPEC,
        ]
        for spec in specs:
            problem = load_problem(spec)
            with self.subTest(spec=spec["steps"][0]["name"]):
                self.assertEqual(
                    sorted(map(tuple, find_orders(problem, limit=None))),
                    sorted(map(tuple, brute_force_orders(problem))),
                )

    def test_six_step_sample_has_no_valid_permutation(self):
        """The six-step sample is unsat under all 720 permutations."""
        problem = load_problem(SIX_STEP_SPEC)
        self.assertEqual(brute_force_orders(problem), [])
        self.assertEqual(find_orders(problem, limit=None), [])

    def test_invalid_specs_are_rejected(self):
        """Unknown constraint endpoints and duplicate names raise."""
        with self.assertRaises(ValueError):
            load_problem(dict(SWAP_SPEC, constraints=[["step-a", "nobody"]]))
        with self.assertRaises(ValueError):
            load_problem(dict(REVERT_SPEC, steps=[REVERT_SPEC["steps"][0]] * 2))


if __name__ == "__main__":
    unittest.main()
