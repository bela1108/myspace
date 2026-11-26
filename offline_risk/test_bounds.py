#!/usr/bin/env python3
"""Sanity checks for the offline exposure accounting case."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

import bounds


class TestOfflineRiskCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = bounds.load_case(bounds.DEFAULT_CASE)
        cls.per, cls.glob, cls.assignments = bounds.compute_bounds(cls.case)

    def test_evidence_prunes_assignments(self):
        # 2**5 = 32 raw, E-1 removes 8, E-2 removes 8, overlap adds back 2.
        self.assertEqual(len(self.assignments), 18)

    def test_per_artifact_bounds(self):
        self.assertEqual(self.per["rel-alpha"], (2, 3))
        self.assertEqual(self.per["rel-beta"], (2, 4))
        self.assertEqual(self.per["rel-gamma"], (1, 4))
        self.assertEqual(self.per["rel-delta"], (1, 2))

    def test_global_bounds(self):
        self.assertEqual(self.glob, (10, 11))

    def test_sum_of_per_artifact_uppers_exceeds_global_upper(self):
        sum_hi = sum(hi for _, hi in self.per.values())
        self.assertEqual(sum_hi, 13)
        self.assertGreater(sum_hi, self.glob[1])

    def test_same_hash_models(self):
        # Same hash, two locations in one artifact -> one exposure.
        a = {"F-007": "rel-beta", "F-008": "rel-gamma", "F-009": "rel-delta",
             "F-010": "rel-gamma", "F-011": "rel-beta"}  # F-011 merges with F-007
        if not bounds.is_valid(self.case, a):
            self.skipTest("assignment pruned by evidence")
        hashes = bounds.artifact_hashes(self.case, a)
        self.assertEqual(len(hashes["rel-beta"]), 3)  # B1, A1, U1(merged)
        # Same hash in different artifacts -> independent exposures.
        self.assertIn("3f8c2e91a7b44d08f6c15e92ab07d3c6e54f1902", hashes["rel-alpha"])
        self.assertIn("3f8c2e91a7b44d08f6c15e92ab07d3c6e54f1902", hashes["rel-beta"])

    def test_best_question_is_f011(self):
        w0, questions = bounds.evaluate_questions(self.case)
        self.assertEqual(w0, 8)
        self.assertEqual(questions[0]["id"], "F-011")
        self.assertEqual(questions[0]["guaranteed_reduction"], 2)


if __name__ == "__main__":
    unittest.main()
