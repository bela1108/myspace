import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.offline_review import (
    CONSISTENT,
    INSUFFICIENT_EVIDENCE,
    POSSIBLE_TIE,
    check_ranking_consistency,
)


VECTORS = {
    "R1": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "R2": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "R3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

TIE_RULES = {
    "3.1": {"allow_ties": True, "score_index": 0, "tolerance": 0.0},
}


class TestOfflineReview(unittest.TestCase):
    def test_explicit_equal_score_tie(self):
        verdict = check_ranking_consistency(
            {"team": [["R1", "R2"], "R3"], "supplier": [["R1", "R2"], "R3"]},
            VECTORS,
            TIE_RULES,
        )
        self.assertEqual(CONSISTENT, verdict)

    def test_equal_scores_disclosed_as_order_are_possible_tie(self):
        verdict = check_ranking_consistency(
            {"team": ["R1", "R2", "R3"], "supplier": ["R2", "R1", "R3"]},
            VECTORS,
            TIE_RULES,
        )
        self.assertEqual(POSSIBLE_TIE, verdict)

    def test_real_score_order_conflict(self):
        verdict = check_ranking_consistency(
            {"team": ["R3", "R1", "R2"], "supplier": ["R1", "R2", "R3"]},
            VECTORS,
            TIE_RULES,
        )
        self.assertEqual(INSUFFICIENT_EVIDENCE, verdict)

    def test_result_does_not_contain_vector_or_score(self):
        verdict = check_ranking_consistency(
            {"team": ["R3", "R1", "R2"]},
            VECTORS,
            TIE_RULES,
        )
        self.assertNotIn("CVSS", verdict)
        self.assertNotIn("9.8", verdict)


if __name__ == "__main__":
    unittest.main()
