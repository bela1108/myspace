import json
import sys
import unittest
from decimal import Decimal as D
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import (
    CVSS2,
    CVSS3,
    CVSS4,
    DECISION_INDETERMINATE,
    DECISION_RELEASE,
    DECISION_STOP,
    CVSSContractError,
    ReleaseContract,
    evaluate_release,
    partition_releases,
)
from cvss.contract import (
    EVIDENCE_COMPLETE_VECTOR,
    EVIDENCE_DISPLAY_SCORE,
    EVIDENCE_DISPLAY_SCORE_ONLY,
    EVIDENCE_INSUFFICIENT,
    ROUNDING_CEILING,
    ROUNDING_FLOOR,
    ROUNDING_HALF_UP,
)

THRESHOLD = D("8.0")

NEAR_LINE_31 = [
    ("CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:L", 7.8, DECISION_RELEASE),
    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:L", 7.9, DECISION_RELEASE),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H", 8.0, DECISION_STOP),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 8.1, DECISION_STOP),
]


class TestReleaseContract(unittest.TestCase):
    def setUp(self):
        self.contract = ReleaseContract(threshold=THRESHOLD)

    def test_json_round_trip_preserves_adjacent_decisions(self):
        decisions = {}
        for vector, expected_score, expected_decision in NEAR_LINE_31:
            material = CVSS3(vector).as_json(minimal=True)
            self.assertEqual(expected_score, material["baseScore"])

            result = self.contract.evaluate(material)
            round_tripped_material = json.loads(json.dumps(material))
            round_tripped_result = self.contract.evaluate(round_tripped_material)

            self.assertEqual(result, round_tripped_result, vector)
            self.assertEqual(result, json.loads(json.dumps(result)), vector)
            self.assertEqual(expected_decision, result["decision"], vector)
            self.assertTrue(result["certain"], vector)
            self.assertEqual(expected_score, result["score"], vector)
            self.assertEqual("{0:.1f}".format(expected_score), result["display_score"])
            self.assertEqual(EVIDENCE_COMPLETE_VECTOR, result["evidence"])
            self.assertEqual(
                result["possible_range"]["minimum"], result["possible_range"]["maximum"]
            )
            decisions[expected_score] = result["decision"]

        self.assertEqual(DECISION_RELEASE, decisions[7.9])
        self.assertEqual(DECISION_STOP, decisions[8.0])

    def test_vector_is_authoritative_over_archived_display_score(self):
        vector, expected_score, expected_decision = NEAR_LINE_31[2]
        material = {"vectorString": vector, "baseScore": 7.9}
        result = self.contract.evaluate(material)

        self.assertEqual(expected_decision, result["decision"])
        self.assertEqual(expected_score, result["score"])
        self.assertFalse(result["score_matches_archived"])
        self.assertIn("archived display score does not match vector score", result["reasons"])

    def test_other_cvss_versions_use_the_same_exit_contract(self):
        cases = [
            ("AV:A/AC:L/Au:N/C:C/I:P/A:C", CVSS2, 8.0, DECISION_STOP, "2.0"),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H",
                CVSS4,
                7.9,
                DECISION_RELEASE,
                "4.0",
            ),
        ]
        for vector, cvss_class, expected_score, expected_decision, version in cases:
            material = cvss_class(vector).as_json(minimal=True)
            result = self.contract.evaluate(json.loads(json.dumps(material)))
            self.assertEqual(expected_score, result["score"])
            self.assertEqual(expected_decision, result["decision"])
            self.assertEqual(version, result["version"])
            self.assertEqual(EVIDENCE_COMPLETE_VECTOR, result["evidence"])

    def test_display_only_history_is_insufficient_evidence(self):
        history = {"baseScore": 8.0, "scorePrecision": 1}
        result = self.contract.evaluate(history)

        self.assertEqual(DECISION_INDETERMINATE, result["decision"])
        self.assertFalse(result["certain"])
        self.assertIsNone(result["should_stop"])
        self.assertEqual([DECISION_RELEASE, DECISION_STOP], result["possible_decisions"])
        self.assertEqual(EVIDENCE_DISPLAY_SCORE_ONLY, result["evidence"])
        self.assertFalse(result["complete_vector"])
        self.assertEqual(7.9, result["possible_range"]["minimum"])
        self.assertEqual(8.1, result["possible_range"]["maximum"])
        self.assertFalse(result["possible_range"]["minimum_inclusive"])
        self.assertFalse(result["possible_range"]["maximum_inclusive"])
        self.assertIn("complete vector is missing", result["reasons"])
        self.assertIn("rounding rule is missing", result["reasons"])

    def test_rounding_rule_changes_the_possible_range(self):
        half_up = self.contract.evaluate(
            {"baseScore": 8.0, "scorePrecision": 1, "rounding": ROUNDING_HALF_UP}
        )
        ceiling = self.contract.evaluate(
            {"baseScore": 8.0, "scorePrecision": 1, "rounding": ROUNDING_CEILING}
        )
        floor = self.contract.evaluate(
            {"baseScore": 8.0, "scorePrecision": 1, "rounding": ROUNDING_FLOOR}
        )

        self.assertEqual(EVIDENCE_DISPLAY_SCORE, half_up["evidence"])
        self.assertEqual(DECISION_INDETERMINATE, half_up["decision"])
        self.assertEqual(7.95, half_up["possible_range"]["minimum"])
        self.assertEqual(8.05, half_up["possible_range"]["maximum"])

        self.assertEqual(DECISION_INDETERMINATE, ceiling["decision"])
        self.assertEqual(7.9, ceiling["possible_range"]["minimum"])
        self.assertFalse(ceiling["possible_range"]["minimum_inclusive"])

        self.assertEqual(DECISION_STOP, floor["decision"])
        self.assertTrue(floor["certain"])
        self.assertEqual(8.0, floor["possible_range"]["minimum"])
        self.assertEqual(8.1, floor["possible_range"]["maximum"])

    def test_score_only_can_be_determinate_when_range_clears_the_line(self):
        result = self.contract.evaluate({"baseScore": 9.9, "scorePrecision": 1})

        self.assertEqual(DECISION_STOP, result["decision"])
        self.assertTrue(result["certain"])
        self.assertEqual(EVIDENCE_DISPLAY_SCORE_ONLY, result["evidence"])
        self.assertEqual(9.8, result["possible_range"]["minimum"])
        self.assertEqual(10.0, result["possible_range"]["maximum"])

    def test_incomplete_vector_falls_back_to_display_score(self):
        material = {
            "vectorString": "CVSS:3.1/AV:N/AC:L",
            "baseScore": 7.9,
            "scorePrecision": 1,
            "rounding": ROUNDING_HALF_UP,
        }
        result = self.contract.evaluate(material)

        self.assertEqual(DECISION_RELEASE, result["decision"])
        self.assertTrue(result["certain"])
        self.assertEqual(EVIDENCE_DISPLAY_SCORE, result["evidence"])
        self.assertFalse(result["complete_vector"])
        self.assertIn("incomplete or malformed vector", result["reasons"])

    def test_display_precision_is_retained(self):
        result = self.contract.evaluate(
            {
                "vectorString": NEAR_LINE_31[2][0],
                "baseScore": 8.0,
                "scorePrecision": 2,
            }
        )
        history = self.contract.evaluate({"baseScore": 8.0, "scorePrecision": 2})

        self.assertEqual("8.00", result["display_score"])
        self.assertEqual(2, result["precision"])
        self.assertEqual("8.00", history["display_score"])
        self.assertEqual(7.99, history["possible_range"]["minimum"])
        self.assertEqual(8.01, history["possible_range"]["maximum"])

    def test_full_vector_keeps_real_score_with_lower_history_precision(self):
        vector, expected_score, expected_decision = NEAR_LINE_31[1]
        result = self.contract.evaluate(
            {"vectorString": vector, "baseScore": 8.0, "scorePrecision": 0}
        )

        self.assertEqual(expected_decision, result["decision"])
        self.assertEqual(expected_score, result["score"])
        self.assertEqual("8", result["display_score"])
        self.assertTrue(result["score_matches_archived"])

    def test_none_rounding_is_treated_as_missing(self):
        result = self.contract.evaluate({"baseScore": 8.0, "rounding": "none"})

        self.assertEqual(DECISION_INDETERMINATE, result["decision"])
        self.assertEqual(EVIDENCE_DISPLAY_SCORE_ONLY, result["evidence"])
        self.assertIn("rounding rule is missing", result["reasons"])

    def test_numeric_string_and_reusable_contract_inputs(self):
        score_only = evaluate_release("9.9", self.contract)
        set_aside = partition_releases(
            [NEAR_LINE_31[1][0], {"baseScore": 8.0, "scorePrecision": 1}],
            self.contract,
        )

        self.assertEqual(DECISION_STOP, score_only["decision"])
        self.assertTrue(score_only["certain"])
        self.assertEqual(1, len(set_aside["determinate"]))
        self.assertEqual(1, len(set_aside["indeterminate"]))

    def test_missing_evidence_is_reported_without_a_range(self):
        for material in ({}, None):
            result = self.contract.evaluate(material)
            self.assertEqual(DECISION_INDETERMINATE, result["decision"])
            self.assertEqual(EVIDENCE_INSUFFICIENT, result["evidence"])
            self.assertIsNone(result["possible_range"])
            self.assertEqual([], result["possible_decisions"])
            self.assertIn("display score is missing", result["reasons"])

    def test_strict_operator_near_the_line(self):
        contract = ReleaseContract(threshold=THRESHOLD, operator=">")
        at_threshold = contract.evaluate({"baseScore": 8.0, "rounding": "exact"})
        above_threshold = contract.evaluate({"baseScore": 8.1, "rounding": "exact"})

        self.assertEqual(DECISION_RELEASE, at_threshold["decision"])
        self.assertEqual(DECISION_STOP, above_threshold["decision"])

    def test_partition_separates_supported_materials(self):
        materials = [CVSS3(vector).as_json(minimal=True) for vector, _, _ in NEAR_LINE_31]
        materials.append({"baseScore": 8.0, "scorePrecision": 1})

        result = self.contract.partition(materials)

        self.assertEqual(4, len(result["determinate"]))
        self.assertEqual(1, len(result["indeterminate"]))
        self.assertEqual([0, 1, 2, 3], [item["index"] for item in result["determinate"]])
        self.assertEqual([4], [item["index"] for item in result["indeterminate"]])

    def test_invalid_contract_configuration_is_rejected(self):
        self.assertRaises(CVSSContractError, ReleaseContract, threshold=-0.1)
        self.assertRaises(CVSSContractError, ReleaseContract, threshold=10.1)
        self.assertRaises(CVSSContractError, ReleaseContract, threshold="bad")
        self.assertRaises(
            CVSSContractError, ReleaseContract, threshold=THRESHOLD, rounding="mystery"
        )
        self.assertRaises(CVSSContractError, ReleaseContract, threshold=THRESHOLD, operator="below")


if __name__ == "__main__":
    unittest.main()
