import json
import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import CVSS3, CVSS4
from cvss.joint_risk import (
    JointCompatibility,
    JointRiskError,
    PolicyValidationError,
    StopShipPolicy,
    VectorDomainError,
    find_recomputable_disagreement,
    verify_reverse_loading,
)


V_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
V_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"  # 5.3
V_NONE = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # 0.0
V_V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"  # 9.9

SMALL_DOMAIN = [V_CRITICAL, V_MEDIUM, V_NONE, V_V4]


class TestStopShipPolicy(unittest.TestCase):
    def test_threshold_validation(self):
        with self.assertRaises(PolicyValidationError):
            StopShipPolicy("alpha", 10.1, "label-a")
        with self.assertRaises(PolicyValidationError):
            StopShipPolicy("alpha", -0.1, "label-a")
        with self.assertRaises(PolicyValidationError):
            StopShipPolicy("alpha", "high", "label-a")
        with self.assertRaises(PolicyValidationError):
            StopShipPolicy("  ", 7.0, "label-a")
        with self.assertRaises(PolicyValidationError):
            StopShipPolicy("alpha", 7.0, "  ")

    def test_decide_uses_threshold_inclusive(self):
        policy = StopShipPolicy("alpha", 5.3, "label-a")
        self.assertEqual(policy.decide(5.3), "stop_ship")
        self.assertEqual(policy.decide(5.2), "keep_shipping")
        self.assertEqual(policy.decide(9.8), "stop_ship")


class TestVectorDomain(unittest.TestCase):
    def test_empty_domain_rejected(self):
        alpha = StopShipPolicy("alpha", 7.0, "label-a")
        beta = StopShipPolicy("beta", 4.0, "label-b")
        with self.assertRaises(VectorDomainError):
            JointCompatibility(alpha, beta, [])

    def test_duplicate_vector_rejected(self):
        alpha = StopShipPolicy("alpha", 7.0, "label-a")
        beta = StopShipPolicy("beta", 4.0, "label-b")
        with self.assertRaises(VectorDomainError):
            JointCompatibility(alpha, beta, [V_MEDIUM, V_MEDIUM])

    def test_malformed_vector_rejected(self):
        alpha = StopShipPolicy("alpha", 7.0, "label-a")
        beta = StopShipPolicy("beta", 4.0, "label-b")
        with self.assertRaises(VectorDomainError):
            JointCompatibility(alpha, beta, ["CVSS:3.1/AV:N/AC:L"])

    def test_unsupported_version_rejected(self):
        alpha = StopShipPolicy("alpha", 7.0, "label-a")
        beta = StopShipPolicy("beta", 4.0, "label-b")
        v2_vector = "AV:L/AC:L/Au:M/C:N/I:P/A:C"
        with self.assertRaises(VectorDomainError):
            JointCompatibility(alpha, beta, [v2_vector])

    def test_duplicate_team_rejected(self):
        alpha = StopShipPolicy("alpha", 7.0, "label-a")
        alpha_again = StopShipPolicy("alpha", 4.0, "label-b")
        with self.assertRaises(PolicyValidationError):
            JointCompatibility(alpha, alpha_again, SMALL_DOMAIN)

    def test_non_policy_rejected(self):
        beta = StopShipPolicy("beta", 4.0, "label-b")
        with self.assertRaises(PolicyValidationError):
            JointCompatibility("alpha", beta, SMALL_DOMAIN)


class TestCompatibilityGrid(unittest.TestCase):
    def setUp(self):
        # Team alpha stops at 7.0, team beta already stops at 4.0.
        self.alpha = StopShipPolicy("alpha", 7.0, "LIABILITY-ALPHA-INTERNAL")
        self.beta = StopShipPolicy("beta", 4.0, "LIABILITY-BETA-INTERNAL")
        self.grid = JointCompatibility(self.alpha, self.beta, SMALL_DOMAIN)

    def test_scores_are_recomputed_by_real_implementation(self):
        self.assertEqual(self.grid.cells[V_CRITICAL].score, float(CVSS3(V_CRITICAL).base_score))
        self.assertEqual(self.grid.cells[V_MEDIUM].score, float(CVSS3(V_MEDIUM).base_score))
        self.assertEqual(self.grid.cells[V_NONE].score, float(CVSS3(V_NONE).base_score))
        self.assertEqual(self.grid.cells[V_V4].score, float(CVSS4(V_V4).base_score))

    def test_joint_cells_and_disagreement_cell(self):
        critical = self.grid.cells[V_CRITICAL]
        medium = self.grid.cells[V_MEDIUM]
        none_cell = self.grid.cells[V_NONE]
        v4_cell = self.grid.cells[V_V4]

        self.assertTrue(critical.joint)
        self.assertEqual(critical.joint_action, "stop_ship")
        self.assertTrue(v4_cell.joint)
        self.assertEqual(v4_cell.joint_action, "stop_ship")
        self.assertTrue(none_cell.joint)
        self.assertEqual(none_cell.joint_action, "keep_shipping")

        # 5.3: alpha keeps shipping (below 7.0), beta stops (>= 4.0)
        self.assertFalse(medium.joint)
        self.assertEqual(medium.status, "no_consensus")
        self.assertEqual(medium.decisions["alpha"], "keep_shipping")
        self.assertEqual(medium.decisions["beta"], "stop_ship")

        self.assertEqual(len(self.grid.joint_commitments()), 3)
        self.assertEqual(len(self.grid.disagreements()), 1)

    def test_individual_scopes_are_retained_on_disagreement(self):
        alpha_scope = self.grid.team_scope("alpha")
        beta_scope = self.grid.team_scope("beta")
        self.assertEqual(alpha_scope[V_MEDIUM], "keep_shipping")
        self.assertEqual(beta_scope[V_MEDIUM], "stop_ship")
        # Both scopes cover the whole agreed domain, not just joint cells.
        self.assertEqual(set(alpha_scope), set(SMALL_DOMAIN))
        self.assertEqual(set(beta_scope), set(SMALL_DOMAIN))

    def test_unknown_team_scope_raises(self):
        with self.assertRaises(JointRiskError):
            self.grid.team_scope("gamma")


class TestCustomerRedaction(unittest.TestCase):
    def setUp(self):
        self.alpha = StopShipPolicy("alpha", 7.0, "LIABILITY-ALPHA-INTERNAL")
        self.beta = StopShipPolicy("beta", 4.0, "LIABILITY-BETA-INTERNAL")
        self.grid = JointCompatibility(self.alpha, self.beta, SMALL_DOMAIN)

    def test_customer_statement_hides_labels_and_attribution(self):
        statement = self.grid.customer_statement()
        serialized = json.dumps(statement)
        self.assertNotIn("LIABILITY-ALPHA-INTERNAL", serialized)
        self.assertNotIn("LIABILITY-BETA-INTERNAL", serialized)
        self.assertNotIn("alpha", serialized)
        self.assertNotIn("beta", serialized)
        self.assertNotIn("team_decisions", serialized)
        self.assertEqual(statement["joint_commitment_count"], 3)
        self.assertEqual(statement["missing_joint_evidence_count"], 1)

        medium_view = next(cell for cell in statement["cells"] if cell["vector"] == V_MEDIUM)
        self.assertEqual(medium_view["status"], "no_consensus")
        self.assertIsNone(medium_view["joint_action"])
        self.assertIn("note", medium_view)

        critical_view = next(cell for cell in statement["cells"] if cell["vector"] == V_CRITICAL)
        self.assertEqual(critical_view["status"], "joint_commitment")
        self.assertEqual(critical_view["joint_action"], "stop_ship")

    def test_internal_report_keeps_labels_and_scopes(self):
        report = self.grid.internal_report()
        serialized = json.dumps(report)
        self.assertIn("LIABILITY-ALPHA-INTERNAL", serialized)
        self.assertIn("LIABILITY-BETA-INTERNAL", serialized)
        medium = next(cell for cell in report["cells"] if cell["vector"] == V_MEDIUM)
        self.assertEqual(medium["team_decisions"]["alpha"], "keep_shipping")
        self.assertEqual(medium["team_decisions"]["beta"], "stop_ship")


class TestAuditTrail(unittest.TestCase):
    def setUp(self):
        self.alpha = StopShipPolicy("alpha", 7.0, "LIABILITY-ALPHA-INTERNAL")
        self.beta = StopShipPolicy("beta", 4.0, "LIABILITY-BETA-INTERNAL")
        self.grid = JointCompatibility(self.alpha, self.beta, SMALL_DOMAIN)

    def test_disagreement_is_recomputable(self):
        evidence = find_recomputable_disagreement(self.grid)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["vector"], V_MEDIUM)
        self.assertEqual(evidence["recomputed_base_score"], 5.3)
        self.assertEqual(evidence["thresholds"]["alpha"], 7.0)
        self.assertEqual(evidence["thresholds"]["beta"], 4.0)
        self.assertEqual(evidence["team_actions"]["alpha"], "keep_shipping")
        self.assertEqual(evidence["team_actions"]["beta"], "stop_ship")

        # The auditor can reproduce the disagreement from scratch.
        reproduced = float(CVSS3(V_MEDIUM).base_score)
        self.assertEqual(reproduced, evidence["recomputed_base_score"])
        self.assertEqual(self.alpha.decide(reproduced), evidence["team_actions"]["alpha"])
        self.assertEqual(self.beta.decide(reproduced), evidence["team_actions"]["beta"])

    def test_no_disagreement_returns_none(self):
        same_one = StopShipPolicy("alpha", 7.0, "label-a")
        same_two = StopShipPolicy("beta", 7.0, "label-b")
        aligned = JointCompatibility(same_one, same_two, SMALL_DOMAIN)
        self.assertIsNone(find_recomputable_disagreement(aligned))

    def test_reverse_loading_keeps_scope_identical(self):
        result = verify_reverse_loading(self.alpha, self.beta, SMALL_DOMAIN)
        self.assertTrue(result["order_independent"])
        self.assertTrue(result["scope_unchanged"])
        self.assertEqual(result["forward_signature"], result["reverse_signature"])

        reverse_grid = JointCompatibility(self.beta, self.alpha, SMALL_DOMAIN)
        self.assertEqual(
            [cell.vector for cell in self.grid.cells.values()],
            [cell.vector for cell in reverse_grid.cells.values()],
        )
        self.assertEqual(
            [cell.status for cell in self.grid.cells.values()],
            [cell.status for cell in reverse_grid.cells.values()],
        )
        for vector in SMALL_DOMAIN:
            forward_cell = self.grid.cells[vector]
            reverse_cell = reverse_grid.cells[vector]
            self.assertEqual(forward_cell.score, reverse_cell.score)
            self.assertEqual(
                set(forward_cell.decisions.values()), set(reverse_cell.decisions.values())
            )

        # Joint scope did not widen: same number of commitments either way.
        self.assertEqual(
            len(self.grid.joint_commitments()), len(reverse_grid.joint_commitments())
        )
        self.assertEqual(
            self.grid.customer_statement(), reverse_grid.customer_statement()
        )


if __name__ == "__main__":
    unittest.main()
