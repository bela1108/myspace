import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.review import (
    TRUST_CONFIRMED,
    TRUST_UNVERIFIED,
    TRUST_UPSTREAM_DEFAULT,
    ReviewPolicy,
    review_vector,
)

VECTOR_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
BASE_31 = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

VECTOR_40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
BASE_40 = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def confirmed_provenance(metrics):
    return dict((metric, TRUST_CONFIRMED) for metric in metrics)


class TestReviewCVSS3(unittest.TestCase):
    def test_confirmed_metrics_are_publishable(self):
        report = review_vector(VECTOR_31, confirmed_provenance(BASE_31))
        self.assertTrue(report.publishable)
        self.assertEqual(report.decision, "publish")
        self.assertEqual(report.missing_evidence, [])
        self.assertEqual(report.scores()[0], 9.8)
        self.assertEqual(report.version, "3.1")

    def test_upstream_default_metric_holds_publication(self):
        provenance = confirmed_provenance(BASE_31)
        provenance["AC"] = TRUST_UPSTREAM_DEFAULT
        report = review_vector(VECTOR_31, provenance)
        self.assertFalse(report.publishable)
        self.assertEqual(report.decision, "hold")
        self.assertEqual([m.abbreviation for m in report.missing_evidence], ["AC"])
        missing = report.missing_evidence[0]
        self.assertEqual(missing.trust, TRUST_UPSTREAM_DEFAULT)
        self.assertEqual(missing.required_trust, TRUST_CONFIRMED)

    def test_unprovenanced_metric_uses_policy_default_trust(self):
        provenance = confirmed_provenance(BASE_31)
        del provenance["PR"]
        report = review_vector(VECTOR_31, provenance)
        self.assertFalse(report.publishable)
        self.assertEqual([m.abbreviation for m in report.missing_evidence], ["PR"])
        self.assertEqual(report.missing_evidence[0].trust, TRUST_UNVERIFIED)

    def test_inherited_environmental_metrics_report_applicable_defaults(self):
        report = review_vector(VECTOR_31, confirmed_provenance(BASE_31))
        by_abbreviation = dict((m.abbreviation, m) for m in report.metrics)
        mav = by_abbreviation["MAV"]
        self.assertFalse(mav.explicit)
        self.assertEqual(mav.effective, "N")
        self.assertIn("inherits AV = N (Network)", mav.default_note)
        cr = by_abbreviation["CR"]
        self.assertEqual(cr.effective, "X")
        self.assertIn("weight 1.0", cr.default_note)
        # Inherited metrics without provenance are informational and never
        # block publication on their own.
        self.assertFalse(mav.reviewed)
        self.assertTrue(mav.sufficient)

    def test_explicit_modified_metric_is_reviewed(self):
        vector = VECTOR_31 + "/MAV:P"
        provenance = confirmed_provenance(BASE_31)
        provenance["MAV"] = TRUST_UPSTREAM_DEFAULT
        policy = ReviewPolicy(required_trust={"environmental": TRUST_UPSTREAM_DEFAULT})
        report = review_vector(vector, provenance, policy)
        by_abbreviation = dict((m.abbreviation, m) for m in report.metrics)
        mav = by_abbreviation["MAV"]
        self.assertTrue(mav.explicit)
        self.assertTrue(mav.reviewed)
        self.assertEqual(mav.required_trust, TRUST_UPSTREAM_DEFAULT)
        self.assertTrue(report.publishable)

    def test_policy_relaxation_allows_upstream_default(self):
        provenance = confirmed_provenance(BASE_31)
        provenance["AC"] = TRUST_UPSTREAM_DEFAULT
        policy = ReviewPolicy(required_trust={"base": TRUST_UPSTREAM_DEFAULT})
        report = review_vector(VECTOR_31, provenance, policy)
        self.assertTrue(report.publishable)

    def test_version_specific_fields_in_explanation(self):
        report = review_vector(VECTOR_31, confirmed_provenance(BASE_31))
        explanation = report.explain()
        self.assertIn("CVSS 3.1 review", explanation)
        self.assertIn("Exploit Code Maturity", explanation)
        self.assertIn("Scope", explanation)
        self.assertNotIn("Attack Requirement", explanation)


class TestReviewCVSS4(unittest.TestCase):
    def test_confirmed_metrics_are_publishable(self):
        report = review_vector(VECTOR_40, confirmed_provenance(BASE_40))
        self.assertTrue(report.publishable)
        self.assertEqual(report.decision, "publish")
        self.assertEqual(report.scores()[0], 10.0)
        self.assertEqual(report.version, "4.0")

    def test_upstream_default_metric_holds_publication(self):
        provenance = confirmed_provenance(BASE_40)
        provenance["AT"] = TRUST_UPSTREAM_DEFAULT
        report = review_vector(VECTOR_40, provenance)
        self.assertFalse(report.publishable)
        self.assertEqual([m.abbreviation for m in report.missing_evidence], ["AT"])

    def test_inherited_defaults(self):
        report = review_vector(VECTOR_40, confirmed_provenance(BASE_40))
        by_abbreviation = dict((m.abbreviation, m) for m in report.metrics)
        self.assertEqual(by_abbreviation["E"].effective, "A")
        self.assertIn("scored as A (Attacked)", by_abbreviation["E"].default_note)
        self.assertEqual(by_abbreviation["CR"].effective, "H")
        self.assertIn("scored as H (High)", by_abbreviation["CR"].default_note)
        mav = by_abbreviation["MAV"]
        self.assertEqual(mav.effective, "N")
        self.assertIn("inherits AV = N (Network)", mav.default_note)
        safety = by_abbreviation["S"]
        self.assertEqual(safety.group, "supplemental")
        self.assertIn("no scoring impact", safety.default_note)

    def test_version_specific_fields_in_explanation(self):
        report = review_vector(VECTOR_40, confirmed_provenance(BASE_40))
        explanation = report.explain()
        self.assertIn("CVSS 4.0 review", explanation)
        self.assertIn("Attack Requirement", explanation)
        self.assertIn("Exploit Maturity", explanation)
        self.assertIn("Safety", explanation)
        self.assertNotIn("Exploit Code Maturity", explanation)


class TestReviewCommon(unittest.TestCase):
    def test_same_score_pair_different_decisions(self):
        provenance = confirmed_provenance(BASE_31)
        confirmed_report = review_vector(VECTOR_31, provenance)
        borrowed = dict(provenance)
        borrowed["AC"] = TRUST_UPSTREAM_DEFAULT
        borrowed_report = review_vector(VECTOR_31, borrowed)
        self.assertEqual(confirmed_report.scores(), borrowed_report.scores())
        self.assertEqual(confirmed_report.decision, "publish")
        self.assertEqual(borrowed_report.decision, "hold")

    def test_unknown_trust_level_rejected(self):
        self.assertRaises(ValueError, review_vector, VECTOR_31, {"AV": "guessed"})
        self.assertRaises(ValueError, ReviewPolicy, {"base": "guessed"})

    def test_unknown_vector_rejected(self):
        self.assertRaises(ValueError, review_vector, "AV:L/AC:L/Au:M/C:N/I:P/A:C")


if __name__ == "__main__":
    unittest.main()
