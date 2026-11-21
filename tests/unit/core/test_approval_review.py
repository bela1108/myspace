#
# SPDX-License-Identifier: Apache-2.0
import datetime
import os

import testtools

from bandit.core import approval_review


FIXTURE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "fixtures", "approval_review")

REVIEW_TIME = datetime.datetime(
    2026, 11, 21, tzinfo=datetime.timezone.utc)


def _fixture(name):
    return os.path.join(FIXTURE_DIR, name)


class ApprovalReviewRegressionTests(testtools.TestCase):
    """Regression test for the batch approval re-review entry point.

    Uses one old JSON baseline and two new reports.  Exactly one
    verifiably unchanged finding keeps its historical approval; every
    other finding must be flagged with the reason it needs a look.
    """

    def setUp(self):
        super().setUp()
        self.report = approval_review.review_approvals(
            baseline=_fixture("baseline_v1.json"),
            new_reports=[
                _fixture("report_api_v2.json"),
                _fixture("report_worker_v2.json"),
            ],
            migration=_fixture("migration_v1_to_v2.json"),
            review_time=REVIEW_TIME,
        )
        self.by_test_id = {
            entry["test_id"]: entry for entry in self.report["findings"]
        }

    def test_summary_counts(self):
        summary = self.report["summary"]
        self.assertEqual(5, summary["total"])
        self.assertEqual(1, summary["carried_over"])
        self.assertEqual(4, summary["needs_review"])
        self.assertEqual(
            {
                "severity_changed": 1,
                "rule_split": 1,
                "approval_expired": 1,
                "incomplete_approval": 1,
            },
            summary["reasons"],
        )

    def test_migration_versions_recorded(self):
        self.assertEqual(
            {"from_version": "1.7.4", "to_version": "1.8.0"},
            self.report["rule_set_migration"],
        )

    def test_unchanged_finding_carries_over_approval(self):
        entry = self.by_test_id["B505"]
        self.assertEqual("carried_over", entry["disposition"])
        self.assertIsNone(entry["reason"])
        self.assertEqual("alice", entry["approval"]["approved_by"])
        self.assertEqual("api-service", entry["report"])

    def test_severity_change_needs_review(self):
        entry = self.by_test_id["B602"]
        self.assertEqual("needs_review", entry["disposition"])
        self.assertEqual("severity_changed", entry["reason"])
        self.assertIn("HIGH", entry["detail"])
        self.assertIn("MEDIUM", entry["detail"])

    def test_rule_split_needs_review(self):
        entry = self.by_test_id["B614"]
        self.assertEqual("needs_review", entry["disposition"])
        self.assertEqual("rule_split", entry["reason"])
        self.assertIn("B301", entry["detail"])
        self.assertEqual("worker-service", entry["report"])

    def test_expired_approval_needs_review(self):
        entry = self.by_test_id["B102"]
        self.assertEqual("needs_review", entry["disposition"])
        self.assertEqual("approval_expired", entry["reason"])
        self.assertIn("dave", entry["detail"])

    def test_incomplete_approval_needs_review(self):
        entry = self.by_test_id["B105"]
        self.assertEqual("needs_review", entry["disposition"])
        self.assertEqual("incomplete_approval", entry["reason"])
        self.assertIn("expires_at", entry["detail"])


class ApprovalReviewUnitTests(testtools.TestCase):
    """Edge cases for findings without a usable baseline match."""

    def _review(self, baseline_results, new_results):
        return approval_review.review_approvals(
            baseline={"results": baseline_results},
            new_reports=[{"results": new_results}],
            migration={},
            review_time=REVIEW_TIME,
        )

    def test_new_finding_needs_review(self):
        report = self._review(
            [],
            [{"filename": "app/new.py", "line_number": 1,
              "test_id": "B999", "issue_severity": "LOW"}],
        )
        entry = report["findings"][0]
        self.assertEqual("needs_review", entry["disposition"])
        self.assertEqual("new_finding", entry["reason"])

    def test_changed_code_needs_review(self):
        baseline_finding = {
            "filename": "app/mod.py", "line_number": 7,
            "test_id": "B505", "issue_severity": "LOW",
            "code": "7  old_code()\n",
            "approval": {
                "approved_by": "alice",
                "approved_at": "2026-01-06T09:00:00Z",
                "expires_at": "2027-01-06T09:00:00Z",
            },
        }
        new_finding = dict(baseline_finding)
        new_finding["code"] = "7  new_code()\n"
        del new_finding["approval"]
        report = self._review([baseline_finding], [new_finding])
        entry = report["findings"][0]
        self.assertEqual("needs_review", entry["disposition"])
        self.assertEqual("finding_changed", entry["reason"])
