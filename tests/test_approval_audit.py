"""Tests for offline use-specific approval reconciliation."""

import json
import unittest

from plyara import Plyara

from approval_audit import APPROVAL_WITHDRAWN
from approval_audit import APPROVED
from approval_audit import OUTBOUND_REPORT_ATTACHMENT
from approval_audit import RECHECK_REQUIRED
from approval_audit import ROUTINE_ARCHIVE_SEARCH
from approval_audit import RULE_REORDERED
from approval_audit import SAME_NAME_REPLACEMENT
from approval_audit import UNAPPROVED
from approval_audit import ReviewForm
from approval_audit import audit_rules
from approval_audit import bind_parsed_rule
from approval_audit import form_from_parsed_rules


ORIGINAL_RULES = """
rule cedar_word
{
    strings:
        $word = "cedar"
    condition:
        $word
}

rule harbor_word
{
    strings:
        $word = "harbor"
    condition:
        $word
}
"""

REORDERED_RULES = """
rule harbor_word
{
    strings:
        $word = "harbor"
    condition:
        $word
}

rule cedar_word
{
    strings:
        $word = "cedar"
    condition:
        $word
}
"""

TEXT_REPLACED_RULES = """
rule cedar_word
{
    strings:
        $word = "cedar"
    condition:
        $word
}

rule harbor_word
{
    strings:
        $word = "anchor"
    condition:
        $word
}
"""

CONDITION_REPLACED_RULES = """
rule cedar_word
{
    strings:
        $word = "cedar"
    condition:
        $word
}

rule harbor_word
{
    strings:
        $word = "harbor"
        $tide = "tide"
    condition:
        $word and $tide
}
"""


def parse_rules(source=ORIGINAL_RULES):
    """Parse the small ordinary-word rules used by a test."""
    return Plyara().parse_string(source)


def two_review_forms(parsed_rules=None):
    """Create matching archive-search and outbound-report review forms."""
    parsed_rules = parsed_rules or parse_rules()
    return [
        form_from_parsed_rules(
            "FORM-ARCHIVE",
            ROUTINE_ARCHIVE_SEARCH,
            parsed_rules,
            approval_id_prefix="ARC",
        ),
        form_from_parsed_rules(
            "FORM-REPORT",
            OUTBOUND_REPORT_ATTACHMENT,
            parsed_rules,
            approval_id_prefix="RPT",
        ),
    ]


class ApprovalAuditTest(unittest.TestCase):
    """Verify binding, reordering, replacement, and withdrawal behavior."""

    def test_baseline_binds_name_plain_condition_and_use(self):
        report = audit_rules(ORIGINAL_RULES, two_review_forms())

        self.assertEqual(report.rule_count, 2)
        self.assertEqual(report.blockers, [])
        for name in ("cedar_word", "harbor_word"):
            for use in (ROUTINE_ARCHIVE_SEARCH, OUTBOUND_REPORT_ATTACHMENT):
                decision = report.decision(name, use)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.status, APPROVED)
                self.assertFalse(decision.reordered)
                self.assertTrue(decision.condition_fingerprint.startswith("sha256:"))
                self.assertIn("condition: $word", decision.plain_condition)
                self.assertEqual(len(decision.evidence), 1)

        archive = report.decision("cedar_word", ROUTINE_ARCHIVE_SEARCH)
        self.assertIn('$word = "cedar"', archive.plain_condition)
        self.assertEqual(archive.evidence[0]["basis"], "FORM-ARCHIVE/ARC-1")
        self.assertEqual(
            report.evidence_for("harbor_word", OUTBOUND_REPORT_ATTACHMENT)[0]["basis"],
            "FORM-REPORT/RPT-2",
        )

        json.dumps(report.to_dict(), ensure_ascii=False)

    def test_accepts_read_only_plyara_parse_results(self):
        parsed_rules = parse_rules()
        report = audit_rules(parsed_rules, two_review_forms(parsed_rules))

        self.assertTrue(report.allowed("cedar_word", ROUTINE_ARCHIVE_SEARCH))
        self.assertTrue(report.allowed("harbor_word", OUTBOUND_REPORT_ATTACHMENT))

    def test_uses_are_bound_separately(self):
        parsed_rules = parse_rules()
        archive_only = ReviewForm(
            form_id="FORM-ARCHIVE-ONLY",
            use=ROUTINE_ARCHIVE_SEARCH,
            rules=[
                bind_parsed_rule(
                    parsed_rules[0],
                    approval_id="ARC-CEDAR",
                    approved_position=0,
                )
            ],
        )

        report = audit_rules(
            ORIGINAL_RULES,
            [archive_only],
            uses=[ROUTINE_ARCHIVE_SEARCH, OUTBOUND_REPORT_ATTACHMENT],
        )

        archive = report.decision("cedar_word", ROUTINE_ARCHIVE_SEARCH)
        external = report.decision("cedar_word", OUTBOUND_REPORT_ATTACHMENT)
        self.assertTrue(archive.allowed)
        self.assertFalse(external.allowed)
        self.assertEqual(external.status, UNAPPROVED)
        self.assertEqual(external.evidence, [])
        self.assertTrue(
            report.findings_for(
                "missing_approval_for_use",
                "cedar_word",
                OUTBOUND_REPORT_ATTACHMENT,
            )
        )

    def test_rule_reorder_keeps_binding_and_locates_basis(self):
        report = audit_rules(REORDERED_RULES, two_review_forms())

        cedar_archive = report.decision("cedar_word", ROUTINE_ARCHIVE_SEARCH)
        cedar_report = report.decision("cedar_word", OUTBOUND_REPORT_ATTACHMENT)
        harbor_archive = report.decision("harbor_word", ROUTINE_ARCHIVE_SEARCH)

        self.assertTrue(cedar_archive.allowed)
        self.assertTrue(cedar_archive.reordered)
        self.assertEqual(cedar_archive.current_position, 1)
        self.assertEqual(cedar_archive.current_start_line, 10)
        self.assertEqual(cedar_archive.evidence[0]["approved_position"], 0)
        self.assertEqual(cedar_archive.evidence[0]["approved_start_line"], 2)
        self.assertEqual(cedar_archive.evidence[0]["basis"], "FORM-ARCHIVE/ARC-1")

        self.assertTrue(cedar_report.allowed)
        self.assertTrue(cedar_report.reordered)
        self.assertEqual(cedar_report.evidence[0]["form_id"], "FORM-REPORT")

        self.assertTrue(harbor_archive.allowed)
        self.assertTrue(harbor_archive.reordered)
        self.assertEqual(harbor_archive.current_position, 0)
        self.assertEqual(harbor_archive.evidence[0]["approved_position"], 1)

        finding = report.findings_for(
            RULE_REORDERED,
            "cedar_word",
            ROUTINE_ARCHIVE_SEARCH,
        )[0]
        self.assertEqual(finding.details["approved_position"], 0)
        self.assertEqual(finding.details["current_position"], 1)
        self.assertIn("审批依据仍有效", finding.message)
        self.assertEqual(len(report.findings_for(RULE_REORDERED)), 4)
        self.assertEqual(report.blockers, [])

    def test_same_name_text_replacement_requires_external_recheck(self):
        report = audit_rules(TEXT_REPLACED_RULES, two_review_forms())

        external = report.decision("harbor_word", OUTBOUND_REPORT_ATTACHMENT)
        archive = report.decision("harbor_word", ROUTINE_ARCHIVE_SEARCH)

        self.assertFalse(external.allowed)
        self.assertEqual(external.status, RECHECK_REQUIRED)
        self.assertTrue(external.needs_recheck)
        self.assertEqual(external.prior_approval_ids, ["RPT-2"])
        self.assertIn("外发报告", external.messages[0])
        self.assertIn("重新核对", external.messages[0])

        finding = report.findings_for(
            SAME_NAME_REPLACEMENT,
            "harbor_word",
            OUTBOUND_REPORT_ATTACHMENT,
        )[0]
        self.assertIn("harbor", finding.details["approved_plain_condition"])
        self.assertIn("anchor", finding.details["current_plain_condition"])

        self.assertFalse(archive.allowed)
        self.assertEqual(archive.status, RECHECK_REQUIRED)
        self.assertTrue(report.allowed("cedar_word", OUTBOUND_REPORT_ATTACHMENT))

    def test_condition_expression_change_requires_explicit_recheck(self):
        report = audit_rules(CONDITION_REPLACED_RULES, two_review_forms())

        external = report.decision("harbor_word", OUTBOUND_REPORT_ATTACHMENT)
        finding = report.findings_for(
            SAME_NAME_REPLACEMENT,
            "harbor_word",
            OUTBOUND_REPORT_ATTACHMENT,
        )[0]

        self.assertFalse(external.allowed)
        self.assertTrue(external.needs_recheck)
        self.assertIn("重新核对", external.messages[0])
        self.assertIn("condition: $word", finding.details["approved_plain_condition"])
        self.assertIn(
            "condition: $word and $tide",
            finding.details["current_plain_condition"],
        )

    def test_withdrawn_approval_blocks_use_but_other_form_remains_basis(self):
        parsed_rules = parse_rules()
        archive_form = ReviewForm(
            form_id="FORM-ARCHIVE",
            use=ROUTINE_ARCHIVE_SEARCH,
            rules=[
                bind_parsed_rule(
                    parsed_rules[0],
                    approval_id="ARC-OLD",
                    approved_position=0,
                    status="withdrawn",
                ),
                bind_parsed_rule(
                    parsed_rules[1],
                    approval_id="ARC-2",
                    approved_position=1,
                ),
            ],
        )
        report_form = form_from_parsed_rules(
            "FORM-REPORT",
            OUTBOUND_REPORT_ATTACHMENT,
            parsed_rules,
            approval_id_prefix="RPT",
        )

        report = audit_rules(ORIGINAL_RULES, [archive_form, report_form])

        withdrawn = report.decision("cedar_word", ROUTINE_ARCHIVE_SEARCH)
        self.assertFalse(withdrawn.allowed)
        self.assertEqual(withdrawn.status, APPROVAL_WITHDRAWN)
        self.assertEqual(withdrawn.prior_approval_ids, ["ARC-OLD"])

        withdrawal = report.findings_for(
            APPROVAL_WITHDRAWN,
            "cedar_word",
            ROUTINE_ARCHIVE_SEARCH,
        )[0]
        self.assertEqual(withdrawal.severity, "blocker")
        self.assertIn("已撤回", withdrawal.message)

        external = report.decision("cedar_word", OUTBOUND_REPORT_ATTACHMENT)
        self.assertTrue(external.allowed)
        self.assertEqual(external.evidence[0]["basis"], "FORM-REPORT/RPT-1")
        self.assertTrue(report.allowed("harbor_word", ROUTINE_ARCHIVE_SEARCH))

    def test_withdrawn_old_approval_can_be_superseded_by_new_basis(self):
        parsed_rules = parse_rules()
        old_approval = bind_parsed_rule(
            parsed_rules[0],
            approval_id="ARC-OLD",
            approved_position=0,
            status="withdrawn",
        )
        new_approval = bind_parsed_rule(
            parsed_rules[0],
            approval_id="ARC-NEW",
            approved_position=0,
        )
        archive_form = ReviewForm(
            form_id="FORM-ARCHIVE",
            use=ROUTINE_ARCHIVE_SEARCH,
            rules=[old_approval, new_approval],
        )

        report = audit_rules(ORIGINAL_RULES, [archive_form])

        decision = report.decision("cedar_word", ROUTINE_ARCHIVE_SEARCH)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.approval_ids, ["ARC-NEW"])
        self.assertEqual(decision.evidence[0]["basis"], "FORM-ARCHIVE/ARC-NEW")

        withdrawal = report.findings_for(
            APPROVAL_WITHDRAWN,
            "cedar_word",
            ROUTINE_ARCHIVE_SEARCH,
        )[0]
        self.assertEqual(withdrawal.severity, "warning")
        self.assertEqual(
            withdrawal.details["superseded_by"],
            ["FORM-ARCHIVE/ARC-NEW"],
        )
        self.assertIn("可依据新审批", withdrawal.message)


if __name__ == "__main__":
    unittest.main()
