#!/usr/bin/env python
"""Tests for the budget-aware scanning backend."""

import os
import unittest

from oletools.common.scan_budget import (
    ATTACHMENT,
    CONTAINER,
    MACRO,
    BudgetExhausted,
    ScanBudget,
)
from oletools.scan_backend import (
    OfficeScanBackend,
    ScanObject,
    SyntheticContainer,
)
from tests.test_utils import DATA_BASE_DIR


def make_synthetic_container():
    """Three objects with deliberately unbalanced costs."""
    return SyntheticContainer([
        {
            "id": "large.docx",
            "costs": {"container": 10, "macro": 10, "attachment": 10},
            "findings": {
                "container": ["OLE storage"],
                "macro": ["AutoOpen"],
                "attachment": ["calc.exe"],
            },
        },
        {
            "id": "small-a.docx",
            "costs": {"container": 2, "macro": 2, "attachment": 2},
            "findings": {"macro": ["small-a-macro"]},
        },
        {
            "id": "small-b.doc",
            "costs": {"container": 2, "macro": 2, "attachment": 2},
            "findings": {"attachment": ["small-b-payload"]},
        },
    ])


class TestScanBudget(unittest.TestCase):
    """Accounting primitives."""

    def test_categories_are_independent(self):
        budget = ScanBudget(container=10, macro=5, attachment=3)
        budget.charge("doc", CONTAINER, 4)
        budget.charge("doc", MACRO, 2)
        budget.charge("doc", ATTACHMENT, 1)
        snapshot = budget.snapshot()
        self.assertEqual(snapshot["used"], {
            CONTAINER: 4, MACRO: 2, ATTACHMENT: 1})
        self.assertEqual(snapshot["remaining"], {
            CONTAINER: 6, MACRO: 3, ATTACHMENT: 2})

    def test_unknown_category_is_rejected(self):
        budget = ScanBudget(container=1)
        with self.assertRaises(ValueError):
            budget.charge("doc", "not-a-stage", 1)

    def test_allocated_accounts_do_not_drain_each_other(self):
        budget = ScanBudget()
        budget.allocate("large", container=10, macro=10, attachment=10)
        budget.allocate("small", container=2, macro=2, attachment=2)
        budget.charge("large", CONTAINER, 10)
        self.assertEqual(budget.account_for("large").remaining(CONTAINER), 0)
        self.assertEqual(budget.account_for("small").remaining(CONTAINER), 2)

    def test_exhaustion_reports_category_and_shortfall(self):
        budget = ScanBudget()
        budget.allocate("doc", container=3)
        with self.assertRaises(BudgetExhausted) as context:
            budget.charge("doc", CONTAINER, 5)
        self.assertEqual(context.exception.object_id, "doc")
        self.assertEqual(context.exception.category, CONTAINER)
        self.assertEqual(context.exception.available, 3)
        self.assertEqual(context.exception.needed, 2)


class TestSyntheticScan(unittest.TestCase):
    """Pause, resume and verdict stability."""

    def setUp(self):
        self.container = make_synthetic_container()
        self.backend = OfficeScanBackend()

    def test_pause_returns_completed_prefix_and_unprocessed_range(self):
        budget = ScanBudget(container=10, macro=10, attachment=10)
        result = self.backend.scan(self.container, budget)
        self.assertTrue(result.paused)
        self.assertEqual(result.covered_prefix, ["large.docx"])
        self.assertEqual(result.covered_prefix_count, 1)
        self.assertEqual(result.unprocessed, ["small-a.docx", "small-b.doc"])
        self.assertEqual(result.unprocessed_range, (1, 3))
        self.assertEqual(result.pause.object_id, "small-a.docx")
        self.assertEqual(result.pause.category, CONTAINER)
        self.assertTrue(result.get("large.docx").complete)
        self.assertTrue(result.get("small-a.docx").pending)

    def test_targeted_top_up_keeps_other_verdicts_stable(self):
        budget = ScanBudget(container=10, macro=10, attachment=10)
        first = self.backend.scan(self.container, budget)
        large_before = first.get("large.docx").to_dict()

        budget.top_up("small-a.docx", container=2, macro=2, attachment=2)
        second = self.backend.resume(first)
        self.assertEqual(second.covered_prefix,
                         ["large.docx", "small-a.docx"])
        self.assertEqual(second.unprocessed, ["small-b.doc"])
        self.assertEqual(second.get("large.docx").to_dict(), large_before)
        self.assertTrue(second.get("small-a.docx").complete)

        budget.top_up("small-b.doc", container=2, macro=2, attachment=2)
        third = self.backend.resume(second)
        self.assertTrue(third.complete)
        self.assertEqual(third.get("large.docx").to_dict(), large_before)
        self.assertEqual(third.get("small-a.docx").to_dict(),
                         second.get("small-a.docx").to_dict())

    def test_partial_object_retains_proven_findings_and_unprocessed_range(self):
        container = SyntheticContainer([
            {"id": "large.docx",
             "costs": {"container": 4, "macro": 4, "attachment": 4},
             "findings": {"container": ["OLE storage"],
                          "macro": ["AutoOpen"],
                          "attachment": ["calc.exe"]}},
        ])
        budget = ScanBudget(container=4, macro=4, attachment=0)
        result = self.backend.scan(container, budget)
        large = result.get("large.docx")
        self.assertTrue(large.partial)
        self.assertEqual(large.findings, ["OLE storage", "AutoOpen"])
        self.assertEqual(large.covered, (CONTAINER, MACRO))
        self.assertEqual(large.unprocessed[ATTACHMENT], (0, 4))
        self.assertEqual(large.unprocessed_stages, (ATTACHMENT,))
        self.assertEqual(result.covered_prefix, [])
        self.assertEqual(result.unprocessed, ["large.docx"])

        budget.top_up("large.docx", attachment=4)
        resumed = self.backend.resume(result)
        completed = resumed.get("large.docx")
        self.assertTrue(completed.complete)
        self.assertEqual(completed.findings,
                         ["OLE storage", "AutoOpen", "calc.exe"])
        self.assertEqual(resumed.covered_prefix, ["large.docx"])

    def test_resume_accepts_three_tuple_top_ups(self):
        budget = ScanBudget(container=1, macro=1, attachment=1)
        first = self.backend.scan(self.container, budget)
        self.assertEqual(first.covered_prefix, [])
        second = self.backend.resume(
            first,
            top_ups=[("large.docx", CONTAINER, 10),
                     ("large.docx", MACRO, 10),
                     ("large.docx", ATTACHMENT, 10)],
        )
        self.assertEqual(second.covered_prefix, ["large.docx"])
        self.assertEqual(second.unprocessed, ["small-a.docx", "small-b.doc"])

    def test_exhausting_one_category_does_not_spend_another(self):
        container = SyntheticContainer([
            {"id": "large.docx",
             "costs": {"container": 10, "macro": 0, "attachment": 0},
             "findings": {"container": ["OLE storage"]}},
            {"id": "small-a.docx",
             "costs": {"container": 2, "macro": 2, "attachment": 2}},
        ])
        budget = ScanBudget(container=10, macro=100, attachment=100)
        first = self.backend.scan(container, budget)
        self.assertTrue(first.paused)
        self.assertEqual(budget.snapshot()["used"], {
            CONTAINER: 10, MACRO: 0, ATTACHMENT: 0})


class TestExistingParserBudget(unittest.TestCase):
    """The legacy parser can be charged through the same ledger."""

    def test_vba_parser_charges_container_and_macro(self):
        sample = os.path.join(DATA_BASE_DIR, "olevba", "sample_with_vba.ppt")
        if not os.path.isfile(sample):
            self.skipTest("sample file is missing")
        from oletools import olevba
        budget = ScanBudget()
        parser = olevba.VBA_Parser(sample, budget=budget, object_id="sample")
        try:
            self.assertTrue(parser.detect_macros())
            modules = parser.extract_all_macros()
            self.assertTrue(modules)
        finally:
            parser.close()
        used = budget.snapshot()["used"]
        self.assertGreater(used[CONTAINER], 0)
        self.assertGreater(used[MACRO], 0)
        self.assertEqual(used[ATTACHMENT], 0)


if __name__ == "__main__":
    unittest.main()
