#
# SPDX-License-Identifier: Apache-2.0
import ast

import testtools

from bandit.core import budget


CALL_SOURCE = "run(exec('print(1)'))\n"
IMPORT_SOURCE = "import subprocess\n"
EMPTY_SOURCE = "value = 1\n"
BROKEN_SOURCE = "def broken(:\n"


def make_budget(
    quota_a,
    quota_b,
    files,
    skip_predicate=None,
    rules=None,
):
    if rules is None:
        rules = [
            budget.BudgetRule("B100", ("Call",)),
            budget.BudgetRule("B200", ("Import",)),
            budget.BudgetRule("B300", ("File",)),
        ]
    domains = [
        budget.AuditDomain("injection", ("B100", "B300"), quota_a),
        budget.AuditDomain("imports", ("B100", "B200"), quota_b),
    ]
    return budget.CoverageBudget(
        rules,
        domains,
        files,
        skip_predicate=skip_predicate,
    )


class BudgetRuleTests(testtools.TestCase):
    def test_rule_requires_id(self):
        self.assertRaises(
            budget.BudgetError, budget.BudgetRule, "", ("Call",)
        )

    def test_rule_requires_check_type(self):
        self.assertRaises(
            budget.BudgetError, budget.BudgetRule, "B100", ()
        )


class AuditDomainTests(testtools.TestCase):
    def test_quota_must_be_non_negative(self):
        self.assertRaises(
            budget.BudgetError,
            budget.AuditDomain,
            "domain",
            ("B100",),
            -1,
        )

    def test_requires_minimum_check(self):
        self.assertRaises(
            budget.BudgetError, budget.AuditDomain, "domain", (), 3
        )


class CoverageBudgetValidationTests(testtools.TestCase):
    def _rules(self):
        return [budget.BudgetRule("B100", ("Call",))]

    def test_duplicate_rule_rejected(self):
        self.assertRaises(
            budget.BudgetError,
            budget.CoverageBudget,
            self._rules() * 2,
            [budget.AuditDomain("d", ("B100",), 1)],
            [],
        )

    def test_duplicate_domain_rejected(self):
        domain = budget.AuditDomain("d", ("B100",), 1)
        self.assertRaises(
            budget.BudgetError,
            budget.CoverageBudget,
            self._rules(),
            [domain, domain],
            [],
        )

    def test_unknown_minimum_rule_rejected(self):
        self.assertRaises(
            budget.BudgetError,
            budget.CoverageBudget,
            self._rules(),
            [budget.AuditDomain("d", ("B999",), 1)],
            [],
        )

    def test_duplicate_file_rejected(self):
        source = budget.SourceFile("a.py", CALL_SOURCE)
        self.assertRaises(
            budget.BudgetError,
            budget.CoverageBudget,
            self._rules(),
            [budget.AuditDomain("d", ("B100",), 1)],
            [source, source],
        )


class CoverageBudgetReplayTests(testtools.TestCase):
    def test_domain_quota_is_ring_fenced(self):
        files = [
            budget.SourceFile("a.py", CALL_SOURCE),
            budget.SourceFile("b.py", IMPORT_SOURCE),
            budget.SourceFile("c.py", EMPTY_SOURCE),
        ]
        report = make_budget(3, 1, files).replay()

        injection = report.domain_ledgers["injection"]
        imports = report.domain_ledgers["imports"]

        self.assertEqual(3, injection.quota)
        self.assertEqual(3, injection.spent)
        self.assertEqual(0, injection.remaining)
        self.assertEqual(1, imports.quota)
        self.assertEqual(1, imports.spent)
        self.assertEqual(0, imports.remaining)

        # B100 is not applicable to c.py for either domain.
        self.assertIn(
            ("c.py", "B100"), injection.not_applicable
        )
        self.assertIn(("c.py", "B100"), imports.not_applicable)

        # The exhausted imports domain cannot borrow injection quota.
        self.assertEqual(
            [("b.py", "B200", "domain quota exhausted")],
            imports.skipped,
        )
        # The single imports quota was spent on B100 in a.py.
        self.assertEqual(
            [("a.py", "B100")], imports.covered
        )
        self.assertEqual(4, report.total_spent)

    def test_replay_is_independent_of_file_order(self):
        files = [
            budget.SourceFile("a.py", CALL_SOURCE),
            budget.SourceFile("b.py", IMPORT_SOURCE),
            budget.SourceFile("c.py", EMPTY_SOURCE),
        ]
        first = make_budget(3, 1, files).replay()
        reversed_files = list(reversed(files))
        second = make_budget(3, 1, reversed_files).replay()

        self.assertEqual(first.as_dict(), second.as_dict())

    def test_fixed_quota_replays_identically(self):
        files = [budget.SourceFile("a.py", CALL_SOURCE)]
        first = make_budget(1, 1, files).replay()
        second = make_budget(1, 1, files).replay()

        self.assertEqual(first.as_dict(), second.as_dict())

    def test_ast_is_parsed_once_and_shared(self):
        parse_calls = []

        def counting_parser(source):
            parse_calls.append(source)
            return ast.parse(source)

        files = [
            budget.SourceFile("a.py", CALL_SOURCE),
            budget.SourceFile("b.py", IMPORT_SOURCE),
        ]
        scanner = make_budget(4, 4, files)
        scanner.parser = counting_parser
        report = scanner.replay()

        self.assertEqual(2, len(parse_calls))
        self.assertEqual(["a.py", "b.py"], report.parsed_files)
        self.assertEqual(2, report.ast_reuses)

    def test_proven_coverage_is_deduplicated_across_domains(self):
        files = [
            budget.SourceFile("a.py", CALL_SOURCE),
            budget.SourceFile("b.py", IMPORT_SOURCE),
        ]
        report = make_budget(4, 4, files).replay()

        # Both domains prove B100 on a.py but it is counted once.
        pair = ("a.py", "B100")
        self.assertEqual(1, report.proven_coverage.count(pair))
        self.assertNotIn(pair, report.unexamined)

    def test_skip_does_not_spend_or_borrow_budget(self):
        files = [budget.SourceFile("a.py", CALL_SOURCE)]

        def skip_one(file_name, rule):
            if rule.rule_id == "B100":
                return "plugin refused file"
            return None

        report = make_budget(2, 2, files, skip_one).replay()

        for ledger in report.domain_ledgers.values():
            self.assertEqual(
                [
                    (
                        "a.py",
                        "B100",
                        "plugin refused file",
                    )
                ],
                ledger.skipped,
            )
        # Only the applicable whole-file B300 check spends budget.
        self.assertEqual(1, report.domain_ledgers["injection"].spent)
        self.assertEqual(0, report.domain_ledgers["imports"].spent)
        self.assertIn(("a.py", "B100"), report.unexamined)

    def test_unparseable_file_is_not_charged(self):
        files = [
            budget.SourceFile("ok.py", CALL_SOURCE),
            budget.SourceFile("broken.py", BROKEN_SOURCE),
        ]
        report = make_budget(5, 5, files).replay()

        self.assertEqual(
            [("broken.py", "invalid syntax")],
            report.unparseable_files,
        )
        injection = report.domain_ledgers["injection"]
        self.assertEqual(2, injection.spent)
        reasons = {
            (file_name, rule_id)
            for file_name, rule_id, _reason in injection.unparseable
        }
        self.assertEqual(
            {("broken.py", "B100"), ("broken.py", "B300")}, reasons
        )
        self.assertIn(("broken.py", "B100"), report.unexamined)

    def test_zero_quota_proves_nothing(self):
        files = [budget.SourceFile("a.py", CALL_SOURCE)]
        report = make_budget(0, 0, files).replay()

        for ledger in report.domain_ledgers.values():
            self.assertEqual(0, ledger.spent)
            self.assertEqual(ledger.quota, ledger.remaining)
        self.assertEqual([], report.proven_coverage)
        self.assertNotEqual([], report.unexamined)

    def test_not_applicable_rule_needs_no_budget(self):
        files = [budget.SourceFile("plain.py", EMPTY_SOURCE)]
        report = make_budget(0, 0, files).replay()

        imports = report.domain_ledgers["imports"]
        self.assertIn(("plain.py", "B100"), imports.not_applicable)
        self.assertIn(("plain.py", "B200"), imports.not_applicable)
        self.assertEqual([], imports.skipped)


class RegistryBridgeTests(testtools.TestCase):
    def test_rules_from_registry(self):
        from bandit.core import extension_loader

        rules = budget.rules_from_registry(
            extension_loader.MANAGER, ("B102", "B301")
        )
        by_id = {rule.rule_id: rule for rule in rules}

        self.assertEqual(("Call",), by_id["B102"].check_types)
        self.assertEqual(("Call",), by_id["B301"].check_types)

    def test_rules_from_registry_unknown_id(self):
        from bandit.core import extension_loader

        self.assertRaises(
            budget.BudgetError,
            budget.rules_from_registry,
            extension_loader.MANAGER,
            ("B99999",),
        )
