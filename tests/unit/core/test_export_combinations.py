#
# SPDX-License-Identifier: Apache-2.0
import json
import textwrap

import testtools

from bandit.core import export_combinations


class ExportCombinationAnalyzerTests(testtools.TestCase):
    def analyze(self, source, protected=(("A", "B"),)):
        return export_combinations.analyze_source(
            textwrap.dedent(source),
            protected=protected,
            filename="sample.py",
        )

    def test_collects_static_tuple_unpacking_helper_and_submissions(self):
        report = self.analyze(
            """\
            RECIPIENT = "partner"
            FLOOR_FIELDS = ("A",)

            def shift_fields():
                floor, shift = ("A", "B")
                return (shift,)

            def send_report():
                export(RECIPIENT, FLOOR_FIELDS)
                export(RECIPIENT, shift_fields())
            """
        )

        finding = report.findings[0]
        self.assertIs(
            finding.status,
            export_combinations.CombinationStatus.CO_EXECUTABLE,
        )
        self.assertEqual(("A", "B"), finding.protected)
        self.assertEqual({"A"}, finding.left.fields)
        self.assertEqual({"B"}, finding.right.fields)
        self.assertEqual("partner", finding.recipient)
        self.assertIn("same scope", finding.reason)

    def test_opposite_if_branches_are_mutually_exclusive(self):
        report = self.analyze(
            """\
            def send_report(include_shift):
                if include_shift:
                    export("partner", ("A",))
                else:
                    export("partner", ("B",))
            """
        )

        finding = report.findings[0]
        self.assertIs(
            finding.status,
            export_combinations.CombinationStatus.MUTUALLY_EXCLUSIVE,
        )
        self.assertIn("different branches", finding.reason)
        self.assertNotEqual(finding.left.lineno, finding.right.lineno)

    def test_unresolved_return_is_unprovable_with_reason(self):
        report = self.analyze(
            """\
            def dynamic_fields():
                return load_fields()

            def send_report():
                export("partner", ("A",))
                export("partner", dynamic_fields())
            """
        )

        finding = report.findings[0]
        self.assertIs(
            finding.status,
            export_combinations.CombinationStatus.UNPROVABLE,
        )
        self.assertIn("load_fields", finding.reason)
        self.assertIn("not a finite same-module return", finding.reason)
        self.assertEqual(set(), finding.right.fields)

    def test_independent_recipients_are_not_aggregated(self):
        report = self.analyze(
            """\
            def send_report():
                export("recipient-one", ("A",))
                export("recipient-two", ("B",))
            """
        )

        finding = report.findings[0]
        self.assertIs(
            finding.status,
            export_combinations.CombinationStatus.INDEPENDENT_RECIPIENTS,
        )
        self.assertIn("independent recipients", finding.reason)

    def test_single_export_point_can_expose_both_labels(self):
        report = self.analyze(
            """\
            export("partner", ("A", "B"))
            """
        )

        finding = report.findings[0]
        self.assertIs(
            finding.status,
            export_combinations.CombinationStatus.CO_EXECUTABLE,
        )
        self.assertIs(finding.left, finding.right)
        self.assertIn("same export point", finding.reason)

    def test_keyword_and_starred_fields_are_collected(self):
        report = self.analyze(
            """\
            FIELDS = ("A", "B")
            export(recipient="partner", fields=("A",))
            export(recipient="partner", *FIELDS)
            """
        )

        finding = report.findings[0]
        self.assertIs(
            finding.status,
            export_combinations.CombinationStatus.CO_EXECUTABLE,
        )
        self.assertIn("B", finding.right.fields)

    def test_report_serializes_pair_identifiers(self):
        report = self.analyze(
            """\
            export("partner", ("A",))
            export("partner", ("B",))
            """
        )

        payload = json.loads(report.to_json())
        finding = payload["findings"][0]
        self.assertEqual("co_executable", finding["status"])
        self.assertEqual(2, len(finding["points"]))
        self.assertEqual("sample.py:1:1", finding["points"][0]["id"])

    def test_alternative_returns_in_one_call_do_not_combine(self):
        report = self.analyze(
            """\
            def fields(flag):
                if flag:
                    return ("A",)
                return ("B",)

            export("partner", fields(flag))
            """
        )

        finding = report.findings[0]
        self.assertIs(
            finding.status,
            export_combinations.CombinationStatus.MUTUALLY_EXCLUSIVE,
        )
        self.assertIs(finding.left, finding.right)
        self.assertEqual({"A", "B"}, finding.left.fields)
        self.assertEqual(2, len(finding.left.field_variants))
        self.assertIn("selects between", finding.reason)


class ProtectedCombinationParsingTests(testtools.TestCase):
    def test_comma_and_pair_inputs_are_normalized(self):
        self.assertEqual(
            (("A", "B"),),
            export_combinations.normalize_protected_combinations(["A,B"]),
        )
        self.assertEqual(
            (("A", "B"),),
            export_combinations.normalize_protected_combinations(["A", "B"]),
        )
        self.assertEqual(
            (("A", "B"), ("C", "D")),
            export_combinations.normalize_protected_combinations(
                ["A,B", "C,D"]
            ),
        )
