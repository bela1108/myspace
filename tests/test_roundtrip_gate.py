"""Tests for the offline round-trip semantic quality gate."""

import json
import tempfile
import unittest
from pathlib import Path

from plyara.roundtrip_gate import (
    compare_yara_texts,
    condition_change_records,
    format_difference_records,
    plyara_rebuild,
    write_exports,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
COLOR_RULES = REPO_ROOT / "rules" / "color_notifications"


def status_for(report, rule_name):
    """Return one rule report."""
    return next(rule for rule in report["rules"] if rule["rule"] == rule_name)


class RoundtripGateTests(unittest.TestCase):
    """Verify equivalence proofs, counterexamples, and export behavior."""

    def test_parentheses_and_whitespace_are_semantically_transparent(self):
        baseline = '''
        rule Example {
            strings:
                $red = "red"
                $notify = "notify"
            condition:
                $red and $notify
        }
        '''
        formatted = '''
        rule Example {
            strings:
                $red    = "red"
                $notify = "notify"
            condition:
                ( ( $red )
                  and
                  ( $notify ) )
        }
        '''

        report = compare_yara_texts(baseline, formatted)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(status_for(report, "Example")["status"], "equivalent")
        self.assertTrue(report["has_text_differences"])

    def test_boolean_equivalence_rewrite_is_proven(self):
        baseline = 'rule Example { strings: $a="a" $b="b" condition: not ($a or $b) }'
        formatted = 'rule Example { strings: $a="a" $b="b" condition: not $a and not $b }'

        report = compare_yara_texts(baseline, formatted)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(status_for(report, "Example")["status"], "equivalent")

    def test_count_boundary_equivalence_and_mutation_counterexample(self):
        equivalent = compare_yara_texts(
            'rule CountRule { strings: $a="a" condition: #a >= 2 }',
            'rule CountRule { strings: $a="a" condition: #a > 1 }',
        )
        self.assertEqual(status_for(equivalent, "CountRule")["status"], "equivalent")

        changed = compare_yara_texts(
            'rule CountRule { strings: $a="a" condition: #a >= 2 }',
            'rule CountRule { strings: $a="a" condition: #a >= 3 }',
        )
        rule_report = status_for(changed, "CountRule")
        witness = rule_report["counterexample"]

        self.assertEqual(changed["status"], "fail")
        self.assertEqual(rule_report["status"], "condition_change")
        self.assertEqual(witness["abstract_occurrence_counts"]["CountRule.$a"], 2)
        self.assertTrue(witness["baseline_result"])
        self.assertFalse(witness["candidate_result"])

    def test_quantifier_mutation_has_counterexample(self):
        report = compare_yara_texts(
            'rule QuantifierRule { strings: $a="a" $b="b" condition: 2 of ($a, $b) }',
            'rule QuantifierRule { strings: $a="a" $b="b" condition: 1 of ($a, $b) }',
        )
        witness = status_for(report, "QuantifierRule")["counterexample"]
        counts = witness["abstract_occurrence_counts"]

        self.assertEqual(report["status"], "fail")
        self.assertEqual(sorted(counts.values()), [0, 1])
        self.assertFalse(witness["baseline_result"])
        self.assertTrue(witness["candidate_result"])

    def test_private_helper_equivalence_and_mutation_are_linked(self):
        baseline = '''
        private rule IsRed {
            strings: $red = "red"
            condition: $red
        }
        rule RedNotice {
            strings: $notice = "notice"
            condition: IsRed and $notice
        }
        '''
        formatted = '''
        private rule IsRed {
            strings: $red = "red"
            condition: ( $red )
        }
        rule RedNotice {
            strings: $notice = "notice"
            condition: ( IsRed and $notice )
        }
        '''
        equivalent = compare_yara_texts(baseline, formatted)
        self.assertEqual(equivalent["status"], "pass")

        changed = compare_yara_texts(
            baseline,
            baseline.replace("IsRed and $notice", "IsRed or $notice"),
        )
        top_rule = status_for(changed, "RedNotice")
        witness = top_rule["counterexample"]["abstract_occurrence_counts"]

        self.assertEqual(changed["status"], "fail")
        self.assertEqual(top_rule["status"], "condition_change")
        self.assertEqual(witness["IsRed.$red"], 0)
        self.assertEqual(witness["RedNotice.$notice"], 1)
        self.assertFalse(top_rule["counterexample"]["baseline_result"])
        self.assertTrue(top_rule["counterexample"]["candidate_result"])

    def test_unsupported_iteration_is_explicitly_uncertain(self):
        source = '''
        rule LoopRule {
            condition:
                for all i in (0..3) : ( true )
        }
        '''
        report = compare_yara_texts(source, source)
        rule_report = status_for(report, "LoopRule")

        self.assertEqual(report["status"], "inconclusive")
        self.assertEqual(rule_report["status"], "uncertain")
        self.assertIn(
            rule_report["limitations"][0]["code"],
            {"unknown_or_unsupported_identifier", "unsupported_token"},
        )

    def test_private_helper_string_change_is_not_modeled_as_formatting(self):
        baseline = '''
        private rule Helper {
            strings: $token = "red"
            condition: $token
        }
        rule Outer {
            strings: $notice = "notice"
            condition: Helper and $notice
        }
        '''
        changed = baseline.replace('$token = "red"', '$token = "crimson"')

        report = compare_yara_texts(baseline, changed)
        outer = status_for(report, "Outer")
        helper = status_for(report, "Helper")

        self.assertEqual(report["status"], "fail")
        self.assertEqual(helper["status"], "string_definition_change")
        self.assertEqual(outer["status"], "dependency_definition_change")
        self.assertEqual(outer["dependency"], "Helper")

    def test_color_notification_formatting_pack_passes(self):
        baseline = (COLOR_RULES / "baseline" / "color_notifications.yar").read_text()
        formatted = (COLOR_RULES / "formatted" / "color_notifications.yar").read_text()

        report = compare_yara_texts(baseline, formatted)
        expected_rules = {
            "cn_has_notification_channel",
            "cn_red_vocabulary",
            "ColorNotification_Red",
            "ColorNotification_Amber",
            "ColorNotification_Green",
            "ColorNotification_Blue",
        }

        self.assertEqual(report["status"], "pass")
        self.assertEqual({rule["rule"] for rule in report["rules"]}, expected_rules)
        self.assertTrue(all(rule["status"] == "equivalent" for rule in report["rules"]))

    def test_plyara_rebuild_of_color_pack_roundtrips(self):
        baseline = (COLOR_RULES / "baseline" / "color_notifications.yar").read_text()
        rebuilt = plyara_rebuild(baseline)

        report = compare_yara_texts(baseline, rebuilt, candidate_label="plyara-rebuild")

        self.assertEqual(report["status"], "pass")

    def test_color_mutations_and_separate_exports(self):
        baseline_path = COLOR_RULES / "baseline" / "color_notifications.yar"
        changed_path = COLOR_RULES / "changed" / "color_notifications.yar"
        report = compare_yara_texts(baseline_path.read_text(), changed_path.read_text())

        with tempfile.TemporaryDirectory() as temporary_directory:
            exports = write_exports(report, Path(temporary_directory))
            condition_records = condition_change_records(report)
            format_records = format_difference_records(report)

            self.assertEqual(report["status"], "fail")
            self.assertEqual(
                {record["rule"] for record in condition_records},
                {
                    "ColorNotification_Red",
                    "ColorNotification_Amber",
                    "ColorNotification_Green",
                    "ColorNotification_Blue",
                },
            )
            self.assertTrue(all(record["counterexample"]["assignments"] for record in condition_records))
            self.assertTrue(format_records)
            self.assertIn("---", format_records[0]["diff"])

            exported_conditions = json.loads(Path(exports["condition_json"]).read_text())
            exported_format = json.loads(Path(exports["format_json"]).read_text())
            self.assertEqual(len(exported_conditions), 4)
            self.assertEqual(
                exported_format[0]["classification"],
                "also_has_semantic_or_gate_issue",
            )
            self.assertTrue(
                Path(exports["condition_markdown"])
                .read_text()
                .startswith("# Condition changes")
            )
            self.assertTrue(Path(exports["format_diff"]).read_text().startswith("--- "))

    def test_format_only_export_is_classified_separately(self):
        baseline = 'rule A { strings: $a="a" condition: $a }'
        formatted = 'rule A {\n strings: $a = "a"\n condition: ( $a )\n}'
        report = compare_yara_texts(baseline, formatted)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            write_exports(report, output)
            records = format_difference_records(report)

            self.assertEqual(report["status"], "pass")
            self.assertTrue(records[0]["format_only"])
            self.assertEqual((output / "condition_changes.json").read_text().strip(), "[]")


if __name__ == "__main__":
    unittest.main()
