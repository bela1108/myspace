"""scope_diff 的单元测试：覆盖等价/扩围/缩围/不可比/未知五种判定。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import plyara  # noqa: E402

import scope_diff  # noqa: E402


def parse_one(text):
    return plyara.Plyara().parse_string(text)[0]


def make_rule(condition, strings_block=""):
    return parse_one(
        "rule T {\n"
        + ("    strings:\n" + strings_block if strings_block else "")
        + "    condition:\n        " + condition + "\n}\n"
    )


STRINGS_3 = (
    "        $a = \"aaa\"\n"
    "        $b = \"bbb\"\n"
    "        $c = \"ccc\"\n"
)


class TestVerdicts(unittest.TestCase):
    def compare(self, old_cond, new_cond, old_strings=STRINGS_3, new_strings=STRINGS_3):
        old = make_rule(old_cond, old_strings)
        new = make_rule(new_cond, new_strings)
        return scope_diff.compare_conditions(old, new)

    def test_pure_reorder_is_equivalent(self):
        verdict, reason = self.compare(
            "($a and $b) or ($c and not $a)",
            "(not $a and $c) or ($b and $a)",
        )
        self.assertEqual(verdict, scope_diff.VERDICT_EQUIVALENT, reason)

    def test_de_morgan_is_equivalent(self):
        verdict, reason = self.compare(
            "not ($a or $b)",
            "(not $a) and (not $b)",
        )
        self.assertEqual(verdict, scope_diff.VERDICT_EQUIVALENT, reason)

    def test_same_definition_different_name_is_equivalent(self):
        old = make_rule("$a and $b", "        $a = \"aaa\"\n        $b = \"bbb\"\n")
        new = make_rule("$x and $y", "        $x = \"aaa\"\n        $y = \"bbb\"\n")
        verdict, reason = scope_diff.compare_conditions(old, new)
        self.assertEqual(verdict, scope_diff.VERDICT_EQUIVALENT, reason)

    def test_added_disjunct_is_expanded(self):
        verdict, reason = self.compare("$a and $b", "($a and $b) or $c")
        self.assertEqual(verdict, scope_diff.VERDICT_EXPANDED, reason)
        self.assertIn("$c=1", reason)

    def test_added_conjunct_is_shrunk(self):
        verdict, reason = self.compare("$a and $b", "$a and $b and $c")
        self.assertEqual(verdict, scope_diff.VERDICT_SHRUNK, reason)

    def test_mutual_change_is_incomparable(self):
        verdict, reason = self.compare("$a and $b", "$a and $c")
        self.assertEqual(verdict, scope_diff.VERDICT_INCOMPARABLE, reason)
        self.assertIn("互有增删", reason)

    def test_changed_string_value_is_incomparable(self):
        old = make_rule("$a", "        $a = \"aaa\"\n")
        new = make_rule("$a", "        $a = \"zzz\"\n")
        verdict, reason = scope_diff.compare_conditions(old, new)
        self.assertEqual(verdict, scope_diff.VERDICT_INCOMPARABLE, reason)

    def test_library_call_is_unknown(self):
        verdict, reason = self.compare(
            'pe.imports("kernel32.dll", "CreateFileA") and $a',
            'pe.imports("kernel32.dll", "CreateFileW") and $a',
        )
        self.assertEqual(verdict, scope_diff.VERDICT_UNKNOWN, reason)

    def test_dynamic_count_is_unknown(self):
        verdict, reason = self.compare("#a > 2 and $b", "#a > 3 and $b")
        self.assertEqual(verdict, scope_diff.VERDICT_UNKNOWN, reason)

    def test_of_expression_is_unknown(self):
        verdict, reason = self.compare("2 of them", "all of them")
        self.assertEqual(verdict, scope_diff.VERDICT_UNKNOWN, reason)

    def test_undefined_string_ref_is_unknown(self):
        verdict, reason = self.compare("$a and $zzz", "$a")
        self.assertEqual(verdict, scope_diff.VERDICT_UNKNOWN, reason)


class TestFileLevel(unittest.TestCase):
    def test_added_and_removed_rules(self):
        old = parse_one("rule A { condition: true }\nrule B { condition: true }\n")
        new = parse_one("rule A { condition: true }\nrule C { condition: true }\n")
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            old_path = os.path.join(tmp, "old.yar")
            new_path = os.path.join(tmp, "new.yar")
            with open(old_path, "w") as fh:
                fh.write("rule A { condition: true }\nrule B { condition: true }\n")
            with open(new_path, "w") as fh:
                fh.write("rule A { condition: true }\nrule C { condition: true }\n")
            results = {r["rule"]: r["verdict"] for r in scope_diff.compare_files(old_path, new_path)}
        self.assertEqual(results["A"], scope_diff.VERDICT_EQUIVALENT)
        self.assertEqual(results["B"], "删除规则")
        self.assertEqual(results["C"], "新增规则")


if __name__ == "__main__":
    unittest.main()

