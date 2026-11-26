# Copyright 2025 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for the three-way semantic review entry point."""
import contextlib
import io
import json
import pathlib
import tempfile
import unittest
import unittest.mock

import plyara
import plyara.command_line
from plyara.review import review_rules


COLOR_BASE = '''
rule Colors
{
    meta:
        author = "security"
    strings:
        $red = "red"
        $green = "green"
    condition:
        $red and not $green
}
'''

COLOR_METADATA = '''
rule Colors
{
    meta:
        author = "review team"
        severity = 2
    strings:
        $red = "red"
        $green = "green"
    condition:
        $red and not $green
}
'''

COLOR_REFACTOR = '''
rule Colors
{
    meta:
        author = "security"
    strings:
        $red = "red"
        $lime = "green"
    condition:
        $red and not $lime
}
'''

COLOR_CONDITION = '''
rule Colors
{
    strings:
        $red = "red"
        $green = "green"
    condition:
        $green
}
'''

COLOR_EDGE_BASE = '''
rule Colors
{
    strings:
        $red = "red"
        $green = "green"
    condition:
        $red
}
'''

COLOR_EDGE_LEFT = '''
rule Colors
{
    strings:
        $red = "red"
        $green = "green"
    condition:
        $green
}
'''

COLOR_EDGE_RIGHT = '''
rule Colors
{
    strings:
        $red = "red"
        $green = "emerald"
    condition:
        $red
}
'''

COLOR_CONFLICT = '''
rule Colors
{
    strings:
        $red = "red"
        $green = "green"
        $lime = "lime"
    condition:
        $lime
}
'''

PROJECT_BASE = '''
rule ColorProject { condition: ProjectAlpha }
rule ProjectAlpha { condition: true }
rule ProjectBeta { condition: false }
'''

PROJECT_REFERENCE = '''
rule ColorProject { condition: ProjectBeta }
rule ProjectAlpha { condition: true }
rule ProjectBeta { condition: false }
'''

PROJECT_TARGET_CHANGE = '''
rule ColorProject { condition: ProjectAlpha }
rule ProjectAlpha { condition: true }
rule ProjectBeta { condition: true }
'''

COLOR_OPAQUE = '''
rule Colors { condition: custom_colors.value > 3 }
'''


class TestThreeWayReview(unittest.TestCase):
    """Check metadata merges, semantic reissues, and manual review items."""

    def test_metadata_merges_independently_of_reference_refactor(self):
        """A metadata-only draft and a local-reference refactor land in separate buckets."""
        report = review_rules(COLOR_BASE, COLOR_METADATA, COLOR_REFACTOR)

        metadata_changes = [change for change in report.mergeable if change.kind == 'metadata']
        self.assertTrue(metadata_changes)
        self.assertTrue(all(change.summary.startswith('metadata key') for change in metadata_changes))

        reissue = report.reissue
        self.assertTrue(any(change.kind == 'string' and change.action == 'rename' for change in reissue))
        self.assertTrue(any(change.kind == 'condition' for change in reissue))
        self.assertTrue(any(change.kind == 'dependency' and '$lime' in change.summary for change in reissue))

        self.assertIn('author = "review team"', report.merged_source)
        self.assertIn('$lime = "green"', report.merged_source)
        self.assertIn('condition:', report.merged_source)
        self.assertEqual(report.status, 'requires_reissue')

    def test_condition_and_reference_interaction_only_appears_when_combined(self):
        """Each draft is explainable alone; the changed edge is coupled only after merging."""
        left_only = review_rules(COLOR_EDGE_BASE, COLOR_EDGE_LEFT, COLOR_EDGE_BASE)
        right_only = review_rules(COLOR_EDGE_BASE, COLOR_EDGE_BASE, COLOR_EDGE_RIGHT)
        combined = review_rules(COLOR_EDGE_BASE, COLOR_EDGE_LEFT, COLOR_EDGE_RIGHT)

        self.assertFalse(left_only.interactions)
        self.assertFalse(right_only.interactions)
        self.assertTrue(combined.interactions)

        interaction = combined.interactions[0]
        self.assertEqual(interaction.kind, 'dependency_interaction')
        self.assertEqual(interaction.expression, '$green')
        self.assertIn('combined draft', interaction.reason)
        self.assertTrue(any(item.kind == 'dependency_interaction' for item in combined.manual_review))

    def test_project_reference_interaction_only_appears_when_combined(self):
        """A new rule reference is coupled to a semantic change in that referenced rule."""
        left_only = review_rules(PROJECT_BASE, PROJECT_REFERENCE, PROJECT_BASE)
        right_only = review_rules(PROJECT_BASE, PROJECT_BASE, PROJECT_TARGET_CHANGE)
        combined = review_rules(PROJECT_BASE, PROJECT_REFERENCE, PROJECT_TARGET_CHANGE)

        self.assertFalse(left_only.interactions)
        self.assertFalse(right_only.interactions)
        self.assertTrue(combined.interactions)
        self.assertEqual(combined.interactions[0].rule, 'ColorProject')
        self.assertEqual(combined.interactions[0].expression, 'ProjectBeta')

    def test_unjudgeable_expression_remains_a_manual_item(self):
        """Unknown expressions are retained as one explicit human-review item."""
        report = review_rules(COLOR_OPAQUE, COLOR_OPAQUE, COLOR_OPAQUE)

        expression_items = [item for item in report.manual_review if item.kind == 'expression']
        self.assertEqual(len(expression_items), 1)
        self.assertIn('custom_colors.value', expression_items[0].expression)
        self.assertIn('unrecognized module', expression_items[0].reason)
        self.assertEqual(expression_items[0].side, 'combined')
        self.assertEqual(report.status, 'manual_review')

    def test_conflicting_conditions_and_strings_require_a_human(self):
        """Different structural edits to the same location are conflicts, not silent picks."""
        report = review_rules(COLOR_BASE, COLOR_CONDITION, COLOR_CONFLICT)

        self.assertTrue(report.conflicts)
        self.assertTrue(any(change.kind == 'condition' and change.action == 'conflict' for change in report.conflicts))
        self.assertTrue(any(item.kind == 'condition_conflict' for item in report.manual_review))
        self.assertEqual(report.status, 'conflict')

    def test_new_rule_requires_reissue(self):
        """A rule that has no approved ancestor must go through issuance."""
        new_rule = 'rule ColorPalette { strings: $blue = "blue" condition: $blue }\n'
        report = review_rules(COLOR_BASE, COLOR_BASE, COLOR_BASE + new_rule)

        added = [change for change in report.reissue if change.rule == 'ColorPalette']
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].action, 'add')

    def test_library_and_parser_entry_points(self):
        """Both public imports expose the same review result."""
        self.assertTrue(callable(plyara.review))
        library_report = plyara.review_rules(COLOR_BASE, COLOR_METADATA, COLOR_REFACTOR)
        module_report = plyara.review(COLOR_BASE, COLOR_METADATA, COLOR_REFACTOR)
        parser_report = plyara.Plyara().review(COLOR_BASE, COLOR_METADATA, COLOR_REFACTOR)

        self.assertEqual(library_report.status, parser_report.status)
        self.assertEqual(library_report.status, module_report.status)
        self.assertEqual(len(library_report.reissue), len(parser_report.reissue))


class TestReviewCLI(unittest.TestCase):
    """Check the command-line review entry point."""

    def test_review_subcommand_emits_json(self):
        """The CLI reads three files and emits the serialized report."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            base = root.joinpath('base.yar')
            left = root.joinpath('left.yar')
            right = root.joinpath('right.yar')
            base.write_text(COLOR_BASE)
            left.write_text(COLOR_METADATA)
            right.write_text(COLOR_REFACTOR)
            argv = ['plyara', 'review', str(base), str(left), str(right)]

            with unittest.mock.patch('sys.argv', argv):
                with unittest.mock.patch('argparse._sys.argv', argv):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        plyara.command_line.main()

        result = json.loads(output.getvalue())
        self.assertIn('mergeable', result)
        self.assertIn('reissue', result)
        self.assertIn('manual_review', result)
        self.assertEqual(result['rules']['Colors']['status'], 'requires_reissue')


if __name__ == '__main__':
    unittest.main()
