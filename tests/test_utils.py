# Copyright 2014 Christian Buia
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
"""Unit tests for plyara utility functions."""
import importlib.resources
import pathlib
import tempfile
import unittest

import plyara.core
from plyara.handoff import build_rule_handoff_plan
from plyara.handoff import check_rule_identities
from plyara.handoff import rule_identity
from plyara.utils import generate_hash
from plyara.utils import rebuild_yara_rule


class TestUtilities(unittest.TestCase):
    """Check the various utility functions."""

    def setUp(self):
        """Prepare for utility unit testing."""
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.utils')
        self.imports = importlib.resources.files('tests.data.imports')
        self.common = importlib.resources.files('tests.data.common')
        # self.maxDiff = None

    def test_generate_hash(self):
        input_string = self.data.joinpath('logic_collision_ruleset.yar').read_text()

        result = plyara.core.Plyara().parse_string(input_string)

        rule_mapping = {}

        for entry in result:
            rulename = entry['rule_name']
            setname, _ = rulename.split('_')
            rulehash = generate_hash(entry)

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():
            self.assertTrue(len(set(hashvalues)) == 1, 'Collision detection failure for {}'.format(setname))

    def test_generate_hash_output_legacy(self):
        rule_hashes = self.data.joinpath('rulehashes_legacy.txt').read_text().splitlines()
        # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result, legacy=True)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_generate_hash_output(self):
        rule_hashes = self.data.joinpath('rulehashes.txt').read_text().splitlines()
        # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_rebuild_yara_rule(self):
        input_string = self.data.joinpath('rebuild_ruleset.yar').read_text(encoding='utf-8')
        test_result = self.data.joinpath('rebuild_ruleset_good_enough.yar').read_text(encoding='utf-8')

        result = plyara.core.Plyara().parse_string(input_string)

        rebuilt_rules = str()
        for rule in result:
            rebuilt_rules += rebuild_yara_rule(rule)

        self.assertEqual(test_result, rebuilt_rules)

    def test_rebuild_yara_rule_metadata(self):
        test_rule = """
        rule check_meta {
            meta:
                string_value = "TEST STRING"
                string_value = "DIFFERENT TEST STRING"
                bool_value = true
                bool_value = false
                digit_value = 5
                digit_value = 10
            condition:
                true
        }
        """
        parsed = plyara.core.Plyara().parse_string(test_rule)
        for rule in parsed:
            unparsed = rebuild_yara_rule(rule)
            self.assertIn('string_value = "TEST STRING"', unparsed)
            self.assertIn('string_value = "DIFFERENT TEST STRING"', unparsed)
            self.assertIn('bool_value = true', unparsed)
            self.assertIn('bool_value = false', unparsed)
            self.assertIn('digit_value = 5', unparsed)
            self.assertIn('digit_value = 10', unparsed)

    def test_rule_handoff_plan_keeps_same_named_rules_distinct(self):
        alpha_rules = '''
        private rule shared_name : detection {
            meta:
                author = "Same Supplier Author"
            condition:
                true
        }
        '''
        beta_rules = '''
        global rule shared_name : triage {
            meta:
                author = "Same Supplier Author"
            condition:
                true
        }
        '''
        maintainers = [
            {
                'name': 'alpha-private-owner',
                'sources': ['supplier-alpha'],
                'scopes': ['private'],
                'tags': ['detection'],
            },
            {
                'name': 'beta-global-owner',
                'sources': ['supplier-beta'],
                'scopes': ['global'],
                'tags': ['triage'],
            },
            {
                'name': 'Same Supplier Author',
                'sources': ['unrelated-space'],
            },
        ]

        with tempfile.TemporaryDirectory() as temp_directory:
            alpha_path = pathlib.Path(temp_directory, 'alpha.yar')
            beta_path = pathlib.Path(temp_directory, 'beta.yar')
            alpha_path.write_text(alpha_rules)
            beta_path.write_text(beta_rules)

            result = build_rule_handoff_plan(
                {
                    'supplier-alpha': alpha_path,
                    'supplier-beta': beta_path,
                },
                maintainers=maintainers,
            )

        self.assertEqual(2, len(result['handoff_plan']))
        self.assertEqual(list(), result['conflicts'])
        self.assertEqual(2, len(result['new_identities']))

        alpha_entry, beta_entry = result['handoff_plan']
        self.assertEqual('supplier-alpha', alpha_entry['publication_space'])
        self.assertEqual('supplier-beta', beta_entry['publication_space'])
        self.assertEqual('Same Supplier Author', alpha_entry['author'])
        self.assertEqual('Same Supplier Author', beta_entry['author'])
        self.assertNotIn('Same Supplier Author', alpha_entry['eligible_maintainers'])
        self.assertNotIn('Same Supplier Author', beta_entry['eligible_maintainers'])
        self.assertEqual(['alpha-private-owner'], alpha_entry['eligible_maintainers'])
        self.assertEqual(['beta-global-owner'], beta_entry['eligible_maintainers'])
        self.assertEqual('ready', alpha_entry['status'])
        self.assertEqual('ready', beta_entry['status'])

        self.assertEqual(
            'supplier-alpha|shared_name|private|detection',
            alpha_entry['pre_handoff_identity']['identity_key'],
        )
        self.assertEqual(
            'supplier-beta|shared_name|global|triage',
            beta_entry['pre_handoff_identity']['identity_key'],
        )
        self.assertNotEqual(
            alpha_entry['pre_handoff_identity']['identity_fingerprint'],
            beta_entry['pre_handoff_identity']['identity_fingerprint'],
        )
        self.assertEqual(
            'shared_name|private|detection',
            alpha_entry['post_handoff_identity']['identity_key'],
        )
        self.assertEqual(
            'shared_name|global|triage',
            beta_entry['post_handoff_identity']['identity_key'],
        )

        post_handoff_identities = [
            entry['post_handoff_identity'] for entry in result['handoff_plan']
        ]
        repeat_check = check_rule_identities(
            post_handoff_identities,
            known_identities=result['identity_registry'],
        )
        self.assertEqual(list(), repeat_check['conflicts'])
        self.assertEqual(list(), repeat_check['new_identities'])
        self.assertEqual(
            sorted(entry['identity_key'] for entry in post_handoff_identities),
            sorted(repeat_check['registry_hits']),
        )
        self.assertEqual(result['identity_registry'], repeat_check['identity_registry'])

    def test_rule_handoff_reports_duplicate_and_missing_maintainer(self):
        rules = '''
        rule shared_name : detection {
            meta:
                author = "Same Supplier Author"
            condition:
                true
        }
        rule shared_name : detection {
            meta:
                author = "Same Supplier Author"
            condition:
                true
        }
        rule other_name : triage {
            condition:
                true
        }
        '''

        with tempfile.TemporaryDirectory() as temp_directory:
            source_path = pathlib.Path(temp_directory, 'rules.yar')
            source_path.write_text(rules)
            result = build_rule_handoff_plan({'supplier-alpha': source_path})

        self.assertEqual(1, len(result['conflicts']))
        self.assertEqual(
            'shared_name||detection', result['conflicts'][0]['identity_key']
        )
        self.assertEqual('duplicate_in_batch', result['conflicts'][0]['reason'])
        conflict_entries = [entry for entry in result['handoff_plan'] if entry['status'] == 'conflict']
        self.assertEqual(2, len(conflict_entries))
        self.assertEqual('blocked', result['handoff_plan'][2]['status'])
        self.assertIsNone(result['handoff_plan'][2]['assigned_maintainer'])

    def test_rule_identity_uses_name_tags_and_scopes_not_author(self):
        first_rule = plyara.core.Plyara().parse_string('''
        private rule shared_name : detection {
            meta:
                author = "First Author"
            condition:
                true
        }
        ''')[0]
        second_rule = plyara.core.Plyara().parse_string('''
        private rule shared_name : detection {
            meta:
                author = "Second Author"
            condition:
                true
        }
        ''')[0]

        first_identity = rule_identity(first_rule)
        second_identity = rule_identity(second_rule)
        check = check_rule_identities([first_identity, second_identity])

        self.assertEqual(1, len(check['conflicts']))
        self.assertEqual(first_identity['identity_key'], check['conflicts'][0]['identity_key'])

    def test_existing_identity_is_a_registry_hit_without_a_new_conflict(self):
        rules = '''
        rule shared_name : detection {
            condition:
                true
        }
        '''

        with tempfile.TemporaryDirectory() as temp_directory:
            source_path = pathlib.Path(temp_directory, 'rules.yar')
            source_path.write_text(rules)
            first_intake = build_rule_handoff_plan({'supplier-alpha': source_path})
            second_intake = build_rule_handoff_plan(
                {'supplier-alpha': source_path},
                known_identities=first_intake['identity_registry'],
            )

        self.assertEqual(list(), second_intake['conflicts'])
        self.assertEqual(list(), second_intake['new_identities'])
        self.assertEqual(1, len(second_intake['registry_hits']))
        self.assertEqual('registry_hit', second_intake['handoff_plan'][0]['status'])


if __name__ == '__main__':
    unittest.main()
