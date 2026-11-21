# This file is part of CycloneDX Python Library
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
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

from contextlib import redirect_stdout
from io import StringIO
from json import loads
from os import path
from unittest import TestCase

from packageurl import PackageURL

from cyclonedx.contrib.bom.compare import compare_manifests, load_manifest, main
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component

_TEST_DATA_DIRECTORY = path.join(path.dirname(__file__), '..', '_data')
COMPARE_DATA_DIRECTORY = path.join(_TEST_DATA_DIRECTORY, 'compare', '1.6')
BASELINE_FILE = path.join(COMPARE_DATA_DIRECTORY, 'baseline.json')
CURRENT_FILE = path.join(COMPARE_DATA_DIRECTORY, 'current.json')
XML_FILE = path.join(_TEST_DATA_DIRECTORY, 'own', 'xml', '1.6', 'component_evidence_identity.xml')


def _candidate_names(match_dict):
    return {candidate['component']['name'] for candidate in match_dict['candidates']}


def _candidate(match_dict, name):
    return next(c for c in match_dict['candidates'] if c['component']['name'] == name)


class TestManifestCompareFixtures(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = compare_manifests(BASELINE_FILE, CURRENT_FILE)
        cls.report_dict = cls.report.to_dict()

    def test_split_keeps_every_candidate_and_its_own_dependencies(self):
        match = self.report.match_for_bom_ref('widget-suite@1.4.0')
        self.assertIsNotNone(match)
        match_dict = match.to_dict()
        self.assertEqual('split', match_dict['status'])
        self.assertEqual('split', match_dict['relationship'])
        self.assertIsNone(match_dict['selected'])
        self.assertEqual({'widget-core', 'widget-ui'}, _candidate_names(match_dict))

        core = _candidate(match_dict, 'widget-core')
        ui = _candidate(match_dict, 'widget-ui')
        self.assertEqual({'parser-ng', 'codec-lib'},
                         {d['name'] for d in core['dependencies']['current']})
        self.assertEqual({'render-ui'},
                         {d['name'] for d in ui['dependencies']['current']})
        self.assertEqual({'legacy-parser', 'codec-lib'},
                         {d['name'] for d in core['dependencies']['baseline']})
        self.assertEqual({'legacy-parser', 'codec-lib'},
                         {d['name'] for d in ui['dependencies']['baseline']})
        self.assertEqual({'legacy-parser'},
                         {d['baseline_dependency']['name'] for d in core['dependencies']['transferred']})
        self.assertIn('no single component was selected', ' '.join(match_dict['notes']))

    def test_repackaged_component_is_selected_by_hash(self):
        match = self.report.match_for_bom_ref('legacy-parser@1.2.0')
        self.assertIsNotNone(match)
        match_dict = match.to_dict()
        self.assertEqual('matched', match_dict['status'])
        self.assertEqual('repackaged', match_dict['relationship'])
        self.assertEqual('parser-ng', match_dict['selected']['name'])
        candidate = _candidate(match_dict, 'parser-ng')
        self.assertIn('hash', candidate['stages'])
        self.assertEqual('SHA-256', candidate['hash_matches'][0]['algorithm'])
        self.assertTrue(candidate['hash_matches'][0]['format_valid'])

    def test_conflicting_evidence_does_not_select_a_favourite(self):
        match = self.report.match_for_bom_ref('telemetry@1.0.0')
        self.assertIsNotNone(match)
        match_dict = match.to_dict()
        self.assertEqual('conflict', match_dict['status'])
        self.assertEqual('unresolved', match_dict['relationship'])
        self.assertIsNone(match_dict['selected'])
        self.assertEqual({'telemetry', 'telemetry-loader'}, _candidate_names(match_dict))
        self.assertEqual(['telemetry-loader@2.0.0'], match_dict['stage_candidates']['hash'])
        self.assertEqual(['telemetry@1.0.0'], match_dict['stage_candidates']['coordinates'])
        self.assertEqual(['telemetry-loader@2.0.0', 'telemetry@1.0.0'],
                         match_dict['stage_candidates']['evidence'])

    def test_same_name_without_other_evidence_is_not_matched(self):
        match = self.report.match_for_bom_ref('opaque@1.0.0')
        self.assertIsNotNone(match)
        match_dict = match.to_dict()
        self.assertEqual('unmatched', match_dict['status'])
        self.assertEqual('removed', match_dict['relationship'])
        self.assertEqual([], match_dict['candidates'])

    def test_dependency_transfer_is_reported(self):
        transfers = self.report_dict['dependency_transfers']
        matching = [
            transfer for transfer in transfers
            if transfer['baseline_dependency']['name'] == 'legacy-parser'
            and transfer['current_dependency']['name'] == 'parser-ng'
        ]
        self.assertTrue(matching)
        self.assertEqual({'demo-app', 'widget-core'},
                         {transfer['current_parent']['name'] for transfer in matching})
        self.assertEqual({'repackaged'}, {transfer['via'] for transfer in matching})

    def test_old_alerts_trace_to_still_possible_current_components(self):
        split_alert = self.report.trace_for_vulnerability('CVE-2026-1001')[0]
        self.assertFalse(split_alert['vulnerability']['still_present_in_current_manifest'])
        split_target = split_alert['targets'][0]
        self.assertEqual('split', split_target['status'])
        split_candidates = {c['component']['name']: c for c in split_target['candidates']}
        self.assertEqual({'widget-core', 'widget-ui'}, set(split_candidates))
        for candidate in split_candidates.values():
            self.assertTrue(candidate['may_affect'])
            self.assertTrue(candidate['reachable'])
            self.assertEqual('demo-app', candidate['dependency_paths'][0][0]['name'])

        parser_alert = self.report.trace_for_vulnerability('CVE-2026-1002')[0]
        parser_candidates = parser_alert['targets'][0]['candidates']
        self.assertEqual(['parser-ng'], [c['component']['name'] for c in parser_candidates])
        self.assertEqual('selected', parser_candidates[0]['selection'])

        telemetry_alert = self.report.trace_for_vulnerability('CVE-2026-1003')[0]
        telemetry_target = telemetry_alert['targets'][0]
        self.assertEqual('conflict', telemetry_target['status'])
        self.assertEqual({'telemetry', 'telemetry-loader'},
                         {c['component']['name'] for c in telemetry_target['candidates']})
        for candidate in telemetry_target['candidates']:
            self.assertEqual('unresolved-candidate', candidate['selection'])

    def test_cli_writes_machine_readable_report(self):
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([BASELINE_FILE, CURRENT_FILE])
        self.assertEqual(0, exit_code)
        report = loads(output.getvalue())
        self.assertEqual('cyclonedx-manifest-comparison/1', report['schema'])
        self.assertEqual(3, report['summary']['alerts_traced'])
        self.assertEqual(1, report['summary']['split'])
        self.assertEqual(1, report['summary']['conflict'])

    def test_identical_manifest_matches_itself(self):
        report = compare_manifests(BASELINE_FILE, BASELINE_FILE)
        self.assertEqual({'matched'}, {match.status for match in report.matches})
        self.assertEqual(3, report.to_dict()['summary']['alerts_traced'])

    def test_hash_algorithm_and_digest_are_normalized_for_matching(self):
        baseline = Bom(components=[Component(
            name='normalized-hash', version='1.0.0',
            purl=PackageURL(type='generic', name='normalized-hash', version='1.0.0'),
            hashes=[HashType(alg=HashAlgorithm.SHA_256, content='A' * 64)],
        )])
        current = Bom(components=[Component(
            name='normalized-hash', version='1.0.0',
            purl=PackageURL(type='generic', name='normalized-hash', version='1.0.0'),
            hashes=[HashType(alg=HashAlgorithm.SHA_256, content='a' * 64)],
        )])
        match = compare_manifests(baseline, current).matches[0]
        match_dict = match.to_dict()
        self.assertEqual('matched', match_dict['status'])
        self.assertEqual('unchanged', match_dict['relationship'])
        self.assertEqual('SHA-256', match_dict['candidates'][0]['hash_matches'][0]['algorithm'])
        self.assertTrue(match_dict['candidates'][0]['hash_matches'][0]['format_valid'])


class TestManifestLoading(TestCase):

    def test_json_manifest_is_loaded(self):
        manifest = load_manifest(BASELINE_FILE)
        self.assertIsInstance(manifest, Bom)
        self.assertIsNotNone(manifest.metadata.component)

    def test_xml_manifest_is_loaded_without_extension_hint(self):
        manifest = load_manifest(XML_FILE)
        self.assertIsInstance(manifest, Bom)
        self.assertGreaterEqual(len(manifest.components), 2)
