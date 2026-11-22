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

import json
import os
import random
import tempfile
from unittest import TestCase

from cyclonedx.timeline import audit_timelines


def bom(serial, timestamp, lifecycle, components=None):
    document = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': serial,
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'lifecycles': [{'name': lifecycle}],
        },
    }
    if components:
        document['components'] = components
    return document


def component(ref, name, occurrences=None, properties=None):
    result = {'bom-ref': ref, 'type': 'library', 'name': name, 'version': '1'}
    if properties:
        result['properties'] = properties
    if occurrences:
        result['evidence'] = {'occurrences': occurrences}
    return result


class TimelineAuditTestCase(TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)

    def write_json(self, name, document):
        path = os.path.join(self._temp.name, name)
        with open(path, 'w', encoding='utf-8') as stream:
            json.dump(document, stream)
        return path

    def test_date_only_allows_both_orders(self):
        delivery = self.write_json('delivery.json', bom(
            'urn:uuid:11111111-1111-4111-8111-111111111111', '2026-11-20', 'delivery',
        ))
        installation = self.write_json('installation.json', bom(
            'urn:uuid:22222222-2222-4222-8222-222222222222', '2026-11-20', 'installation',
        ))
        report = audit_timelines([delivery, installation]).to_json()
        self.assertTrue(report['consistent'])
        self.assertTrue(report['order']['ambiguous'])
        self.assertIn(
            ['bom:urn:uuid:11111111-1111-4111-8111-111111111111@1#manifest',
             'bom:urn:uuid:22222222-2222-4222-8222-222222222222@1#manifest'],
            report['order']['ambiguous'],
        )

    def test_reverse_claim_conflict_is_minimal(self):
        builder = self.write_json('builder.json', bom(
            'urn:uuid:11111111-1111-4111-8111-111111111111', '2026-11-20T09:00:00Z', 'delivery',
        ))
        installer = self.write_json('installer.json', bom(
            'urn:uuid:22222222-2222-4222-8222-222222222222', '2026-11-21T10:00:00Z', 'installation',
        ))
        unrelated = self.write_json('unrelated.json', bom(
            'urn:uuid:33333333-3333-4333-8333-333333333333', '2026-11-15T00:00:00Z', 'design',
        ))
        report = audit_timelines([builder, installer, unrelated], [
            {'before': 'phase:installation', 'after': 'phase:delivery', 'id': 'reverse'},
        ]).to_json()
        self.assertFalse(report['consistent'])
        conflict = report['minimalConflict']
        self.assertEqual(['reverse'], conflict['constraintIds'])
        self.assertEqual(['builder.json', 'installer.json'], conflict['sources'])
        self.assertNotIn('unrelated.json', conflict['sources'])

    def test_two_reverse_claims_have_order_cycle(self):
        delivery = self.write_json('delivery.json', bom(
            'urn:uuid:11111111-1111-4111-8111-111111111111', '2026-11-20', 'delivery',
        ))
        installation = self.write_json('installation.json', bom(
            'urn:uuid:22222222-2222-4222-8222-222222222222', '2026-11-20', 'installation',
        ))
        report = audit_timelines([delivery, installation], [
            {'before': 'phase:delivery', 'after': 'phase:installation', 'id': 'forward'},
            {'before': 'phase:installation', 'after': 'phase:delivery', 'id': 'reverse'},
        ]).to_json()
        self.assertFalse(report['consistent'])
        self.assertEqual(['forward', 'reverse'], report['minimalConflict']['constraintIds'])
        self.assertEqual('order-cycle', report['minimalConflict']['reason'])

    def test_evidence_ids_do_not_depend_on_load_order(self):
        paths = [
            self.write_json('a.json', bom(
                'urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '2026-11-20T09:00:00Z', 'delivery',
            )),
            self.write_json('b.json', bom(
                'urn:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '2026-11-21T09:00:00Z', 'installation',
            )),
            self.write_json('c.json', bom(
                'urn:uuid:cccccccc-cccc-4ccc-8ccc-cccccccccccc', '2026-11-19T09:00:00Z', 'build',
            )),
        ]
        constraints = [
            {'before': 'phase:delivery', 'after': 'phase:installation', 'id': 'forward'},
            {'before': 'phase:build', 'after': 'phase:delivery', 'id': 'build'},
        ]
        baseline = audit_timelines(paths, constraints).to_json()
        baseline_ids = [item['id'] for item in baseline['evidence']]
        for _ in range(5):
            shuffled = paths[:]
            random.shuffle(shuffled)
            shuffled_constraints = constraints[:]
            random.shuffle(shuffled_constraints)
            candidate = audit_timelines(shuffled, shuffled_constraints).to_json()
            self.assertEqual(baseline_ids, [item['id'] for item in candidate['evidence']])
            self.assertEqual(baseline['order']['entailed'], candidate['order']['entailed'])
            self.assertEqual(baseline['minimalConflicts'], candidate['minimalConflicts'])

    def test_component_and_occurrence_evidence(self):
        builder = self.write_json('builder.json', bom(
            'urn:uuid:11111111-1111-4111-8111-111111111111',
            '2026-11-20',
            'build',
            [component(
                'pkg:generic/widget@1',
                'widget',
                [{'bom-ref': 'occ-build', 'location': 'logs/build-2026-11-20.log'}],
                [{'name': 'event:timestamp', 'value': '2026-11-20T08:00:00Z'}],
            )],
        ))
        installer = self.write_json('installer.json', bom(
            'urn:uuid:22222222-2222-4222-8222-222222222222',
            '2026-11-21',
            'installation',
            [component(
                'pkg:generic/widget@1',
                'widget',
                [{'bom-ref': 'occ-install', 'location': 'logs/install-2026-11-21.log'}],
            )],
        ))
        report = audit_timelines([builder, installer], [
            {'before': 'component:pkg:generic/widget@1', 'after': 'occurrence:logs/install-2026-11-21.log'},
        ]).to_json()
        self.assertTrue(report['consistent'])
        self.assertTrue(report['order']['entailed'])
        self.assertTrue(report['witness'])

    def test_xml_input(self):
        folder = self._temp.name
        build_path = os.path.join(folder, 'build.xml')
        install_path = os.path.join(folder, 'install.xml')
        with open(build_path, 'w', encoding='utf-8') as stream:
            stream.write("""<?xml version='1.0' encoding='UTF-8'?>
<bom xmlns='http://cyclonedx.org/schema/bom/1.6'
     serialNumber='urn:uuid:55555555-5555-4555-8555-555555555555' version='1'>
  <metadata>
    <timestamp>2026-11-20</timestamp>
    <lifecycles><lifecycle><phase>build</phase></lifecycle></lifecycles>
  </metadata>
</bom>
""")
        with open(install_path, 'w', encoding='utf-8') as stream:
            stream.write("""<?xml version='1.0' encoding='UTF-8'?>
<bom xmlns='http://cyclonedx.org/schema/bom/1.6'
     serialNumber='urn:uuid:66666666-6666-4666-8666-666666666666' version='1'>
  <metadata>
    <timestamp>2026-11-21</timestamp>
    <lifecycles><lifecycle><name>installation</name></lifecycle></lifecycles>
  </metadata>
</bom>
""")
        report = audit_timelines([build_path, install_path], [
            {'before': 'phase:build', 'after': 'phase:installation'},
        ]).to_json()
        self.assertTrue(report['consistent'])
        self.assertEqual(2, report['bomCount'])
