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
from json import loads as json_loads
from pathlib import Path
from typing import Any, Dict, List
from unittest import TestCase

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import ComponentType
from cyclonedx.output.json import JsonV1Dot7
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from examples.key_module_recall.asset_inventory import (
    AssetEntry,
    LifecycleKind,
    SealRecord,
    build_sbom,
    index_entries,
    load_asset_inventory,
)
from examples.key_module_recall.reconcile import (
    CoverageStatus,
    load_disposition_list,
    reconcile,
)
from examples.key_module_recall.replacement_policy import (
    build_replacement_index,
    build_reverse_replacement_index,
    load_replacement_policy,
)

DATA_DIR = Path(__file__).parents[2] / 'examples' / 'key_module_recall' / 'data'


class KeyModuleRecallTest(TestCase):

    def setUp(self) -> None:
        self.entries = load_asset_inventory(DATA_DIR / 'asset_inventory.json')
        self.rules = load_replacement_policy(DATA_DIR / 'replacement_policy.json')
        self.dispositions = load_disposition_list(DATA_DIR / 'disposition_list.json')
        self.bom = build_sbom(self.entries)

    def test_types_and_lifecycles_come_from_inventory(self) -> None:
        by_ref = {entry.bom_ref: entry for entry in self.entries}
        self.assertEqual(by_ref['device-alpha'].component_type, ComponentType.DEVICE)
        self.assertEqual(
            by_ref['module-alpha'].component_type,
            ComponentType.CRYPTOGRAPHIC_ASSET,
        )
        self.assertEqual(by_ref['spare-k100-shared'].lifecycle, LifecycleKind.SEALED)
        self.assertIsNotNone(by_ref['spare-k100-shared'].seal)

    def test_json_round_trip_preserves_type_lifecycle_and_seal(self) -> None:
        serialized = JsonV1Dot7(self.bom).output_as_string()
        validation_error = JsonStrictValidator(SchemaVersion.V1_7).validate_str(serialized)
        self.assertIsNone(validation_error)

        reparsed = Bom.from_json(json_loads(serialized))  # type: ignore[attr-defined]
        re_serialized = JsonV1Dot7(reparsed).output_as_string()
        self.assertEqual(json_loads(re_serialized), json_loads(serialized))

        indexed = index_entries(reparsed)
        spare = indexed['spare-k100-shared']
        self.assertEqual(spare.component_type, ComponentType.CRYPTOGRAPHIC_ASSET)
        self.assertEqual(spare.lifecycle, LifecycleKind.SEALED)
        self.assertIsNotNone(spare.seal)
        self.assertEqual(spare.seal.seal_id, 'WHS-SEAL-2026-0441')
        self.assertEqual(indexed['module-alpha'].lifecycle, LifecycleKind.INSTALLED)
        self.assertEqual(indexed['module-alpha'].parent_ref, 'device-alpha')

    def test_replacement_limits_only_come_from_independent_policy(self) -> None:
        forward = build_replacement_index(self.rules)
        reverse = build_reverse_replacement_index(self.rules)
        self.assertEqual(
            forward['module-alpha'], {'spare-k100-shared'}
        )
        self.assertEqual(
            reverse['spare-k100-shared'], {'module-alpha', 'module-bravo'}
        )
        # The shared spare exists once in the BOM even though it serves two devices.
        spare_components = [
            component for component in self.bom.components
            if component.bom_ref.value == 'spare-k100-shared'
        ]
        self.assertEqual(len(spare_components), 1)

    def test_report_marks_pending_device_and_covered_device(self) -> None:
        report = reconcile(self.bom, self.rules, self.dispositions)
        self.assertFalse(report.is_complete)
        self.assertEqual(report.pending_device_refs, ['device-alpha'])
        self.assertEqual(report.covered_device_refs, ['device-bravo'])

        statuses = {item.bom_ref: item.status for item in report.item_results}
        self.assertEqual(statuses['device-alpha'], CoverageStatus.PENDING_RECALL)
        self.assertEqual(statuses['device-bravo'], CoverageStatus.DEVICE_RECALLED)
        self.assertEqual(statuses['module-alpha'], CoverageStatus.INSTALLATION_PENDING)
        self.assertEqual(statuses['module-bravo'], CoverageStatus.INSTALLATION_COVERED)
        self.assertEqual(statuses['spare-k100-shared'], CoverageStatus.SEALED_PENDING)

    def test_seal_only_proves_current_unavailability(self) -> None:
        report = reconcile(self.bom, self.rules, self.dispositions)
        self.assertEqual(report.seal_only_refs, ['spare-k100-shared'])
        spare = next(
            item for item in report.item_results if item.bom_ref == 'spare-k100-shared'
        )
        self.assertTrue(spare.sealed)
        self.assertFalse(spare.recall_listed)
        self.assertTrue(
            any('does not satisfy the recall requirement' in note for note in spare.notes)
        )

    def test_sealed_spare_becomes_complete_only_when_disposition_recalls_it(self) -> None:
        full_dispositions = self.dispositions + [
            type(self.dispositions[0])(  # type: ignore[call-arg]
                bom_ref='spare-k100-shared',
                disposition='recalled',
                reference='RC-2026-1199',
            ),
            type(self.dispositions[0])(
                bom_ref='device-alpha',
                disposition='recalled',
                reference='RC-2026-1199',
            ),
            type(self.dispositions[0])(
                bom_ref='module-alpha',
                disposition='recalled',
                reference='RC-2026-1199',
            ),
        ]
        report = reconcile(self.bom, self.rules, full_dispositions)
        statuses = {item.bom_ref: item.status for item in report.item_results}
        self.assertEqual(
            statuses['spare-k100-shared'], CoverageStatus.SEALED_AND_RECALLED
        )
        self.assertTrue(report.is_complete)
        self.assertEqual(report.seal_only_refs, [])

    def test_unknown_references_are_reported_not_silently_accepted(self) -> None:
        bad_dispositions = self.dispositions + [
            type(self.dispositions[0])(
                bom_ref='ghost-module',
                disposition='recalled',
            )
        ]
        report = reconcile(self.bom, self.rules, bad_dispositions)
        self.assertEqual(report.unknown_disposition_refs, ['ghost-module'])

    def test_sealed_spare_without_replacement_rule_is_out_of_scope(self) -> None:
        unrelated = AssetEntry(
            bom_ref='spare-unrelated',
            name='Sealed spare for another product line',
            component_type=ComponentType.CRYPTOGRAPHIC_ASSET,
            lifecycle=LifecycleKind.SEALED,
            seal=SealRecord(
                seal_id='WHS-SEAL-OTHER',
                location='Warehouse B',
                sealed_since='2026-09-01',
            ),
        )
        bom = build_sbom(self.entries + [unrelated])
        report = reconcile(bom, self.rules, self.dispositions)
        result = next(
            item for item in report.item_results if item.bom_ref == 'spare-unrelated'
        )
        self.assertEqual(result.status, CoverageStatus.SEALED_OUT_OF_SCOPE)
        self.assertIn('spare-unrelated', report.seal_only_refs)
        self.assertEqual(result.replaceable_for, [])

    def test_report_json_is_serializable(self) -> None:
        report = reconcile(self.bom, self.rules, self.dispositions)
        encoded: Dict[str, Any] = report.to_json()
        # Round-trip through plain JSON to guarantee a stable external contract.
        self.assertEqual(json.loads(json.dumps(encoded)), encoded)
        self.assertIsInstance(encoded['items'], list)

    def test_demo_data_files_are_consistent(self) -> None:
        inventory_doc = json.loads(
            (DATA_DIR / 'asset_inventory.json').read_text(encoding='utf-8')
        )
        inventory_refs: List[str] = [
            asset['bomRef'] for asset in inventory_doc['assets']
        ]
        policy_doc = json.loads(
            (DATA_DIR / 'replacement_policy.json').read_text(encoding='utf-8')
        )
        for rule in policy_doc['replacementRules']:
            self.assertIn(rule['installedRef'], inventory_refs)
            self.assertIn(rule['spareRef'], inventory_refs)
