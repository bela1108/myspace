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
from collections.abc import Iterator
from unittest import TestCase

from packageurl import PackageURL

from cyclonedx.model import Copyright, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.physical_review import (
    CommitmentKind,
    CommitmentState,
    IndependentRetest,
    PhysicalAction,
    PhysicalStateEvent,
    SignedCommitment,
    annotate_bom,
    commitments_from_bom,
    review_bom,
    review_physical_state,
    reviewed_bom_json,
)
from cyclonedx.physical_review.bom import P_STATE


def _all_components(bom: Bom) -> Iterator[Component]:
    def walk(component: Component) -> Iterator[Component]:
        yield component
        for child in component.components or ():
            yield from walk(child)

    if bom.metadata.component:
        yield from walk(bom.metadata.component)
    for component in bom.components:
        yield from walk(component)


class PhysicalStateReviewTest(TestCase):
    def setUp(self) -> None:
        self.software = Component(
            type=ComponentType.LIBRARY,
            group='acme.instruments',
            name='seal-agent',
            version='2.4.1',
            bom_ref='software/seal-agent@2.4.1',
            purl=PackageURL.from_string('pkg:pypi/seal-agent@2.4.1'),
            properties=[Property(name='canary', value='software-fields-preserved')],
        )
        self.instrument = Component(
            type=ComponentType.DEVICE,
            name='field-analyzer',
            version='9',
            bom_ref='instrument/analyzer-7',
        )
        self.evidence_components = [
            Component(
                type=ComponentType.DATA,
                name='signed initial inspection item',
                bom_ref='evidence/initial',
                evidence=ComponentEvidence(copyright=[Copyright(text='signed initial evidence')]),
                properties=[
                    Property(name='physical-review:evidence-id', value='E-INIT'),
                    Property(name='physical-review:commitment-id', value='C-INIT'),
                    Property(name='physical-review:commitment-kind',
                             value=CommitmentKind.INITIAL_INSPECTION_GUARANTEE.value),
                    Property(name='physical-review:physical-item-id', value='analyzer-7'),
                    Property(name='physical-review:signed', value='true'),
                ],
            ),
            Component(
                type=ComponentType.DATA,
                name='signed original seal approval',
                bom_ref='evidence/seal',
                evidence=ComponentEvidence(copyright=[Copyright(text='signed seal evidence')]),
                properties=[
                    Property(name='physical-review:evidence-id', value='E-SEAL'),
                    Property(name='physical-review:commitment-id', value='C-SEAL'),
                    Property(name='physical-review:commitment-kind',
                             value=CommitmentKind.SEAL_APPROVAL.value),
                    Property(name='physical-review:physical-item-id', value='filter-sn-new'),
                    Property(name='physical-review:seal-id', value='eseal-original'),
                    Property(name='physical-review:physical-model', value='filter-x'),
                    Property(name='physical-review:signed', value='true'),
                ],
            ),
            Component(
                type=ComponentType.DATA,
                name='signed repair guarantee item',
                bom_ref='evidence/repair',
                evidence=ComponentEvidence(copyright=[Copyright(text='signed repair evidence')]),
                properties=[
                    Property(name='physical-review:evidence-id', value='E-REPAIR'),
                    Property(name='physical-review:commitment-id', value='C-REPAIR'),
                    Property(name='physical-review:commitment-kind',
                             value=CommitmentKind.REPAIR_GUARANTEE.value),
                    Property(name='physical-review:state', value=CommitmentState.SUSPENDED.value),
                    Property(name='physical-review:physical-item-id', value='module-sn-repaired'),
                    Property(name='physical-review:repair-declaration-id', value='RD-7'),
                    Property(name='physical-review:coverage', value='partial'),
                    Property(name='physical-review:signed', value='true'),
                ],
            ),
        ]
        self.bom = Bom(components=[self.software, self.instrument, *self.evidence_components])

        self.events = [
            PhysicalStateEvent(
                sequence=1,
                action=PhysicalAction.SEAL_REPLACED,
                seal_id='eseal-original',
                physical_item_id='analyzer-7',
                note='electronic seal replaced',
            ),
            PhysicalStateEvent(
                sequence=2,
                action=PhysicalAction.REPAIR_DECLARED,
                physical_item_id='module-sn-repaired',
                repair_declaration_id='RD-7',
                retest=IndependentRetest(
                    retest_id='RT-MODULE-7',
                    physical_item_id='module-sn-repaired',
                    passed=True,
                    independent=True,
                    sequence=2,
                ),
            ),
            PhysicalStateEvent(
                sequence=3,
                action=PhysicalAction.ITEM_REINSTALLED,
                seal_id='eseal-original',
                physical_item_id='filter-sn-new',
                model='FILTER-X',
                note='same-model consumable installed back',
            ),
            PhysicalStateEvent(
                sequence=4,
                action=PhysicalAction.RETEST_RECORDED,
                seal_id='eseal-original',
                physical_item_id='filter-sn-new',
                retest=IndependentRetest(
                    retest_id='RT-FILTER-NEW',
                    physical_item_id='filter-sn-new',
                    seal_id='eseal-original',
                    passed=True,
                    independent=True,
                    sequence=4,
                ),
            ),
        ]

    def test_bom_properties_are_read_as_signed_commitments(self) -> None:
        commitments = commitments_from_bom(self.bom)
        self.assertEqual(
            {'C-INIT', 'C-SEAL', 'C-REPAIR'},
            {item.commitment_id for item in commitments},
        )
        seal = next(item for item in commitments if item.commitment_id == 'C-SEAL')
        self.assertEqual('eseal-original', seal.seal_id)
        self.assertEqual('filter-sn-new', seal.physical_item_id)
        self.assertEqual('evidence/seal', seal.bom_ref)

    def test_replacement_sequence_decides_each_promise(self) -> None:
        review = review_bom(
            self.bom,
            self.events,
            retests=[
                IndependentRetest(
                    retest_id='RT-FILTER-OLD-MODEL-MATCH-ONLY',
                    physical_item_id='filter-sn-old',
                    passed=True,
                    independent=True,
                    sequence=1,
                ),
            ],
        )

        self.assertEqual([1, 2, 3, 4], [item.sequence for item in review.sequence_reviews])

        initial = review.state_for('C-INIT')
        self.assertEqual(CommitmentState.INVALIDATED, initial.state)
        self.assertIn('pre-opening', initial.reason)

        repair = review.state_for('C-REPAIR')
        self.assertEqual(CommitmentState.REESTABLISHED, repair.state)
        self.assertEqual('partial', repair.coverage.value)
        self.assertEqual('RT-MODULE-7', repair.retest_id)

        sequence_three = review.sequence_reviews[2]
        seal_decision_three = next(
            item for item in sequence_three.decisions if item.commitment_id == 'C-SEAL'
        )
        self.assertEqual(CommitmentState.SUSPENDED, seal_decision_three.after)
        self.assertTrue(seal_decision_three.is_suspended)
        self.assertIsNone(seal_decision_three.retest_id)
        self.assertIn('same-model', seal_decision_three.reason)

        seal_final = review.state_for('C-SEAL')
        self.assertEqual(CommitmentState.REESTABLISHED, seal_final.state)
        self.assertEqual('RT-FILTER-NEW', seal_final.retest_id)

        sequence_four = review.sequence_reviews[3]
        self.assertEqual(1, len(sequence_four.reestablished))
        self.assertEqual('C-SEAL', sequence_four.reestablished[0].commitment_id)

    def test_same_model_or_non_independent_retest_cannot_restore(self) -> None:
        review = review_physical_state(
            commitments=[
                {
                    'commitment_id': 'SEAL-1',
                    'kind': CommitmentKind.SEAL_APPROVAL.value,
                    'physical_item_id': 'part-sn-1',
                    'physical_model': 'M-1',
                },
            ],
            events=[
                {
                    'sequence': 1,
                    'action': PhysicalAction.ITEM_REINSTALLED.value,
                    'physical_item_id': 'part-sn-1',
                    'model': 'M-1',
                },
            ],
            retests=[
                {
                    'retest_id': 'RT-OTHER-SERIAL',
                    'physical_item_id': 'part-sn-2',
                    'passed': True,
                    'independent': True,
                },
                {
                    'retest_id': 'RT-NOT-INDEPENDENT',
                    'physical_item_id': 'part-sn-1',
                    'passed': True,
                    'independent': False,
                },
            ],
        )

        state = review.state_for('SEAL-1')
        self.assertEqual(CommitmentState.SUSPENDED, state.state)
        self.assertIsNone(state.retest_id)

    def test_old_retest_does_not_cover_later_reinstall(self) -> None:
        review = review_physical_state(
            commitments=[
                SignedCommitment(
                    commitment_id='SEAL-1',
                    kind=CommitmentKind.SEAL_APPROVAL,
                    physical_item_id='part-sn-1',
                ),
            ],
            retests=[
                IndependentRetest(
                    retest_id='RT-OLD',
                    physical_item_id='part-sn-1',
                    passed=True,
                    sequence=1,
                ),
            ],
            events=[
                PhysicalStateEvent(sequence=1, action=PhysicalAction.RETEST_RECORDED,
                                   physical_item_id='part-sn-1', retest_id='RT-OLD'),
                PhysicalStateEvent(sequence=2, action=PhysicalAction.ITEM_REINSTALLED,
                                   physical_item_id='part-sn-1'),
            ],
        )

        self.assertEqual(
            CommitmentState.REESTABLISHED,
            review.sequence_reviews[0].decisions[0].after,
        )
        self.assertEqual(2, review.sequence_reviews[1].sequence)
        self.assertEqual(CommitmentState.SUSPENDED,
                         review.sequence_reviews[1].decisions[0].after)
        self.assertEqual(CommitmentState.SUSPENDED, review.state_for('SEAL-1').state)

    def test_original_bom_and_software_fields_survive_annotation_and_json_roundtrip(self) -> None:
        original_json = JsonV1Dot6(self.bom).output_as_string()
        review = review_bom(self.bom, self.events)
        annotated = annotate_bom(review)
        annotated_json = reviewed_bom_json(review)
        roundtrip = Bom.from_json(json.loads(annotated_json))

        self.assertIs(self.bom, review.source_bom)
        self.assertIs(self.bom, review.old_bom)
        self.assertIsNotNone(review.old_bom_json)
        self.assertEqual(original_json, JsonV1Dot6(self.bom).output_as_string())
        self.assertNotIn(P_STATE, {prop.name for prop in self.software.properties})

        software = next(
            component for component in _all_components(roundtrip)
            if component.bom_ref.value == 'software/seal-agent@2.4.1'
        )
        self.assertEqual(ComponentType.LIBRARY, software.type)
        self.assertEqual('acme.instruments', software.group)
        self.assertEqual('seal-agent', software.name)
        self.assertEqual('2.4.1', software.version)
        self.assertEqual('pkg:pypi/seal-agent@2.4.1', str(software.purl))
        self.assertEqual('software-fields-preserved',
                         next(prop.value for prop in software.properties if prop.name == 'canary'))

        seal_evidence = next(
            component for component in _all_components(roundtrip)
            if component.bom_ref.value == 'evidence/seal'
        )
        state_properties = [prop.value for prop in seal_evidence.properties if prop.name == P_STATE]
        self.assertEqual([CommitmentState.REESTABLISHED.value], state_properties)

        annotated_names = {prop.name for prop in annotated.properties}
        self.assertIn('physical-review:history', annotated_names)
        self.assertIn('physical-review:final-states', annotated_names)
        self.assertIn('physical-review:source-bom-serial', annotated_names)

    def test_review_json_is_serializable(self) -> None:
        review = review_bom(self.bom, self.events[:3])
        payload = json.loads(review.to_json())
        self.assertEqual(3, len(payload['sequence_reviews']))
        self.assertEqual('suspended', payload['states'][1]['state'])
