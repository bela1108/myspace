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

"""CycloneDX BOM adapter for physical-state reviews.

The adapter uses standard CycloneDX ``Property`` entries.  It never mutates the
input BOM; :func:`annotate_bom` returns a deep copy while the review result
keeps a reference to the original BOM.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Iterable, Optional, Union

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component

from .model import PhysicalStateEvent, PhysicalStateReview, SignedCommitment
from .reviewer import PhysicalStateReviewer

PROPERTY_NAMESPACE = 'physical-review'
P_EVIDENCE_ID = f'{PROPERTY_NAMESPACE}:evidence-id'
P_COMMITMENT_ID = f'{PROPERTY_NAMESPACE}:commitment-id'
P_KIND = f'{PROPERTY_NAMESPACE}:commitment-kind'
P_STATE = f'{PROPERTY_NAMESPACE}:state'
P_COVERAGE = f'{PROPERTY_NAMESPACE}:coverage'
P_ITEM_ID = f'{PROPERTY_NAMESPACE}:physical-item-id'
P_SEAL_ID = f'{PROPERTY_NAMESPACE}:seal-id'
P_MODEL = f'{PROPERTY_NAMESPACE}:physical-model'
P_SIGNED = f'{PROPERTY_NAMESPACE}:signed'
P_SIGNATURE_REF = f'{PROPERTY_NAMESPACE}:signature-ref'
P_BOM_REF = f'{PROPERTY_NAMESPACE}:bom-ref'
P_LAST_REASON = f'{PROPERTY_NAMESPACE}:last-reason'
P_LAST_SEQUENCE = f'{PROPERTY_NAMESPACE}:last-sequence'
P_RETEST_ID = f'{PROPERTY_NAMESPACE}:retest-id'


def _property_map(owner: object) -> dict[str, str]:
    result: dict[str, str] = {}
    for prop in getattr(owner, 'properties', None) or ():
        if prop.name and prop.value is not None:
            result.setdefault(prop.name, prop.value)
    return result


def _as_bool(value: Optional[str], *, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in {'0', 'false', 'no', 'off'}


def _walk_components(bom: Bom) -> Iterable[Component]:
    root_component = getattr(bom.metadata, 'component', None)
    if root_component is not None:
        yield from _component_tree(root_component)
    for component in bom.components or ():
        yield from _component_tree(component)


def _component_tree(component: Component) -> Iterable[Component]:
    yield component
    for child in getattr(component, 'components', None) or ():
        yield from _component_tree(child)


def _commitment_from_properties(
    props: dict[str, str],
    *,
    bom_ref: Optional[str],
    component_name: Optional[str] = None,
) -> Optional[SignedCommitment]:
    commitment_id = props.get(P_COMMITMENT_ID) or props.get(P_EVIDENCE_ID)
    if not commitment_id:
        return None
    if P_SIGNED in props and not _as_bool(props.get(P_SIGNED), default=True):
        return None
    return SignedCommitment(
        commitment_id=commitment_id,
        evidence_id=props.get(P_EVIDENCE_ID, ''),
        physical_item_id=props.get(P_ITEM_ID, ''),
        kind=props.get(P_KIND, 'custom'),
        state=props.get(P_STATE, 'established'),
        coverage=props.get(P_COVERAGE, 'full'),
        seal_id=props.get(P_SEAL_ID),
        bom_ref=props.get(P_BOM_REF) or bom_ref,
        component_name=component_name,
        physical_model=props.get(P_MODEL),
        signed=_as_bool(props.get(P_SIGNED), default=True),
        signature_ref=props.get(P_SIGNATURE_REF),
    )


def commitments_from_bom(bom: Bom) -> tuple[SignedCommitment, ...]:
    """Read signed commitments encoded as ``physical-review:*`` properties."""
    commitments: list[SignedCommitment] = []

    bom_commitment = _commitment_from_properties(_property_map(bom), bom_ref=None)
    if bom_commitment is not None:
        commitments.append(bom_commitment)

    for component in _walk_components(bom):
        bom_ref = component.bom_ref.value if component.bom_ref is not None else None
        commitment = _commitment_from_properties(
            _property_map(component),
            bom_ref=bom_ref,
            component_name=component.name,
        )
        if commitment is not None:
            commitments.append(commitment)

    return tuple(commitments)


def review_bom(
    bom: Bom,
    events: Iterable[Union[PhysicalStateEvent, dict[str, object]]],
    *,
    retests: Iterable[object] = (),
    commitments: Optional[Iterable[SignedCommitment]] = None,
) -> PhysicalStateReview:
    """Review a CycloneDX BOM without modifying it."""
    signed_commitments = tuple(commitments) if commitments is not None else commitments_from_bom(bom)
    return PhysicalStateReviewer(commitments=signed_commitments, retests=retests).review(
        events,
        source_bom=bom,
    )


def _component_by_bom_ref(bom: Bom) -> dict[str, Component]:
    result: dict[str, Component] = {}
    for component in _walk_components(bom):
        if component.bom_ref is not None and component.bom_ref.value:
            result[component.bom_ref.value] = component
    return result


def _append_properties(owner: object, new_properties: Iterable[Property]) -> None:
    existing = list(getattr(owner, 'properties', None) or ())
    owner.properties = [*existing, *new_properties]


def annotate_bom(review: PhysicalStateReview) -> Bom:
    """Return a deep-copied BOM annotated with final review states.

    The source BOM referenced by ``review.source_bom`` is not mutated.  If the
    review has no source BOM, a new empty BOM is returned.
    """
    annotated = Bom() if review.source_bom is None else deepcopy(review.source_bom)

    components = _component_by_bom_ref(annotated)
    for snapshot in review.states:
        commitment = next(
            (item for item in review.commitments if item.commitment_id == snapshot.commitment_id),
            None,
        )
        if commitment is None or not commitment.bom_ref:
            continue
        component = components.get(commitment.bom_ref)
        if component is None:
            continue
        props = [
            Property(name=P_STATE, value=snapshot.state.value),
            Property(name=P_COVERAGE, value=snapshot.coverage.value),
            Property(name=P_LAST_REASON, value=snapshot.reason),
        ]
        if snapshot.since_sequence is not None:
            props.append(Property(name=P_LAST_SEQUENCE, value=str(snapshot.since_sequence)))
        if snapshot.retest_id:
            props.append(Property(name=P_RETEST_ID, value=snapshot.retest_id))
        _append_properties(component, props)

    history = [
        {
            'sequence': item.sequence,
            'decisions': [
                {
                    'commitment_id': decision.commitment_id,
                    'before': decision.before.value,
                    'after': decision.after.value,
                    'disposition': decision.disposition.value,
                    'changed': decision.changed,
                    'reason': decision.reason,
                    'retest_id': decision.retest_id,
                }
                for decision in item.decisions
            ],
        }
        for item in review.sequence_reviews
    ]
    _append_properties(annotated, [
        Property(name=f'{PROPERTY_NAMESPACE}:final-states', value=json.dumps([
            {
                'commitment_id': item.commitment_id,
                'state': item.state.value,
                'coverage': item.coverage.value,
                'since_sequence': item.since_sequence,
                'reason': item.reason,
                'retest_id': item.retest_id,
            }
            for item in review.states
        ], ensure_ascii=False, sort_keys=True)),
        Property(name=f'{PROPERTY_NAMESPACE}:history', value=json.dumps(
            history, ensure_ascii=False, sort_keys=True,
        )),
    ])
    source = review.source_bom
    if isinstance(source, Bom):
        _append_properties(annotated, [
            Property(name=f'{PROPERTY_NAMESPACE}:source-bom-serial', value=str(source.serial_number)),
            Property(name=f'{PROPERTY_NAMESPACE}:source-bom-version', value=str(source.version)),
        ])
    return annotated


def reviewed_bom_json(review: PhysicalStateReview, *, indent: int = 2) -> str:
    """Serialize :func:`annotate_bom` with the offline JSON v1.6 output."""
    from cyclonedx.output.json import JsonV1Dot6

    return JsonV1Dot6(annotate_bom(review)).output_as_string(indent=indent)
