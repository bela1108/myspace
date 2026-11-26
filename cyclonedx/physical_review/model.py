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

"""Domain objects for physical-state review of signed evidence line items."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, FrozenSet, Mapping, Optional, Tuple, Union


class CommitmentKind(str, Enum):
    """Kinds of promises attached to signed evidence."""

    INITIAL_INSPECTION_GUARANTEE = 'initial_inspection_guarantee'
    SEAL_APPROVAL = 'seal_approval'
    REPAIR_GUARANTEE = 'repair_guarantee'
    CUSTOM = 'custom'


class CommitmentState(str, Enum):
    """Review state of one promise.

    ``INVALIDATED`` is also exposed as common synonyms.  The serialized value
    remains stable at ``invalidated``.
    """

    ESTABLISHED = 'established'
    INVALIDATED = 'invalidated'
    SUSPENDED = 'suspended'
    REESTABLISHED = 'reestablished'

    REVOKED = 'invalidated'
    INVALID = 'invalidated'
    PENDING = 'suspended'
    RESTORED = 'reestablished'
    REINSTATED = 'reestablished'


class ReviewDisposition(str, Enum):
    """The decision applied at one replacement sequence."""

    UNCHANGED = 'unchanged'
    INVALIDATE = 'invalidated'
    SUSPEND = 'suspended'
    REESTABLISH = 'reestablished'

    REVOKE = 'invalidated'
    RESTORE = 'reestablished'
    REINSTATE = 'reestablished'


class Coverage(str, Enum):
    """Coverage of a guarantee after review."""

    FULL = 'full'
    PARTIAL = 'partial'
    NONE = 'none'


class PhysicalAction(str, Enum):
    """Physical intervention in replacement order."""

    SEAL_REPLACED = 'seal_replaced'
    SEAL_BROKEN = 'seal_broken'
    ITEM_REMOVED = 'item_removed'
    ITEM_INSTALLED = 'item_installed'
    ITEM_REINSTALLED = 'item_reinstalled'
    REPAIR_DECLARED = 'repair_declared'
    RETEST_RECORDED = 'retest_recorded'
    REVIEW_REQUESTED = 'review_requested'


def _enum_value(value: Any, enum_type: type[Enum], default: Enum) -> Enum:
    if isinstance(value, enum_type):
        return value
    if value is None:
        return default
    try:
        return enum_type(str(value))
    except ValueError:
        names = {name.lower(): member for name, member in enum_type.__members__.items()}
        member = names.get(str(value).lower())
        if member is not None:
            return member
        raise


@dataclass(frozen=True)
class IndependentRetest:
    """An independent retest tied to one physical instance.

    Model or part-number equality is never enough to associate a retest with a
    promise.  ``physical_item_id`` must identify the actual serialized object.
    """

    physical_item_id: str = ''
    passed: bool = False
    independent: bool = True
    retest_id: str = ''
    sequence: Optional[int] = None
    seal_id: Optional[str] = None
    report_ref: Optional[str] = None
    tester_id: Optional[str] = None
    repair_declaration_id: Optional[str] = None
    covers: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.physical_item_id:
            raise ValueError('physical_item_id is required for an independent retest')
        if isinstance(self.covers, str):
            object.__setattr__(self, 'covers', frozenset({self.covers}))
        else:
            object.__setattr__(self, 'covers', frozenset(self.covers or ()))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> 'IndependentRetest':
        aliases = ('item_id', 'physical_id', 'serial', 'serial_number')
        item_id = data.get('physical_item_id') or next((data[key] for key in aliases if data.get(key)), '')
        covers = data.get('covers') or data.get('cover') or frozenset()
        return cls(
            physical_item_id=str(item_id),
            passed=bool(data.get('passed', False)),
            independent=bool(data.get('independent', True)),
            retest_id=str(data.get('retest_id') or data.get('id') or ''),
            sequence=data.get('sequence'),
            seal_id=data.get('seal_id'),
            report_ref=data.get('report_ref') or data.get('report'),
            tester_id=data.get('tester_id') or data.get('reviewer'),
            repair_declaration_id=data.get('repair_declaration_id') or data.get('repair_id'),
            covers=frozenset(covers) if not isinstance(covers, str) else frozenset({covers}),
        )


@dataclass(frozen=True)
class SignedCommitment:
    """One promise contained in signed itemized evidence."""

    commitment_id: str
    evidence_id: str = ''
    physical_item_id: str = ''
    kind: Union[CommitmentKind, str] = CommitmentKind.CUSTOM
    state: Union[CommitmentState, str] = CommitmentState.ESTABLISHED
    coverage: Union[Coverage, str] = Coverage.FULL
    seal_id: Optional[str] = None
    bom_ref: Optional[str] = None
    component_name: Optional[str] = None
    physical_model: Optional[str] = None
    repair_declaration_id: Optional[str] = None
    signed: bool = True
    signature_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.commitment_id:
            raise ValueError('commitment_id is required')
        object.__setattr__(self, 'kind', _enum_value(self.kind, CommitmentKind, CommitmentKind.CUSTOM))
        object.__setattr__(self, 'state', _enum_value(self.state, CommitmentState, CommitmentState.ESTABLISHED))
        object.__setattr__(self, 'coverage', _enum_value(self.coverage, Coverage, Coverage.FULL))

    @property
    def component_ref(self) -> Optional[str]:
        return self.bom_ref

    @property
    def item_id(self) -> str:
        return self.physical_item_id

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> 'SignedCommitment':
        item_id = (
            data.get('physical_item_id')
            or data.get('item_id')
            or data.get('physical_id')
            or data.get('serial_number')
            or ''
        )
        return cls(
            commitment_id=str(data.get('commitment_id') or data.get('id') or data.get('evidence_id') or ''),
            evidence_id=str(data.get('evidence_id') or ''),
            physical_item_id=str(item_id),
            kind=data.get('kind') or CommitmentKind.CUSTOM,
            state=data.get('state') or data.get('initial_state') or CommitmentState.ESTABLISHED,
            coverage=data.get('coverage') or Coverage.FULL,
            seal_id=data.get('seal_id'),
            bom_ref=data.get('bom_ref') or data.get('component_ref') or data.get('ref'),
            component_name=data.get('component_name') or data.get('name'),
            physical_model=data.get('physical_model') or data.get('model'),
            repair_declaration_id=data.get('repair_declaration_id') or data.get('repair_id'),
            signed=bool(data.get('signed', True)),
            signature_ref=data.get('signature_ref') or data.get('signature_id') or data.get('signature'),
        )


@dataclass(frozen=True)
class PhysicalStateEvent:
    """One ordered event in the electronic-seal/replacement sequence."""

    sequence: int
    action: Union[PhysicalAction, str] = PhysicalAction.SEAL_REPLACED
    physical_item_id: Optional[str] = None
    item_id: Optional[str] = None
    installed_item_id: Optional[str] = None
    removed_item_id: Optional[str] = None
    seal_id: Optional[str] = None
    instrument_id: Optional[str] = None
    model: Optional[str] = None
    note: Optional[str] = None
    repair_declaration_id: Optional[str] = None
    retest_id: Optional[str] = None
    retest: Optional[IndependentRetest] = None
    commitment_ids: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, 'action', _enum_value(self.action, PhysicalAction, PhysicalAction.SEAL_REPLACED))
        ids = set(self.commitment_ids or ())
        if isinstance(self.commitment_ids, str):
            ids = {self.commitment_ids}
        object.__setattr__(self, 'commitment_ids', frozenset(ids))
        if self.physical_item_id is None and self.item_id is not None:
            object.__setattr__(self, 'physical_item_id', self.item_id)

    @property
    def affected_item_ids(self) -> FrozenSet[str]:
        return frozenset(value for value in (
            self.physical_item_id,
            self.item_id,
            self.installed_item_id,
            self.removed_item_id,
        ) if value)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> 'PhysicalStateEvent':
        retest_data = data.get('retest')
        retest = IndependentRetest.from_mapping(retest_data) if isinstance(retest_data, Mapping) else retest_data
        ids = data.get('commitment_ids') or data.get('commitments') or frozenset()
        return cls(
            sequence=int(data['sequence']),
            action=data.get('action') or data.get('type') or PhysicalAction.SEAL_REPLACED,
            physical_item_id=data.get('physical_item_id') or data.get('item_id'),
            installed_item_id=data.get('installed_item_id'),
            removed_item_id=data.get('removed_item_id'),
            seal_id=data.get('seal_id'),
            instrument_id=data.get('instrument_id'),
            model=data.get('model') or data.get('physical_model'),
            note=data.get('note') or data.get('reason_note'),
            repair_declaration_id=data.get('repair_declaration_id') or data.get('repair_id'),
            retest_id=data.get('retest_id'),
            retest=retest,
            commitment_ids=frozenset(ids) if not isinstance(ids, str) else frozenset({ids}),
        )


@dataclass(frozen=True)
class StateSnapshot:
    """Current state of a commitment after one or more sequences."""

    commitment_id: str
    state: CommitmentState
    coverage: Coverage
    since_sequence: Optional[int]
    reason: str
    evidence_id: str = ''
    retest_id: Optional[str] = None


@dataclass(frozen=True)
class CommitmentDecision:
    """The review decision for one commitment at one sequence."""

    sequence: int
    commitment_id: str
    kind: CommitmentKind
    before: CommitmentState
    after: CommitmentState
    disposition: ReviewDisposition
    reason: str
    changed: bool
    evidence_id: str = ''
    retest_id: Optional[str] = None
    coverage: Coverage = Coverage.FULL

    @property
    def is_invalidated(self) -> bool:
        return self.after == CommitmentState.INVALIDATED

    @property
    def is_suspended(self) -> bool:
        return self.after == CommitmentState.SUSPENDED

    @property
    def is_reestablished(self) -> bool:
        return self.after == CommitmentState.REESTABLISHED

    is_revoked = is_invalidated
    is_restored = is_reestablished
    is_reinstated = is_reestablished


@dataclass(frozen=True)
class SequenceReview:
    """All decisions and state snapshots for one replacement sequence."""

    sequence: int
    event: PhysicalStateEvent
    decisions: Tuple[CommitmentDecision, ...]
    states: Tuple[StateSnapshot, ...]

    def _where(self, state: CommitmentState) -> Tuple[CommitmentDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.after == state)

    @property
    def invalidated(self) -> Tuple[CommitmentDecision, ...]:
        return self._where(CommitmentState.INVALIDATED)

    @property
    def suspended(self) -> Tuple[CommitmentDecision, ...]:
        return self._where(CommitmentState.SUSPENDED)

    @property
    def reestablished(self) -> Tuple[CommitmentDecision, ...]:
        return self._where(CommitmentState.REESTABLISHED)

    revoked = invalidated
    restored = reestablished
    reinstated = reestablished


@dataclass(frozen=True)
class PhysicalStateReview:
    """Complete ordered review and final commitment states."""

    commitments: Tuple[SignedCommitment, ...]
    sequence_reviews: Tuple[SequenceReview, ...]
    states: Tuple[StateSnapshot, ...]
    source_bom: Any = None

    @property
    def decisions(self) -> Tuple[CommitmentDecision, ...]:
        return tuple(decision for review in self.sequence_reviews for decision in review.decisions)

    def state_for(self, commitment_id: str) -> StateSnapshot:
        for state in self.states:
            if state.commitment_id == commitment_id:
                return state
        raise KeyError(commitment_id)

    @property
    def old_bom(self) -> Any:
        """The untouched source CycloneDX BOM, when one was supplied."""
        return self.source_bom

    @property
    def old_bom_json(self) -> Optional[str]:
        """Stable v1.6 JSON serialization of :attr:`old_bom`, if available."""
        if self.source_bom is None:
            return None
        from cyclonedx.output.json import JsonV1Dot6

        return JsonV1Dot6(self.source_bom).output_as_string()

    def decisions_for(self, commitment_id: str) -> Tuple[CommitmentDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.commitment_id == commitment_id)

    def _final_where(self, state: CommitmentState) -> Tuple[StateSnapshot, ...]:
        return tuple(item for item in self.states if item.state == state)

    @property
    def invalidated(self) -> Tuple[StateSnapshot, ...]:
        return self._final_where(CommitmentState.INVALIDATED)

    @property
    def suspended(self) -> Tuple[StateSnapshot, ...]:
        return self._final_where(CommitmentState.SUSPENDED)

    @property
    def reestablished(self) -> Tuple[StateSnapshot, ...]:
        return self._final_where(CommitmentState.REESTABLISHED)

    revoked = invalidated
    restored = reestablished
    reinstated = reestablished

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation without embedding the BOM object."""
        from dataclasses import asdict

        def encode(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, frozenset):
                return sorted(value)
            return value

        data = asdict(self, dict_factory=lambda items: {key: encode(value) for key, value in items})
        data.pop('source_bom', None)
        return data

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        import json

        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=True)
