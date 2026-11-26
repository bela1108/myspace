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

"""Ordered physical-state review for signed CycloneDX evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Iterable, Optional, Union

from .model import (
    CommitmentDecision,
    CommitmentKind,
    CommitmentState,
    Coverage,
    IndependentRetest,
    PhysicalAction,
    PhysicalStateEvent,
    PhysicalStateReview,
    ReviewDisposition,
    SequenceReview,
    SignedCommitment,
    StateSnapshot,
    _enum_value,
)


def _coerce_commitment(value: Union[SignedCommitment, Mapping[str, object]]) -> SignedCommitment:
    if isinstance(value, SignedCommitment):
        return value
    if isinstance(value, Mapping):
        return SignedCommitment.from_mapping(value)
    raise TypeError(f'unsupported commitment: {value!r}')


def _coerce_event(value: Union[PhysicalStateEvent, Mapping[str, object]]) -> PhysicalStateEvent:
    if isinstance(value, PhysicalStateEvent):
        return value
    if isinstance(value, Mapping):
        return PhysicalStateEvent.from_mapping(value)
    raise TypeError(f'unsupported physical-state event: {value!r}')


def _coerce_retest(value: Union[IndependentRetest, Mapping[str, object]]) -> IndependentRetest:
    if isinstance(value, IndependentRetest):
        return value
    if isinstance(value, Mapping):
        return IndependentRetest.from_mapping(value)
    raise TypeError(f'unsupported retest: {value!r}')


class PhysicalStateReviewer:
    """Decide promise validity after each ordered physical replacement event."""

    def __init__(
        self,
        commitments: Iterable[Union[SignedCommitment, Mapping[str, object]]] = (),
        retests: Iterable[Union[IndependentRetest, Mapping[str, object]]] = (),
    ) -> None:
        self.commitments = tuple(_coerce_commitment(item) for item in commitments)
        self.retests = tuple(_coerce_retest(item) for item in retests)
        ids = [item.commitment_id for item in self.commitments]
        if len(ids) != len(set(ids)):
            raise ValueError('commitment_id values must be unique')

    def review(
        self,
        events: Iterable[Union[PhysicalStateEvent, Mapping[str, object]]],
        *,
        source_bom: object = None,
    ) -> PhysicalStateReview:
        ordered_events = sorted(
            (_coerce_event(event) for event in events),
            key=lambda event: event.sequence,
        )
        states = {
            item.commitment_id: StateSnapshot(
                commitment_id=item.commitment_id,
                state=item.state,
                coverage=item.coverage,
                since_sequence=0 if item.state != CommitmentState.ESTABLISHED else None,
                reason='initial signed evidence state',
                evidence_id=item.evidence_id,
            )
            for item in self.commitments
        }
        sequence_reviews = []

        for event in ordered_events:
            decisions = []
            for commitment in self.commitments:
                if not self._affected(commitment, event):
                    continue
                previous = states[commitment.commitment_id]
                decision = self._decide(commitment, previous, event)
                decisions.append(decision)
                if decision.after != previous.state or decision.reason != previous.reason:
                    states[commitment.commitment_id] = StateSnapshot(
                        commitment_id=commitment.commitment_id,
                        state=decision.after,
                        coverage=decision.coverage,
                        since_sequence=event.sequence if decision.changed else previous.since_sequence,
                        reason=decision.reason,
                        evidence_id=commitment.evidence_id,
                        retest_id=decision.retest_id,
                    )
            sequence_reviews.append(SequenceReview(
                sequence=event.sequence,
                event=event,
                decisions=tuple(decisions),
                states=tuple(states.values()),
            ))

        return PhysicalStateReview(
            commitments=self.commitments,
            sequence_reviews=tuple(sequence_reviews),
            states=tuple(states.values()),
            source_bom=source_bom,
        )

    @staticmethod
    def _affected(commitment: SignedCommitment, event: PhysicalStateEvent) -> bool:
        if event.commitment_ids:
            return commitment.commitment_id in event.commitment_ids
        if event.affected_item_ids or event.seal_id:
            item_match = bool(
                commitment.physical_item_id
                and commitment.physical_item_id in event.affected_item_ids
            )
            seal_match = bool(event.seal_id and commitment.seal_id == event.seal_id)
            return item_match or seal_match
        return True

    def _candidate_retests(self, event: PhysicalStateEvent) -> tuple[IndependentRetest, ...]:
        candidates = list(self.retests)
        if event.retest is not None:
            candidates.append(event.retest)
        if event.retest_id:
            by_id = {retest.retest_id: retest for retest in candidates if retest.retest_id}
            if event.retest_id in by_id:
                candidates.append(by_id[event.retest_id])
        return tuple(candidates)

    def _qualifying_retest(
        self,
        commitment: SignedCommitment,
        previous: StateSnapshot,
        event: PhysicalStateEvent,
    ) -> Optional[IndependentRetest]:
        for retest in self._candidate_retests(event):
            if not retest.independent or not retest.passed:
                continue
            if retest.physical_item_id != commitment.physical_item_id:
                continue
            if retest.seal_id and commitment.seal_id and retest.seal_id != commitment.seal_id:
                continue
            if (
                retest.repair_declaration_id
                and commitment.repair_declaration_id
                and retest.repair_declaration_id != commitment.repair_declaration_id
            ):
                continue
            if retest.covers and not (
                commitment.commitment_id in retest.covers
                or commitment.kind.value in retest.covers
            ):
                continue
            if retest.sequence is not None and retest.sequence > event.sequence:
                continue
            earliest_sequence = previous.since_sequence if previous.state == CommitmentState.SUSPENDED else None
            if event.action in (PhysicalAction.ITEM_INSTALLED, PhysicalAction.ITEM_REINSTALLED):
                earliest_sequence = event.sequence if earliest_sequence is None else max(
                    earliest_sequence, event.sequence
                )
            if (
                retest.sequence is not None
                and earliest_sequence is not None
                and retest.sequence < earliest_sequence
            ):
                continue
            return retest
        return None

    def _decide(  # noqa: C901 - explicit policy branches are intentionally readable
        self,
        commitment: SignedCommitment,
        previous: StateSnapshot,
        event: PhysicalStateEvent,
    ) -> CommitmentDecision:
        action = event.action
        if not isinstance(action, PhysicalAction):
            action = _enum_value(action, PhysicalAction, PhysicalAction.REVIEW_REQUESTED)
        kind = commitment.kind
        if not isinstance(kind, CommitmentKind):
            kind = _enum_value(kind, CommitmentKind, CommitmentKind.CUSTOM)

        before = previous.state
        after = before
        disposition = ReviewDisposition.UNCHANGED
        reason = previous.reason
        retest_id = previous.retest_id
        coverage = previous.coverage
        qualifying = self._qualifying_retest(commitment, previous, event)

        if action in (PhysicalAction.SEAL_REPLACED, PhysicalAction.SEAL_BROKEN, PhysicalAction.ITEM_REMOVED):
            if kind == CommitmentKind.INITIAL_INSPECTION_GUARANTEE:
                after = CommitmentState.INVALIDATED
                disposition = ReviewDisposition.INVALIDATE
                reason = 'initial inspection guarantee applies only to pre-opening state'
            elif kind == CommitmentKind.SEAL_APPROVAL:
                after = CommitmentState.SUSPENDED
                disposition = ReviewDisposition.SUSPEND
                reason = 'seal change requires physical-state review and independent retest'
            elif kind == CommitmentKind.REPAIR_GUARANTEE:
                after = CommitmentState.SUSPENDED
                disposition = ReviewDisposition.SUSPEND
                reason = 'repair guarantee is suspended across a later seal intervention'

        elif action in (PhysicalAction.ITEM_INSTALLED, PhysicalAction.ITEM_REINSTALLED):
            if qualifying is not None:
                after = CommitmentState.REESTABLISHED
                disposition = ReviewDisposition.REESTABLISH
                reason = 'matching physical instance passed an independent retest'
                retest_id = qualifying.retest_id or None
                if kind == CommitmentKind.REPAIR_GUARANTEE:
                    coverage = Coverage.PARTIAL
            elif kind == CommitmentKind.SEAL_APPROVAL:
                after = CommitmentState.SUSPENDED
                disposition = ReviewDisposition.SUSPEND
                if self._same_model_without_identity_test(commitment, event):
                    reason = 'same-model reinstall does not identify the physical item or prove retest'
                else:
                    reason = 'seal approval remains suspended without an independent retest of this physical item'
            elif kind == CommitmentKind.INITIAL_INSPECTION_GUARANTEE:
                after = CommitmentState.INVALIDATED
                disposition = ReviewDisposition.INVALIDATE
                reason = 'reinstallation cannot revive the pre-opening inspection state'
            elif kind == CommitmentKind.REPAIR_GUARANTEE:
                after = CommitmentState.SUSPENDED
                disposition = ReviewDisposition.SUSPEND
                reason = 'repair guarantee remains suspended until independent retest passes'

        elif action == PhysicalAction.REPAIR_DECLARED:
            if qualifying is not None:
                after = CommitmentState.REESTABLISHED
                disposition = ReviewDisposition.REESTABLISH
                reason = 'repair declaration plus independent retest restores partial guarantee'
                retest_id = qualifying.retest_id or None
                coverage = Coverage.PARTIAL
            else:
                after = CommitmentState.SUSPENDED
                disposition = ReviewDisposition.SUSPEND
                reason = 'repair declaration is pending an independent retest'

        elif action == PhysicalAction.RETEST_RECORDED:
            recorded = event.retest or next(
                (item for item in self.retests if item.retest_id == event.retest_id), None
            )
            if qualifying is not None:
                after = CommitmentState.REESTABLISHED
                disposition = ReviewDisposition.REESTABLISH
                reason = 'independent retest passed for the exact physical item'
                retest_id = qualifying.retest_id or None
                if kind == CommitmentKind.REPAIR_GUARANTEE:
                    coverage = Coverage.PARTIAL
            else:
                after = CommitmentState.SUSPENDED
                disposition = ReviewDisposition.SUSPEND
                if recorded is not None and not recorded.independent:
                    reason = 'retest is not independent'
                elif recorded is not None and not recorded.passed:
                    reason = 'retest did not pass'
                elif recorded is not None and recorded.physical_item_id != commitment.physical_item_id:
                    reason = 'retest belongs to a different physical instance; same model is insufficient'
                else:
                    reason = 'no qualifying independent retest for this physical item'

        elif action == PhysicalAction.REVIEW_REQUESTED:
            if qualifying is not None:
                after = CommitmentState.REESTABLISHED
                disposition = ReviewDisposition.REESTABLISH
                reason = 'independent retest supports reestablishment'
                retest_id = qualifying.retest_id or None
            elif kind in (CommitmentKind.SEAL_APPROVAL, CommitmentKind.REPAIR_GUARANTEE):
                after = CommitmentState.SUSPENDED
                disposition = ReviewDisposition.SUSPEND
                reason = 'physical-state review is incomplete without an independent retest'

        changed = after != before
        return CommitmentDecision(
            sequence=event.sequence,
            commitment_id=commitment.commitment_id,
            kind=kind,
            before=before,
            after=after,
            disposition=disposition,
            reason=reason,
            changed=changed,
            evidence_id=commitment.evidence_id,
            retest_id=retest_id,
            coverage=coverage,
        )

    @staticmethod
    def _same_model_without_identity_test(
        commitment: SignedCommitment,
        event: PhysicalStateEvent,
    ) -> bool:
        return bool(
            event.model
            and commitment.physical_model
            and event.model.strip().lower() == commitment.physical_model.strip().lower()
        )


def review_physical_state(
    commitments: Iterable[Union[SignedCommitment, Mapping[str, object]]] = (),
    events: Iterable[Union[PhysicalStateEvent, Mapping[str, object]]] = (),
    *,
    retests: Iterable[Union[IndependentRetest, Mapping[str, object]]] = (),
    source_bom: object = None,
) -> PhysicalStateReview:
    """Functional shortcut for one ordered physical-state review."""
    return PhysicalStateReviewer(commitments=commitments, retests=retests).review(
        events,
        source_bom=source_bom,
    )
