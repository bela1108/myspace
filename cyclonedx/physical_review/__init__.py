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

"""Offline physical-state review for signed CycloneDX evidence."""

from .bom import (
    PROPERTY_NAMESPACE,
    annotate_bom,
    commitments_from_bom,
    review_bom,
    reviewed_bom_json,
)
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
)
from .reviewer import PhysicalStateReviewer, review_physical_state

CommitmentStatus = CommitmentState
PhysicalStatusReview = PhysicalStateReview
PhysicalStateReviewService = PhysicalStateReviewer
SealReplacement = PhysicalStateEvent
ReplacementSequence = PhysicalStateEvent
SealReview = PhysicalStateReviewer
PhysicalEvidenceReview = PhysicalStateReview
SignedEvidenceReview = PhysicalStateReview
review_signed_evidence = review_bom
review_seal_replacements = review_physical_state

__all__ = [
    'CommitmentDecision',
    'CommitmentKind',
    'CommitmentState',
    'CommitmentStatus',
    'Coverage',
    'IndependentRetest',
    'PROPERTY_NAMESPACE',
    'PhysicalAction',
    'PhysicalStateEvent',
    'PhysicalStateReview',
    'PhysicalStateReviewService',
    'PhysicalStateReviewer',
    'PhysicalStatusReview',
    'PhysicalEvidenceReview',
    'ReviewDisposition',
    'SealReplacement',
    'SealReview',
    'SequenceReview',
    'SignedCommitment',
    'SignedEvidenceReview',
    'StateSnapshot',
    'ReplacementSequence',
    'annotate_bom',
    'commitments_from_bom',
    'review_bom',
    'review_physical_state',
    'review_seal_replacements',
    'review_signed_evidence',
    'reviewed_bom_json',
]
