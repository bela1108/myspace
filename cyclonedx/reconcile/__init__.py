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

"""
Traceable reconciliation of archive records against CycloneDX component declarations.

The public entry point is :func:`reconcile`.  For repeated audits of the same
read-only archive manifest and declarations, keep a :class:`Reconciler` and call
:meth:`Reconciler.audit` with a revised set of exclusion decisions.
"""

__all__ = [
    'AmbiguousFinding',
    'ArchiveEntry',
    'ArchiveManifest',
    'ArchiveOnlyFinding',
    'ArchivePath',
    'AuditChange',
    'AuditDiff',
    'AuditFingerprints',
    'AuditResult',
    'AuditSummary',
    'ComponentConflict',
    'ComponentDeclaration',
    'ComponentOnlyFinding',
    'ContentDigest',
    'DecisionReference',
    'DecisionStatus',
    'DigestFanout',
    'ExcludedRecord',
    'ExclusionDecision',
    'ExclusionTarget',
    'LocationContention',
    'MatchBasis',
    'MatchRecord',
    'RecordKind',
    'Reconciler',
    'ReconciliationError',
    'bom_from_file',
    'declarations_from_bom_file',
    'declarations_from_file',
    'decisions_from_file',
    'diff_audits',
    'load_inputs',
    'manifest_from_file',
    'reconcile',
    'render_audit',
    'render_diff',
]

from ..exception.reconcile import ReconciliationError
from .engine import Reconciler, diff_audits, reconcile
from .loaders import (
    bom_from_file,
    declarations_from_bom_file,
    declarations_from_file,
    decisions_from_file,
    load_inputs,
    manifest_from_file,
)
from .model import (
    AmbiguousFinding,
    ArchiveEntry,
    ArchiveManifest,
    ArchiveOnlyFinding,
    ArchivePath,
    AuditChange,
    AuditDiff,
    AuditFingerprints,
    AuditResult,
    AuditSummary,
    ComponentConflict,
    ComponentDeclaration,
    ComponentOnlyFinding,
    ContentDigest,
    DecisionReference,
    DecisionStatus,
    DigestFanout,
    ExcludedRecord,
    ExclusionDecision,
    ExclusionTarget,
    LocationContention,
    MatchBasis,
    MatchRecord,
    RecordKind,
)
from .report import render_audit, render_diff
