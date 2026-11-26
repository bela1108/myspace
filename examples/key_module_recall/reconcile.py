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

"""Recall coverage reconciliation.

The reconciliation joins three independently maintained inputs:

* a CycloneDX BOM (component type and lifecycle come from the asset inventory);
* the independent replacement policy (the only source of replacement limits);
* the local disposition list (which physical bom-refs have actually been
  recalled, and which devices are awaiting recall).

A warehouse seal is treated strictly as availability evidence: a sealed spare
is never marked as recalled merely because it is sealed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import ComponentType

from .asset_inventory import AssetEntry, LifecycleKind, index_entries
from .replacement_policy import (
    ReplacementRule,
    build_replacement_index,
    build_reverse_replacement_index,
)


class CoverageStatus(str, Enum):
    """Recall coverage status of one physical object."""

    #: Device not present in the disposition list; recall still outstanding.
    PENDING_RECALL = 'pending-recall'
    #: Device present in the disposition list as recalled.
    DEVICE_RECALLED = 'device-recalled'
    #: Installed module whose host device still has to be recalled.
    INSTALLATION_PENDING = 'installation-pending'
    #: Installed module on a device already covered by the disposition list.
    INSTALLATION_COVERED = 'installation-covered'
    #: Spare that can replace an installed module but is not yet recalled.
    REPLACEABLE_UNCOVERED = 'replaceable-uncovered'
    #: Spare listed in the disposition list as recalled.
    SPARE_COVERED = 'spare-covered'
    #: Sealed spare: currently unavailable, but recall is still outstanding.
    SEALED_PENDING = 'sealed-pending'
    #: Sealed spare that is also listed as recalled in the disposition list.
    SEALED_AND_RECALLED = 'sealed-and-recalled'
    #: Unsealed spare that no installed module is allowed to use as replacement.
    SPARE_OUT_OF_SCOPE = 'spare-out-of-scope'
    #: Sealed spare outside replacement scope; the seal only shows unavailability.
    SEALED_OUT_OF_SCOPE = 'sealed-out-of-scope'


@dataclass(frozen=True)
class DispositionRecord:
    """One entry of the local disposition list."""

    bom_ref: str
    disposition: str
    reference: Optional[str] = None
    note: str = ''

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'DispositionRecord':
        return cls(
            bom_ref=data['bomRef'],
            disposition=data['disposition'],
            reference=data.get('reference'),
            note=data.get('note', ''),
        )


@dataclass(frozen=True)
class ItemResult:
    """Reconciliation result for one tracked component."""

    bom_ref: str
    name: str
    component_type: str
    lifecycle: str
    status: CoverageStatus
    host_device_ref: Optional[str]
    recall_listed: bool
    sealed: bool
    replaceable_for: List[str] = field(default_factory=list)
    replacement_spares: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            'bomRef': self.bom_ref,
            'name': self.name,
            'componentType': self.component_type,
            'lifecycle': self.lifecycle,
            'status': self.status.value,
            'hostDeviceRef': self.host_device_ref,
            'recallListed': self.recall_listed,
            'sealed': self.sealed,
            'replaceableFor': self.replaceable_for,
            'replacementSpares': self.replacement_spares,
            'notes': self.notes,
        }


@dataclass(frozen=True)
class ReconciliationReport:
    """Aggregated recall coverage report."""

    item_results: List[ItemResult]
    pending_device_refs: List[str]
    covered_device_refs: List[str]
    seal_only_refs: List[str]
    unknown_disposition_refs: List[str]
    policy_refs_unknown_to_bom: List[str]

    @property
    def is_complete(self) -> bool:
        """True when every installed module and every replaceable spare is covered."""
        outstanding = {
            CoverageStatus.PENDING_RECALL,
            CoverageStatus.INSTALLATION_PENDING,
            CoverageStatus.REPLACEABLE_UNCOVERED,
            CoverageStatus.SEALED_PENDING,
        }
        return not any(result.status in outstanding for result in self.item_results)

    def to_json(self) -> Dict[str, Any]:
        return {
            'complete': self.is_complete,
            'pendingDeviceRefs': self.pending_device_refs,
            'coveredDeviceRefs': self.covered_device_refs,
            'sealOnlyRefs': self.seal_only_refs,
            'unknownDispositionRefs': self.unknown_disposition_refs,
            'policyRefsUnknownToBom': self.policy_refs_unknown_to_bom,
            'items': [result.to_json() for result in self.item_results],
        }


def load_disposition_list(path: Path) -> List[DispositionRecord]:
    """Load the local disposition list JSON document."""
    document = json.loads(path.read_text(encoding='utf-8'))
    return [DispositionRecord.from_json(item) for item in document['dispositions']]


def _recalled_refs(records: List[DispositionRecord]) -> Set[str]:
    return {
        record.bom_ref for record in records
        if record.disposition.lower() == 'recalled'
    }


def reconcile(
    bom: Bom,
    replacement_rules: List[ReplacementRule],
    disposition_records: List[DispositionRecord],
) -> ReconciliationReport:
    """Reconcile BOM objects against replacement limits and dispositions."""
    entries: Dict[str, AssetEntry] = index_entries(bom)
    replacement_index = build_replacement_index(replacement_rules)
    reverse_index = build_reverse_replacement_index(replacement_rules)
    recalled = _recalled_refs(disposition_records)

    unknown_disposition = sorted(
        record.bom_ref for record in disposition_records
        if record.bom_ref not in entries
    )
    policy_refs = {
        ref for rule in replacement_rules for ref in (rule.installed_ref, rule.spare_ref)
    }
    unknown_policy_refs = sorted(ref for ref in policy_refs if ref not in entries)

    host_device_of = _resolve_host_devices(entries)

    item_results: List[ItemResult] = []
    pending_devices: Set[str] = set()
    covered_devices: Set[str] = set()
    seal_only: Set[str] = set()

    for ref in sorted(entries):
        entry = entries[ref]
        is_recalled = ref in recalled
        replacement_spares = sorted(replacement_index.get(ref, set()))
        replaceable_for = sorted(reverse_index.get(ref, set()))
        notes: List[str] = []

        status = _classify(
            entry=entry,
            is_recalled=is_recalled,
            replacement_spares=replacement_spares,
            replaceable_for=replaceable_for,
            notes=notes,
        )

        host = host_device_of.get(ref)
        if entry.component_type is ComponentType.DEVICE:
            if is_recalled:
                covered_devices.add(ref)
            else:
                pending_devices.add(ref)
        if entry.seal is not None and not is_recalled:
            seal_only.add(ref)

        item_results.append(ItemResult(
            bom_ref=ref,
            name=entry.name,
            component_type=entry.component_type.value,
            lifecycle=entry.lifecycle.value,
            status=status,
            host_device_ref=host,
            recall_listed=is_recalled,
            sealed=entry.seal is not None,
            replaceable_for=replaceable_for,
            replacement_spares=replacement_spares,
            notes=notes,
        ))

    return ReconciliationReport(
        item_results=item_results,
        pending_device_refs=sorted(pending_devices),
        covered_device_refs=sorted(covered_devices - pending_devices),
        seal_only_refs=sorted(seal_only),
        unknown_disposition_refs=unknown_disposition,
        policy_refs_unknown_to_bom=unknown_policy_refs,
    )


def _classify(
    *,
    entry: AssetEntry,
    is_recalled: bool,
    replacement_spares: List[str],
    replaceable_for: List[str],
    notes: List[str],
) -> CoverageStatus:
    if entry.component_type is ComponentType.DEVICE:
        if is_recalled:
            notes.append('device is listed as recalled in the disposition list')
            return CoverageStatus.DEVICE_RECALLED
        notes.append('device is not in the disposition list and still awaits physical recall')
        return CoverageStatus.PENDING_RECALL

    if entry.lifecycle is LifecycleKind.INSTALLED:
        if is_recalled:
            notes.append('installed module is listed as recalled in the disposition list')
            return CoverageStatus.INSTALLATION_COVERED
        notes.append('installed module is not recalled; its host device must be returned')
        if replacement_spares:
            notes.append(
                'allowed replacement spares per independent policy: '
                + ', '.join(replacement_spares)
            )
        return CoverageStatus.INSTALLATION_PENDING

    # Every remaining object is a spare (optionally warehouse-sealed).
    # Only spares that the independent policy links to an installed module are
    # in scope of the recall; a sealed but unrelated spare is reported
    # separately so that a seal is never mistaken for recall coverage.
    eligible = bool(replaceable_for)
    if eligible:
        notes.append(
            'replacement eligibility is declared solely by the independent policy: '
            + ', '.join(replaceable_for)
        )
    else:
        notes.append('spare is not declared as a replacement for any installed module')

    if entry.seal is not None:
        if is_recalled:
            notes.append('seal recorded and disposition list separately confirms recall')
            return CoverageStatus.SEALED_AND_RECALLED
        if not eligible:
            notes.append(
                'warehouse seal proves current unavailability; the spare is outside '
                'the replacement scope and is not counted toward recall coverage'
            )
            return CoverageStatus.SEALED_OUT_OF_SCOPE
        notes.append(
            'warehouse seal proves the spare is currently unavailable only; '
            'it does not satisfy the recall requirement'
        )
        return CoverageStatus.SEALED_PENDING

    if is_recalled:
        return CoverageStatus.SPARE_COVERED
    if eligible:
        return CoverageStatus.REPLACEABLE_UNCOVERED
    return CoverageStatus.SPARE_OUT_OF_SCOPE


def _resolve_host_devices(entries: Dict[str, AssetEntry]) -> Mapping[str, str]:
    """Map every nested component to its nearest ancestor device bom-ref."""
    host_of: Dict[str, str] = {}
    for ref, entry in entries.items():
        ancestor = entry.parent_ref
        while ancestor is not None:
            parent = entries.get(ancestor)
            if parent is None:
                break
            if parent.component_type.value == ComponentType.DEVICE.value:
                host_of[ref] = ancestor
                break
            ancestor = parent.parent_ref
    return host_of
