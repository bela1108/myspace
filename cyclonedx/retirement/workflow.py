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

"""In-memory BOM workflow for retiring and writing off a cryptographic asset.

The asset is simultaneously flagged as deactivated for external services and as
still queryable from the archive (read-only). Each consuming service keeps an
independent settlement, even when several services reference the very same
asset. The BOM can only be closed once the destruction receipts are complete;
until then the asset's effective level stays read-only instead of destroyed.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple

from ..model import Property
from ..model.bom import Bom
from ..model.component import Component, ComponentType
from ..model.service import Service


class RetirementError(Exception):
    """Base error for retirement workflow rule violations."""


class UnknownAssetError(RetirementError):
    """Raised when an operation references an asset that was never registered."""


class UnknownServiceError(RetirementError):
    """Raised when an operation references a service that was never registered."""


class DuplicateProofError(RetirementError):
    """Raised when a role submits an end-proof more than once."""


class BookNotClosableError(RetirementError):
    """Raised when close is attempted before every destruction receipt is present."""


class AssetLevel(str, Enum):
    """Effective availability level of the retired material."""

    READ_ONLY = 'read-only'
    DESTROYED = 'destroyed'


class ServiceSettlementState(str, Enum):
    """Independent settlement state of a single service-to-asset reference."""

    PENDING = 'pending'
    SETTLED = 'settled'


PROPERTY_PREFIX = 'retirement'


@dataclass(frozen=True)
class EndProof:
    """Proof that a role ended its use of the asset."""

    role: str
    reference: str


@dataclass(frozen=True)
class DestructionReceipt:
    """Receipt confirming destruction of one material copy or backing store."""

    receipt_id: str
    issued_by: str


@dataclass(frozen=True)
class ServiceSettlement:
    """Settlement result for a single service referencing the shared asset."""

    service_ref: str
    service_name: str
    asset_ref: str
    state: ServiceSettlementState
    end_proof: Optional[EndProof]


@dataclass(frozen=True)
class ClosureReport:
    """Immutable snapshot emitted when the retirement book is finally closed."""

    asset_ref: str
    asset_name: str
    level: AssetLevel
    external_deactivated: bool
    archive_queryable: bool
    proof_roles: Tuple[str, ...]
    destruction_receipts: Tuple[DestructionReceipt, ...]
    settlements: Tuple[ServiceSettlement, ...]
    closed: bool

    @property
    def legal_refs(self) -> Tuple[ServiceSettlement, ...]:
        """References that still legally depend on the material."""
        return self.settlements


@dataclass
class _AssetRecord:
    component: Component
    external_deactivated: bool = True
    archive_queryable: bool = True
    closed: bool = False
    end_proofs: Dict[str, EndProof] = field(default_factory=dict)
    destruction_receipts: Dict[str, DestructionReceipt] = field(default_factory=dict)
    # service bom-ref value -> settlement for this specific asset
    settlements: Dict[str, ServiceSettlement] = field(default_factory=dict)

    @property
    def level(self) -> AssetLevel:
        if self.closed and self.destruction_receipts:
            return AssetLevel.DESTROYED
        return AssetLevel.READ_ONLY


class RetirementBom:
    """In-memory BOM tracking retirement and write-off of a shared asset."""

    def __init__(self, bom: Optional[Bom] = None) -> None:
        self._bom = bom or Bom()
        self._assets: Dict[str, _AssetRecord] = {}
        self._services: Dict[str, Service] = {}

    @property
    def bom(self) -> Bom:
        return self._bom

    def register_asset(
        self,
        name: str,
        *,
        bom_ref: str,
        description: Optional[str] = None,
    ) -> Component:
        """Register a cryptographic asset and flag it as retired-but-archived."""
        component = Component(
            name=name,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=bom_ref,
            description=description,
            properties=[
                Property(name=f'{PROPERTY_PREFIX}:external-deactivated', value='true'),
                Property(name=f'{PROPERTY_PREFIX}:archive-queryable', value='true'),
                Property(name=f'{PROPERTY_PREFIX}:level', value=AssetLevel.READ_ONLY.value),
                Property(name=f'{PROPERTY_PREFIX}:closed', value='false'),
            ],
        )
        self._bom.components.add(component)
        self._assets[bom_ref] = _AssetRecord(component=component)
        return component

    def register_service(self, name: str, *, bom_ref: str) -> Service:
        """Register a consuming service in the underlying BOM."""
        service = Service(name=name, bom_ref=bom_ref)
        self._bom.services.add(service)
        self._services[bom_ref] = service
        return service

    def reference_asset(self, service_ref: str, asset_ref: str) -> None:
        """Record that a service legally depends on an asset.

        Every (service, asset) pair gets its own independent settlement, so two
        services may reference the same asset without sharing a settlement.
        """
        service = self._require_service(service_ref)
        record = self._require_asset(asset_ref)
        self._bom.register_dependency(target=service, depends_on=[record.component])
        if service_ref not in record.settlements:
            record.settlements[service_ref] = ServiceSettlement(
                service_ref=service_ref,
                service_name=service.name,
                asset_ref=asset_ref,
                state=ServiceSettlementState.PENDING,
                end_proof=None,
            )

    def submit_end_proof(self, service_ref: str, asset_ref: str, role: str, proof_ref: str) -> EndProof:
        """Record which role submitted the proof ending a service's use."""
        service = self._require_service(service_ref)
        record = self._require_asset(asset_ref)
        if service_ref not in record.settlements:
            self.reference_asset(service_ref, asset_ref)
        existing = record.end_proofs.get(role)
        if existing is not None:
            raise DuplicateProofError(
                f'role {role!r} already submitted end-proof {existing.reference!r} for asset {asset_ref!r}'
            )
        proof = EndProof(role=role, reference=proof_ref)
        record.end_proofs[role] = proof
        record.settlements[service_ref] = ServiceSettlement(
            service_ref=service_ref,
            service_name=service.name,
            asset_ref=asset_ref,
            state=ServiceSettlementState.SETTLED,
            end_proof=proof,
        )
        return proof

    def record_destruction_receipt(self, asset_ref: str, receipt_id: str, issued_by: str) -> DestructionReceipt:
        """Add a destruction receipt; receipts from every backing store are required."""
        record = self._require_asset(asset_ref)
        receipt = DestructionReceipt(receipt_id=receipt_id, issued_by=issued_by)
        record.destruction_receipts[receipt_id] = receipt
        return receipt

    def effective_level(self, asset_ref: str) -> AssetLevel:
        """Return whether the material is only read-only or already destroyed."""
        return self._require_asset(asset_ref).level

    def legal_references(self, asset_ref: str) -> List[ServiceSettlement]:
        """Return the service references that still legally depend on the material."""
        record = self._require_asset(asset_ref)
        return list(record.settlements.values())

    def proof_roles(self, asset_ref: str) -> List[str]:
        """Return the roles that have submitted an end-proof for the asset."""
        record = self._require_asset(asset_ref)
        return list(record.end_proofs.keys())

    def close_book(
        self,
        asset_ref: str,
        *,
        expected_receipts: Optional[Iterable[str]] = None,
    ) -> ClosureReport:
        """Close the retirement book once every destruction receipt is present.

        ``expected_receipts`` names the receipts that must exist. When omitted,
        at least one recorded receipt is still required so that a book can never
        be closed without any destruction evidence.
        """
        record = self._require_asset(asset_ref)
        expected = list(expected_receipts) if expected_receipts is not None \
            else list(record.destruction_receipts.keys())
        missing = [receipt_id for receipt_id in expected if receipt_id not in record.destruction_receipts]
        if missing or not record.destruction_receipts:
            raise BookNotClosableError(
                f'asset {asset_ref!r} cannot be closed; missing destruction receipts: {missing or expected}'
            )
        record.closed = True
        self._sync_properties(record)
        return self.report(asset_ref)

    def report(self, asset_ref: str) -> ClosureReport:
        """Build an immutable snapshot of the retirement state of one asset."""
        record = self._require_asset(asset_ref)
        return ClosureReport(
            asset_ref=asset_ref,
            asset_name=record.component.name,
            level=record.level,
            external_deactivated=record.external_deactivated,
            archive_queryable=record.archive_queryable,
            proof_roles=tuple(record.end_proofs.keys()),
            destruction_receipts=tuple(record.destruction_receipts.values()),
            settlements=tuple(record.settlements.values()),
            closed=record.closed,
        )

    def _sync_properties(self, record: _AssetRecord) -> None:
        values = {
            f'{PROPERTY_PREFIX}:external-deactivated': 'true' if record.external_deactivated else 'false',
            f'{PROPERTY_PREFIX}:archive-queryable': 'true' if record.archive_queryable else 'false',
            f'{PROPERTY_PREFIX}:level': record.level.value,
            f'{PROPERTY_PREFIX}:closed': 'true' if record.closed else 'false',
        }
        for prop in record.component.properties:
            if prop.name in values:
                prop.value = values[prop.name]

    def _require_asset(self, asset_ref: str) -> _AssetRecord:
        record = self._assets.get(asset_ref)
        if record is None:
            raise UnknownAssetError(f'unknown cryptographic asset: {asset_ref!r}')
        return record

    def _require_service(self, service_ref: str) -> Service:
        service = self._services.get(service_ref)
        if service is None:
            raise UnknownServiceError(f'unknown service: {service_ref!r}')
        return service
