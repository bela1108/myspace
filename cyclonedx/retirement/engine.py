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
Offline reconciliation engine for interface retirement.

The engine joins the three evidence sources described in
:mod:`cyclonedx.retirement.model` against one or more CycloneDX BOMs:

* services and dependency references are read from the BOM of the revision a
  usage declaration points at, so the same ``bom-ref`` occurring in two BOMs
  is always interpreted per revision;
* a service acting as both proxy and direct consumer produces one line per
  direction;
* a declaration without a matching confirmation receipt remains pending.

No network access happens; all inputs are local objects or parsed BOMs.
"""

from dataclasses import dataclass
from typing import Iterable, Optional

from ..model.bom import Bom
from ..model.service import Service
from .model import (
    ConfirmationReceipt,
    ConsumerRole,
    CredentialClass,
    FlowDirection,
    ReconciliationLine,
    ReconciliationStatus,
    UsageDeclaration,
)


@dataclass(frozen=True)
class UsageClaim:
    """
    Raw service usage statement, before directional expansion.

    A service may carry more than one :class:`ConsumerRole`. A proxy always
    participates with an inbound and an outbound leg, while a direct consumer
    only has an outbound leg. :meth:`RetirementReconciler.expand_claims`
    turns each claim into one :class:`UsageDeclaration` per role/direction.
    """

    bom_ref: str
    credential_name: str
    bom_revision: str
    roles: tuple[ConsumerRole, ...]


@dataclass(frozen=True)
class _ReceiptKey:
    bom_revision: str
    bom_ref: str
    credential_name: str
    direction: Optional[FlowDirection]


@dataclass(frozen=True)
class ReconciliationReport:
    """Result of a reconciliation run."""

    lines: tuple[ReconciliationLine, ...]

    @property
    def pending_lines(self) -> tuple[ReconciliationLine, ...]:
        """All lines that still wait for a confirmation receipt."""
        return tuple(line for line in self.lines if line.is_pending)

    @property
    def confirmed_lines(self) -> tuple[ReconciliationLine, ...]:
        """All lines backed by a confirmation receipt."""
        return tuple(
            line for line in self.lines
            if line.status is ReconciliationStatus.CONFIRMED
        )


class RetirementReconciler:
    """
    Reconcile service usage declarations with local confirmation receipts.

    Args:
        boms: mapping of BOM revision -> :class:`~cyclonedx.model.bom.Bom`.
            A ``bom-ref`` is only ever looked up in the BOM of the revision
            stated by the declaration, so identical refs across revisions do
            not collide.
        credentials: credential categories issued for the retired interface.
        receipts: locally collected confirmation receipts.
    """

    def __init__(
        self, *,
        boms: dict[str, Bom],
        credentials: Iterable[CredentialClass],
        receipts: Iterable[ConfirmationReceipt],
    ) -> None:
        self._boms = dict(boms)
        self._credentials = {item.name: item for item in credentials}
        self._receipts = self._index_receipts(receipts)

    @staticmethod
    def _index_receipts(
        receipts: Iterable[ConfirmationReceipt],
    ) -> dict[_ReceiptKey, ConfirmationReceipt]:
        index: dict[_ReceiptKey, ConfirmationReceipt] = {}
        for receipt in receipts:
            index[_ReceiptKey(
                bom_revision=receipt.bom_revision,
                bom_ref=receipt.bom_ref,
                credential_name=receipt.credential_name,
                direction=receipt.direction,
            )] = receipt
        return index

    def _service_for(self, declaration: UsageDeclaration) -> Optional[Service]:
        bom = self._boms.get(declaration.bom_revision)
        if bom is None:
            return None
        for service in bom.services:
            if service.bom_ref.value == declaration.bom_ref:
                return service
        return None

    def _find_receipt(
        self, declaration: UsageDeclaration,
    ) -> Optional[ConfirmationReceipt]:
        # A direction-specific receipt is the authoritative match. Receipts
        # recorded without a direction act as a generic confirmation.
        return (
            self._receipts.get(_ReceiptKey(
                bom_revision=declaration.bom_revision,
                bom_ref=declaration.bom_ref,
                credential_name=declaration.credential_name,
                direction=declaration.direction,
            ))
            or self._receipts.get(_ReceiptKey(
                bom_revision=declaration.bom_revision,
                bom_ref=declaration.bom_ref,
                credential_name=declaration.credential_name,
                direction=None,
            ))
        )

    def _reconcile_line(
        self, declaration: UsageDeclaration,
    ) -> ReconciliationLine:
        service = self._service_for(declaration)
        service_name = service.name if service is not None else declaration.bom_ref

        if service is None:
            return ReconciliationLine(
                declaration=declaration,
                service_name=service_name,
                status=ReconciliationStatus.UNKNOWN_SERVICE,
                missing_reason=(
                    f'service {declaration.bom_ref!r} not found in BOM '
                    f'revision {declaration.bom_revision!r}'
                ),
            )

        if declaration.credential_name not in self._credentials:
            return ReconciliationLine(
                declaration=declaration,
                service_name=service_name,
                status=ReconciliationStatus.UNKNOWN_CREDENTIAL,
                missing_reason=(
                    f'credential class {declaration.credential_name!r} '
                    'is not registered'
                ),
            )

        receipt = self._find_receipt(declaration)
        if receipt is not None:
            return ReconciliationLine(
                declaration=declaration,
                service_name=service_name,
                status=ReconciliationStatus.CONFIRMED,
                receipt=receipt,
            )

        return ReconciliationLine(
            declaration=declaration,
            service_name=service_name,
            status=ReconciliationStatus.PENDING_CONFIRMATION,
            missing_reason=(
                f'no confirmation receipt from {service_name!r} for '
                f'{declaration.credential_name!r} '
                f'({declaration.role.value}/{declaration.direction.value})'
            ),
        )

    def reconcile(
        self, declarations: Iterable[UsageDeclaration],
    ) -> ReconciliationReport:
        """Reconcile every usage declaration against the known receipts."""
        lines = tuple(
            self._reconcile_line(declaration) for declaration in declarations
        )
        return ReconciliationReport(lines=lines)

    @staticmethod
    def expand_claims(
        claims: Iterable[UsageClaim],
    ) -> tuple[UsageDeclaration, ...]:
        """
        Expand raw usage claims into directional declarations.

        Each :attr:`ConsumerRole.PROXY` role yields an inbound and an
        outbound declaration; each :attr:`ConsumerRole.DIRECT_CONSUMER` role
        yields a single outbound declaration. A service carrying both roles
        therefore ends up with separate lines per direction.
        """
        declarations: list[UsageDeclaration] = []
        for claim in claims:
            for role in dict.fromkeys(claim.roles):
                if role is ConsumerRole.PROXY:
                    directions = (FlowDirection.INBOUND, FlowDirection.OUTBOUND)
                else:
                    directions = (FlowDirection.OUTBOUND,)
                for direction in directions:
                    declarations.append(UsageDeclaration(
                        bom_ref=claim.bom_ref,
                        role=role,
                        direction=direction,
                        credential_name=claim.credential_name,
                        bom_revision=claim.bom_revision,
                    ))
        return tuple(declarations)
