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


"""Domain models for the offline decommission reconciliation.

The reconciliation joins three kinds of evidence that are supplied
out-of-band (offline) with the service/dependency references kept in
CycloneDX BOMs:

* :class:`CredentialClaim` - which credential category a service is known to
  use against the interface that is about to be retired;
* :class:`ServiceUsageDeclaration` - the role a service plays relative to the
  interface (direct consumer and/or forwarding proxy);
* :class:`RetirementReceipt` - the locally collected confirmation that a
  consumer finished its retirement work.

Service names and credential types are plain test identifiers, for example
``"test-service-alpha"`` and ``"test-credential-api-key"``.
"""

from enum import Enum
from typing import Iterable, Optional


class UsageRole(str, Enum):
    """Role a service takes relative to the retired interface."""

    #: service calls the retired interface for its own needs
    DIRECT_CONSUMER = 'direct-consumer'
    #: service forwards calls of other consumers towards the interface
    FORWARDING_PROXY = 'forwarding-proxy'


class TrafficDirection(str, Enum):
    """Direction of a reconciled usage.

    A service that is both a proxy and a direct consumer appears once per
    direction, so that the two roles can be retired and confirmed
    independently.
    """

    #: the service itself consumes the retired interface
    OUTBOUND = 'outbound'
    #: downstream traffic reaches the interface through this service
    INBOUND = 'inbound'


class ReconciliationStatus(str, Enum):
    """Aggregated retirement state of one reconciled direction."""

    #: the local confirmation receipt was collected
    CONFIRMED = 'confirmed'
    #: the consumer receipt is still missing
    PENDING_CONFIRMATION = 'pending-confirmation'


class CredentialClaim:
    """Evidence that a service uses a credential of a given category.

    Credential categories are free-form test names, for example
    ``"test-credential-api-key"``.
    """

    def __init__(self, *, service_ref: str, credential_type: str) -> None:
        self.service_ref = service_ref
        self.credential_type = credential_type

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, CredentialClaim)
            and self.service_ref == other.service_ref
            and self.credential_type == other.credential_type
        )

    def __hash__(self) -> int:
        return hash((self.service_ref, self.credential_type))

    def __repr__(self) -> str:
        return (
            f'CredentialClaim(service_ref={self.service_ref!r}, '
            f'credential_type={self.credential_type!r})'
        )


class ServiceUsageDeclaration:
    """Out-of-band declaration of the role(s) a service plays.

    ``roles`` may contain both :class:`UsageRole` values; the reconciliation
    splits such a service into one item per :class:`TrafficDirection`.
    """

    def __init__(
        self, *,
        service_ref: str,
        roles: Iterable[UsageRole],
    ) -> None:
        self.service_ref = service_ref
        self.roles = frozenset(roles)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ServiceUsageDeclaration)
            and self.service_ref == other.service_ref
            and self.roles == other.roles
        )

    def __hash__(self) -> int:
        return hash((self.service_ref, self.roles))

    def __repr__(self) -> str:
        roles = sorted(role.value for role in self.roles)
        return (
            f'ServiceUsageDeclaration(service_ref={self.service_ref!r}, '
            f'roles={roles!r})'
        )


class RetirementReceipt:
    """Local confirmation receipt for a service's retirement.

    Receipts are matched by ``service_ref``. Each receipt confirms every
    reconciled direction of that service - directions are kept separate on
    the :class:`ReconciliationItem`, while the receipt only proves that the
    consumer side of the service is done.
    """

    def __init__(self, *, service_ref: str) -> None:
        self.service_ref = service_ref

    def confirms(self, service_ref: str) -> bool:
        return self.service_ref == service_ref

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, RetirementReceipt)
            and self.service_ref == other.service_ref
        )

    def __hash__(self) -> int:
        return hash(self.service_ref)

    def __repr__(self) -> str:
        return f'RetirementReceipt(service_ref={self.service_ref!r})'


class ServiceRevision:
    """A service reference as read from one particular BOM revision.

    The same ``bom_ref`` may appear in several BOMs; each occurrence keeps
    the BOM's own serial number and document revision (``Bom.version``) plus
    the service version stated by that BOM, so references are always read
    per revision and never merged across BOMs.
    """

    def __init__(
        self, *,
        bom_ref: str,
        name: str,
        service_version: Optional[str],
        bom_serial: str,
        bom_revision: int,
    ) -> None:
        self.bom_ref = bom_ref
        self.name = name
        self.service_version = service_version
        self.bom_serial = bom_serial
        self.bom_revision = bom_revision

    @property
    def revision_label(self) -> str:
        """Human readable pointer to the exact BOM revision."""
        return f'{self.bom_serial}/{self.bom_revision}'

    def __repr__(self) -> str:
        return (
            f'ServiceRevision(bom_ref={self.bom_ref!r}, '
            f'revision={self.revision_label!r})'
        )


class ReconciliationItem:
    """Result of reconciling one (service, direction) usage of the interface.

    A service carrying both roles produces two items, one per
    :class:`TrafficDirection`. The item stays
    :attr:`ReconciliationStatus.PENDING_CONFIRMATION` until a matching
    :class:`RetirementReceipt` is supplied.
    """

    def __init__(
        self, *,
        service_ref: str,
        service_name: Optional[str],
        role: UsageRole,
        direction: TrafficDirection,
        credential_types: Iterable[str],
        revisions: Iterable[ServiceRevision],
        receipt_present: bool,
    ) -> None:
        self.service_ref = service_ref
        self.service_name = service_name
        self.role = role
        self.direction = direction
        self.credential_types = tuple(credential_types)
        self.revisions = tuple(revisions)
        self.receipt_present = receipt_present

    @property
    def status(self) -> ReconciliationStatus:
        if self.receipt_present:
            return ReconciliationStatus.CONFIRMED
        return ReconciliationStatus.PENDING_CONFIRMATION

    def __repr__(self) -> str:
        return (
            f'ReconciliationItem(service_ref={self.service_ref!r}, '
            f'role={self.role!r}, direction={self.direction!r}, '
            f'status={self.status!r})'
        )
