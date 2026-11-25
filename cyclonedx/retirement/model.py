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
Domain model for the offline retirement reconciliation.

The three inputs of a reconciliation are intentionally kept independent:

* :class:`CredentialClass` describes a category of credentials issued against
  the interface that is being retired;
* :class:`UsageDeclaration` is the service usage statement: a service that
  still relies on the interface, either as a direct consumer or as a proxy
  that forwards traffic;
* :class:`ConfirmationReceipt` is the local acknowledgement recorded once a
  service confirmed that its usage was removed.

All objects are plain, offline data containers. They never reach out to the
network on their own.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ConsumerRole(str, Enum):
    """Role a service plays relative to the retired interface."""

    #: The service calls the interface itself.
    DIRECT_CONSUMER = 'direct_consumer'
    #: The service forwards calls between the retired interface and its own
    #: downstream consumers.
    PROXY = 'proxy'


class FlowDirection(str, Enum):
    """
    Direction of a usage edge, relative to the service making the declaration.

    A proxy participates in two directions, while a direct consumer only has
    an outbound leg towards the retired interface.
    """

    #: Traffic leaves the service, towards the retired interface.
    OUTBOUND = 'outbound'
    #: Traffic enters the service, e.g. forwarded on behalf of another consumer.
    INBOUND = 'inbound'


class ReconciliationStatus(str, Enum):
    """Outcome of reconciling a single usage declaration with the receipts."""

    #: A matching local confirmation receipt is available.
    CONFIRMED = 'confirmed'
    #: No confirmation receipt was recorded yet.
    PENDING_CONFIRMATION = 'pending_confirmation'
    #: The declaration references a credential category that is not known.
    UNKNOWN_CREDENTIAL = 'unknown_credential'
    #: The declaration references a service that cannot be located in any BOM.
    UNKNOWN_SERVICE = 'unknown_service'


@dataclass(frozen=True)
class CredentialClass:
    """
    A category of credentials issued for the retired interface.

    The ``name`` is the identifier used by usage declarations and confirmation
    receipts. Test data may use arbitrary descriptive names.
    """

    name: str
    description: Optional[str] = None


@dataclass(frozen=True)
class UsageDeclaration:
    """
    A statement that a service still uses the retired interface.

    ``bom_ref`` is the ``bom-ref`` of the service inside the BOM identified by
    ``bom_revision``. The same ``bom_ref`` may appear in BOMs of different
    revisions; each declaration is therefore scoped to its own revision.

    For a :attr:`ConsumerRole.PROXY` service, ``direction`` distinguishes the
    inbound (downstream consumers calling the proxy) and outbound (the proxy
    calling the retired interface) legs. A direct consumer always declares an
    :attr:`FlowDirection.OUTBOUND` leg.
    """

    bom_ref: str
    role: ConsumerRole
    direction: FlowDirection
    credential_name: str
    bom_revision: str


@dataclass(frozen=True)
class ConfirmationReceipt:
    """
    A locally recorded acknowledgement that a service retired its usage.

    Receipts are matched against usage declarations by the service identity
    (``bom_ref`` + ``bom_revision``) and the credential category. A proxy
    needs one receipt per direction; when a receipt covers a specific
    direction it carries the same :class:`FlowDirection` as the declaration.
    """

    bom_ref: str
    credential_name: str
    bom_revision: str
    direction: Optional[FlowDirection] = None
    note: Optional[str] = None


@dataclass(frozen=True)
class ReconciliationLine:
    """
    The reconciliation verdict for one usage declaration.

    ``service_name`` is resolved from the BOM of the matching revision and
    falls back to the ``bom_ref`` when the service cannot be located. Lines
    without a receipt stay in
    :attr:`ReconciliationStatus.PENDING_CONFIRMATION`.
    """

    declaration: UsageDeclaration
    service_name: str
    status: ReconciliationStatus
    receipt: Optional[ConfirmationReceipt] = None
    missing_reason: Optional[str] = field(default=None)

    @property
    def is_pending(self) -> bool:
        """Whether this line still waits for a confirmation receipt."""
        return self.status in (
            ReconciliationStatus.PENDING_CONFIRMATION,
            ReconciliationStatus.UNKNOWN_CREDENTIAL,
            ReconciliationStatus.UNKNOWN_SERVICE,
        )
