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

"""Offline decommission reconciliation.

This contrib package cross-checks the retirement of a decommissioned service
against the service/dependency references kept in CycloneDX BOMs and a set of
locally provided evidence:

* :class:`~cyclonedx.contrib.decommission.model.CredentialClaim` - which
  credential categories a service still uses against the retired interface,
* :class:`~cyclonedx.contrib.decommission.model.ServiceUsageDeclaration` -
  whether a service acts as direct consumer and/or forwarding proxy,
* :class:`~cyclonedx.contrib.decommission.model.RetirementReceipt` - the
  locally collected confirmation that a consumer finished its retirement.

Everything works fully offline on already deserialized
:class:`~cyclonedx.model.bom.Bom` instances - no network access is required.
"""

from .model import (
    CredentialClaim,
    ReconciliationItem,
    ReconciliationStatus,
    RetirementReceipt,
    ServiceRevision,
    ServiceUsageDeclaration,
    TrafficDirection,
    UsageRole,
)
from .reconcile import DecommissionReconciler, DutyTicket

__all__ = [
    'CredentialClaim',
    'DecommissionReconciler',
    'DutyTicket',
    'ReconciliationItem',
    'ReconciliationStatus',
    'RetirementReceipt',
    'ServiceRevision',
    'ServiceUsageDeclaration',
    'TrafficDirection',
    'UsageRole',
]
