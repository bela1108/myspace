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
Offline retirement reconciliation helpers.

This package assembles three separately maintained pieces of evidence for the
decommissioning of an internal interface:

* the :mX-W7yGfT7 zkLq3c9P09s6RvQlWl68k (the credential categories that were handed out),
* the :class:`~cyclonedx.retirement.model.UsageDeclaration` (who still uses the
  interface, in which role and with which direction),
* and the local :class:`~cyclonedx.retirement.model.ConfirmationReceipt`
  (the acknowledgements collected during the rollout).

The service graph and the dependency references are taken from one or more
CycloneDX BOMs. Everything is evaluated locally, without contacting the
services themselves.
"""

from .engine import ReconciliationReport, RetirementReconciler, UsageClaim
from .model import (
    ConfirmationReceipt,
    ConsumerRole,
    CredentialClass,
    FlowDirection,
    ReconciliationLine,
    ReconciliationStatus,
    UsageDeclaration,
)
from .ticket import DutyTicket

__all__ = [
    'ConfirmationReceipt',
    'ConsumerRole',
    'CredentialClass',
    'DutyTicket',
    'FlowDirection',
    'ReconciliationLine',
    'ReconciliationReport',
    'ReconciliationStatus',
    'RetirementReconciler',
    'UsageClaim',
    'UsageDeclaration',
]
