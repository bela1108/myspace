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

"""Old cryptographic key module recall reconciliation demo.

This package shows how a CycloneDX hardware BOM can be reconciled against a
local disposition list. It deliberately keeps three concerns separate:

#. The :mod:`asset_inventory` module owns the *type* and *lifecycle* of every
   object and renders them into a CycloneDX BOM (devices, installed modules
   and pre-positioned spares).
#. The :mod:`replacement_policy` module is an independent list that only
   declares which spare is allowed to replace which installed module.
#. The :mod:`reconcile` module joins the BOM, the replacement policy and the
   local disposition list and reports the recall coverage.
"""

from .asset_inventory import (
    AssetEntry,
    LifecycleKind,
    SealRecord,
    build_sbom,
    load_asset_inventory,
)
from .reconcile import (
    CoverageStatus,
    ReconciliationReport,
    reconcile,
)
from .replacement_policy import ReplacementRule, load_replacement_policy

__all__ = [
    'AssetEntry',
    'CoverageStatus',
    'LifecycleKind',
    'ReconciliationReport',
    'ReplacementRule',
    'SealRecord',
    'build_sbom',
    'load_asset_inventory',
    'load_replacement_policy',
    'reconcile',
]
