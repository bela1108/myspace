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
VEX verdict reuse analysis across two BOM revisions.

When a supplier re-issues a component without bumping its version, the
delivered build artifact may still have changed (different hashes) while the
component coordinates (``group``/``name``/``version``/``purl``) stay the same.
This package compares the previously signed BOM against the new one and
decides, per previously signed VEX verdict, whether the verdict may be carried
over unchanged or whether a new analysis is required.

Three notions are kept strictly separate throughout the analysis:

* the **artifact identity** - the concrete build (hashes / SWHIDs / OmniBOR ids),
* the **component coordinates** - where the artifact is published (purl / cpe),
* the **bom-ref** - a BOM-local, graph-only reference role that must never be
  used to correlate components across two different BOM documents.
"""

from .engine import VexReuseEngine
from .model import (
    ArtifactIdentity,
    ComponentCoordinates,
    ReuseDecision,
    ReuseReason,
    SignedVerdict,
    VexReuseEntry,
    VexReuseReport,
)

__all__ = [
    'ArtifactIdentity',
    'ComponentCoordinates',
    'ReuseDecision',
    'ReuseReason',
    'SignedVerdict',
    'VexReuseEngine',
    'VexReuseEntry',
    'VexReuseReport',
]
