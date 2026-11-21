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
Offline impact explanation for CycloneDX BOMs.

This package reconstructs, for a given deployment root and an applicable component scope, the dependency paths that
connect the root to the components referenced by a vulnerability's ``affects``. Everything is derived from the BOM's
own :class:`~cyclonedx.model.dependency.Dependency` graph, so no network access is required.

Edges that cannot be fully verified -- because they close a cycle, point at a missing reference, cross the boundary of
the applicable scope, or lead to a target whose affected version range is unknown -- are never silently dropped. They
are reported as :class:`~cyclonedx.impact.model.UnresolvedEdge` entries so that a human reviewer can confirm them.
"""

from .analyzer import analyze_impact
from .enums import AffectedStatus, ImpactEdgeStatus, ImpactPathStatus
from .model import ImpactPath, ImpactReport, UnresolvedEdge, VulnerabilityImpact

__all__ = [
    'AffectedStatus',
    'ImpactEdgeStatus',
    'ImpactPath',
    'ImpactPathStatus',
    'ImpactReport',
    'UnresolvedEdge',
    'VulnerabilityImpact',
    'analyze_impact',
]
