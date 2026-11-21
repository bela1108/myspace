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


"""Enums used by the offline impact explanation API."""

from enum import Enum


class ImpactPathStatus(str, Enum):
    """
    Confidence of a reconstructed deployment path to an affected component.

    * :attr:`CONFIRMED` - every edge on the path is a present, in-scope dependency edge and the
      vulnerability ``affects`` entry asserts that the reached component is affected.
    * :attr:`PENDING` - the path is reachable from the deployment root, but at least one edge or the
      affected status itself could not be verified offline and must be reviewed manually.
    """

    CONFIRMED = 'confirmed'
    PENDING = 'pending'


class ImpactEdgeStatus(str, Enum):
    """
    Verification state of a single dependency edge considered during path reconstruction.

    * :attr:`VERIFIED` - the edge exists in the BOM dependency graph and both endpoints are known
      components inside the applicable component scope.
    * :attr:`CYCLE` - following the edge would revisit a component already present on the current
      path; traversal was stopped to avoid an endless loop.
    * :attr:`MISSING_REFERENCE` - the edge targets a ``bom-ref`` that is not declared by any
      component in the BOM, so the subtree behind it cannot be inspected.
    * :attr:`OUT_OF_SCOPE` - the edge leaves the component scope the caller declared as applicable.
    """

    VERIFIED = 'verified'
    CYCLE = 'cycle'
    MISSING_REFERENCE = 'missing_reference'
    OUT_OF_SCOPE = 'out_of_scope'


class AffectedStatus(str, Enum):
    """
    Offline interpretation of a ``vulnerability.affects`` entry against the actual component.

    * :attr:`AFFECTED` - at least one version/range entry explicitly marks the component affected.
    * :attr:`UNAFFECTED` - version/range entries exist but all of them explicitly mark it unaffected.
    * :attr:`UNKNOWN_RANGE` - no version/range entries were supplied or none assert a definite
      affected/unaffected state, so applicability cannot be decided offline.
    * :attr:`MISSING_TARGET` - the referenced ``bom-ref`` does not match any component in the BOM.
    """

    AFFECTED = 'affected'
    UNAFFECTED = 'unaffected'
    UNKNOWN_RANGE = 'unknown_range'
    MISSING_TARGET = 'missing_target'
