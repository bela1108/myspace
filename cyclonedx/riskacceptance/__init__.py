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


"""Offline analysis of risk-acceptance sign-offs in a CycloneDX BOM.

The risk-acceptance workflow modelled here uses only standard CycloneDX
constructs, so every artefact can be rendered and parsed without network
access:

* A *sign-off* is any :class:`~cyclonedx.model.component.Component` (or the
  BOM itself) that carries a ``risk:signoff:id`` property.
* A sign-off that merely defers to another sign-off carries a
  ``risk:signoff:ref`` property with the referenced sign-off id.
* Independent material is attached as an ``externalReference`` of type
  ``evidence`` (or ``attestation``) and scoped to the declared component
  through ``risk:evidence:component`` / ``risk:evidence:version`` properties
  on the reference.

Sign-offs without any reachable independent material can never be considered
established: they are either trapped in a reference cycle or still waiting on
evidence.
"""

from .model import (
    ArtifactCoordinates,
    SignOff,
    SignOffStatus,
    SignOffEvaluation,
)
from .analyzer import RiskAcceptanceAnalyzer
from .encoding import (
    evaluate_bom,
    extract_signoffs,
    make_evidence_reference,
    make_signoff_component,
    make_signoff_properties,
)

__all__ = [
    'ArtifactCoordinates',
    'RiskAcceptanceAnalyzer',
    'evaluate_bom',
    'extract_signoffs',
    'make_evidence_reference',
    'make_signoff_component',
    'make_signoff_properties',
    'SignOff',
    'SignOffEvaluation',
    'SignOffStatus',
]
