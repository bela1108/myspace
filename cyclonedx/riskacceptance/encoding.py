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
Encoding of risk-acceptance sign-offs on top of standard CycloneDX objects.

The convention used here is deliberately schema-only:

* Sign-offs live on :class:`~cyclonedx.model.component.Component` objects
  (or the BOM root) and are marked by a ``risk:signoff:id`` property.
* ``risk:signoff:owner`` records the accepting group (procurement,
  platform or product), while ``risk:signoff:ref`` points at another
  sign-off id that the acceptance merely relies on.
* Independent material is an ``externalReference`` of type ``evidence`` or
  ``attestation``. Its artifact scope is declared on the reference with
  ``risk:evidence:component`` (``group/name``) and
  ``risk:evidence:version``. References without that scope are treated as
  un-scoped and can never establish a sign-off.

Format note: external reference properties are part of CycloneDX 1.7.
JSON documents round-trip through this library without loss. Standard XML
documents produced by other tools parse correctly; this library version
cannot itself render external-reference properties to XML yet.
"""

from collections.abc import Iterable
from typing import Optional

from ..model import ExternalReference, ExternalReferenceType, Property
from ..model.bom import Bom
from ..model.component import Component, ComponentType
from .model import (
    ArtifactCoordinates, Evidence, SignOff, SignOffEvaluation,
)

SIGNOFF_ID = 'risk:signoff:id'
SIGNOFF_OWNER = 'risk:signoff:owner'
SIGNOFF_REF = 'risk:signoff:ref'
EVIDENCE_COMPONENT = 'risk:evidence:component'
EVIDENCE_VERSION = 'risk:evidence:version'

_INDEPENDENT_REFERENCE_TYPES = frozenset({
    ExternalReferenceType.EVIDENCE,
    ExternalReferenceType.ATTESTATION,
})


def _property_map(properties: Iterable[Property]) -> dict[str, str]:
    values: dict[str, list[str]] = {}
    for prop in properties:
        if prop.value is not None:
            values.setdefault(prop.name, []).append(prop.value)
    return {name: vals[0] for name, vals in values.items() if vals}


def _reference_properties(reference: ExternalReference) -> dict[str, str]:
    return _property_map(reference.properties)


def _coordinates(group: Optional[str], name: str,
                  version: Optional[str], bom_ref: Optional[str]
                  ) -> ArtifactCoordinates:
    return ArtifactCoordinates(
        group=group or None,
        name=name,
        version=version or None,
        bom_ref=bom_ref,
    )


def _component_coordinates(component: Component) -> ArtifactCoordinates:
    return _coordinates(
        group=component.group,
        name=component.name,
        version=component.version,
        bom_ref=component.bom_ref.value,
    )


def _evidence_from_reference(
    reference: ExternalReference,
) -> Optional[Evidence]:
    if reference.type not in _INDEPENDENT_REFERENCE_TYPES:
        return None
    props = _reference_properties(reference)
    component_spec = props.get(EVIDENCE_COMPONENT)
    if not component_spec:
        return Evidence(
            url=str(reference.url),
            reference_type=reference.type.value,
            scope=None,
            hashes=tuple(sorted(
                f"{item.alg.value}:{item.content}"
                for item in reference.hashes
            )),
        )
    if "/" in component_spec:
        group, name = component_spec.rsplit("/", 1)
    else:
        group, name = None, component_spec
    scope = _coordinates(
        group=group,
        name=name,
        version=props.get(EVIDENCE_VERSION),
        bom_ref=None,
    )
    return Evidence(
        url=str(reference.url),
        reference_type=reference.type.value,
        scope=scope,
        hashes=tuple(sorted(
            f"{item.alg.value}:{item.content}"
            for item in reference.hashes
        )),
    )


def _signoff_from_carrier(
    properties: Iterable[Property],
    references: Iterable[ExternalReference],
    artifact: ArtifactCoordinates,
) -> Optional[SignOff]:
    props = _property_map(properties)
    signoff_id = props.get(SIGNOFF_ID)
    if not signoff_id:
        return None
    refs = [prop.value for prop in properties
            if prop.name == SIGNOFF_REF and prop.value]
    evidence = [
        item for item in (
            _evidence_from_reference(reference)
            for reference in references
        )
        if item is not None
    ]
    return SignOff(
        signoff_id=signoff_id,
        owner=props.get(SIGNOFF_OWNER),
        artifact=artifact,
        references=refs,
        evidence=evidence,
    )


def extract_signoffs(bom: Bom) -> list[SignOff]:
    """Extract all risk-acceptance sign-offs carried by a BOM.

    Both component-level sign-offs and a possible BOM-level sign-off are
    considered. Every extracted sign-off keeps the declared artifact
    coordinates, so evidence can be re-checked after component
    replacements even when ``bom-ref`` values changed.
    """
    signoffs: list[SignOff] = []
    for component in bom.components:
        signoff = _signoff_from_carrier(
            component.properties,
            component.external_references,
            _component_coordinates(component),
        )
        if signoff is not None:
            signoffs.append(signoff)
    if bom.metadata.component is not None:
        root = bom.metadata.component
        signoff = _signoff_from_carrier(
            root.properties,
            root.external_references,
            _component_coordinates(root),
        )
        if signoff is not None:
            signoffs.append(signoff)
    return signoffs


def make_evidence_reference(
    url: str,
    artifact: ArtifactCoordinates,
    *,
    reference_type: ExternalReferenceType = ExternalReferenceType.EVIDENCE,
) -> ExternalReference:
    """Build an artifact-scoped evidence/attestation external reference."""
    component_spec = (artifact.name if not artifact.group
                      else f"{artifact.group}/{artifact.name}")
    properties = [Property(name=EVIDENCE_COMPONENT, value=component_spec)]
    if artifact.version is not None:
        properties.append(Property(
            name=EVIDENCE_VERSION, value=artifact.version))
    return ExternalReference(
        type=reference_type,
        url=url,
        properties=properties,
    )


def make_signoff_properties(
    *,
    signoff_id: str,
    owner: Optional[str] = None,
    references: Optional[Iterable[str]] = None,
) -> list[Property]:
    """Build the property set that marks a carrier as a sign-off."""
    properties = [Property(name=SIGNOFF_ID, value=signoff_id)]
    if owner is not None:
        properties.append(Property(name=SIGNOFF_OWNER, value=owner))
    for referenced in references or ():
        properties.append(Property(name=SIGNOFF_REF, value=referenced))
    return properties


def make_signoff_component(
    artifact: ArtifactCoordinates,
    *,
    signoff_id: str,
    owner: Optional[str] = None,
    references: Optional[Iterable[str]] = None,
    evidence: Optional[Iterable[ExternalReference]] = None,
) -> Component:
    """Convenience factory for tests and the offline example script."""
    return Component(
        type=ComponentType.LIBRARY,
        group=artifact.group,
        name=artifact.name,
        version=artifact.version,
        bom_ref=artifact.bom_ref,
        properties=make_signoff_properties(
            signoff_id=signoff_id, owner=owner, references=references),
        external_references=list(evidence or ()),
    )


def evaluate_bom(bom: Bom) -> list[SignOffEvaluation]:
    """Extract sign-offs from ``bom`` and classify them offline."""
    from .analyzer import RiskAcceptanceAnalyzer
    return RiskAcceptanceAnalyzer().evaluate(extract_signoffs(bom))
