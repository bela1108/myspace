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

"""Asset inventory: the authoritative source of component type and lifecycle.

The inventory is rendered into a CycloneDX 1.7 BOM. Only objects declared here
may appear in a BOM, and their ``component.type`` / lifecycle phase are taken
exclusively from this inventory. Neither the replacement policy nor the
disposition list is allowed to invent or reclassify a component.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cyclonedx.model import ExternalReference, ExternalReferenceType, Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.lifecycle import LifecyclePhase, PredefinedLifecycle

#: Namespace for every property that is specific to this recall workflow.
NAMESPACE = 'urn:example:key-module-recall'


class LifecycleKind(str, Enum):
    """Lifecycle as recorded by the asset inventory, not by the recall list."""

    INSTALLED = 'installed'
    SPARE = 'spare'
    SEALED = 'sealed'


_LIFECYCLE_PROPERTY = f'{NAMESPACE}:lifecycle'
_SEAL_PROPERTY = f'{NAMESPACE}:seal'
_SERIAL_PROPERTY = f'{NAMESPACE}:serial-number'


@dataclass(frozen=True)
class SealRecord:
    """Evidence that a spare is currently sealed in the warehouse.

    A seal only proves that the component is currently unavailable for
    installation. It never changes the component's lifecycle and it never
    counts as recall or destruction evidence.
    """

    seal_id: str
    location: str
    sealed_since: str
    note: str = ''

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'SealRecord':
        return cls(
            seal_id=data['sealId'],
            location=data['location'],
            sealed_since=data['sealedSince'],
            note=data.get('note', ''),
        )


@dataclass(frozen=True)
class AssetEntry:
    """One physical object tracked by the asset inventory."""

    bom_ref: str
    name: str
    component_type: ComponentType
    lifecycle: LifecycleKind
    version: Optional[str] = None
    serial_number: Optional[str] = None
    parent_ref: Optional[str] = None
    seal: Optional[SealRecord] = None
    description: Optional[str] = None

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'AssetEntry':
        seal_data = data.get('seal')
        return cls(
            bom_ref=data['bomRef'],
            name=data['name'],
            component_type=ComponentType(data['componentType']),
            lifecycle=LifecycleKind(data['lifecycle']),
            version=data.get('version'),
            serial_number=data.get('serialNumber'),
            parent_ref=data.get('parentRef'),
            seal=SealRecord.from_json(seal_data) if seal_data else None,
            description=data.get('description'),
        )


def load_asset_inventory(path: Path) -> List[AssetEntry]:
    """Load the local asset inventory JSON document."""
    document = json.loads(path.read_text(encoding='utf-8'))
    entries = [AssetEntry.from_json(item) for item in document['assets']]
    _validate_inventory(entries)
    return entries


def _validate_inventory(entries: Iterable[AssetEntry]) -> None:
    refs = [entry.bom_ref for entry in entries]
    if len(refs) != len(set(refs)):
        raise ValueError('asset inventory contains duplicate bomRef values')
    known_refs = set(refs)
    for entry in entries:
        if entry.parent_ref is not None and entry.parent_ref not in known_refs:
            raise ValueError(
                f'asset {entry.bom_ref!r} references unknown parent {entry.parent_ref!r}'
            )
        if entry.lifecycle is LifecycleKind.SEALED and entry.seal is None:
            raise ValueError(f'sealed asset {entry.bom_ref!r} must carry seal evidence')
        if entry.lifecycle is not LifecycleKind.SEALED and entry.seal is not None:
            raise ValueError(f'seal evidence is only valid for sealed assets: {entry.bom_ref!r}')


def _component_properties(entry: AssetEntry) -> List[Property]:
    properties = [
        Property(name=_LIFECYCLE_PROPERTY, value=entry.lifecycle.value),
    ]
    if entry.serial_number is not None:
        properties.append(Property(name=_SERIAL_PROPERTY, value=entry.serial_number))
    if entry.seal is not None:
        seal = entry.seal
        properties.extend([
            Property(name=_SEAL_PROPERTY, value=seal.seal_id),
            Property(name=f'{_SEAL_PROPERTY}:location', value=seal.location),
            Property(name=f'{_SEAL_PROPERTY}:sealedSince', value=seal.sealed_since),
            Property(name=f'{_SEAL_PROPERTY}:meaning',
                     value='seal proves current unavailability only; it is not recall evidence'),
        ])
        if seal.note:
            properties.append(Property(name=f'{_SEAL_PROPERTY}:note', value=seal.note))
    return properties


def _to_component(entry: AssetEntry) -> Component:
    external_references: List[ExternalReference] = []
    if entry.seal is not None:
        external_references.append(ExternalReference(
            type=ExternalReferenceType.EVIDENCE,
            url=XsUri(f'urn:example:warehouse-seal:{entry.seal.seal_id}'),
            comment='Warehouse seal: the spare is currently unavailable; the seal itself '
                    'does not prove recall, destruction or permanent removal from service.',
        ))
    return Component(
        bom_ref=entry.bom_ref,
        name=entry.name,
        type=entry.component_type,
        version=entry.version,
        description=entry.description,
        properties=_component_properties(entry),
        external_references=external_references,
    )


def build_sbom(entries: Iterable[AssetEntry]) -> Bom:
    """Render the asset inventory into a CycloneDX :class:`Bom`.

    Device components nest the modules recorded against them. Spares are kept
    as independent top-level components so that one shared spare is not
    duplicated per device.
    """
    entries = list(entries)
    components_by_ref: Dict[str, Component] = {
        entry.bom_ref: _to_component(entry) for entry in entries
    }

    bom = Bom()
    for entry in entries:
        component = components_by_ref[entry.bom_ref]
        if entry.parent_ref is None:
            bom.components.add(component)
        else:
            components_by_ref[entry.parent_ref].components.add(component)
            bom.register_dependency(components_by_ref[entry.parent_ref], [component])

    # The standard BOM-level lifecycle marks the operations phase. The
    # per-component state (installed / spare / sealed) travels with each
    # component in the namespaced lifecycle property so that it survives a
    # JSON round trip and stays bound to the right physical object.
    bom.metadata.lifecycles.add(PredefinedLifecycle(LifecyclePhase.OPERATIONS))
    # BOM-level property makes the lifecycle convention explicit for consumers.
    bom.metadata.properties.add(Property(
        name=f'{NAMESPACE}:lifecycle-source',
        value='asset inventory; component.type and lifecycle are not derived '
              'from replacement policy or disposition list',
    ))
    return bom


def index_entries(bom: Bom) -> Dict[str, AssetEntry]:
    """Reconstruct asset entries from a (possibly round-tripped) BOM.

    The reconstruction only trusts data that the asset inventory originally
    wrote: component type comes from the CycloneDX component and lifecycle
    comes from the namespaced lifecycle property.
    """
    indexed: Dict[str, AssetEntry] = {}

    def walk(component: Component, parent_ref: Optional[str]) -> None:
        lifecycle_value = _first_property(component, _LIFECYCLE_PROPERTY)
        seal_id = _first_property(component, _SEAL_PROPERTY)
        seal: Optional[SealRecord]
        if seal_id is None:
            seal = None
        else:
            seal = SealRecord(
                seal_id=seal_id,
                location=_first_property(component, f'{_SEAL_PROPERTY}:location') or '',
                sealed_since=_first_property(component, f'{_SEAL_PROPERTY}:sealedSince') or '',
                note=_first_property(component, f'{_SEAL_PROPERTY}:note') or '',
            )
        indexed[component.bom_ref.value] = AssetEntry(
            bom_ref=component.bom_ref.value,
            name=component.name,
            component_type=component.type,
            lifecycle=LifecycleKind(lifecycle_value),
            version=component.version,
            serial_number=_first_property(component, _SERIAL_PROPERTY),
            parent_ref=parent_ref,
            seal=seal,
            description=component.description,
        )
        for child in component.components:
            walk(child, component.bom_ref.value)

    for top_level in bom.components:
        walk(top_level, None)
    return indexed


def _first_property(component: Component, name: str) -> Optional[str]:
    for prop in component.properties:
        if prop.name == name:
            return prop.value
    return None
