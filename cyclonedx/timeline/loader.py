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

"""Offline readers for CycloneDX JSON and XML documents.

The readers intentionally work on the raw document shape instead of the
library-wide model classes.  This keeps date-only timestamps distinguishable
from midnight instants and makes the audit usable on minimal, schema-tolerant
test fixtures.
"""

import json
import os
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable, Iterator, Optional, Union
from xml.etree.ElementTree import Element, ParseError

try:
    from defusedxml.ElementTree import (
        fromstring as _xml_fromstring,  # type: ignore[import-untyped]
    )
except ImportError:  # pragma: no cover - defusedxml is optional
    from xml.etree.ElementTree import fromstring as _xml_fromstring  # nosec B405

PathLike = Union[str, os.PathLike[str]]


class LoadError(ValueError):
    """Raised when an input document cannot be read as a CycloneDX BOM."""


@dataclass
class LifecycleRecord:
    phase: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None

    @property
    def label(self) -> str:
        return self.phase or self.name or 'unnamed-lifecycle'


@dataclass
class PropertyRecord:
    name: str
    value: str


@dataclass
class OccurrenceRecord:
    ref: Optional[str] = None
    location: Optional[str] = None
    line: Optional[int] = None
    offset: Optional[int] = None
    symbol: Optional[str] = None
    additional_context: Optional[str] = None


@dataclass
class ComponentRecord:
    ref: Optional[str] = None
    group: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    purl: Optional[str] = None
    description: Optional[str] = None
    properties: list[PropertyRecord] = field(default_factory=list)
    occurrences: list[OccurrenceRecord] = field(default_factory=list)
    components: list['ComponentRecord'] = field(default_factory=list)

    @property
    def display(self) -> str:
        if self.purl:
            return self.purl
        if self.group and self.name:
            return f'{self.group}/{self.name}'
        return self.name or self.ref or 'unnamed-component'


@dataclass
class BomDocument:
    source: str
    path: str
    content_hash: str
    fmt: str
    serial_number: Optional[str] = None
    version: int = 1
    timestamp_raw: Optional[str] = None
    lifecycles: list[LifecycleRecord] = field(default_factory=list)
    properties: list[PropertyRecord] = field(default_factory=list)
    root_component: Optional[ComponentRecord] = None
    components: list[ComponentRecord] = field(default_factory=list)


def _local_name(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def _xml_children(element: Optional[Element], name: str) -> list[Element]:
    if element is None:
        return []
    return [child for child in element if _local_name(child.tag) == name]


def _xml_child(element: Optional[Element], name: str) -> Optional[Element]:
    for child in _xml_children(element, name):
        return child
    return None


def _xml_text(element: Optional[Element], name: str) -> Optional[str]:
    child = _xml_child(element, name)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def _xml_int(element: Optional[Element], name: str) -> Optional[int]:
    text = _xml_text(element, name)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _xml_properties(element: Optional[Element]) -> list[PropertyRecord]:
    properties = _xml_child(element, 'properties')
    result: list[PropertyRecord] = []
    for prop in _xml_children(properties, 'property'):
        name = prop.get('name')
        if not name:
            continue
        result.append(PropertyRecord(name=name, value=(prop.text or '').strip()))
    return result


def _json_properties(data: Any) -> list[PropertyRecord]:
    result: list[PropertyRecord] = []
    if not isinstance(data, list):
        return result
    for prop in data:
        if not isinstance(prop, dict):
            continue
        name = prop.get('name')
        if not name:
            continue
        value = prop.get('value', '')
        result.append(PropertyRecord(name=str(name), value=str(value)))
    return result


def _json_lifecycles(data: Any) -> list[LifecycleRecord]:
    result: list[LifecycleRecord] = []
    if not isinstance(data, list):
        return result
    for item in data:
        if not isinstance(item, dict):
            continue
        phase = item.get('phase')
        name = item.get('name')
        description = item.get('description')
        result.append(LifecycleRecord(
            phase=str(phase) if phase is not None else None,
            name=str(name) if name is not None else None,
            description=str(description) if description is not None else None,
        ))
    return result


def _xml_lifecycles(metadata: Optional[Element]) -> list[LifecycleRecord]:
    result: list[LifecycleRecord] = []
    lifecycles = _xml_child(metadata, 'lifecycles')
    for lifecycle in _xml_children(lifecycles, 'lifecycle'):
        phase = _xml_text(lifecycle, 'phase')
        name = _xml_text(lifecycle, 'name')
        description = _xml_text(lifecycle, 'description')
        result.append(LifecycleRecord(phase=phase, name=name, description=description))
    return result


def _json_occurrences(data: Any) -> list[OccurrenceRecord]:
    result: list[OccurrenceRecord] = []
    if not isinstance(data, list):
        return result
    for item in data:
        if not isinstance(item, dict):
            continue
        line = item.get('line')
        offset = item.get('offset')
        additional = item.get('additionalContext', item.get('additional_context'))
        result.append(OccurrenceRecord(
            ref=item.get('bom-ref', item.get('bomRef')),
            location=item.get('location'),
            line=int(line) if isinstance(line, int) else None,
            offset=int(offset) if isinstance(offset, int) else None,
            symbol=item.get('symbol'),
            additional_context=str(additional) if additional is not None else None,
        ))
    return result


def _xml_occurrences(evidence: Optional[Element]) -> list[OccurrenceRecord]:
    result: list[OccurrenceRecord] = []
    occurrences = _xml_child(evidence, 'occurrences')
    for occurrence in _xml_children(occurrences, 'occurrence'):
        result.append(OccurrenceRecord(
            ref=occurrence.get('bom-ref'),
            location=_xml_text(occurrence, 'location'),
            line=_xml_int(occurrence, 'line'),
            offset=_xml_int(occurrence, 'offset'),
            symbol=_xml_text(occurrence, 'symbol'),
            additional_context=_xml_text(occurrence, 'additionalContext'),
        ))
    return result


def _json_component(data: dict[str, Any]) -> ComponentRecord:
    evidence = data.get('evidence')
    occurrences = _json_occurrences(evidence.get('occurrences')) if isinstance(evidence, dict) else []
    return ComponentRecord(
        ref=data.get('bom-ref', data.get('bomRef')),
        group=data.get('group'),
        name=data.get('name'),
        version=str(data.get('version')) if data.get('version') is not None else None,
        purl=data.get('purl'),
        description=data.get('description'),
        properties=_json_properties(data.get('properties')),
        occurrences=occurrences,
        components=[_json_component(child) for child in (data.get('components') or [])
                    if isinstance(child, dict)],
    )


def _xml_component(element: Element) -> ComponentRecord:
    evidence = _xml_child(element, 'evidence')
    return ComponentRecord(
        ref=element.get('bom-ref'),
        group=_xml_text(element, 'group'),
        name=_xml_text(element, 'name'),
        version=_xml_text(element, 'version'),
        purl=_xml_text(element, 'purl'),
        description=_xml_text(element, 'description'),
        properties=_xml_properties(element),
        occurrences=_xml_occurrences(evidence),
        components=[_xml_component(child) for child in _xml_children(_xml_child(element, 'components'), 'component')],
    )


def _parse_xml(raw: bytes, source: str, path: str, content_hash: str) -> BomDocument:
    try:
        root = _xml_fromstring(raw)
    except ParseError as error:
        raise LoadError(f'{source}: invalid XML: {error}') from error
    if _local_name(root.tag) != 'bom':
        raise LoadError(f'{source}: XML root is not a CycloneDX <bom>')

    metadata = _xml_child(root, 'metadata')
    components: list[ComponentRecord] = []
    components_element = _xml_child(root, 'components')
    for component in _xml_children(components_element, 'component'):
        components.append(_xml_component(component))

    root_component_element = _xml_child(metadata, 'component')
    version_text = root.get('version', '1')
    try:
        version = int(version_text)
    except ValueError:
        version = 1

    return BomDocument(
        source=source,
        path=path,
        content_hash=content_hash,
        fmt='xml',
        serial_number=root.get('serialNumber'),
        version=version,
        timestamp_raw=_xml_text(metadata, 'timestamp'),
        lifecycles=_xml_lifecycles(metadata),
        properties=_xml_properties(root) + _xml_properties(metadata),
        root_component=_xml_component(root_component_element) if root_component_element is not None else None,
        components=components,
    )


def _json_document(data: dict[str, Any], source: str, path: str, content_hash: str) -> BomDocument:
    metadata = data.get('metadata') if isinstance(data.get('metadata'), dict) else {}
    version = data.get('version', 1)
    try:
        version_int = int(version)
    except (TypeError, ValueError):
        version_int = 1
    root_component_data = metadata.get('component')
    root_component = _json_component(root_component_data) if isinstance(root_component_data, dict) else None
    components = [_json_component(component) for component in (data.get('components') or [])
                  if isinstance(component, dict)]
    return BomDocument(
        source=source,
        path=path,
        content_hash=content_hash,
        fmt='json',
        serial_number=data.get('serialNumber', data.get('serial_number')),
        version=version_int,
        timestamp_raw=metadata.get('timestamp'),
        lifecycles=_json_lifecycles(metadata.get('lifecycles')),
        properties=_json_properties(data.get('properties')) + _json_properties(metadata.get('properties')),
        root_component=root_component,
        components=components,
    )


def _looks_like_bom(data: dict[str, Any]) -> bool:
    if str(data.get('bomFormat', '')).lower() == 'cyclonedx':
        return True
    return any(key in data for key in (
        'specVersion', 'spec_version', 'serialNumber', 'serial_number',
        'metadata', 'components', 'services', 'vulnerabilities',
    ))


def _iter_inputs(paths: Iterable[object]) -> Iterator[object]:
    for raw in paths:
        if isinstance(raw, (dict, bytes, bytearray)):
            yield raw
            continue
        if isinstance(raw, str) and raw.lstrip().startswith(('{', '[', '<')) and not os.path.exists(raw):
            yield raw.encode('utf-8')
            continue
        if not isinstance(raw, (str, os.PathLike)):
            raise LoadError(f'unsupported document input: {raw!r}')
        path = os.fspath(raw)
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs.sort()
                for name in sorted(files):
                    if name.lower().endswith(('.json', '.xml')):
                        yield os.path.join(root, name)
        else:
            yield path


def load_documents(paths: Iterable[object]) -> list[BomDocument]:  # noqa: C901
    # Read BOM documents without making any network access.
    documents: list[BomDocument] = []
    seen: set[str] = set()
    for item in _iter_inputs(paths):
        if isinstance(item, dict):
            item_hash = sha256(
                json.dumps(item, sort_keys=True, separators=(',', ':')).encode('utf-8')
            ).hexdigest()
            if item_hash in seen:
                continue
            seen.add(item_hash)
            source = f'memory:{item_hash[:8]}'
            documents.append(_json_document(item, source, source, item_hash))
            continue
        if isinstance(item, (bytes, bytearray)):
            raw = bytes(item)
            content_hash = sha256(raw).hexdigest()
            source = f'memory:{content_hash[:8]}'
            path = source
        else:
            path = str(item)
            try:
                with open(path, 'rb') as stream:
                    raw = stream.read()
            except OSError as error:
                raise LoadError(f'{path}: {error}') from error
            source = os.path.basename(path)
            content_hash = sha256(raw).hexdigest()
        if content_hash in seen:
            continue
        seen.add(content_hash)
        stripped = raw.lstrip()
        if not stripped:
            raise LoadError(f'{source}: empty document')
        try:
            if stripped.startswith(b'<'):
                documents.append(_parse_xml(raw, source, path, content_hash))
            else:
                data = json.loads(raw.decode('utf-8-sig'))
                if isinstance(data, list):
                    for index, entry in enumerate(data):
                        if not isinstance(entry, dict):
                            raise LoadError(f'{source}: JSON array item {index} is not an object')
                        item_hash = sha256(
                            json.dumps(entry, sort_keys=True, separators=(',', ':')).encode('utf-8')
                        ).hexdigest()
                        if not _looks_like_bom(entry):
                            continue
                        if item_hash in seen:
                            continue
                        seen.add(item_hash)
                        documents.append(_json_document(entry, source, path, item_hash))
                elif isinstance(data, dict):
                    if not _looks_like_bom(data):
                        continue
                    documents.append(_json_document(data, source, path, content_hash))
                else:
                    raise LoadError(f'{source}: JSON root must be an object or array')
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LoadError(f'{source}: invalid JSON: {error}') from error

    if not documents:
        raise LoadError('no CycloneDX documents found')
    return documents
