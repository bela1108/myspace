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

# Extract dated evidence from normalized CycloneDX documents.

import json
import re
from hashlib import sha256
from typing import Iterator, Optional
from urllib.parse import quote

from .loader import BomDocument, ComponentRecord, PropertyRecord
from .model import UNKNOWN_SPAN, Evidence, TimeSpan
from .timeutil import parse_time_span

_TIME_MARKERS = (
    'timestamp', 'datetime', 'occurredat', 'observedat', 'deliveredat',
    'installedat', 'builtat', 'createdat', 'completedat', 'startedat',
    'finishedat', 'shippedat', 'receivedat', 'deployedat', 'releasedat',
    'eventdate', 'eventtime', 'occurred', 'observed',
)
_EVENT_MARKERS = (
    'event', 'timeline', 'lifecycle', 'stage', 'phase', 'milestone',
    'delivery', 'deliver', 'install', 'build', 'ship', 'receive',
    'deploy', 'release',
)
_TIME_EXCLUSIONS = ('validuntil', 'expires', 'expiry', 'ttl', 'hash', 'checksum')


def _normalize_name(value: object) -> str:
    return re.sub(r'[^a-z0-9]+', '', str(value).lower())


def _slug(value: object) -> str:
    return quote(str(value), safe=':@.-_~')


def _digest(value: str) -> str:
    return sha256(value.encode('utf-8')).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def is_time_property(name: str) -> bool:
    normalized = _normalize_name(name)
    if any(excluded in normalized for excluded in _TIME_EXCLUSIONS):
        return False
    if normalized in ('date', 'time', 'when'):
        return True
    return any(marker in normalized for marker in _TIME_MARKERS)


def is_event_property(name: str) -> bool:
    normalized = _normalize_name(name)
    return any(marker in normalized for marker in _EVENT_MARKERS)


def _property_span(prop: PropertyRecord) -> Optional[TimeSpan]:
    return parse_time_span(prop.value)


def _combine_spans(spans: list[TimeSpan]) -> Optional[TimeSpan]:
    if not spans:
        return None
    if len(spans) == 1:
        return spans[0]
    starts = [span.start for span in spans if span.start is not None]
    ends = [span.end for span in spans if span.end is not None]
    start = min(starts) if starts else None
    end = max(ends) if ends else None
    return TimeSpan(
        start=start,
        end=end,
        precision='range',
        raw=' | '.join(span.raw for span in spans if span.raw),
    )


def _document_bases(documents: list[BomDocument]) -> dict[int, str]:
    groups: dict[str, list[BomDocument]] = {}
    for document in documents:
        if document.serial_number:
            base = f'bom:{document.serial_number}@{document.version}'
        else:
            base = f'bom:sha256:{document.content_hash[:16]}'
        groups.setdefault(base, []).append(document)
    result: dict[int, str] = {}
    for base, group in groups.items():
        hashes = {document.content_hash for document in group}
        if len(hashes) <= 1:
            for document in group:
                result[id(document)] = base
        else:
            for document in sorted(group, key=lambda item: (item.content_hash, item.source)):
                result[id(document)] = f'{base}~{document.content_hash[:8]}'
    return result


def _iter_components(document: BomDocument) -> Iterator[ComponentRecord]:
    def walk(component: ComponentRecord) -> Iterator[ComponentRecord]:
        yield component
        for child in component.components:
            yield from walk(child)
    if document.root_component is not None:
        yield from walk(document.root_component)
    for component in document.components:
        yield from walk(component)


def _component_identity(component: ComponentRecord) -> dict[str, object]:
    return {
        'ref': component.ref,
        'group': component.group,
        'name': component.name,
        'version': component.version,
        'purl': component.purl,
    }


def _component_id(base: str, component: ComponentRecord) -> str:
    if component.ref:
        return f'{base}#component/{_slug(component.ref)}'
    identity = _canonical(_component_identity(component))
    return f'{base}#component/sha256:{_digest(identity)[:12]}'


def _unique(identifier: str, used: set[str], salt: str) -> str:
    if identifier not in used:
        used.add(identifier)
        return identifier
    candidate = f'{identifier}~{_digest(salt)[:8]}'
    counter = 2
    while candidate in used:
        candidate = f'{identifier}~{_digest(salt)[:8]}-{counter}'
        counter += 1
    used.add(candidate)
    return candidate


def _lifecycle_labels(document: BomDocument) -> list[str]:
    labels: list[str] = []
    for lifecycle in document.lifecycles:
        label = lifecycle.phase or lifecycle.name or 'unnamed-lifecycle'
        if label not in labels:
            labels.append(label)
    return labels


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    result: dict[str, Evidence] = {}
    for item in evidence:
        existing = result.get(item.id)
        if existing is None:
            result[item.id] = item
            continue
        if _canonical(existing.to_json()) == _canonical(item.to_json()):
            continue
        item.id = f'{item.id}~{_digest(_canonical(item.to_json()))[:8]}'
        while item.id in result:
            item.id = f'{item.id}-x'
        result[item.id] = item
    return sorted(result.values(), key=lambda item: item.id)


def extract_evidence(documents: list[BomDocument]) -> list[Evidence]:  # noqa: C901
    bases = _document_bases(documents)
    evidence: list[Evidence] = []
    for document in sorted(documents, key=lambda item: (bases[id(item)], item.content_hash)):
        base = bases[id(document)]
        manifest_span = parse_time_span(document.timestamp_raw) or UNKNOWN_SPAN
        manifest_source = 'metadata.timestamp' if document.timestamp_raw else 'unknown'
        labels = _lifecycle_labels(document)
        evidence.append(Evidence(
            id=f'{base}#manifest',
            kind='manifest',
            bom_id=base,
            source=document.source,
            span=manifest_span,
            label=document.serial_number or document.source,
            time_source=manifest_source,
            details={
                'serialNumber': document.serial_number,
                'version': document.version,
                'lifecycleLabels': labels,
                'format': document.fmt,
            },
        ))

        lifecycle_ids: set[str] = set()
        for lifecycle in document.lifecycles:
            label = lifecycle.phase or lifecycle.name or 'unnamed-lifecycle'
            identifier = _unique(f'{base}#lifecycle/{_slug(label)}', lifecycle_ids, label)
            evidence.append(Evidence(
                id=identifier,
                kind='lifecycle',
                bom_id=base,
                source=document.source,
                span=manifest_span,
                label=f'lifecycle:{label}',
                phase=lifecycle.phase,
                lifecycle_name=lifecycle.name,
                description=lifecycle.description,
                time_source=manifest_source,
            ))

        for prop in document.properties:
            span = _property_span(prop)
            if span is None and not is_event_property(prop.name):
                continue
            identifier = f'{base}#property/{_slug(prop.name)}'
            evidence.append(Evidence(
                id=identifier,
                kind='property',
                bom_id=base,
                source=document.source,
                span=span or manifest_span,
                label=f'{prop.name}={prop.value}',
                property_name=prop.name,
                time_source=f'property:{prop.name}' if span else manifest_source,
                details={'scope': 'bom', 'value': prop.value},
            ))

        component_ids: set[str] = set()
        for component in _iter_components(document):
            identity = _component_identity(component)
            component_id = _unique(_component_id(base, component), component_ids, _canonical(identity))
            timed = [(prop, _property_span(prop)) for prop in component.properties if is_time_property(prop.name)]
            timed = [(prop, span) for prop, span in timed if span is not None]
            evented = [(prop, _property_span(prop)) for prop in component.properties if is_event_property(prop.name)]
            explicit_spans = [span for _, span in timed if span is not None]
            component_span = _combine_spans(explicit_spans) or manifest_span
            time_source = (
                'property:' + ','.join(prop.name for prop, _ in timed)
                if explicit_spans else manifest_source
            )
            evidence.append(Evidence(
                id=component_id,
                kind='component',
                bom_id=base,
                source=document.source,
                span=component_span,
                label=component.display,
                component_ref=component.ref,
                component_name=component.name,
                component_version=component.version,
                purl=component.purl,
                time_source=time_source,
                details={
                    'group': component.group,
                    'description': component.description,
                    'occurrenceCount': len(component.occurrences),
                    'propertyCount': len(component.properties),
                },
            ))

            property_ids: set[str] = set()
            for prop, span in timed:
                if span is None:
                    continue
                identifier = _unique(
                    f'{component_id}#property/{_slug(prop.name)}',
                    property_ids,
                    _canonical({'name': prop.name, 'value': prop.value}),
                )
                evidence.append(Evidence(
                    id=identifier,
                    kind='property',
                    bom_id=base,
                    source=document.source,
                    span=span,
                    label=f'{prop.name}={prop.value}',
                    component_ref=component.ref,
                    component_name=component.name,
                    component_version=component.version,
                    purl=component.purl,
                    property_name=prop.name,
                    time_source=f'property:{prop.name}',
                    details={'scope': 'component', 'value': prop.value},
                ))
            for prop, span in evented:
                if any(prop is timed_prop for timed_prop, _ in timed):
                    continue
                identifier = _unique(
                    f'{component_id}#property/{_slug(prop.name)}',
                    property_ids,
                    _canonical({'name': prop.name, 'value': prop.value}),
                )
                evidence.append(Evidence(
                    id=identifier,
                    kind='property',
                    bom_id=base,
                    source=document.source,
                    span=span or component_span,
                    label=f'{prop.name}={prop.value}',
                    component_ref=component.ref,
                    component_name=component.name,
                    component_version=component.version,
                    purl=component.purl,
                    property_name=prop.name,
                    time_source=f'property:{prop.name}' if span else time_source,
                    details={'scope': 'component', 'value': prop.value},
                ))

            occurrence_ids: set[str] = set()
            for occurrence in component.occurrences:
                occurrence_span: Optional[TimeSpan] = None
                occurrence_source = ''
                if occurrence.additional_context:
                    occurrence_span = parse_time_span(occurrence.additional_context)
                    occurrence_source = 'occurrence.additionalContext'
                if occurrence_span is None and occurrence.location:
                    occurrence_span = parse_time_span(occurrence.location)
                    occurrence_source = 'occurrence.location'
                if occurrence_span is None:
                    occurrence_span = component_span
                    occurrence_source = time_source
                assert occurrence_span is not None
                occurrence_key = _canonical({
                    'ref': occurrence.ref,
                    'location': occurrence.location,
                    'line': occurrence.line,
                    'offset': occurrence.offset,
                    'symbol': occurrence.symbol,
                    'additionalContext': occurrence.additional_context,
                })
                occurrence_slug = _slug(occurrence.ref) if occurrence.ref else f'sha256:{_digest(occurrence_key)[:12]}'
                identifier = _unique(f'{component_id}#occurrence/{occurrence_slug}', occurrence_ids, occurrence_key)
                evidence.append(Evidence(
                    id=identifier,
                    kind='occurrence',
                    bom_id=base,
                    source=document.source,
                    span=occurrence_span,
                    label=occurrence.location or occurrence.ref or 'occurrence',
                    component_ref=component.ref,
                    component_name=component.name,
                    component_version=component.version,
                    purl=component.purl,
                    location=occurrence.location,
                    occurrence_ref=occurrence.ref,
                    time_source=occurrence_source,
                    details={
                        'line': occurrence.line,
                        'offset': occurrence.offset,
                        'symbol': occurrence.symbol,
                        'additionalContext': occurrence.additional_context,
                    },
                ))
    return _dedupe(evidence)
