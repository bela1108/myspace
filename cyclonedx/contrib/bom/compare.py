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
Compare two CycloneDX manifests without relying on a particular SBOM generator.

The matcher deliberately keeps matching stages separate:

1. verifiable content hashes,
2. component coordinates (PURL/CPE/group-name-version),
3. component evidence (identities, occurrences and call stacks).

Evidence from a later stage never silently overrides an earlier stage.  If the
stages disagree, or if several plausible counterparts exist, the result keeps
all candidates and does not select one.  A component that was split into
multiple new components is therefore represented as a split with each
candidate's own dependency edges intact.

This module also provides a small command line entry point::

    python -m cyclonedx.contrib.bom.compare baseline.json current.json
"""

__all__ = [
    'ComponentDescriptor',
    'ComponentMatch',
    'HashDescriptor',
    'ManifestComparison',
    'ManifestMatcher',
    'compare_manifests',
    'load_manifest',
    'main',
]

import json
import sys
from argparse import ArgumentParser, Namespace
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from io import StringIO
from os import PathLike
from typing import Any, Optional

from ...model.bom import Bom
from ...model.component import Component
from ...model.component_evidence import ComponentEvidence, IdentityField

_SCHEMA_ID = 'cyclonedx-manifest-comparison/1'

_STAGES = ('hash', 'coordinates', 'evidence')

_WEAK_HASH_ALGORITHMS = frozenset({'md5', 'sha-1'})

_HASH_HEX_LENGTHS = {
    'md5': 32,
    'sha-1': 40,
    'sha-256': 64,
    'sha-384': 96,
    'sha-512': 128,
    'sha3-256': 64,
    'sha3-384': 96,
    'sha3-512': 128,
    'blake2b-256': 64,
    'blake2b-384': 96,
    'blake2b-512': 128,
    'blake3': 64,
    'streebog-256': 64,
    'streebog-512': 128,
}

_IDENTITY_WEIGHTS = {
    IdentityField.HASH.value: 6,
    IdentityField.PURL.value: 5,
    IdentityField.CPE.value: 5,
    IdentityField.SWID.value: 4,
    IdentityField.SWHID.value: 4,
    IdentityField.OMNIBOR_ID.value: 4,
    IdentityField.NAME.value: 2,
    IdentityField.GROUP.value: 2,
    IdentityField.VERSION.value: 2,
}

_STRONG_EVIDENCE_PREFIXES = (
    'identity:hash=',
    'identity:purl=',
    'identity:cpe=',
    'identity:swid=',
    'identity:swhid=',
    'identity:omniborId=',
    'occurrence:',
    'callstack:',
    'evidence:hash=',
    'evidence:filename=',
)


def _normalize_algorithm(value: str) -> str:
    return value.strip().lower()


def _normalize_digest(value: str) -> str:
    return value.strip().lower()


def _normalize_evidence_value(value: str) -> str:
    return value.strip().replace('\\', '/').casefold()


def _hash_format_valid(algorithm: str, digest: str) -> bool:
    expected = _HASH_HEX_LENGTHS.get(algorithm)
    if expected is None:
        return False
    return len(digest) == expected and all(c in '0123456789abcdef' for c in digest)


@dataclass(frozen=True)
class HashDescriptor:
    """A hash that can be compared without trusting a component name."""

    algorithm: str
    digest: str
    weak: bool
    format_valid: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            'algorithm': self.algorithm,
            'digest': self.digest,
            'weak': self.weak,
            'format_valid': self.format_valid,
        }


@dataclass(frozen=True)
class ComponentDescriptor:
    """Stable, report-friendly view of a component in one manifest."""

    bom_ref: str
    type: str
    name: str
    group: Optional[str] = None
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    hashes: tuple[HashDescriptor, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            'bom_ref': self.bom_ref,
            'type': self.type,
            'name': self.name,
            'group': self.group,
            'version': self.version,
            'purl': self.purl,
            'cpe': self.cpe,
            'hashes': [h.to_dict() for h in self.hashes],
        }
        return data


@dataclass
class _ComponentRecord:
    key: str
    bom_ref: str
    order: int
    component: Component
    descriptor: ComponentDescriptor
    hashes: dict[tuple[str, str], HashDescriptor]
    purl_exact: Optional[str]
    purl_lineage: Optional[str]
    cpe: Optional[str]
    evidence: dict[str, int]
    dependencies: tuple[str, ...]


@dataclass
class _Candidate:
    record: _ComponentRecord
    stages: set[str] = field(default_factory=set)
    hash_matches: list[HashDescriptor] = field(default_factory=list)
    coordinate_matches: list[str] = field(default_factory=list)
    evidence_matches: list[str] = field(default_factory=list)
    evidence_coverage: float = 0.0
    dependency_analysis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            'component': self.record.descriptor.to_dict(),
            'stages': [s for s in _STAGES if s in self.stages],
            'hash_matches': [h.to_dict() for h in self.hash_matches],
            'coordinate_matches': list(self.coordinate_matches),
            'evidence_matches': list(self.evidence_matches),
            'evidence_coverage': round(self.evidence_coverage, 4),
            'dependencies': self.dependency_analysis,
        }


@dataclass
class ComponentMatch:
    """One baseline component and every still-plausible current counterpart."""

    baseline: ComponentDescriptor
    status: str
    relationship: str
    candidates: list[_Candidate]
    stage_candidates: dict[str, list[str]]
    baseline_dependencies: list[dict[str, Any]]
    notes: list[str] = field(default_factory=list)

    @property
    def selected(self) -> Optional[ComponentDescriptor]:
        if self.status != 'matched' or len(self.candidates) != 1:
            return None
        return self.candidates[0].record.descriptor

    def to_dict(self) -> dict[str, Any]:
        selected = self.selected
        return {
            'baseline': self.baseline.to_dict(),
            'status': self.status,
            'relationship': self.relationship,
            'selected': None if selected is None else selected.to_dict(),
            'candidates': [c.to_dict() for c in self.candidates],
            'stage_candidates': self.stage_candidates,
            'baseline_dependencies': self.baseline_dependencies,
            'notes': list(self.notes),
        }


@dataclass
class ManifestComparison:
    """Machine-readable comparison result."""

    baseline_label: str
    current_label: str
    matches: list[ComponentMatch]
    unmatched_current: list[ComponentDescriptor]
    dependency_transfers: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    warnings: list[str]

    def match_for_bom_ref(self, bom_ref: str) -> Optional[ComponentMatch]:
        for match in self.matches:
            if match.baseline.bom_ref == bom_ref:
                return match
        return None

    def trace_for_vulnerability(self, vulnerability_id: str) -> list[dict[str, Any]]:
        return [a for a in self.alerts if a['vulnerability']['id'] == vulnerability_id]

    def to_dict(self) -> dict[str, Any]:
        counts = {status: 0 for status in ('matched', 'split', 'ambiguous', 'conflict', 'unmatched')}
        for match in self.matches:
            counts[match.status] = counts.get(match.status, 0) + 1
        return {
            'schema': _SCHEMA_ID,
            'baseline': {'label': self.baseline_label, 'component_count': len(self.matches)},
            'current': {
                'label': self.current_label,
                'unmatched_component_count': len(self.unmatched_current),
            },
            'matching': {
                'stages': list(_STAGES),
                'selection_policy': (
                    'a component is selected only when all non-empty stages agree on exactly one candidate'
                ),
            },
            'summary': {
                'components_compared': len(self.matches),
                **counts,
                'alerts_traced': len(self.alerts),
                'dependency_transfers': len(self.dependency_transfers),
            },
            'components': [m.to_dict() for m in self.matches],
            'unmatched_current': [c.to_dict() for c in self.unmatched_current],
            'dependency_transfers': list(self.dependency_transfers),
            'alerts': list(self.alerts),
            'warnings': list(self.warnings),
        }

    def to_json(self, *, pretty: bool = False) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            sort_keys=True,
            ensure_ascii=False,
        )


def load_manifest(source: Any) -> Bom:
    """
    Load a CycloneDX manifest from a ``Bom``, a JSON object, a path or a file object.

    JSON and XML are detected from the document content, not from the file
    extension or from a generator-specific hint.
    """
    if isinstance(source, Bom):
        return source
    if isinstance(source, Mapping):
        return Bom.from_json(dict(source))  # type: ignore[attr-defined]
    if hasattr(source, 'read'):
        return _load_manifest_text(_coerce_text(source.read()))
    if isinstance(source, (str, bytes, PathLike)):
        with open(source, encoding='utf-8') as stream:
            return _load_manifest_text(stream.read())
    raise TypeError(f'unsupported manifest source: {source!r}')


def _coerce_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8-sig')
    return str(value)


def _load_manifest_text(text: str) -> Bom:
    stripped = text.lstrip('\ufeff \t\r\n')
    if stripped.startswith('<'):
        return Bom.from_xml(StringIO(stripped))  # type: ignore[attr-defined]
    return Bom.from_json(json.loads(stripped))  # type: ignore[attr-defined]


def _purl_exact(component: Component) -> Optional[str]:
    return None if component.purl is None else str(component.purl)


def _purl_key(component: Component, *, include_version: bool) -> Optional[str]:
    purl = component.purl
    if purl is None:
        return None
    qualifiers = tuple(sorted((purl.qualifiers or {}).items()))
    return repr((
        purl.type,
        purl.namespace,
        purl.name,
        purl.version if include_version else None,
        qualifiers,
        purl.subpath,
    ))


def _component_identity_values(component: Component, field_name: str) -> tuple[str, ...]:
    if field_name == IdentityField.NAME.value:
        return (component.name,)
    if field_name == IdentityField.GROUP.value:
        return (component.group,) if component.group else ()
    if field_name == IdentityField.VERSION.value:
        return (component.version,) if component.version else ()
    if field_name == IdentityField.PURL.value:
        purl = _purl_exact(component)
        return (purl,) if purl else ()
    if field_name == IdentityField.CPE.value:
        return (component.cpe,) if component.cpe else ()
    if field_name == IdentityField.HASH.value:
        return tuple(f'{h.alg.value.lower()}:{h.content.strip().lower()}' for h in component.hashes)
    if field_name == IdentityField.SWID.value:
        return (component.swid.tag_id,) if component.swid else ()
    if field_name == IdentityField.SWHID.value:
        return tuple(str(swhid) for swhid in component.swhids)
    if field_name == IdentityField.OMNIBOR_ID.value:
        return tuple(omnibor.id for omnibor in component.omnibor_ids)
    return ()


def _identity_values(identity: Any, component: Component) -> tuple[str, ...]:
    values: list[str] = []
    if identity.concluded_value:
        values.append(identity.concluded_value)
    values.extend(method.value for method in identity.methods if method.value)
    if values:
        return tuple(values)
    return _component_identity_values(component, identity.field.value)


def _evidence_tokens(component: Component) -> dict[str, int]:
    evidence = component.evidence
    if evidence is None:
        return {}
    tokens: dict[str, int] = {}
    _add_identity_tokens(tokens, component, evidence)
    _add_occurrence_tokens(tokens, evidence)
    _add_callstack_tokens(tokens, evidence)
    return tokens


def _add_identity_tokens(tokens: dict[str, int], component: Component, evidence: ComponentEvidence) -> None:
    for identity in evidence.identity:
        field_name = identity.field.value
        for value in _identity_values(identity, component):
            token = f'identity:{field_name}={_normalize_evidence_value(value)}'
            tokens[token] = _IDENTITY_WEIGHTS.get(field_name, 2)


def _add_occurrence_tokens(tokens: dict[str, int], evidence: ComponentEvidence) -> None:
    for occurrence in evidence.occurrences:
        location = _normalize_evidence_value(occurrence.location)
        tokens[f'occurrence:{location}'] = 4
        if occurrence.symbol:
            tokens[f'symbol:{_normalize_evidence_value(occurrence.symbol)}'] = 2


def _add_callstack_tokens(tokens: dict[str, int], evidence: ComponentEvidence) -> None:
    if evidence.callstack is None:
        return
    for frame in evidence.callstack.frames:
        function = '' if frame.function is None else frame.function
        tokens[f'callstack:{_normalize_evidence_value(frame.module)}#{_normalize_evidence_value(function)}'] = 3
        if frame.full_filename:
            tokens[f'callstack-file:{_normalize_evidence_value(frame.full_filename)}'] = 4


def _hash_descriptors(component: Component) -> tuple[HashDescriptor, ...]:
    descriptors = []
    for hash_type in component.hashes:
        algorithm = hash_type.alg.value
        algorithm_key = _normalize_algorithm(algorithm)
        digest = _normalize_digest(hash_type.content)
        descriptors.append(HashDescriptor(
            algorithm=algorithm,
            digest=digest,
            weak=algorithm_key in _WEAK_HASH_ALGORITHMS,
            format_valid=_hash_format_valid(algorithm_key, digest),
        ))
    return tuple(sorted(descriptors, key=lambda h: (h.algorithm, h.digest)))


def _dependency_map(bom: Bom) -> dict[str, tuple[str, ...]]:
    edges: dict[str, set[str]] = {}
    stack = list(bom.dependencies)
    seen: set[int] = set()
    while stack:
        dependency = stack.pop()
        if id(dependency) in seen:
            continue
        seen.add(id(dependency))
        ref = dependency.ref.value
        if ref is None:
            continue
        targets = edges.setdefault(ref, set())
        for child in dependency.dependencies:
            if child.ref.value is not None:
                targets.add(child.ref.value)
            stack.append(child)
    return {ref: tuple(sorted(targets)) for ref, targets in edges.items()}


def _build_records(
    bom: Bom,
    label: str,
    warnings: list[str],
) -> tuple[list[_ComponentRecord], dict[str, _ComponentRecord]]:
    dependencies = _dependency_map(bom)
    used_keys: dict[str, int] = {}
    records = []
    seen_objects: set[int] = set()
    for order, component in enumerate(bom._get_all_components()):
        if id(component) in seen_objects:
            continue
        seen_objects.add(id(component))
        bom_ref = component.bom_ref.value or f'@anonymous-{order}'
        count = used_keys.get(bom_ref, 0) + 1
        used_keys[bom_ref] = count
        key = bom_ref if count == 1 else f'{bom_ref}#{count}'
        if count > 1:
            warnings.append(f'{label}: duplicate bom-ref {bom_ref!r}; report key is {key!r}')
        descriptors = _hash_descriptors(component)
        record = _ComponentRecord(
            key=key,
            bom_ref=bom_ref,
            order=order,
            component=component,
            descriptor=ComponentDescriptor(
                bom_ref=key,
                type=component.type.value,
                name=component.name,
                group=component.group,
                version=component.version,
                purl=_purl_exact(component),
                cpe=component.cpe,
                hashes=descriptors,
            ),
            hashes={(h.algorithm, h.digest): h for h in descriptors},
            purl_exact=_purl_key(component, include_version=True),
            purl_lineage=_purl_key(component, include_version=False),
            cpe=component.cpe,
            evidence=_evidence_tokens(component),
            dependencies=dependencies.get(bom_ref, ()),
        )
        records.append(record)
    records.sort(key=lambda r: (r.descriptor.group or '', r.descriptor.name, r.descriptor.version or '', r.key))
    by_ref: dict[str, _ComponentRecord] = {}
    for record in records:
        by_ref[record.key] = record
        by_ref.setdefault(record.bom_ref, record)
    return records, by_ref


def _hash_candidates(
    baseline: _ComponentRecord,
    current_records: Sequence[_ComponentRecord],
) -> dict[str, list[HashDescriptor]]:
    hits: dict[str, list[HashDescriptor]] = {}
    for current in current_records:
        common = [h for key, h in baseline.hashes.items() if key in current.hashes]
        if common:
            hits[current.key] = sorted(common, key=lambda h: (h.algorithm, h.digest))
    return hits


def _coordinate_labels(baseline: _ComponentRecord, current: _ComponentRecord) -> list[str]:
    labels = []
    if baseline.purl_exact is not None and baseline.purl_exact == current.purl_exact:
        labels.append('purl')
    elif baseline.purl_lineage is not None and baseline.purl_lineage == current.purl_lineage:
        labels.append('purl-version-drift' if baseline.descriptor.version != current.descriptor.version
                      else 'purl-without-version')
    if baseline.cpe is not None and baseline.cpe == current.cpe:
        labels.append('cpe')
    if baseline.descriptor.group and baseline.descriptor.group == current.descriptor.group \
            and baseline.descriptor.name == current.descriptor.name:
        if baseline.descriptor.version and current.descriptor.version:
            labels.append('group-name-version' if baseline.descriptor.version == current.descriptor.version
                          else 'group-name-version-drift')
        else:
            labels.append('group-name')
    return labels


def _coordinate_candidates(
    baseline: _ComponentRecord,
    current_records: Sequence[_ComponentRecord],
) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for current in current_records:
        labels = _coordinate_labels(baseline, current)
        if labels:
            hits[current.key] = labels
    return hits


def _evidence_candidates(
    baseline: _ComponentRecord,
    current_records: Sequence[_ComponentRecord],
) -> dict[str, tuple[list[str], float]]:
    hits: dict[str, tuple[list[str], float]] = {}
    if not baseline.evidence:
        return hits
    for current in current_records:
        shared = sorted(set(baseline.evidence) & set(current.evidence))
        if not shared:
            continue
        weight = sum(baseline.evidence[token] for token in shared)
        strong = any(token.startswith(_STRONG_EVIDENCE_PREFIXES) for token in shared)
        if strong or (len(shared) >= 2 and weight >= 3):
            coverage = len(shared) / len(baseline.evidence)
            hits[current.key] = (shared, coverage)
    return hits


def _evidence_anchor_partition(
    baseline: _ComponentRecord,
    evidence_hits: Mapping[str, tuple[list[str], float]],
    evidence_keys: Sequence[str],
) -> bool:
    if len(evidence_keys) < 2:
        return False
    anchors_by_candidate = []
    for key in evidence_keys:
        anchors = {
            token for token in evidence_hits[key][0]
            if baseline.evidence[token] >= 3
        }
        if not anchors:
            return False
        anchors_by_candidate.append(anchors)
    shared_anchors = set().union(*anchors_by_candidate)
    if len(shared_anchors) < 2:
        return False
    return not any(anchors == shared_anchors for anchors in anchors_by_candidate)


def _sets_agree(stage_sets: Sequence[set[str]]) -> bool:
    non_empty = [stage_set for stage_set in stage_sets if stage_set]
    return not non_empty or all(stage_set == non_empty[0] for stage_set in non_empty)


def _classify(
    baseline: _ComponentRecord,
    hash_hits: Mapping[str, list[HashDescriptor]],
    coordinate_hits: Mapping[str, list[str]],
    evidence_hits: Mapping[str, tuple[list[str], float]],
) -> str:
    hash_keys = set(hash_hits)
    coordinate_keys = set(coordinate_hits)
    evidence_keys = set(evidence_hits)
    stage_sets = [hash_keys, coordinate_keys, evidence_keys]
    if not any(stage_sets):
        return 'unmatched'
    if _evidence_anchor_partition(baseline, evidence_hits, sorted(evidence_keys)):
        return 'split'
    if not _sets_agree(stage_sets):
        return 'conflict'
    unique = set().union(*stage_sets)
    return 'matched' if len(unique) == 1 else 'ambiguous'


def _relationship(
    status: str,
    hash_matches: Sequence[HashDescriptor],
    coordinate_matches: Sequence[str],
) -> str:
    if status == 'split':
        return 'split'
    if status == 'unmatched':
        return 'removed'
    if status in ('ambiguous', 'conflict'):
        return 'unresolved'
    if hash_matches:
        exact_coordinates = {'purl', 'cpe', 'group-name-version'} & set(coordinate_matches)
        return 'unchanged' if exact_coordinates else 'repackaged'
    if coordinate_matches:
        if any('version-drift' in label for label in coordinate_matches):
            return 'version-drift'
        return 'coordinate-only'
    return 'evidence-linked'


def _descriptor_for_ref(
    ref: str,
    by_ref: Mapping[str, _ComponentRecord],
) -> dict[str, Any]:
    record = by_ref.get(ref)
    if record is None:
        return {'bom_ref': ref}
    return record.descriptor.to_dict()


def _candidate_dependency_analysis(
    baseline: _ComponentRecord,
    candidate: _ComponentRecord,
    baseline_by_ref: Mapping[str, _ComponentRecord],
    current_by_ref: Mapping[str, _ComponentRecord],
    match_by_baseline: Mapping[str, ComponentMatch],
) -> dict[str, Any]:
    preserved = []
    transferred = []
    matched_current_refs: set[str] = set()
    for baseline_ref in baseline.dependencies:
        dependency_match = match_by_baseline.get(baseline_ref)
        if dependency_match is None:
            continue
        counterpart_refs = {item.record.bom_ref for item in dependency_match.candidates}
        for current_ref in candidate.dependencies:
            if current_ref not in counterpart_refs:
                continue
            matched_current_refs.add(current_ref)
            entry = {
                'baseline_dependency': _descriptor_for_ref(baseline_ref, baseline_by_ref),
                'current_dependency': _descriptor_for_ref(current_ref, current_by_ref),
                'via': dependency_match.relationship,
            }
            if baseline_ref == current_ref:
                preserved.append(entry)
            else:
                transferred.append(entry)
    dropped = [
        _descriptor_for_ref(ref, baseline_by_ref)
        for ref in baseline.dependencies
        if ref in match_by_baseline
        if not any(
            item.record.bom_ref in candidate.dependencies
            for item in match_by_baseline[ref].candidates
        )
    ]
    added = [
        _descriptor_for_ref(ref, current_by_ref)
        for ref in candidate.dependencies
        if ref not in matched_current_refs
    ]
    return {
        'baseline': [_descriptor_for_ref(ref, baseline_by_ref) for ref in baseline.dependencies],
        'current': [_descriptor_for_ref(ref, current_by_ref) for ref in candidate.dependencies],
        'preserved': preserved,
        'transferred': transferred,
        'dropped': dropped,
        'added': added,
    }


def _make_candidates(
    baseline: _ComponentRecord,
    hash_hits: Mapping[str, list[HashDescriptor]],
    coordinate_hits: Mapping[str, list[str]],
    evidence_hits: Mapping[str, tuple[list[str], float]],
    current_by_ref: Mapping[str, _ComponentRecord],
    baseline_by_ref: Mapping[str, _ComponentRecord],
    match_by_baseline: Mapping[str, ComponentMatch],
) -> list[_Candidate]:
    keys = sorted(set(hash_hits) | set(coordinate_hits) | set(evidence_hits))
    candidates = []
    for key in keys:
        candidate = _Candidate(record=current_by_ref[key])
        if key in hash_hits:
            candidate.stages.add('hash')
            candidate.hash_matches = hash_hits[key]
        if key in coordinate_hits:
            candidate.stages.add('coordinates')
            candidate.coordinate_matches = coordinate_hits[key]
        if key in evidence_hits:
            shared, coverage = evidence_hits[key]
            candidate.stages.add('evidence')
            candidate.evidence_matches = shared
            candidate.evidence_coverage = coverage
        candidate.dependency_analysis = _candidate_dependency_analysis(
            baseline, candidate.record, baseline_by_ref, current_by_ref, match_by_baseline)
        candidates.append(candidate)
    return candidates


def _stage_candidates(
    hash_hits: Mapping[str, list[HashDescriptor]],
    coordinate_hits: Mapping[str, list[str]],
    evidence_hits: Mapping[str, tuple[list[str], float]],
) -> dict[str, list[str]]:
    return {
        'hash': sorted(hash_hits),
        'coordinates': sorted(coordinate_hits),
        'evidence': sorted(evidence_hits),
    }


def _note_for_status(
    status: str,
    stage_candidates: Mapping[str, list[str]],
) -> list[str]:
    if status == 'split':
        return [
            'baseline evidence is partitioned across multiple current components; '
            'all split candidates are retained and no single component was selected',
        ]
    if status == 'conflict':
        return [
            'matching stages disagree on the counterpart; no candidate was selected',
            'conflicting stage candidates: ' + json.dumps(stage_candidates, sort_keys=True),
        ]
    if status == 'ambiguous':
        return ['multiple candidates have the same stage support; no candidate was selected']
    if status == 'unmatched':
        return ['no hash, coordinate or evidence match was found']
    return []


def _compare_components(
    baseline_records: Sequence[_ComponentRecord],
    current_records: Sequence[_ComponentRecord],
    baseline_by_ref: Mapping[str, _ComponentRecord],
    current_by_ref: Mapping[str, _ComponentRecord],
) -> list[ComponentMatch]:
    staged = []
    for baseline in baseline_records:
        hash_hits = _hash_candidates(baseline, current_records)
        coordinate_hits = _coordinate_candidates(baseline, current_records)
        evidence_hits = _evidence_candidates(baseline, current_records)
        status = _classify(baseline, hash_hits, coordinate_hits, evidence_hits)
        stage_candidates = _stage_candidates(hash_hits, coordinate_hits, evidence_hits)
        staged.append((baseline, hash_hits, coordinate_hits, evidence_hits, status, stage_candidates))

    match_by_baseline: dict[str, ComponentMatch] = {}
    for baseline, _, _, _, status, stage_candidates in staged:
        match_by_baseline[baseline.bom_ref] = ComponentMatch(
            baseline=baseline.descriptor,
            status=status,
            relationship='unresolved',
            candidates=[],
            stage_candidates=stage_candidates,
            baseline_dependencies=[],
        )

    matches = []
    for baseline, hash_hits, coordinate_hits, evidence_hits, status, stage_candidates in staged:
        candidates = _make_candidates(
            baseline, hash_hits, coordinate_hits, evidence_hits,
            current_by_ref, baseline_by_ref, match_by_baseline)
        relationship = _relationship(
            status,
            [h for candidate in candidates for h in candidate.hash_matches],
            [label for candidate in candidates for label in candidate.coordinate_matches],
        ) if status == 'matched' else _relationship(status, [], [])
        match = ComponentMatch(
            baseline=baseline.descriptor,
            status=status,
            relationship=relationship,
            candidates=candidates,
            stage_candidates=stage_candidates,
            baseline_dependencies=[
                _descriptor_for_ref(ref, baseline_by_ref) for ref in baseline.dependencies
            ],
            notes=_note_for_status(status, stage_candidates),
        )
        matches.append(match)
        match_by_baseline[baseline.bom_ref] = match

    # Dependency views were built before the final match objects existed. Refresh
    # them now so every candidate sees the completed cross-version mapping.
    for match, (baseline, *_rest) in zip(matches, staged):
        for candidate in match.candidates:
            candidate.dependency_analysis = _candidate_dependency_analysis(
                baseline, candidate.record, baseline_by_ref, current_by_ref, match_by_baseline)
    return matches


def _dependency_transfers(matches: Sequence[ComponentMatch]) -> list[dict[str, Any]]:
    transfers = []
    seen = set()
    for match in matches:
        for candidate in match.candidates:
            for transfer in candidate.dependency_analysis.get('transferred', []):
                key = (
                    match.baseline.bom_ref,
                    candidate.record.bom_ref,
                    transfer['baseline_dependency']['bom_ref'],
                    transfer['current_dependency']['bom_ref'],
                )
                if key in seen:
                    continue
                seen.add(key)
                transfers.append({
                    'baseline_parent': match.baseline.to_dict(),
                    'current_parent': candidate.record.descriptor.to_dict(),
                    'baseline_dependency': transfer['baseline_dependency'],
                    'current_dependency': transfer['current_dependency'],
                    'via': transfer['via'],
                })
    return transfers


def _incoming_edges(edges: Mapping[str, Sequence[str]]) -> dict[str, int]:
    incoming = {ref: 0 for ref in edges}
    for targets in edges.values():
        for target in targets:
            incoming[target] = incoming.get(target, 0) + 1
    return incoming


def _dependency_paths(
    edges: Mapping[str, Sequence[str]],
    roots: Sequence[str],
    target: str,
    limit: int = 5,
) -> list[list[str]]:
    paths = []
    queue = deque((root, [root]) for root in roots)
    while queue and len(paths) < limit:
        node, path = queue.popleft()
        if node == target:
            paths.append(path)
            continue
        if len(path) > 32:
            continue
        for child in edges.get(node, ()):
            if child not in path:
                queue.append((child, [*path, child]))
    return paths


def _graph_roots(bom: Bom, edges: Mapping[str, Sequence[str]], records: Sequence[_ComponentRecord]) -> list[str]:
    if bom.metadata.component is not None and bom.metadata.component.bom_ref.value:
        root = bom.metadata.component.bom_ref.value
        if root in edges:
            return [root]
    incoming = _incoming_edges(edges)
    roots = sorted(ref for ref, count in incoming.items() if count == 0)
    return roots or [record.key for record in records]


def _alert_candidate(
    candidate: _Candidate,
    selected: bool,
    edges: Mapping[str, Sequence[str]],
    roots: Sequence[str],
    current_by_ref: Mapping[str, _ComponentRecord],
) -> dict[str, Any]:
    paths = _dependency_paths(edges, roots, candidate.record.bom_ref)
    return {
        'component': candidate.record.descriptor.to_dict(),
        'selection': 'selected' if selected else 'unresolved-candidate',
        'may_affect': True,
        'basis': [stage for stage in _STAGES if stage in candidate.stages],
        'dependency_paths': [
            [_descriptor_for_ref(ref, current_by_ref) for ref in path]
            for path in paths
        ],
        'reachable': bool(paths),
    }


def _alerts(
    baseline: Bom,
    current: Bom,
    matches: Sequence[ComponentMatch],
    current_records: Sequence[_ComponentRecord],
    current_by_ref: Mapping[str, _ComponentRecord],
) -> list[dict[str, Any]]:
    edges = _dependency_map(current)
    roots = _graph_roots(current, edges, current_records)
    current_vulnerability_ids = {v.id for v in current.vulnerabilities if v.id}
    match_by_ref = {match.baseline.bom_ref: match for match in matches}
    alerts = []
    for vulnerability in baseline.vulnerabilities:
        trace_targets = []
        for target in vulnerability.affects:
            match = match_by_ref.get(target.ref)
            if match is None:
                trace_targets.append({
                    'baseline_component': {'bom_ref': target.ref},
                    'status': 'unmatched',
                    'relationship': 'unknown',
                    'candidates': [],
                    'notes': ['vulnerability target is not a component in the baseline manifest'],
                })
                continue
            selected = match.selected
            trace_targets.append({
                'baseline_component': match.baseline.to_dict(),
                'status': match.status,
                'relationship': match.relationship,
                'candidates': [
                    _alert_candidate(
                        candidate,
                        selected is not None and candidate.record.bom_ref == selected.bom_ref,
                        edges, roots, current_by_ref)
                    for candidate in match.candidates
                ],
                'notes': list(match.notes),
            })
        source = vulnerability.source
        alerts.append({
            'vulnerability': {
                'id': vulnerability.id or vulnerability.bom_ref.value or 'unknown',
                'bom_ref': vulnerability.bom_ref.value,
                'source': None if source is None else {
                    'name': source.name,
                    'url': None if source.url is None else str(source.url),
                },
                'affects': sorted(target.ref for target in vulnerability.affects),
                'still_present_in_current_manifest': (
                    vulnerability.id in current_vulnerability_ids if vulnerability.id else False
                ),
            },
            'targets': trace_targets,
        })
    return alerts


def _unmatched_current(
    current_records: Sequence[_ComponentRecord],
    matches: Sequence[ComponentMatch],
) -> list[ComponentDescriptor]:
    matched_refs = {
        candidate.record.bom_ref
        for match in matches
        for candidate in match.candidates
    }
    return [
        record.descriptor
        for record in current_records
        if record.bom_ref not in matched_refs
    ]


class ManifestMatcher:
    """Conservative, generator-independent cross-version manifest matcher."""

    def compare(
        self,
        baseline: Any,
        current: Any,
        *,
        baseline_label: str = 'baseline',
        current_label: str = 'current',
    ) -> ManifestComparison:
        warnings: list[str] = []
        baseline_bom = load_manifest(baseline)
        current_bom = load_manifest(current)
        baseline_records, baseline_by_ref = _build_records(baseline_bom, baseline_label, warnings)
        current_records, current_by_ref = _build_records(current_bom, current_label, warnings)
        matches = _compare_components(
            baseline_records, current_records, baseline_by_ref, current_by_ref)
        return ManifestComparison(
            baseline_label=baseline_label,
            current_label=current_label,
            matches=matches,
            unmatched_current=_unmatched_current(current_records, matches),
            dependency_transfers=_dependency_transfers(matches),
            alerts=_alerts(baseline_bom, current_bom, matches, current_records, current_by_ref),
            warnings=warnings,
        )


def compare_manifests(
    baseline: Any,
    current: Any,
    *,
    baseline_label: str = 'baseline',
    current_label: str = 'current',
) -> ManifestComparison:
    """Compare two CycloneDX manifests and return a report object."""
    return ManifestMatcher().compare(
        baseline, current, baseline_label=baseline_label, current_label=current_label)


def _build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog='cyclonedx-bom-compare',
        description='Compare CycloneDX manifests using hash, coordinate and evidence stages.',
    )
    parser.add_argument('baseline', help='baseline CycloneDX JSON or XML manifest')
    parser.add_argument('current', help='current CycloneDX JSON or XML manifest')
    parser.add_argument('-o', '--output', help='write the JSON report to this path instead of stdout')
    parser.add_argument('--pretty', action='store_true', help='indent the JSON report')
    return parser


def _run(args: Namespace) -> int:
    comparison = compare_manifests(
        args.baseline,
        args.current,
        baseline_label=args.baseline,
        current_label=args.current,
    )
    report = comparison.to_json(pretty=args.pretty)
    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(report)
            stream.write('\n')
    else:
        sys.stdout.write(report)
        sys.stdout.write('\n')
    return 0


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entry point used by ``python -m cyclonedx.contrib.bom.compare``."""
    return _run(_build_parser().parse_args(None if argv is None else list(argv)))


if __name__ == '__main__':
    raise SystemExit(main())
