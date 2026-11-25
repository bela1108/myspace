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

"""File and JSON loaders for archive reconciliation inputs."""

from json import load as json_load
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, cast

from ..exception.reconcile import ReconciliationError
from .model import (
    ArchiveEntry,
    ArchiveManifest,
    ArchivePath,
    ComponentDeclaration,
    ContentDigest,
    DecisionStatus,
    ExclusionDecision,
    ExclusionTarget,
)

if TYPE_CHECKING:  # pragma: no cover
    from ..model.bom import Bom


def _first(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _require(mapping: Dict[str, Any], name: str, *keys: str) -> Any:
    value = _first(mapping, *keys)
    if value is None:
        raise ReconciliationError(f'missing required field {name!r}')
    return value


def _as_sequence(value: Any, field_name: str) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    raise ReconciliationError(f'{field_name!r} must be a list')


def _digest_from_value(value: Any) -> ContentDigest:
    if isinstance(value, ContentDigest):
        return value
    if isinstance(value, str):
        return ContentDigest.from_composite(value)
    if isinstance(value, dict):
        algorithm = _first(value, 'algorithm', 'alg', 'name')
        digest_value = _first(value, 'value', 'content', 'digest')
        if algorithm is None or digest_value is None:
            raise ReconciliationError(f'invalid digest object: {value!r}')
        return ContentDigest(algorithm=str(algorithm), value=str(digest_value))
    raise ReconciliationError(f'invalid digest value: {value!r}')


def _digests_from_mapping(mapping: Dict[str, Any]) -> Tuple[ContentDigest, ...]:
    digests: List[ContentDigest] = []
    hashes_value = _first(mapping, 'hashes', 'digests')
    if hashes_value is not None:
        if isinstance(hashes_value, dict):
            digests.extend(
                ContentDigest(algorithm=str(algorithm), value=str(value))
                for algorithm, value in hashes_value.items()
            )
        else:
            digests.extend(_digest_from_value(value) for value in _as_sequence(hashes_value, 'hashes'))
    digest_value = _first(mapping, 'digest')
    if digest_value is not None:
        digests.append(_digest_from_value(digest_value))
    for algorithm in ('sha256', 'sha1', 'sha512', 'md5'):
        value = mapping.get(algorithm)
        if value is not None:
            digests.append(ContentDigest(algorithm=algorithm, value=str(value)))
    return tuple(sorted(set(digests)))


def _location_from_value(value: Any) -> ArchivePath:
    if isinstance(value, ArchivePath):
        return value
    if isinstance(value, str):
        return ArchivePath.parse(value)
    if isinstance(value, dict):
        nested = _first(value, 'location', 'archive_path')
        if nested is not None:
            return _location_from_value(nested)
        path = _first(value, 'path', 'member')
        if path is None:
            raise ReconciliationError(f'archive location object needs a path: {value!r}')
        containers = _first(value, 'containers', 'container')
        if containers is None:
            containers = ()
        elif isinstance(containers, str):
            containers = (containers,)
        else:
            containers = _as_sequence(containers, 'containers')
        return ArchivePath.from_parts((str(container) for container in containers), str(path))
    raise ReconciliationError(f'invalid archive location: {value!r}')


def manifest_from_dict(data: Dict[str, Any]) -> ArchiveManifest:
    """Build an :class:`ArchiveManifest` from a JSON-compatible mapping."""
    archive = str(_require(data, 'archive', 'archive', 'name'))
    entries: List[ArchiveEntry] = []
    for index, item in enumerate(_as_sequence(_require(data, 'entries', 'entries', 'files'), 'entries')):
        if not isinstance(item, dict):
            raise ReconciliationError(f'archive entry #{index} must be an object')
        entry_id = str(_require(item, 'entry_id', 'entry_id', 'entryId', 'id'))
        if 'location' in item:
            location_value = item['location']
        elif 'path' in item:
            location_value = item
        else:
            raise ReconciliationError(f'archive entry {entry_id!r} needs a location')
        location = _location_from_value(location_value)
        size_value = item.get('size')
        size = int(size_value) if size_value is not None else None
        entries.append(ArchiveEntry(
            entry_id=entry_id,
            location=location,
            hashes=_digests_from_mapping(item),
            size=size,
            media_type=_first(item, 'media_type', 'mediaType'),
        ))
    return ArchiveManifest(archive=archive, entries=tuple(entries))


def manifest_from_file(filename: str) -> ArchiveManifest:
    """Load an archive manifest JSON file."""
    with open(filename, encoding='utf-8') as stream:
        data = json_load(stream)
    if not isinstance(data, dict):
        raise ReconciliationError('archive manifest root must be an object')
    return manifest_from_dict(data)


def _declaration_from_dict(data: Dict[str, Any], index: int) -> ComponentDeclaration:
    if not isinstance(data, dict):
        raise ReconciliationError(f'component declaration #{index} must be an object')
    bom_ref = str(_require(data, 'bom_ref', 'bom_ref', 'bom-ref', 'bomRef', 'ref'))
    name = str(_require(data, 'name', 'name'))
    locations_value = _first(data, 'locations')
    if locations_value is None:
        occurrences = _first(data, 'occurrences')
        if occurrences is None:
            evidence = data.get('evidence')
            if isinstance(evidence, dict):
                occurrences = evidence.get('occurrences')
        locations = [
            _location_from_value(occurrence.get('location') if isinstance(occurrence, dict) else occurrence)
            for occurrence in _as_sequence(occurrences, 'occurrences')
        ]
    else:
        locations = [_location_from_value(location) for location in _as_sequence(locations_value, 'locations')]
    return ComponentDeclaration(
        bom_ref=bom_ref,
        name=name,
        version=_first(data, 'version'),
        purl=_first(data, 'purl'),
        component_type=_first(data, 'component_type', 'componentType', 'type'),
        hashes=_digests_from_mapping(data),
        locations=tuple(locations),
    )


def declarations_from_dict(data: Any) -> Tuple[ComponentDeclaration, ...]:
    """Build component declarations from a list or ``components`` object."""
    if isinstance(data, dict):
        items = _first(data, 'components', 'declarations')
        if items is None and data.get('bomFormat') == 'CycloneDX':
            from ..model.bom import Bom
            return ComponentDeclaration.from_bom(Bom.from_json(data))  # type: ignore[attr-defined]
        data = items
    return tuple(
        _declaration_from_dict(item, index)
        for index, item in enumerate(_as_sequence(data, 'components'))
    )


def declarations_from_file(filename: str) -> Tuple[ComponentDeclaration, ...]:
    """Load declarations from a plain JSON declaration file."""
    with open(filename, encoding='utf-8') as stream:
        data = json_load(stream)
    return declarations_from_dict(data)


def bom_from_file(filename: str) -> 'Bom':
    """Load a CycloneDX BOM from JSON or XML based on the file extension."""
    from ..model.bom import Bom
    if filename.lower().endswith('.xml'):
        with open(filename, encoding='utf-8') as stream:
            return cast(Bom, Bom.from_xml(stream))  # type: ignore[attr-defined]
    with open(filename, encoding='utf-8') as stream:
        data = json_load(stream)
    return cast(Bom, Bom.from_json(data))  # type: ignore[attr-defined]


def declarations_from_bom_file(filename: str) -> Tuple[ComponentDeclaration, ...]:
    """Load and extract declarations from a CycloneDX BOM file."""
    return ComponentDeclaration.from_bom(bom_from_file(filename))


def _target_from_value(value: Any) -> ExclusionTarget:
    if isinstance(value, ExclusionTarget):
        return value
    normalized = str(value).strip().lower().replace('_', '-')
    aliases = {
        'archive': ExclusionTarget.ARCHIVE_RECORD,
        'archive-record': ExclusionTarget.ARCHIVE_RECORD,
        'physical': ExclusionTarget.ARCHIVE_RECORD,
        'component': ExclusionTarget.COMPONENT_DECLARATION,
        'component-declaration': ExclusionTarget.COMPONENT_DECLARATION,
        'declaration': ExclusionTarget.COMPONENT_DECLARATION,
        'both': ExclusionTarget.BOTH,
        'either': ExclusionTarget.BOTH,
    }
    try:
        return aliases[normalized]
    except KeyError as error:
        raise ReconciliationError(f'unknown exclusion target: {value!r}') from error


def _strings(value: Any, field_name: str) -> Tuple[str, ...]:
    return tuple(str(item) for item in _as_sequence(value, field_name))


def _decision_from_dict(data: Dict[str, Any], index: int) -> ExclusionDecision:
    if not isinstance(data, dict):
        raise ReconciliationError(f'exclusion decision #{index} must be an object')
    digests: List[ContentDigest] = []
    for key in ('digests', 'hashes'):
        if key in data:
            digests.extend(_digest_from_value(value) for value in _as_sequence(data[key], key))
    return ExclusionDecision(
        decision_id=str(_require(data, 'decision_id', 'decision_id', 'decisionId', 'id')),
        target=_target_from_value(_require(data, 'target', 'target')),
        rationale=str(_require(data, 'rationale', 'rationale', 'reason')),
        decided_by=str(_require(data, 'decided_by', 'decided_by', 'decidedBy', 'by')),
        decided_at=str(_require(data, 'decided_at', 'decided_at', 'decidedAt', 'at')),
        status=DecisionStatus(str(data.get('status', DecisionStatus.APPROVED.value))),
        revision=int(data.get('revision', 1)),
        entry_ids=_strings(_first(data, 'entry_ids', 'entryIds', 'entries'), 'entry_ids'),
        locations=_strings(_first(data, 'locations'), 'locations'),
        digests=tuple(digests),
        component_refs=_strings(_first(data, 'component_refs', 'componentRefs', 'components'), 'component_refs'),
        purls=_strings(_first(data, 'purls'), 'purls'),
    )


def decisions_from_dict(data: Any) -> Tuple[ExclusionDecision, ...]:
    """Build exclusion decisions from a list or ``decisions`` object."""
    if isinstance(data, dict):
        data = _first(data, 'decisions', 'exclusions')
    return tuple(
        _decision_from_dict(item, index)
        for index, item in enumerate(_as_sequence(data, 'decisions'))
    )


def decisions_from_file(filename: str) -> Tuple[ExclusionDecision, ...]:
    """Load exclusion decisions from a JSON file."""
    with open(filename, encoding='utf-8') as stream:
        data = json_load(stream)
    return decisions_from_dict(data)


def load_inputs(
    manifest_file: str,
    decisions_file: str,
    *,
    bom_file: Optional[str] = None,
    declarations_file: Optional[str] = None,
) -> Tuple[ArchiveManifest, Tuple[ComponentDeclaration, ...], Tuple[ExclusionDecision, ...]]:
    """Load the three reconciliation inputs from files."""
    if (bom_file is None) == (declarations_file is None):
        raise ReconciliationError('provide exactly one of bom_file or declarations_file')
    if bom_file is not None:
        declarations = declarations_from_bom_file(bom_file)
    elif declarations_file is not None:
        declarations = declarations_from_file(declarations_file)
    else:  # pragma: no cover - guarded above
        raise ReconciliationError('provide exactly one of bom_file or declarations_file')
    return (
        manifest_from_file(manifest_file),
        declarations,
        decisions_from_file(decisions_file),
    )

