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

"""Immutable models for archive reconciliation."""

import re
from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Iterable, List, Optional, Tuple

from ..exception.reconcile import ReconciliationError

if TYPE_CHECKING:  # pragma: no cover
    from ..model import HashType
    from ..model.bom import Bom
    from ..model.component import Component


FORMAT_VERSION = 1


class RecordKind(str, Enum):
    """The kind of source record a finding refers to."""

    ARCHIVE_RECORD = 'archive-record'
    COMPONENT_DECLARATION = 'component-declaration'
    AMBIGUOUS_DECLARATION = 'ambiguous-declaration'


class ExclusionTarget(str, Enum):
    """The reconciliation side an exclusion decision is allowed to suppress."""

    ARCHIVE_RECORD = 'archive-record'
    COMPONENT_DECLARATION = 'component-declaration'
    BOTH = 'both'


class DecisionStatus(str, Enum):
    """Lifecycle state of an exclusion decision."""

    APPROVED = 'approved'
    REJECTED = 'rejected'
    WITHDRAWN = 'withdrawn'


class MatchBasis(str, Enum):
    """How an archive record and a component declaration were linked."""

    LOCATION_AND_DIGEST = 'location-and-digest'
    LOCATION_ONLY = 'location-only'
    LOCATION_DIGEST_MISMATCH = 'location-digest-mismatch'
    DIGEST_ONLY = 'digest-only'
    DIGEST_RELOCATED = 'digest-relocated'


_ALGORITHM_ALIASES = {
    'md5': 'MD5',
    'sha1': 'SHA-1',
    'sha256': 'SHA-256',
    'sha384': 'SHA-384',
    'sha512': 'SHA-512',
    'sha3256': 'SHA3-256',
    'sha3384': 'SHA3-384',
    'sha3512': 'SHA3-512',
    'blake2b256': 'BLAKE2b-256',
    'blake2b384': 'BLAKE2b-384',
    'blake2b512': 'BLAKE2b-512',
    'blake3': 'BLAKE3',
    'streebog256': 'Streebog-256',
    'streebog512': 'Streebog-512',
}


def _normalize_algorithm(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ReconciliationError('hash algorithm must not be empty')
    key = re.sub(r'[^a-z0-9]', '', stripped.lower())
    return _ALGORITHM_ALIASES.get(key, stripped.upper())


def _normalize_digest_value(value: str) -> str:
    stripped = value.strip().lower()
    if not stripped:
        raise ReconciliationError('hash value must not be empty')
    if not re.fullmatch(r'[0-9a-f]+', stripped):
        raise ReconciliationError(f'hash value is not hexadecimal: {value!r}')
    return stripped


def _normalize_archive_part(value: str) -> str:
    normalized = value.replace('\\', '/').strip()
    if '!/' in normalized:
        raise ReconciliationError(f'archive path part must not contain the layer separator: {value!r}')
    while normalized.startswith('./'):
        normalized = normalized[2:]
    parts = [part for part in normalized.split('/') if part not in ('', '.')]
    if not parts:
        raise ReconciliationError(f'archive path segment must not be empty: {value!r}')
    if '..' in parts:
        raise ReconciliationError(f'archive path must not traverse upwards: {value!r}')
    return '/'.join(parts)


@dataclass(frozen=True, order=True)
class ContentDigest:
    """
    A normalized content digest.

    Algorithm names are canonicalized (``sha256``, ``SHA256`` and ``SHA-256``
    all become ``SHA-256``) and hexadecimal values are lower-cased, so equality
    is stable across manifests produced by different tools.
    """

    algorithm: str
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'algorithm', _normalize_algorithm(self.algorithm))
        object.__setattr__(self, 'value', _normalize_digest_value(self.value))

    @property
    def key(self) -> Tuple[str, str]:
        """Stable dictionary key for the digest."""
        return self.algorithm, self.value

    @classmethod
    def from_composite(cls, value: str) -> 'ContentDigest':
        """Parse ``ALGORITHM:hex-value``."""
        algorithm, separator, digest_value = value.partition(':')
        if not separator:
            raise ReconciliationError(f'composite digest needs "algorithm:value": {value!r}')
        return cls(algorithm=algorithm, value=digest_value)

    @classmethod
    def from_hash_type(cls, hash_type: 'HashType') -> 'ContentDigest':
        """Convert a :class:`cyclonedx.model.HashType`."""
        return cls(algorithm=hash_type.alg.value, value=hash_type.content)

    def as_dict(self) -> dict[str, str]:
        return {'algorithm': self.algorithm, 'value': self.value}

    def __str__(self) -> str:
        return f'{self.algorithm}:{self.value}'


@dataclass(frozen=True, order=True)
class ArchivePath:
    """
    A canonical location inside one or more nested archive containers.

    ``containers`` names the archive files from outermost to innermost, and
    ``path`` is the member path inside the innermost container.  The canonical
    string uses ``!/`` as the layer separator, for example::

        release-1.0.tar!/payload/runtime.tar!/app/main.py
    """

    containers: Tuple[str, ...]
    path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'containers', tuple(_normalize_archive_part(c) for c in self.containers))
        object.__setattr__(self, 'path', _normalize_archive_part(self.path))

    @classmethod
    def parse(cls, value: str) -> 'ArchivePath':
        """Parse a canonical ``outer!/inner!/path`` location."""
        parts = value.split('!/')
        if len(parts) < 1 or not parts[-1].strip():
            raise ReconciliationError(f'invalid archive location: {value!r}')
        return cls(
            containers=tuple(parts[:-1]),
            path=parts[-1],
        )

    @classmethod
    def from_parts(cls, containers: Iterable[str], path: str) -> 'ArchivePath':
        """Build a path from an explicit container chain and member path."""
        return cls(containers=tuple(containers), path=path)

    @property
    def container(self) -> Optional[str]:
        """The innermost container, or ``None`` for a top-level member."""
        return self.containers[-1] if self.containers else None

    def is_inside(self, container: str) -> bool:
        """Whether this location is inside the named container."""
        return container in self.containers

    def as_dict(self) -> dict[str, object]:
        return {'containers': list(self.containers), 'path': self.path}

    def __str__(self) -> str:
        return '!/'.join((*self.containers, self.path))


@dataclass(frozen=True)
class ArchiveEntry:
    """A read-only record from the archive's file manifest."""

    entry_id: str
    location: ArchivePath
    hashes: Tuple[ContentDigest, ...]
    size: Optional[int] = None
    media_type: Optional[str] = None

    def __post_init__(self) -> None:
        entry_id = self.entry_id.strip()
        if not entry_id:
            raise ReconciliationError('archive entry_id must not be empty')
        location = self.location
        hashes = tuple(sorted(set(self.hashes)))
        if not hashes:
            raise ReconciliationError(f'archive entry {entry_id!r} needs at least one digest')
        if self.size is not None and self.size < 0:
            raise ReconciliationError(f'archive entry {entry_id!r} has a negative size')
        object.__setattr__(self, 'entry_id', entry_id)
        object.__setattr__(self, 'location', location)
        object.__setattr__(self, 'hashes', hashes)

    def as_dict(self) -> dict[str, object]:
        return {
            'entry_id': self.entry_id,
            'location': str(self.location),
            'containers': list(self.location.containers),
            'path': self.location.path,
            'hashes': [h.as_dict() for h in self.hashes],
            'size': self.size,
            'media_type': self.media_type,
        }


@dataclass(frozen=True)
class ArchiveManifest:
    """An immutable, read-only inventory of archive records."""

    archive: str
    entries: Tuple[ArchiveEntry, ...]

    def __post_init__(self) -> None:
        archive = self.archive.strip()
        if not archive:
            raise ReconciliationError('archive name must not be empty')
        entries = tuple(sorted(self.entries, key=lambda entry: entry.entry_id))
        seen_ids: set[str] = set()
        seen_locations: set[ArchivePath] = set()
        for entry in entries:
            if entry.entry_id in seen_ids:
                raise ReconciliationError(f'duplicate archive entry_id: {entry.entry_id!r}')
            if entry.location in seen_locations:
                raise ReconciliationError(f'duplicate archive location: {entry.location}')
            seen_ids.add(entry.entry_id)
            seen_locations.add(entry.location)
        object.__setattr__(self, 'archive', archive)
        object.__setattr__(self, 'entries', entries)

    def as_dict(self) -> dict[str, object]:
        return {
            'archive': self.archive,
            'format_version': FORMAT_VERSION,
            'entries': [entry.as_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class ComponentDeclaration:
    """The reconciliation-relevant part of a CycloneDX component."""

    bom_ref: str
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    component_type: Optional[str] = None
    hashes: Tuple[ContentDigest, ...] = ()
    locations: Tuple[ArchivePath, ...] = ()

    def __post_init__(self) -> None:
        bom_ref = self.bom_ref.strip()
        name = self.name.strip()
        if not bom_ref:
            raise ReconciliationError('component bom_ref must not be empty')
        if not name:
            raise ReconciliationError(f'component {bom_ref!r} needs a name')
        hashes = tuple(sorted(set(self.hashes)))
        locations = tuple(sorted(set(self.locations)))
        object.__setattr__(self, 'bom_ref', bom_ref)
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'hashes', hashes)
        object.__setattr__(self, 'locations', locations)

    @classmethod
    def from_component(cls, component: 'Component') -> 'ComponentDeclaration':
        """Extract a declaration from a CycloneDX component."""
        fallback_version = component.version or 'unknown'
        bom_ref = component.bom_ref.value or (
            str(component.purl) if component.purl else f'{component.name}@{fallback_version}'
        )
        locations: List[ArchivePath] = []
        if component.evidence is not None:
            locations = [ArchivePath.parse(occurrence.location) for occurrence in component.evidence.occurrences]
        return cls(
            bom_ref=bom_ref,
            name=component.name,
            version=component.version,
            purl=str(component.purl) if component.purl else None,
            component_type=component.type.value,
            hashes=tuple(ContentDigest.from_hash_type(hash_type) for hash_type in component.hashes),
            locations=tuple(locations),
        )

    @classmethod
    def from_bom(cls, bom: 'Bom', *, include_metadata_component: bool = False) -> Tuple['ComponentDeclaration', ...]:
        """Extract all (including nested) component declarations from a BOM."""
        roots: List[Component] = []
        if include_metadata_component and bom.metadata.component is not None:
            roots.append(bom.metadata.component)
        roots.extend(bom.components)
        declarations: List[ComponentDeclaration] = []
        seen: set[int] = set()
        for root in roots:
            for component in root.iter_all_nested_components(include_self=True):
                if id(component) in seen:
                    continue
                seen.add(id(component))
                declarations.append(cls.from_component(component))
        return tuple(sorted(declarations, key=lambda declaration: declaration.bom_ref))

    def as_dict(self) -> dict[str, object]:
        return {
            'bom_ref': self.bom_ref,
            'name': self.name,
            'version': self.version,
            'purl': self.purl,
            'component_type': self.component_type,
            'hashes': [h.as_dict() for h in self.hashes],
            'locations': [str(location) for location in self.locations],
        }


@dataclass(frozen=True)
class DecisionReference:
    """Traceable snapshot of a decision that affected a finding."""

    decision_id: str
    revision: int
    rationale: str
    decided_by: str
    decided_at: str
    status: DecisionStatus

    def as_dict(self) -> dict[str, object]:
        return {
            'decision_id': self.decision_id,
            'revision': self.revision,
            'rationale': self.rationale,
            'decided_by': self.decided_by,
            'decided_at': self.decided_at,
            'status': self.status.value,
        }


@dataclass(frozen=True)
class ExclusionDecision:
    """
    An explicit, auditable decision to suppress one class of reconciliation gap.

    Selector dimensions are combined with AND: every populated dimension must
    match.  Values within one dimension are combined with OR.  At least one
    selector is mandatory; a decision cannot be a blanket "ignore everything".
    """

    decision_id: str
    target: ExclusionTarget
    rationale: str
    decided_by: str
    decided_at: str
    status: DecisionStatus = DecisionStatus.APPROVED
    revision: int = 1
    entry_ids: Tuple[str, ...] = ()
    locations: Tuple[str, ...] = ()
    digests: Tuple[ContentDigest, ...] = ()
    component_refs: Tuple[str, ...] = ()
    purls: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        decision_id = self.decision_id.strip()
        rationale = self.rationale.strip()
        decided_by = self.decided_by.strip()
        decided_at = self.decided_at.strip()
        if not decision_id:
            raise ReconciliationError('exclusion decision_id must not be empty')
        if not rationale:
            raise ReconciliationError(f'exclusion {decision_id!r} needs a rationale')
        if not decided_by:
            raise ReconciliationError(f'exclusion {decision_id!r} needs decided_by')
        if not decided_at:
            raise ReconciliationError(f'exclusion {decision_id!r} needs decided_at')
        if self.revision < 1:
            raise ReconciliationError(f'exclusion {decision_id!r} revision must be >= 1')
        target = ExclusionTarget(self.target)
        status = DecisionStatus(self.status)
        entry_ids = tuple(sorted(set(self.entry_ids)))
        locations = tuple(sorted(set(self.locations)))
        digests = tuple(sorted(set(self.digests)))
        component_refs = tuple(sorted(set(self.component_refs)))
        purls = tuple(sorted(set(self.purls)))
        if not any((entry_ids, locations, digests, component_refs, purls)):
            raise ReconciliationError(f'exclusion {decision_id!r} needs at least one explicit selector')
        if target is ExclusionTarget.ARCHIVE_RECORD and (component_refs or purls):
            raise ReconciliationError(
                f'exclusion {decision_id!r} targets archive records but selects components')
        if target is ExclusionTarget.COMPONENT_DECLARATION and entry_ids:
            raise ReconciliationError(
                f'exclusion {decision_id!r} targets declarations but selects archive entry ids')
        object.__setattr__(self, 'decision_id', decision_id)
        object.__setattr__(self, 'rationale', rationale)
        object.__setattr__(self, 'decided_by', decided_by)
        object.__setattr__(self, 'decided_at', decided_at)
        object.__setattr__(self, 'target', target)
        object.__setattr__(self, 'status', status)
        object.__setattr__(self, 'entry_ids', entry_ids)
        object.__setattr__(self, 'locations', locations)
        object.__setattr__(self, 'digests', digests)
        object.__setattr__(self, 'component_refs', component_refs)
        object.__setattr__(self, 'purls', purls)

    def matches_archive(self, entry: ArchiveEntry) -> bool:
        """Whether every populated selector applies to this archive record."""
        if self.target not in (ExclusionTarget.ARCHIVE_RECORD, ExclusionTarget.BOTH):
            return False
        if self.entry_ids and entry.entry_id not in self.entry_ids:
            return False
        if self.locations and not any(fnmatchcase(str(entry.location), pattern) for pattern in self.locations):
            return False
        if self.digests:
            entry_keys = {digest.key for digest in entry.hashes}
            if not entry_keys.intersection(digest.key for digest in self.digests):
                return False
        if self.component_refs or self.purls:
            return False
        return True

    def matches_component(self, declaration: ComponentDeclaration) -> bool:
        """Whether every populated selector applies to this component declaration."""
        if self.target not in (ExclusionTarget.COMPONENT_DECLARATION, ExclusionTarget.BOTH):
            return False
        if self.entry_ids:
            return False
        if self.component_refs and declaration.bom_ref not in self.component_refs:
            return False
        if self.purls and declaration.purl not in self.purls:
            return False
        if self.locations and not any(
            fnmatchcase(str(location), pattern)
            for location in declaration.locations
            for pattern in self.locations
        ):
            return False
        if self.digests:
            declaration_keys = {digest.key for digest in declaration.hashes}
            if not declaration_keys.intersection(digest.key for digest in self.digests):
                return False
        return True

    @property
    def is_approved(self) -> bool:
        return self.status is DecisionStatus.APPROVED

    def reference(self) -> DecisionReference:
        return DecisionReference(
            decision_id=self.decision_id,
            revision=self.revision,
            rationale=self.rationale,
            decided_by=self.decided_by,
            decided_at=self.decided_at,
            status=self.status,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            'decision_id': self.decision_id,
            'target': self.target.value,
            'rationale': self.rationale,
            'decided_by': self.decided_by,
            'decided_at': self.decided_at,
            'status': self.status.value,
            'revision': self.revision,
            'entry_ids': list(self.entry_ids),
            'locations': list(self.locations),
            'digests': [digest.as_dict() for digest in self.digests],
            'component_refs': list(self.component_refs),
            'purls': list(self.purls),
        }


@dataclass(frozen=True)
class MatchRecord:
    """A traceable link between an archive record and a declaration."""

    component_ref: str
    entry_id: str
    location: ArchivePath
    basis: MatchBasis
    shared_digests: Tuple[ContentDigest, ...]
    component_hashes: Tuple[ContentDigest, ...]
    entry_hashes: Tuple[ContentDigest, ...]
    declared_locations: Tuple[ArchivePath, ...]
    digest_fanout: bool
    location_contention: bool

    def as_dict(self) -> dict[str, object]:
        return {
            'component_ref': self.component_ref,
            'entry_id': self.entry_id,
            'location': str(self.location),
            'basis': self.basis.value,
            'shared_digests': [digest.as_dict() for digest in self.shared_digests],
            'component_hashes': [digest.as_dict() for digest in self.component_hashes],
            'entry_hashes': [digest.as_dict() for digest in self.entry_hashes],
            'declared_locations': [str(location) for location in self.declared_locations],
            'digest_fanout': self.digest_fanout,
            'location_contention': self.location_contention,
        }


@dataclass(frozen=True)
class ArchiveOnlyFinding:
    """An archive record that no component declaration explains."""

    entry_id: str
    location: ArchivePath
    hashes: Tuple[ContentDigest, ...]
    size: Optional[int]
    media_type: Optional[str]
    reason: str
    digest_fanout_locations: Tuple[ArchivePath, ...] = ()
    ignored_decision_ids: Tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            'kind': RecordKind.ARCHIVE_RECORD.value,
            'entry_id': self.entry_id,
            'location': str(self.location),
            'hashes': [digest.as_dict() for digest in self.hashes],
            'size': self.size,
            'media_type': self.media_type,
            'reason': self.reason,
            'digest_fanout_locations': [str(location) for location in self.digest_fanout_locations],
            'ignored_decision_ids': list(self.ignored_decision_ids),
        }


@dataclass(frozen=True)
class ComponentOnlyFinding:
    """A component declaration for which no archive record exists."""

    component_ref: str
    name: str
    version: Optional[str]
    purl: Optional[str]
    hashes: Tuple[ContentDigest, ...]
    declared_locations: Tuple[ArchivePath, ...]
    reason: str
    ignored_decision_ids: Tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            'kind': RecordKind.COMPONENT_DECLARATION.value,
            'component_ref': self.component_ref,
            'name': self.name,
            'version': self.version,
            'purl': self.purl,
            'hashes': [digest.as_dict() for digest in self.hashes],
            'declared_locations': [str(location) for location in self.declared_locations],
            'reason': self.reason,
            'ignored_decision_ids': list(self.ignored_decision_ids),
        }


@dataclass(frozen=True)
class CandidateEntry:
    """One possible archive record for an ambiguous declaration."""

    entry_id: str
    location: ArchivePath

    def as_dict(self) -> dict[str, object]:
        return {'entry_id': self.entry_id, 'location': str(self.location)}


@dataclass(frozen=True)
class AmbiguousFinding:
    """A declaration that cannot be linked without guessing."""

    component_ref: str
    name: str
    hashes: Tuple[ContentDigest, ...]
    declared_locations: Tuple[ArchivePath, ...]
    candidate_entries: Tuple[CandidateEntry, ...]
    reason: str
    ignored_decision_ids: Tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            'kind': RecordKind.AMBIGUOUS_DECLARATION.value,
            'component_ref': self.component_ref,
            'name': self.name,
            'hashes': [digest.as_dict() for digest in self.hashes],
            'declared_locations': [str(location) for location in self.declared_locations],
            'candidate_entries': [candidate.as_dict() for candidate in self.candidate_entries],
            'reason': self.reason,
            'ignored_decision_ids': list(self.ignored_decision_ids),
        }


@dataclass(frozen=True)
class ExcludedRecord:
    """An unexplained record suppressed by one or more approved decisions."""

    record_kind: RecordKind
    record_id: str
    location: Optional[ArchivePath]
    hashes: Tuple[ContentDigest, ...]
    component_ref: Optional[str]
    reason: str
    decisions: Tuple[DecisionReference, ...]
    ignored_decision_ids: Tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            'record_kind': self.record_kind.value,
            'record_id': self.record_id,
            'location': str(self.location) if self.location is not None else None,
            'hashes': [digest.as_dict() for digest in self.hashes],
            'component_ref': self.component_ref,
            'reason': self.reason,
            'decisions': [decision.as_dict() for decision in self.decisions],
            'ignored_decision_ids': list(self.ignored_decision_ids),
        }


@dataclass(frozen=True)
class ComponentConflict:
    """A location match whose content digest does not agree."""

    component_ref: str
    entry_id: str
    location: ArchivePath
    component_hashes: Tuple[ContentDigest, ...]
    entry_hashes: Tuple[ContentDigest, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            'component_ref': self.component_ref,
            'entry_id': self.entry_id,
            'location': str(self.location),
            'component_hashes': [digest.as_dict() for digest in self.component_hashes],
            'entry_hashes': [digest.as_dict() for digest in self.entry_hashes],
        }


@dataclass(frozen=True)
class DigestFanout:
    """One digest found at more than one archive location."""

    digest: ContentDigest
    entry_ids: Tuple[str, ...]
    locations: Tuple[ArchivePath, ...]
    declared_by: Tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            'digest': self.digest.as_dict(),
            'entry_ids': list(self.entry_ids),
            'locations': [str(location) for location in self.locations],
            'declared_by': list(self.declared_by),
        }


@dataclass(frozen=True)
class LocationContention:
    """One archive location declared by more than one component."""

    location: ArchivePath
    entry_ids: Tuple[str, ...]
    component_refs: Tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            'location': str(self.location),
            'entry_ids': list(self.entry_ids),
            'component_refs': list(self.component_refs),
        }


@dataclass(frozen=True)
class AuditSummary:
    """Counts that make the report easy to gate on."""

    archive_entries: int
    component_declarations: int
    matched_archive_entries: int
    matched_component_declarations: int
    archive_only: int
    component_only: int
    excluded: int
    ambiguous: int
    conflicts: int
    digest_fanout: int
    location_contention: int

    def as_dict(self) -> dict[str, int]:
        return {
            'archive_entries': self.archive_entries,
            'component_declarations': self.component_declarations,
            'matched_archive_entries': self.matched_archive_entries,
            'matched_component_declarations': self.matched_component_declarations,
            'archive_only': self.archive_only,
            'component_only': self.component_only,
            'excluded': self.excluded,
            'ambiguous': self.ambiguous,
            'conflicts': self.conflicts,
            'digest_fanout': self.digest_fanout,
            'location_contention': self.location_contention,
        }


@dataclass(frozen=True)
class AuditFingerprints:
    """Content-addressed identity of every audit input."""

    manifest: str
    declarations: str
    policy: str
    audit: str

    def as_dict(self) -> dict[str, str]:
        return {
            'manifest': self.manifest,
            'declarations': self.declarations,
            'policy': self.policy,
            'audit': self.audit,
        }


@dataclass(frozen=True)
class AuditChange:
    """A record whose reconciliation status changed between two audits."""

    record_kind: RecordKind
    record_id: str
    before: str
    after: str
    decision_ids_before: Tuple[str, ...]
    decision_ids_after: Tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            'record_kind': self.record_kind.value,
            'record_id': self.record_id,
            'before': self.before,
            'after': self.after,
            'decision_ids_before': list(self.decision_ids_before),
            'decision_ids_after': list(self.decision_ids_after),
        }


@dataclass(frozen=True)
class AuditDiff:
    """A comparison of two audits of the same manifest and declarations."""

    manifest_changed: bool
    declarations_changed: bool
    policy_changed: bool
    changes: Tuple[AuditChange, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            'manifest_changed': self.manifest_changed,
            'declarations_changed': self.declarations_changed,
            'policy_changed': self.policy_changed,
            'changes': [change.as_dict() for change in self.changes],
        }


@dataclass(frozen=True)
class AuditResult:
    """The complete, deterministic result of one reconciliation run."""

    manifest_label: str
    summary: AuditSummary
    fingerprints: AuditFingerprints
    matches: Tuple[MatchRecord, ...]
    archive_only: Tuple[ArchiveOnlyFinding, ...]
    component_only: Tuple[ComponentOnlyFinding, ...]
    excluded: Tuple[ExcludedRecord, ...]
    ambiguous: Tuple[AmbiguousFinding, ...]
    conflicts: Tuple[ComponentConflict, ...]
    digest_fanout: Tuple[DigestFanout, ...]
    location_contention: Tuple[LocationContention, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            'format_version': FORMAT_VERSION,
            'archive': self.manifest_label,
            'fingerprints': self.fingerprints.as_dict(),
            'summary': self.summary.as_dict(),
            'matches': [match.as_dict() for match in self.matches],
            'archive_only': [finding.as_dict() for finding in self.archive_only],
            'component_only': [finding.as_dict() for finding in self.component_only],
            'excluded': [record.as_dict() for record in self.excluded],
            'ambiguous': [finding.as_dict() for finding in self.ambiguous],
            'conflicts': [conflict.as_dict() for conflict in self.conflicts],
            'digest_fanout': [fanout.as_dict() for fanout in self.digest_fanout],
            'location_contention': [contention.as_dict() for contention in self.location_contention],
        }

    def render_text(self) -> str:
        """Render the audit as human-readable text."""
        from .report import render_audit
        return render_audit(self)
