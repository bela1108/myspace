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

"""Deterministic reconciliation engine for archive records and component declarations."""

from collections import defaultdict
from hashlib import sha256
from json import dumps as json_dumps
from typing import DefaultDict, Dict, Iterable, List, Set, Tuple

from ..exception.reconcile import ReconciliationError
from .model import (
    FORMAT_VERSION,
    AmbiguousFinding,
    ArchiveEntry,
    ArchiveManifest,
    ArchiveOnlyFinding,
    ArchivePath,
    AuditChange,
    AuditDiff,
    AuditFingerprints,
    AuditResult,
    AuditSummary,
    CandidateEntry,
    ComponentConflict,
    ComponentDeclaration,
    ComponentOnlyFinding,
    ContentDigest,
    DecisionReference,
    DigestFanout,
    ExcludedRecord,
    ExclusionDecision,
    LocationContention,
    MatchBasis,
    MatchRecord,
    RecordKind,
)

_DigestKey = Tuple[str, str]


def _fingerprint(value: object) -> str:
    encoded = json_dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return 'sha256:' + sha256(encoded.encode('utf-8')).hexdigest()


def _sort_decisions(decisions: Iterable[ExclusionDecision]) -> Tuple[ExclusionDecision, ...]:
    ordered = tuple(sorted(decisions, key=lambda decision: (decision.decision_id, decision.revision)))
    seen: Set[str] = set()
    for decision in ordered:
        if decision.decision_id in seen:
            raise ReconciliationError(f'duplicate exclusion decision_id: {decision.decision_id!r}')
        seen.add(decision.decision_id)
    return ordered


def _decision_references(decisions: Iterable[ExclusionDecision]) -> Tuple[DecisionReference, ...]:
    return tuple(decision.reference() for decision in sorted(
        decisions, key=lambda decision: (decision.decision_id, decision.revision)))


def _ignored_decision_ids(decisions: Iterable[ExclusionDecision]) -> Tuple[str, ...]:
    return tuple(sorted({decision.decision_id for decision in decisions if not decision.is_approved}))


class Reconciler:
    """
    Audit an immutable archive manifest against immutable component declarations.

    The manifest and declarations are indexed once.  Each call to :meth:`audit`
    accepts a complete exclusion-decision set, so changing an exclusion scope
    does not require rebuilding or re-reading the evidence inputs.
    """

    def __init__(self, manifest: ArchiveManifest, declarations: Iterable[ComponentDeclaration]) -> None:
        self._manifest = manifest
        declarations_sorted = tuple(sorted(declarations, key=lambda declaration: declaration.bom_ref))
        seen_refs: Set[str] = set()
        for declaration in declarations_sorted:
            if declaration.bom_ref in seen_refs:
                raise ReconciliationError(f'duplicate component bom_ref: {declaration.bom_ref!r}')
            seen_refs.add(declaration.bom_ref)
        self._declarations = declarations_sorted

        self._manifest_fingerprint = _fingerprint(manifest.as_dict())
        self._declarations_fingerprint = _fingerprint([declaration.as_dict() for declaration in declarations_sorted])

        self._entries_by_location: Dict[ArchivePath, ArchiveEntry] = {
            entry.location: entry for entry in manifest.entries
        }
        self._entries_by_digest: DefaultDict[_DigestKey, List[ArchiveEntry]] = defaultdict(list)
        for entry in manifest.entries:
            for digest in entry.hashes:
                self._entries_by_digest[digest.key].append(entry)

        self._declarations_by_location: DefaultDict[ArchivePath, List[ComponentDeclaration]] = defaultdict(list)
        self._declarations_by_digest: DefaultDict[_DigestKey, List[ComponentDeclaration]] = defaultdict(list)
        for declaration in declarations_sorted:
            for location in declaration.locations:
                self._declarations_by_location[location].append(declaration)
            for digest in declaration.hashes:
                self._declarations_by_digest[digest.key].append(declaration)

        self._digest_fanout = self._build_digest_fanout()
        self._location_contention = self._build_location_contention()
        self._fanout_keys = {finding.digest.key for finding in self._digest_fanout}
        self._contended_locations = {finding.location for finding in self._location_contention}
        self._declared_digest_keys = set(self._declarations_by_digest)

    @property
    def manifest(self) -> ArchiveManifest:
        return self._manifest

    @property
    def declarations(self) -> Tuple[ComponentDeclaration, ...]:
        return self._declarations

    def audit(self, decisions: Iterable[ExclusionDecision] = ()) -> AuditResult:
        """Run one audit with the supplied complete decision set."""
        decision_set = _sort_decisions(decisions)
        approved = tuple(decision for decision in decision_set if decision.is_approved)
        policy_fingerprint = _fingerprint([decision.as_dict() for decision in decision_set])
        audit_fingerprint = _fingerprint({
            'format_version': FORMAT_VERSION,
            'manifest': self._manifest_fingerprint,
            'declarations': self._declarations_fingerprint,
            'policy': policy_fingerprint,
        })

        matches, conflicts, claimed_entry_ids, matched_component_refs = self._match_records()
        archive_only, archive_excluded = self._archive_findings(
            decision_set, approved, claimed_entry_ids)
        component_only, component_excluded, ambiguous = self._declaration_findings(
            decision_set, approved, matched_component_refs)
        excluded = archive_excluded + component_excluded

        matches.sort(key=lambda match: (match.component_ref, match.location, match.entry_id))
        archive_only.sort(key=lambda finding: (finding.location, finding.entry_id))
        component_only.sort(key=lambda finding: finding.component_ref)
        excluded.sort(key=lambda record: (record.record_kind.value, record.record_id))
        ambiguous.sort(key=lambda finding: finding.component_ref)
        conflicts.sort(key=lambda conflict: (conflict.component_ref, conflict.entry_id))

        summary = AuditSummary(
            archive_entries=len(self._manifest.entries),
            component_declarations=len(self._declarations),
            matched_archive_entries=len(claimed_entry_ids),
            matched_component_declarations=len(matched_component_refs),
            archive_only=len(archive_only),
            component_only=len(component_only),
            excluded=len(excluded),
            ambiguous=len(ambiguous),
            conflicts=len(conflicts),
            digest_fanout=len(self._digest_fanout),
            location_contention=len(self._location_contention),
        )
        return AuditResult(
            manifest_label=self._manifest.archive,
            summary=summary,
            fingerprints=AuditFingerprints(
                manifest=self._manifest_fingerprint,
                declarations=self._declarations_fingerprint,
                policy=policy_fingerprint,
                audit=audit_fingerprint,
            ),
            matches=tuple(matches),
            archive_only=tuple(archive_only),
            component_only=tuple(component_only),
            excluded=tuple(excluded),
            ambiguous=tuple(ambiguous),
            conflicts=tuple(conflicts),
            digest_fanout=self._digest_fanout,
            location_contention=self._location_contention,
        )

    def _match_records(
        self,
    ) -> Tuple[List[MatchRecord], List[ComponentConflict], Set[str], Set[str]]:
        claimed_entry_ids: Set[str] = set()
        matched_component_refs: Set[str] = set()
        matches: List[MatchRecord] = []
        conflicts: List[ComponentConflict] = []
        for declaration in self._declarations:
            location_hits = [
                self._entries_by_location[location]
                for location in declaration.locations
                if location in self._entries_by_location
            ]
            if location_hits:
                for entry in location_hits:
                    self._add_location_match(declaration, entry, matches, conflicts)
                    claimed_entry_ids.add(entry.entry_id)
                    matched_component_refs.add(declaration.bom_ref)
                continue
            candidates = self._digest_candidates(declaration)
            if len(candidates) == 1:
                entry = candidates[0]
                basis = MatchBasis.DIGEST_RELOCATED if declaration.locations else MatchBasis.DIGEST_ONLY
                shared = self._shared_digests(declaration, entry)
                matches.append(self._make_match(declaration, entry, basis, shared))
                claimed_entry_ids.add(entry.entry_id)
                matched_component_refs.add(declaration.bom_ref)
        return matches, conflicts, claimed_entry_ids, matched_component_refs

    def _add_location_match(
        self,
        declaration: ComponentDeclaration,
        entry: ArchiveEntry,
        matches: List[MatchRecord],
        conflicts: List[ComponentConflict],
    ) -> None:
        shared = self._shared_digests(declaration, entry)
        common_algorithms = (
            {digest.algorithm for digest in declaration.hashes}
            & {digest.algorithm for digest in entry.hashes}
        )
        if shared:
            basis = MatchBasis.LOCATION_AND_DIGEST
        elif common_algorithms:
            basis = MatchBasis.LOCATION_DIGEST_MISMATCH
            conflicts.append(ComponentConflict(
                component_ref=declaration.bom_ref,
                entry_id=entry.entry_id,
                location=entry.location,
                component_hashes=declaration.hashes,
                entry_hashes=entry.hashes,
            ))
        else:
            basis = MatchBasis.LOCATION_ONLY
        matches.append(self._make_match(declaration, entry, basis, shared))

    def _archive_findings(
        self,
        decision_set: Tuple[ExclusionDecision, ...],
        approved: Tuple[ExclusionDecision, ...],
        claimed_entry_ids: Set[str],
    ) -> Tuple[List[ArchiveOnlyFinding], List[ExcludedRecord]]:
        archive_only: List[ArchiveOnlyFinding] = []
        excluded: List[ExcludedRecord] = []
        for entry in self._manifest.entries:
            if entry.entry_id in claimed_entry_ids:
                continue
            matching_approved = [decision for decision in approved if decision.matches_archive(entry)]
            matching_ignored = [
                decision for decision in decision_set
                if not decision.is_approved and decision.matches_archive(entry)
            ]
            reason = self._archive_only_reason(entry)
            if matching_approved:
                excluded.append(ExcludedRecord(
                    record_kind=RecordKind.ARCHIVE_RECORD,
                    record_id=entry.entry_id,
                    location=entry.location,
                    hashes=entry.hashes,
                    component_ref=None,
                    reason=reason,
                    decisions=_decision_references(matching_approved),
                    ignored_decision_ids=_ignored_decision_ids(matching_ignored),
                ))
                continue
            archive_only.append(ArchiveOnlyFinding(
                entry_id=entry.entry_id,
                location=entry.location,
                hashes=entry.hashes,
                size=entry.size,
                media_type=entry.media_type,
                reason=reason,
                digest_fanout_locations=self._fanout_locations(entry),
                ignored_decision_ids=_ignored_decision_ids(matching_ignored),
            ))
        return archive_only, excluded

    def _declaration_findings(
        self,
        decision_set: Tuple[ExclusionDecision, ...],
        approved: Tuple[ExclusionDecision, ...],
        matched_component_refs: Set[str],
    ) -> Tuple[List[ComponentOnlyFinding], List[ExcludedRecord], List[AmbiguousFinding]]:
        component_only: List[ComponentOnlyFinding] = []
        excluded: List[ExcludedRecord] = []
        ambiguous: List[AmbiguousFinding] = []
        for declaration in self._declarations:
            if declaration.bom_ref in matched_component_refs:
                continue
            candidates = self._digest_candidates(declaration)
            if len(candidates) > 1:
                self._record_ambiguous_declaration(
                    declaration, candidates, decision_set, approved, excluded, ambiguous)
                continue
            self._record_unmatched_declaration(
                declaration, decision_set, approved, component_only, excluded)
        return component_only, excluded, ambiguous

    def _record_ambiguous_declaration(
        self,
        declaration: ComponentDeclaration,
        candidates: List[ArchiveEntry],
        decision_set: Tuple[ExclusionDecision, ...],
        approved: Tuple[ExclusionDecision, ...],
        excluded: List[ExcludedRecord],
        ambiguous: List[AmbiguousFinding],
    ) -> None:
        matching_approved = [decision for decision in approved if decision.matches_component(declaration)]
        matching_ignored = [
            decision for decision in decision_set
            if not decision.is_approved and decision.matches_component(declaration)
        ]
        if matching_approved:
            excluded.append(ExcludedRecord(
                record_kind=RecordKind.AMBIGUOUS_DECLARATION,
                record_id=declaration.bom_ref,
                location=None,
                hashes=declaration.hashes,
                component_ref=declaration.bom_ref,
                reason='digest-appears-at-multiple-paths',
                decisions=_decision_references(matching_approved),
                ignored_decision_ids=_ignored_decision_ids(matching_ignored),
            ))
            return
        ambiguous.append(AmbiguousFinding(
            component_ref=declaration.bom_ref,
            name=declaration.name,
            hashes=declaration.hashes,
            declared_locations=declaration.locations,
            candidate_entries=tuple(
                CandidateEntry(entry_id=entry.entry_id, location=entry.location)
                for entry in candidates
            ),
            reason='digest-appears-at-multiple-paths',
            ignored_decision_ids=_ignored_decision_ids(matching_ignored),
        ))

    def _record_unmatched_declaration(
        self,
        declaration: ComponentDeclaration,
        decision_set: Tuple[ExclusionDecision, ...],
        approved: Tuple[ExclusionDecision, ...],
        component_only: List[ComponentOnlyFinding],
        excluded: List[ExcludedRecord],
    ) -> None:
        matching_approved = [decision for decision in approved if decision.matches_component(declaration)]
        matching_ignored = [
            decision for decision in decision_set
            if not decision.is_approved and decision.matches_component(declaration)
        ]
        reason = 'no-archive-record' if (declaration.hashes or declaration.locations) else 'no-locator-or-digest'
        if matching_approved:
            excluded.append(ExcludedRecord(
                record_kind=RecordKind.COMPONENT_DECLARATION,
                record_id=declaration.bom_ref,
                location=None,
                hashes=declaration.hashes,
                component_ref=declaration.bom_ref,
                reason=reason,
                decisions=_decision_references(matching_approved),
                ignored_decision_ids=_ignored_decision_ids(matching_ignored),
            ))
            return
        component_only.append(ComponentOnlyFinding(
            component_ref=declaration.bom_ref,
            name=declaration.name,
            version=declaration.version,
            purl=declaration.purl,
            hashes=declaration.hashes,
            declared_locations=declaration.locations,
            reason=reason,
            ignored_decision_ids=_ignored_decision_ids(matching_ignored),
        ))

    def _shared_digests(self, declaration: ComponentDeclaration, entry: ArchiveEntry) -> Tuple[ContentDigest, ...]:
        entry_keys = {digest.key for digest in entry.hashes}
        return tuple(sorted({digest for digest in declaration.hashes if digest.key in entry_keys}))

    def _digest_candidates(self, declaration: ComponentDeclaration) -> List[ArchiveEntry]:
        candidates: Dict[str, ArchiveEntry] = {}
        for digest in declaration.hashes:
            for entry in self._entries_by_digest.get(digest.key, ()):
                candidates[entry.entry_id] = entry
        return sorted(candidates.values(), key=lambda entry: (entry.location, entry.entry_id))

    def _make_match(
        self,
        declaration: ComponentDeclaration,
        entry: ArchiveEntry,
        basis: MatchBasis,
        shared: Tuple[ContentDigest, ...],
    ) -> MatchRecord:
        return MatchRecord(
            component_ref=declaration.bom_ref,
            entry_id=entry.entry_id,
            location=entry.location,
            basis=basis,
            shared_digests=shared,
            component_hashes=declaration.hashes,
            entry_hashes=entry.hashes,
            declared_locations=declaration.locations,
            digest_fanout=any(digest.key in self._fanout_keys for digest in entry.hashes),
            location_contention=entry.location in self._contended_locations,
        )

    def _archive_only_reason(self, entry: ArchiveEntry) -> str:
        if any(digest.key in self._fanout_keys for digest in entry.hashes):
            return 'digest-appears-at-multiple-paths'
        if any(digest.key in self._declared_digest_keys for digest in entry.hashes):
            return 'digest-declared-at-another-location'
        return 'no-component-declaration'

    def _fanout_locations(self, entry: ArchiveEntry) -> Tuple[ArchivePath, ...]:
        locations: Set[ArchivePath] = set()
        for finding in self._digest_fanout:
            if any(digest.key == finding.digest.key for digest in entry.hashes):
                locations.update(location for location in finding.locations if location != entry.location)
        return tuple(sorted(locations))

    def _build_digest_fanout(self) -> Tuple[DigestFanout, ...]:
        findings: List[DigestFanout] = []
        for key, entries in self._entries_by_digest.items():
            locations = tuple(sorted({entry.location for entry in entries}))
            if len(locations) <= 1:
                continue
            entry_ids = tuple(sorted(entry.entry_id for entry in entries))
            declared_by = tuple(sorted({
                declaration.bom_ref
                for declaration in self._declarations_by_digest.get(key, ())
            }))
            findings.append(DigestFanout(
                digest=ContentDigest(algorithm=key[0], value=key[1]),
                entry_ids=entry_ids,
                locations=locations,
                declared_by=declared_by,
            ))
        return tuple(sorted(findings, key=lambda finding: finding.digest))

    def _build_location_contention(self) -> Tuple[LocationContention, ...]:
        findings: List[LocationContention] = []
        for location, declarations in self._declarations_by_location.items():
            refs = tuple(sorted({declaration.bom_ref for declaration in declarations}))
            if len(refs) <= 1:
                continue
            entry = self._entries_by_location.get(location)
            findings.append(LocationContention(
                location=location,
                entry_ids=(entry.entry_id,) if entry is not None else (),
                component_refs=refs,
            ))
        return tuple(sorted(findings, key=lambda finding: finding.location))


def reconcile(
    manifest: ArchiveManifest,
    declarations: Iterable[ComponentDeclaration],
    decisions: Iterable[ExclusionDecision] = (),
) -> AuditResult:
    """
    Reconcile archive records against component declarations in one call.

    Use :class:`Reconciler` directly when the same inputs must be audited again
    after an exclusion scope changes.
    """
    return Reconciler(manifest, declarations).audit(decisions)


def _status_map(result: AuditResult) -> Dict[Tuple[RecordKind, str], Tuple[str, Tuple[str, ...]]]:
    statuses: Dict[Tuple[RecordKind, str], Tuple[str, Tuple[str, ...]]] = {}
    for match in result.matches:
        statuses[(RecordKind.ARCHIVE_RECORD, match.entry_id)] = ('matched', ())
        statuses[(RecordKind.COMPONENT_DECLARATION, match.component_ref)] = ('matched', ())
    for finding in result.archive_only:
        statuses[(RecordKind.ARCHIVE_RECORD, finding.entry_id)] = ('archive-only', ())
    for finding in result.component_only:
        statuses[(RecordKind.COMPONENT_DECLARATION, finding.component_ref)] = ('component-only', ())
    for finding in result.ambiguous:
        statuses[(RecordKind.COMPONENT_DECLARATION, finding.component_ref)] = ('ambiguous', ())
    for record in result.excluded:
        kind = (
            RecordKind.COMPONENT_DECLARATION
            if record.record_kind is RecordKind.AMBIGUOUS_DECLARATION
            else record.record_kind
        )
        statuses[(kind, record.record_id)] = (
            'excluded',
            tuple(decision.decision_id for decision in record.decisions),
        )
    return statuses


def diff_audits(before: AuditResult, after: AuditResult) -> AuditDiff:
    """
    Compare two audits, typically before and after an exclusion-scope revision.

    The diff reports record-level transitions (for example ``archive-only`` to
    ``excluded``) and whether the manifest, declarations, or decision policy
    changed.
    """
    before_statuses = _status_map(before)
    after_statuses = _status_map(after)
    changes: List[AuditChange] = []
    for key in sorted(set(before_statuses) | set(after_statuses), key=lambda item: (item[0].value, item[1])):
        before_status, before_decisions = before_statuses.get(key, ('absent', ()))
        after_status, after_decisions = after_statuses.get(key, ('absent', ()))
        if before_status == after_status and before_decisions == after_decisions:
            continue
        changes.append(AuditChange(
            record_kind=key[0],
            record_id=key[1],
            before=before_status,
            after=after_status,
            decision_ids_before=before_decisions,
            decision_ids_after=after_decisions,
        ))
    return AuditDiff(
        manifest_changed=before.fingerprints.manifest != after.fingerprints.manifest,
        declarations_changed=before.fingerprints.declarations != after.fingerprints.declarations,
        policy_changed=before.fingerprints.policy != after.fingerprints.policy,
        changes=tuple(changes),
    )
