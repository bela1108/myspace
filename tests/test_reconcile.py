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

import json
import tarfile
from contextlib import redirect_stdout
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
from typing import Tuple
from unittest import TestCase

from cyclonedx.reconcile import (
    ArchiveEntry,
    ArchiveManifest,
    ArchivePath,
    AuditResult,
    ComponentDeclaration,
    ContentDigest,
    DecisionStatus,
    ExclusionDecision,
    ExclusionTarget,
    Reconciler,
    diff_audits,
    reconcile,
)
from cyclonedx.reconcile.__main__ import main
from cyclonedx.reconcile.loaders import (
    declarations_from_bom_file,
    decisions_from_file,
    manifest_from_file,
)


DATA = Path(__file__).parent / '_data' / 'reconcile' / 'two_layer'
OUTER = 'release-1.0.tar'
INNER = 'payload/runtime.tar'


def _sha(text: str) -> ContentDigest:
    return ContentDigest(algorithm='SHA-256', value=sha256(text.encode('utf-8')).hexdigest())


def _fixture_inputs() -> Tuple[ArchiveManifest, Tuple[ComponentDeclaration, ...]]:
    manifest = manifest_from_file(str(DATA / 'manifest.json'))
    declarations = declarations_from_bom_file(str(DATA / 'sbom.cdx.json'))
    return manifest, declarations


def _fixture_audit(version: str) -> AuditResult:
    manifest, declarations = _fixture_inputs()
    decisions = decisions_from_file(str(DATA / ('decisions-' + version + '.json')))
    reconciler = Reconciler(manifest, declarations)
    return reconciler.audit(decisions)


class TestReconcileFixture(TestCase):

    def test_static_archives_match_manifest(self) -> None:
        manifest, declarations = _fixture_inputs()
        self.assertEqual(47, len(manifest.entries))
        self.assertEqual(40, len(declarations))

        with tarfile.open(DATA / OUTER, mode='r') as outer:
            self.assertEqual(
                ['META-INF/MANIFEST.json', 'META-INF/sbom.cdx.json', INNER],
                outer.getnames(),
            )
            inner_bytes = outer.extractfile(INNER).read()
            outer_members = {
                name: outer.extractfile(name).read()
                for name in ('META-INF/MANIFEST.json', 'META-INF/sbom.cdx.json', INNER)
            }
        with tarfile.open(fileobj=BytesIO(inner_bytes), mode='r') as inner:
            inner_members = {name: inner.extractfile(name).read() for name in inner.getnames()}
            self.assertEqual(44, len(inner_members))

        entries = {str(entry.location): entry for entry in manifest.entries}
        for name, data in outer_members.items():
            entry = entries[str(ArchivePath((OUTER,), name))]
            self.assertEqual([{'algorithm': 'SHA-256', 'value': sha256(data).hexdigest()}],
                             [digest.as_dict() for digest in entry.hashes])
            self.assertEqual(len(data), entry.size)
        for name, data in inner_members.items():
            entry = entries[str(ArchivePath((OUTER, INNER), name))]
            self.assertEqual([{'algorithm': 'SHA-256', 'value': sha256(data).hexdigest()}],
                             [digest.as_dict() for digest in entry.hashes])
            self.assertEqual(len(data), entry.size)

    def test_container_internal_locations_are_canonical(self) -> None:
        manifest, _ = _fixture_inputs()
        entry = next(item for item in manifest.entries if item.entry_id == 'F004')
        self.assertEqual((OUTER, INNER), entry.location.containers)
        self.assertEqual('app/audit.py', entry.location.path)
        self.assertEqual(OUTER + '!/' + INNER + '!/app/audit.py', str(entry.location))

        result = _fixture_audit('v2')
        match = next(item for item in result.matches if item.component_ref == 'pkg:generic/app-audit@1.0.0')
        self.assertEqual(entry.location, match.location)
        self.assertIn(entry.location, match.declared_locations)

    def test_required_sections_are_separate_and_ordered(self) -> None:
        result = _fixture_audit('v2')
        self.assertEqual(41, result.summary.matched_archive_entries)
        self.assertEqual(38, result.summary.matched_component_declarations)
        self.assertEqual(3, result.summary.archive_only)
        self.assertEqual(1, result.summary.component_only)
        self.assertEqual(4, result.summary.excluded)
        self.assertEqual(
            {'pkg:generic/ghost-helper@1.0.0'},
            {finding.component_ref for finding in result.component_only},
        )
        self.assertEqual({'F007', 'F034', 'F044'}, {finding.entry_id for finding in result.archive_only})
        self.assertEqual(
            {'F001', 'F002', 'F003', 'pkg:generic/optional-codec@1.0.0'},
            {record.record_id for record in result.excluded},
        )
        text = result.render_text()
        archive_heading = text.index('Archive records without declaration (3)')
        component_heading = text.index('Declarations without archive record (1)')
        excluded_heading = text.index('Confirmed exclusions (4)')
        self.assertLess(archive_heading, component_heading)
        self.assertLess(component_heading, excluded_heading)

    def test_digest_fanout_and_location_contention_are_distinct(self) -> None:
        result = _fixture_audit('v2')
        self.assertEqual(1, len(result.digest_fanout))
        self.assertEqual(1, len(result.location_contention))

        fanout = result.digest_fanout[0]
        self.assertEqual(2, len(fanout.locations))
        self.assertIn(ArchivePath((OUTER, INNER), 'vendor/requests/__init__.py'), fanout.locations)
        self.assertIn(ArchivePath((OUTER, INNER), 'vendor/requests_copy/__init__.py'), fanout.locations)
        self.assertEqual(('pkg:generic/requests-core@1.0.0',), fanout.declared_by)

        contention = result.location_contention[0]
        self.assertEqual(ArchivePath((OUTER, INNER), 'vendor/runtime/shared.py'), contention.location)
        self.assertEqual(
            ('pkg:generic/runtime-compat@1.0.0', 'pkg:generic/runtime-core@1.0.0'),
            contention.component_refs,
        )
        shared_matches = [item for item in result.matches if item.location == contention.location]
        self.assertEqual(2, len(shared_matches))
        self.assertTrue(all(item.location_contention for item in shared_matches))
        self.assertEqual(1, len({item.entry_id for item in shared_matches}))

        copy = next(item for item in result.archive_only if item.entry_id == 'F044')
        self.assertEqual('digest-appears-at-multiple-paths', copy.reason)
        self.assertIn(ArchivePath((OUTER, INNER), 'vendor/requests/__init__.py'), copy.digest_fanout_locations)

    def test_reaudit_after_decision_scope_change(self) -> None:
        manifest, declarations = _fixture_inputs()
        reconciler = Reconciler(manifest, declarations)
        before = reconciler.audit(decisions_from_file(str(DATA / 'decisions-v1.json')))
        after = reconciler.audit(decisions_from_file(str(DATA / 'decisions-v2.json')))

        self.assertEqual(4, before.summary.archive_only)
        self.assertEqual(3, before.summary.excluded)
        self.assertEqual(3, after.summary.archive_only)
        self.assertEqual(4, after.summary.excluded)

        diff = diff_audits(before, after)
        self.assertTrue(diff.policy_changed)
        self.assertFalse(diff.manifest_changed)
        self.assertFalse(diff.declarations_changed)
        self.assertEqual(1, len(diff.changes))
        change = diff.changes[0]
        self.assertEqual('F003', change.record_id)
        self.assertEqual('archive-only', change.before)
        self.assertEqual('excluded', change.after)
        self.assertEqual(('EX-003',), change.decision_ids_after)
        self.assertEqual(after.fingerprints.manifest, before.fingerprints.manifest)
        self.assertEqual(after.fingerprints.declarations, before.fingerprints.declarations)
        self.assertNotEqual(after.fingerprints.policy, before.fingerprints.policy)

    def test_json_representation_is_serializable(self) -> None:
        result = _fixture_audit('v2')
        payload = json.loads(json.dumps(result.as_dict(), sort_keys=True))
        self.assertEqual(47, payload['summary']['archive_entries'])
        self.assertEqual(40, payload['summary']['component_declarations'])
        self.assertEqual(3, len(payload['archive_only']))
        self.assertEqual(1, len(payload['component_only']))
        self.assertEqual(4, len(payload['excluded']))

    def test_cli_json_and_failure_gate(self) -> None:
        arguments = [
            '--manifest', str(DATA / 'manifest.json'),
            '--bom', str(DATA / 'sbom.cdx.json'),
            '--decisions', str(DATA / 'decisions-v2.json'),
            '--baseline-decisions', str(DATA / 'decisions-v1.json'),
            '--json',
        ]
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, main(arguments))
        payload = json.loads(output.getvalue())
        self.assertEqual(47, payload['audit']['summary']['archive_entries'])
        self.assertEqual(1, len(payload['diff']['changes']))
        self.assertEqual('excluded', payload['diff']['changes'][0]['after'])

        with redirect_stdout(StringIO()):
            self.assertEqual(2, main(arguments[:-1] + ['--fail-on-unexplained']))


class TestReconcileEdgeCases(TestCase):

    def test_rejected_decision_does_not_exclude(self) -> None:
        digest = _sha('physical')
        manifest = ArchiveManifest('x.tar', (ArchiveEntry('E1', ArchivePath.parse('x.tar!/a.txt'), (digest,)),))
        decision = ExclusionDecision(
            decision_id='EX-R',
            target=ExclusionTarget.ARCHIVE_RECORD,
            rationale='rejected by review',
            decided_by='reviewer',
            decided_at='2026-11-21',
            status=DecisionStatus.REJECTED,
            entry_ids=('E1',),
        )
        result = reconcile(manifest, (), (decision,))
        self.assertEqual(1, result.summary.archive_only)
        self.assertEqual(0, result.summary.excluded)
        self.assertEqual(('EX-R',), result.archive_only[0].ignored_decision_ids)

    def test_digest_fanout_without_declared_location_is_ambiguous(self) -> None:
        digest = _sha('duplicate')
        manifest = ArchiveManifest('x.tar', (
            ArchiveEntry('E1', ArchivePath.parse('x.tar!/a.txt'), (digest,)),
            ArchiveEntry('E2', ArchivePath.parse('x.tar!/b.txt'), (digest,)),
        ))
        declaration = ComponentDeclaration(
            bom_ref='pkg:generic/c@1',
            name='c',
            hashes=(digest,),
        )
        result = reconcile(manifest, (declaration,))
        self.assertEqual(1, result.summary.ambiguous)
        self.assertEqual(0, result.summary.component_only)
        self.assertEqual(2, result.summary.archive_only)
        self.assertEqual(2, len(result.ambiguous[0].candidate_entries))
        self.assertEqual(1, len(result.digest_fanout))

    def test_same_location_different_digest_is_conflict(self) -> None:
        declared = _sha('declared')
        archived = _sha('archived')
        location = ArchivePath.parse('x.tar!/a.txt')
        manifest = ArchiveManifest('x.tar', (ArchiveEntry('E1', location, (archived,)),))
        declaration = ComponentDeclaration(
            bom_ref='pkg:generic/c@1',
            name='c',
            hashes=(declared,),
            locations=(location,),
        )
        result = reconcile(manifest, (declaration,))
        self.assertEqual(1, result.summary.conflicts)
        self.assertEqual(1, result.summary.matched_archive_entries)
        self.assertEqual(0, result.summary.archive_only)
        self.assertEqual(1, len(result.conflicts))
        self.assertEqual('location-digest-mismatch', result.matches[0].basis.value)

    def test_exclusion_requires_explicit_selectors(self) -> None:
        with self.assertRaises(ValueError):
            ExclusionDecision(
                decision_id='EX-EMPTY',
                target=ExclusionTarget.BOTH,
                rationale='too broad',
                decided_by='reviewer',
                decided_at='2026-11-21',
            )
