# Copyright 2026, TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Tests for the offline forensic cross-check package."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forensics.cli import main as cli_main
from forensics.crosscheck import in_scope, run_crosscheck
from forensics.generate.builder import BundleKeys, target_file, write_bundle
from forensics.generate.demo import (
    APP_PATH,
    DELEGATED_ROLE,
    DELEGATED_PATHS,
    FIRMWARE_PATH,
    MANIFEST_PATH,
    build_demo,
)
from forensics.models import (
    CONFLICT,
    CONSISTENT,
    REASON_CUSTOM,
    REASON_HASH,
    REASON_LENGTH,
    REASON_MISSING,
    REASON_TRUST,
    UNDECIDED,
    PartyInput,
)
from forensics.report import render_json, render_markdown
from forensics.verification import verify_party
from tuf.api.metadata import TargetFile


def _make_input(base: Path, party: str, scope: list[str]) -> PartyInput:
    party_dir = base / party
    return PartyInput(
        party=party,
        root=party_dir / 'root.json',
        metadata_dir=party_dir,
        scope=tuple(scope),
    )


class TestScopeMatching(unittest.TestCase):
    def test_star_does_not_cross_directory(self) -> None:
        self.assertTrue(in_scope('release/app.tar.gz', ('release/*',)))
        self.assertFalse(in_scope('release/sub/app.tar.gz', ('release/*',)))

    def test_empty_scope_matches_nothing(self) -> None:
        self.assertFalse(in_scope('release/app.tar.gz', ()))

    def test_multiple_patterns(self) -> None:
        self.assertTrue(
            in_scope('release/a.bin', ('other/*', 'release/*.bin'))
        )


class TestDemoCrosscheck(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        build_demo(self.base)
        self.inputs = (
            _make_input(self.base, 'alpha', ['release/*']),
            _make_input(self.base, 'beta', ['release/*']),
        )

    def test_demo_verdicts(self) -> None:
        report = run_crosscheck(self.inputs)
        by_path = {verdict.target_path: verdict for verdict in report.verdicts}

        conflict = by_path[APP_PATH]
        self.assertEqual(conflict.verdict, CONFLICT)
        self.assertIn(REASON_HASH, conflict.reasons)
        self.assertIn(REASON_LENGTH, conflict.reasons)
        # A proven conflict must point at both originals.
        self.assertEqual(set(conflict.statements), {'alpha', 'beta'})
        for statement in conflict.statements.values():
            self.assertTrue(statement.evidence.metadata_sha256)

        undecided = by_path[MANIFEST_PATH]
        self.assertEqual(undecided.verdict, UNDECIDED)
        self.assertIn(REASON_MISSING, undecided.reasons)
        self.assertEqual(set(undecided.statements), {'alpha'})

        consistent = by_path[FIRMWARE_PATH]
        self.assertEqual(consistent.verdict, CONSISTENT)
        self.assertEqual(consistent.reasons, [])

    def test_beta_missing_role_is_recorded_not_trusted(self) -> None:
        report = run_crosscheck(self.inputs)
        beta = report.parties['beta']
        self.assertTrue(beta.verified)
        self.assertNotIn(DELEGATED_ROLE, beta.verified_roles)
        self.assertTrue(
            any('missing' in error for error in beta.errors)
        )

    def test_reports_contain_all_verdicts(self) -> None:
        report = run_crosscheck(self.inputs)
        json_data = json.loads(render_json(report))
        self.assertEqual(json_data['summary']['conflicts'], 1)
        self.assertEqual(json_data['summary']['undecided'], 1)
        markdown = render_markdown(report)
        self.assertIn('Proven conflicts', markdown)
        self.assertIn('Undecided', markdown)
        self.assertIn(APP_PATH, markdown)

    def test_cli_returns_conflict_exit_code(self) -> None:
        exit_code = cli_main([
            '--alpha', str(self.base / 'alpha-manifest.json'),
            '--beta', str(self.base / 'beta-manifest.json'),
            '--format', 'json',
        ])
        self.assertEqual(exit_code, 2)


class TestTamperedSignature(unittest.TestCase):
    def test_unsigned_role_breaks_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            base = Path(temp_name)
            keys = BundleKeys.generate(DELEGATED_ROLE)
            write_bundle(
                base,
                keys,
                top_targets={
                    APP_PATH: target_file(APP_PATH, b'payload\n'),
                },
                delegated_targets={},
                delegated_paths=list(DELEGATED_PATHS),
            )
            # Corrupt the targets payload without a valid signature.
            targets_path = base / 'targets.json'
            data = json.loads(targets_path.read_text(encoding='utf-8'))
            data['signed']['version'] = 99
            targets_path.write_text(
                json.dumps(data), encoding='utf-8'
            )
            result = verify_party(
                'alpha',
                base / 'root.json',
                base,
                ('release/*',),
            )
            self.assertFalse(result.verified)
            self.assertFalse(result.statements)
            self.assertTrue(
                any('targets' in error for error in result.errors)
            )



class TestCustomFieldConflict(unittest.TestCase):
    def test_same_hash_but_different_custom_is_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            base = Path(temp_name)
            shared = target_file(APP_PATH, b'same bytes\n')
            # Build two bundles whose app claims share length/hashes but
            # carry different signed custom metadata.
            custom_target = TargetFile(
                length=shared.length,
                hashes=dict(shared.hashes),
                path=shared.path,
                unrecognized_fields={'custom': {'channel': 'beta'}},
            )
            alpha_keys = BundleKeys.generate(DELEGATED_ROLE)
            beta_keys = BundleKeys.generate(DELEGATED_ROLE)
            write_bundle(
                base / 'alpha',
                alpha_keys,
                top_targets={APP_PATH: shared},
                delegated_targets={},
                delegated_paths=list(DELEGATED_PATHS),
            )
            write_bundle(
                base / 'beta',
                beta_keys,
                top_targets={APP_PATH: custom_target},
                delegated_targets={},
                delegated_paths=list(DELEGATED_PATHS),
            )
            report = run_crosscheck((
                _make_input(base, 'alpha', ['release/*']),
                _make_input(base, 'beta', ['release/*']),
            ))
            verdict = next(
                v for v in report.verdicts if v.target_path == APP_PATH
            )
            self.assertEqual(verdict.verdict, CONFLICT)
            self.assertEqual(verdict.reasons, [REASON_CUSTOM])


class TestBrokenTrustStaysUndecided(unittest.TestCase):
    def test_unverifiable_bundle_cannot_prove_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            base = Path(temp_name)
            keys = BundleKeys.generate(DELEGATED_ROLE)
            write_bundle(
                base / 'alpha',
                keys,
                top_targets={APP_PATH: target_file(APP_PATH, b'one\n')},
                delegated_targets={},
                delegated_paths=list(DELEGATED_PATHS),
            )
            other = BundleKeys.generate(DELEGATED_ROLE)
            write_bundle(
                base / 'beta',
                other,
                top_targets={APP_PATH: target_file(APP_PATH, b'two bytes\n')},
                delegated_targets={},
                delegated_paths=list(DELEGATED_PATHS),
            )
            # Tamper beta targets after signing so its trust chain breaks.
            targets_path = base / 'beta' / 'targets.json'
            data = json.loads(targets_path.read_text(encoding='utf-8'))
            data['signed']['version'] = 42
            targets_path.write_text(json.dumps(data), encoding='utf-8')

            report = run_crosscheck((
                _make_input(base, 'alpha', ['release/*']),
                _make_input(base, 'beta', ['release/*']),
            ))
            verdict = next(
                v for v in report.verdicts if v.target_path == APP_PATH
            )
            self.assertEqual(verdict.verdict, UNDECIDED)
            self.assertIn(REASON_TRUST, verdict.reasons)
            self.assertFalse(report.parties['beta'].verified)


if __name__ == '__main__':
    unittest.main()
