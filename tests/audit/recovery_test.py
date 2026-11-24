import json
import os
from pathlib import Path

import pytest

from detect_secrets.audit import recovery
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import main
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


PROBE_ROOT = Path('test_data/recovery_probe')
PROBE_MANIFEST = str(PROBE_ROOT / 'probe.yaml')
SAMPLES_FILE = str(PROBE_ROOT / 'samples.py')


def _plugin_config(*classnames: str):
    mapping = {
        'AlphaTokenDetector': PROBE_ROOT / 'plugins' / 'alpha_token.py',
        'BetaTokenDetector': PROBE_ROOT / 'plugins' / 'beta_token.py',
    }
    return [
        {
            'name': classname,
            'path': 'file://' + os.path.abspath(str(mapping[classname])),
        }
        for classname in classnames
    ]



def _build_probe_baseline() -> SecretsCollection:
    with transient_settings({
        'plugins_used': _plugin_config('AlphaTokenDetector', 'BetaTokenDetector'),
    }):
        from detect_secrets.core.plugins.util import (
            get_mapping_from_secret_type_to_class,
        )
        get_mapping_from_secret_type_to_class.cache_clear()
        secrets = SecretsCollection()
        secrets.scan_file(SAMPLES_FILE)
    return secrets


def _leading_json(message: str) -> dict:
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(message.lstrip())
    return obj

class TestRunRecoveryProbe:
    def test_all_plugins_healthy(self):
        report = recovery.run_recovery_probe(PROBE_MANIFEST)

        assert report.passed is True
        assert report.comparison_only is False
        assert set(report.json()['plugins']) == {
            'AlphaTokenDetector',
            'BetaTokenDetector',
        }

        alpha = report.json()['plugins']['AlphaTokenDetector']
        beta = report.json()['plugins']['BetaTokenDetector']
        for plugin in (alpha, beta):
            assert plugin['exclusive-positive'] == 1
            assert plugin['shared-positive'] == 1
            assert plugin['detected-positive'] == 2
            assert plugin['missed-positive'] == 0
            assert plugin['expected-negative'] == 1
            assert plugin['ignored-negative'] == 1
            assert plugin['flagged-negative'] == 0
            assert plugin['passed'] is True

    def test_stopped_plugin_fails_even_though_aggregate_looks_fine(self):
        # Simulate Beta never running: only Alpha is active. Alpha still catches
        # the shared marker, so the raw number of findings looks healthy.
        manifest = recovery.load_probe_manifest(PROBE_MANIFEST)
        with transient_settings({'plugins_used': _plugin_config('AlphaTokenDetector')}):
            from detect_secrets.core.plugins.util import (
                get_mapping_from_secret_type_to_class,
            )
            get_mapping_from_secret_type_to_class.cache_clear()
            report = recovery.evaluate_recovery(
                manifest,
                tuple(recovery._scan_probe_samples(manifest)),
            )

        alpha = {p.plugin_classname: p for p in report.plugins}['AlphaTokenDetector']
        beta = {p.plugin_classname: p for p in report.plugins}['BetaTokenDetector']

        assert alpha.passed is True
        assert alpha.detected_positive == 2
        assert beta.passed is False
        assert beta.detected_positive == 0
        assert beta.missed_positive == 2
        assert report.passed is False
        assert any('BetaTokenDetector' in reason for reason in report.failures)

    def test_negative_sample_being_flagged_fails(self):
        manifest = recovery.load_probe_manifest(PROBE_MANIFEST)
        detections = []
        for sample in manifest.samples:
            if sample.is_negative:
                detections.append(
                    recovery.PluginDetection('AlphaTokenDetector', sample.secret_hash),
                )
            else:
                for plugin_name in sample.expected_plugins:
                    detections.append(
                        recovery.PluginDetection(plugin_name, sample.secret_hash),
                    )

        report = recovery.evaluate_recovery(manifest, iter(detections))
        alpha = {p.plugin_classname: p for p in report.plugins}['AlphaTokenDetector']

        assert alpha.flagged_negative == 1
        assert alpha.passed is False
        assert report.passed is False


class TestHistoricalComparison:
    def test_old_baseline_is_comparison_only(self):
        secrets = _build_probe_baseline()
        with mock_named_temporary_file() as f:
            baseline.save_to_file(secrets, f.name)
            f.seek(0)
            report = recovery.compare_historical_baseline(PROBE_MANIFEST, f.name)

        assert report.comparison_only is True
        # A baseline that predates the probe can never satisfy the release gate.
        assert report.passed is False
        assert report.comparison_baseline == f.name
        for plugin in report.plugins:
            assert plugin.missed_positive == 0
            assert plugin.flagged_negative == 0

    def test_invalid_baseline_raises_probe_error(self):
        with mock_named_temporary_file() as f:
            f.write(b'not a baseline')
            f.seek(0)
            with pytest.raises(recovery.RecoveryProbeError):
                recovery.compare_historical_baseline(PROBE_MANIFEST, f.name)


class TestRecoveryProbeCli:
    def test_gate_passes_when_healthy(self, printer):
        return_code = main([
            'audit',
            '--probe', PROBE_MANIFEST,
            '--gate',
            '--json',
        ])
        assert return_code == 0
        data = _leading_json(printer.message)
        assert data['passed'] is True

    def test_gate_fails_when_plugin_is_stopped(self, printer, tmp_path):
        import shutil
        probe_dir = tmp_path / 'probe'
        shutil.copytree(PROBE_ROOT, probe_dir)
        manifest_path = probe_dir / 'probe.yaml'
        manifest = manifest_path.read_text()
        manifest = manifest.replace(
            '    - classname: BetaTokenDetector\n      path: plugins/beta_token.py\n',
            '',
        )
        manifest_path.write_text(manifest)

        return_code = main([
            'audit',
            '--probe', str(manifest_path),
            '--gate',
            '--json',
        ])
        assert return_code == 1
        data = _leading_json(printer.message)
        assert data['passed'] is False
        assert data['plugins']['BetaTokenDetector']['missed-positive'] == 2

    def test_comparison_baseline_never_passes_gate(self, printer):
        secrets = _build_probe_baseline()
        with mock_named_temporary_file() as f:
            baseline.save_to_file(secrets, f.name)
            f.seek(0)
            return_code = main([
                'audit',
                '--probe', PROBE_MANIFEST,
                '--compare-baseline', f.name,
                '--gate',
                '--json',
            ])

        assert return_code == 1
        data = _leading_json(printer.message)
        assert data['comparison-only'] is True
        assert data['passed'] is False

    def test_gate_requires_probe_manifest(self):
        with pytest.raises(SystemExit):
            main(['audit', '--gate', 'some-baseline.file'])


class TestProbeManifestValidation:
    def test_missing_samples_key(self, tmp_path):
        manifest = tmp_path / 'probe.yaml'
        manifest.write_text('version: 1.0.0\n')
        with pytest.raises(recovery.RecoveryProbeError):
            recovery.load_probe_manifest(str(manifest))

    def test_positive_sample_without_plugins(self, tmp_path):
        manifest = tmp_path / 'probe.yaml'
        manifest.write_text(
            'samples:\n'
            '  - id: x\n'
            '    marker: RP-X-00000000\n'
            '    is_negative: false\n'
            '    expected_plugins: []\n',
        )
        with pytest.raises(recovery.RecoveryProbeError):
            recovery.load_probe_manifest(str(manifest))
