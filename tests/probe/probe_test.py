import json
import os
import tempfile

import pytest

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.exceptions import InvalidFile
from detect_secrets.main import main
from detect_secrets.probe import ProbeManifest
from detect_secrets.probe import TestSample
from detect_secrets.probe import run_probe
from detect_secrets.settings import configure_settings_from_baseline
from detect_secrets.settings import get_settings
from tests.probe.testing_plugins import AlphaTestDetector
from tests.probe.testing_plugins import BetaTestDetector


MANIFEST = {
    'samples': [
        {
            'id': 'alpha-one',
            'value': 'token=alpha-marker-one',
            'expected_plugins': ['AlphaTestDetector'],
        },
        {
            'id': 'alpha-two',
            'value': 'token=alpha-marker-two',
            'expected_plugins': ['AlphaTestDetector'],
        },
        {
            'id': 'beta-one',
            'value': 'token=beta-marker-one',
            'expected_plugins': ['BetaTestDetector'],
        },
        {
            'id': 'beta-two',
            'value': 'token=beta-marker-two',
            'expected_plugins': ['BetaTestDetector'],
        },
    ],
}


def workspace_temp_file(mode, suffix):
    return tempfile.NamedTemporaryFile(
        mode=mode,
        suffix=suffix,
        dir=os.getcwd(),
        delete=False,
    )


@pytest.fixture
def manifest_file():
    handle = workspace_temp_file(mode='w+', suffix='.json')
    json.dump(MANIFEST, handle)
    handle.flush()
    try:
        yield handle.name
    finally:
        handle.close()
        os.unlink(handle.name)


@pytest.fixture
def registered_plugins():
    mapping = get_mapping_from_secret_type_to_class()
    mapping[AlphaTestDetector.secret_type] = AlphaTestDetector
    mapping[BetaTestDetector.secret_type] = BetaTestDetector
    yield
    get_mapping_from_secret_type_to_class.cache_clear()


def enable_only(*plugin_classes):
    configure_settings_from_baseline(
        {
            'plugins_used': [
                {'name': plugin_class.__name__}
                for plugin_class in plugin_classes
            ],
        },
    )


def test_healthy_run_accounts_each_plugin_separately(
    registered_plugins,
    manifest_file,
):
    enable_only(AlphaTestDetector, BetaTestDetector)
    manifest = ProbeManifest.load_from_file(manifest_file)

    report = run_probe(manifest.samples)

    assert report.all_healthy is True
    alpha = report.contributions['AlphaTestDetector']
    beta = report.contributions['BetaTestDetector']
    assert alpha.true_positives == 2
    assert alpha.shared_true_positives == 0
    assert alpha.missed_positives == 0
    assert alpha.ignored_negatives == 2
    assert alpha.false_positives == 0
    assert beta.true_positives == 2
    assert beta.ignored_negatives == 2
    assert report.failures == []


def test_disabled_plugin_cannot_hide_behind_healthy_totals(
    registered_plugins,
    manifest_file,
):
    enable_only(AlphaTestDetector, BetaTestDetector)
    get_settings().disable_plugins('BetaTestDetector')
    manifest = ProbeManifest.load_from_file(manifest_file)

    report = run_probe(manifest.samples)

    assert report.all_healthy is False

    alpha = report.contributions['AlphaTestDetector']
    assert alpha.is_healthy is True
    assert alpha.true_positives == 2
    assert alpha.ignored_negatives == 2

    beta = report.contributions['BetaTestDetector']
    assert beta.enabled is False
    assert beta.missed_positives == 2
    assert beta.missed_sample_ids == ['beta-one', 'beta-two']
    assert beta.is_healthy is False

    failures = ' '.join(report.failures)
    assert 'BetaTestDetector' in failures
    assert 'beta-one' in failures
    assert 'beta-two' in failures
    assert report.json()['release-verified'] is False


def test_shared_positive_is_counted_for_each_owner(registered_plugins):
    enable_only(AlphaTestDetector, BetaTestDetector)
    manifest = ProbeManifest(
        [
            TestSample(
                id='shared-marker',
                value='alpha-marker-one plus beta-marker-one',
                expected_plugins=[
                    'AlphaTestDetector',
                    'BetaTestDetector',
                ],
            ),
        ],
    )

    report = run_probe(manifest.samples)

    assert report.all_healthy is True
    assert report.contributions['AlphaTestDetector'].shared_true_positives == 1
    assert report.contributions['BetaTestDetector'].shared_true_positives == 1
    assert report.contributions['AlphaTestDetector'].true_positives == 0
    assert report.contributions['BetaTestDetector'].true_positives == 0


def test_flagging_another_plugins_marker_is_a_false_positive(
    registered_plugins,
):
    enable_only(AlphaTestDetector, BetaTestDetector)
    manifest = ProbeManifest(
        [
            TestSample(
                id='alpha-only',
                value='alpha-marker-one',
                expected_plugins=['AlphaTestDetector'],
            ),
        ],
    )

    report = run_probe(manifest.samples)

    alpha = report.contributions['AlphaTestDetector']
    beta = report.contributions['BetaTestDetector']
    assert alpha.true_positives == 1
    assert alpha.false_positives == 0
    assert beta.true_positives == 0
    assert beta.ignored_negatives == 1
    assert beta.false_positives == 0


def test_cli_returns_zero_when_all_plugins_healthy(
    registered_plugins,
    manifest_file,
    printer,
):
    enable_only(AlphaTestDetector, BetaTestDetector)

    exit_code = main(['probe', manifest_file, '--json'])

    assert exit_code == 0
    payload = json.loads(printer.message)
    assert payload['release-verified'] is True
    assert set(payload['plugins'].keys()) == {
        'AlphaTestDetector',
        'BetaTestDetector',
    }


def test_cli_blocks_release_when_one_plugin_disabled(
    registered_plugins,
    manifest_file,
    printer,
):
    enable_only(AlphaTestDetector, BetaTestDetector)
    get_settings().disable_plugins('BetaTestDetector')

    exit_code = main(['probe', manifest_file, '--json'])

    assert exit_code == 1
    payload = json.loads(printer.message)
    assert payload['release-verified'] is False
    assert payload['plugins']['BetaTestDetector']['enabled'] is False
    assert payload['plugins']['BetaTestDetector']['positives']['missed'] == 2


@pytest.fixture
def baseline_factory():
    from detect_secrets.core.potential_secret import PotentialSecret

    def write(secrets):
        baseline = {
            'version': '1.5.0',
            'plugins_used': [{'name': 'AlphaTestDetector'}],
            'filters_used': [],
            'results': {},
            'generated_at': '2026-01-01T00:00:00.000000Z',
        }
        for filename, secret_type, secret_value in secrets:
            baseline['results'].setdefault(filename, []).append(
                {
                    'type': secret_type,
                    'hashed_secret': PotentialSecret.hash_secret(secret_value),
                    'line_number': 1,
                    'is_verified': True,
                },
            )
        handle = workspace_temp_file(mode='w+', suffix='.baseline')
        json.dump(baseline, handle)
        handle.flush()
        return handle

    return write


def test_baseline_comparison_matches_samples_by_identity(
    registered_plugins,
    manifest_file,
    baseline_factory,
):
    from detect_secrets.probe import compare_against_baseline

    manifest = ProbeManifest.load_from_file(manifest_file)
    alpha_sample = manifest.get_sample('alpha-one')
    baseline_handle = baseline_factory(
        [
            (
                alpha_sample.filename,
                AlphaTestDetector.secret_type,
                alpha_sample.value,
            ),
        ],
    )

    try:
        comparison = compare_against_baseline(
            manifest.samples,
            baseline_handle.name,
        )
    finally:
        baseline_handle.close()
        os.unlink(baseline_handle.name)

    assert comparison['reference-only'] is True
    by_id = {entry['id']: entry for entry in comparison['samples']}
    assert by_id['alpha-one']['found-in-baseline'] is True
    assert by_id['alpha-one']['baseline-plugins'] == [
        AlphaTestDetector.secret_type,
    ]
    assert by_id['beta-one']['found-in-baseline'] is False
    assert by_id['beta-one']['baseline-plugins'] == []


def test_baseline_reference_does_not_authorize_release(
    registered_plugins,
    manifest_file,
    baseline_factory,
    printer,
):
    enable_only(AlphaTestDetector, BetaTestDetector)
    get_settings().disable_plugins('BetaTestDetector')
    manifest = ProbeManifest.load_from_file(manifest_file)
    beta_sample = manifest.get_sample('beta-one')
    baseline_handle = baseline_factory(
        [
            (
                beta_sample.filename,
                BetaTestDetector.secret_type,
                beta_sample.value,
            ),
        ],
    )

    try:
        exit_code = main(
            [
                'probe',
                manifest_file,
                '--reference-baseline',
                baseline_handle.name,
                '--json',
            ],
        )
    finally:
        baseline_handle.close()
        os.unlink(baseline_handle.name)

    assert exit_code == 1
    payload = json.loads(printer.message)
    assert payload['release-verified'] is False
    assert payload['baseline-reference']['reference-only'] is True


def test_invalid_manifest_is_rejected():
    handle = workspace_temp_file(mode='w+', suffix='.json')
    json.dump({'samples': [{'id': 'broken'}]}, handle)
    handle.flush()
    try:
        with pytest.raises(InvalidFile):
            ProbeManifest.load_from_file(handle.name)
    finally:
        handle.close()
        os.unlink(handle.name)


def test_duplicate_sample_ids_are_rejected():
    handle = workspace_temp_file(mode='w+', suffix='.json')
    payload = {
        'samples': [
            {
                'id': 'dup',
                'value': 'alpha-marker-one',
                'expected_plugins': ['AlphaTestDetector'],
            },
            {
                'id': 'dup',
                'value': 'beta-marker-one',
                'expected_plugins': ['BetaTestDetector'],
            },
        ],
    }
    json.dump(payload, handle)
    handle.flush()
    try:
        with pytest.raises(InvalidFile):
            ProbeManifest.load_from_file(handle.name)
    finally:
        handle.close()
        os.unlink(handle.name)
