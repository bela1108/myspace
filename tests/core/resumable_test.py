import json
import os

import pytest

from detect_secrets.core import scan
from detect_secrets.core.resumable import get_checkpoint_invalidation_reason
from detect_secrets.core.resumable import REASON_SETTINGS_CHANGED
from detect_secrets.core.resumable import REASON_SOURCE_CHANGED
from detect_secrets.core.resumable import run_resumable_scan
from detect_secrets.core.resumable import SimulatedCheckpointInterruption
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import CheckpointInvalidError
from detect_secrets.settings import transient_settings


PLUGIN_SETTINGS = {
    'plugins_used': [
        {'name': 'BasicAuthDetector'},
    ],
}

SOURCE = (
    'first = https://alice:letmein1@example.com/甲\n'
    '说明 = 多字节字符会被分段\n'
    '# pragma: allowlist nextline secret\n'
    'allowed = https://bob:allowed1@example.com/乙\n'
    'second = https://carol:secretone@example.com/丙\n'
    'third = https://dave:secrettwo@example.com/丁\n'
    '最后一行 = 没有换行符'
)


def _direct_collection(filename):
    collection = SecretsCollection()
    for secret in scan.scan_file(filename):
        collection[secret.filename].add(secret)
    return collection


def _result_log_lines(filename):
    with open(filename, 'rb') as f:
        return [line for line in f.read().splitlines() if line.strip()]


def _read_source_fixture(tmp_path, name='scan-target.txt', content=SOURCE):
    source = tmp_path / name
    source.write_text(content, encoding='utf-8')
    return source, tmp_path / 'scan.checkpoint.json', tmp_path / 'scan.results.jsonl'


def _checkpoint_payload(filename):
    with open(filename, encoding='utf-8') as f:
        return json.load(f)


@pytest.mark.parametrize('batch_size', [1, 2, 3, 5, 8, 13, 1024])
def test_matches_direct_scan_across_batch_boundaries(tmp_path, batch_size):
    source, checkpoint, result_log = _read_source_fixture(tmp_path)

    with transient_settings(PLUGIN_SETTINGS):
        expected = _direct_collection(str(source))
        actual = run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=batch_size,
            result_path=str(result_log),
        )

    assert actual.json() == expected.json()
    assert len(_result_log_lines(str(result_log))) == len(expected)

    payload = _checkpoint_payload(str(checkpoint))
    assert set(payload['cursor']) == {'offset', 'line_number', 'output_offset'}
    assert 'results' not in payload
    assert 'hashed_secret' not in json.dumps(payload)

    checkpoint_text = checkpoint.read_text(encoding='utf-8')
    result_text = result_log.read_text(encoding='utf-8')
    for plaintext in ('secretone', 'secrettwo', 'https://', '多字节'):
        assert plaintext not in checkpoint_text
        assert plaintext not in result_text


@pytest.mark.parametrize('hook_name', ['before_checkpoint', 'after_checkpoint'])
def test_interruption_around_checkpoint_commits_exactly_once(tmp_path, hook_name):
    source, checkpoint, result_log = _read_source_fixture(tmp_path)

    def stop(_checkpoint):
        raise SimulatedCheckpointInterruption(hook_name)

    with transient_settings(PLUGIN_SETTINGS):
        with pytest.raises(SimulatedCheckpointInterruption):
            run_resumable_scan(
                str(source),
                str(checkpoint),
                batch_size=32,
                result_path=str(result_log),
                **{hook_name: stop},
            )

        if hook_name == 'after_checkpoint':
            assert checkpoint.exists()
        else:
            # Results may be appended before the checkpoint commit. They are
            # uncommitted and must be discarded on resume.
            assert not checkpoint.exists() or _checkpoint_payload(str(checkpoint))

        recovered = run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=32,
            result_path=str(result_log),
        )
        expected = _direct_collection(str(source))

    assert recovered.json() == expected.json()
    assert len(_result_log_lines(str(result_log))) == len(expected)


def test_source_change_invalidates_cursor_even_with_same_size_and_mtime(tmp_path):
    source, checkpoint, result_log = _read_source_fixture(tmp_path)

    with transient_settings(PLUGIN_SETTINGS):
        run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=32,
            result_path=str(result_log),
        )

        original = source.read_bytes()
        stat = source.stat()
        replacement = original.replace(b'secretone', b'secrettwo')
        assert len(replacement) == len(original)
        source.write_bytes(replacement)
        os.utime(str(source), ns=(stat.st_atime_ns, stat.st_mtime_ns))

        with pytest.raises(CheckpointInvalidError) as error:
            run_resumable_scan(
                str(source),
                str(checkpoint),
                batch_size=32,
                result_path=str(result_log),
            )

        assert error.value.reason == REASON_SOURCE_CHANGED
        assert get_checkpoint_invalidation_reason(
            str(checkpoint),
            str(source),
        ) == REASON_SOURCE_CHANGED


def test_settings_change_invalidates_cursor(tmp_path):
    source, checkpoint, result_log = _read_source_fixture(tmp_path)

    with transient_settings(PLUGIN_SETTINGS):
        run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=32,
            result_path=str(result_log),
        )

    with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}]}):
        with pytest.raises(CheckpointInvalidError) as error:
            run_resumable_scan(
                str(source),
                str(checkpoint),
                batch_size=32,
                result_path=str(result_log),
            )

        assert error.value.reason == REASON_SETTINGS_CHANGED


def test_restart_on_invalid_checkpoint_scans_new_source(tmp_path):
    source, checkpoint, result_log = _read_source_fixture(tmp_path)

    with transient_settings(PLUGIN_SETTINGS):
        run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=32,
            result_path=str(result_log),
        )

        source.write_text(
            'replaced = https://eve:newsecret@example.com/戊\n',
            encoding='utf-8',
        )
        restarted = run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=32,
            result_path=str(result_log),
            restart_on_invalid=True,
        )
        expected = _direct_collection(str(source))

    assert restarted.json() == expected.json()
    assert len(_result_log_lines(str(result_log))) == len(expected)


def test_transformed_config_file_remains_resumable(tmp_path):
    content = (
        '[section]\n'
        '说明 = 多字节\n'
        'link = https://alice:letmein1@example.com/甲\n'
        'link_two = https://bob:secretone@example.com/乙\n'
    )

    for index, batch_size in enumerate((1, 7, 64)):
        case_dir = tmp_path / str(index)
        case_dir.mkdir()
        source, checkpoint, result_log = _read_source_fixture(
            case_dir,
            name='config.ini',
            content=content,
        )

        with transient_settings(PLUGIN_SETTINGS):
            expected = _direct_collection(str(source))
            actual = run_resumable_scan(
                str(source),
                str(checkpoint),
                batch_size=batch_size,
                result_path=str(result_log),
            )

        assert actual.json() == expected.json()


def test_default_result_log_recovers_committed_results(tmp_path):
    source = tmp_path / 'default-log.txt'
    source.write_text(SOURCE, encoding='utf-8')
    checkpoint = tmp_path / 'default.checkpoint.json'

    def stop(_checkpoint):
        raise SimulatedCheckpointInterruption('after checkpoint')

    with transient_settings(PLUGIN_SETTINGS):
        with pytest.raises(SimulatedCheckpointInterruption):
            list(
                scan.scan_file_resumable(
                    str(source),
                    str(checkpoint),
                    batch_size=32,
                    after_checkpoint=stop,
                ),
            )

        recovered = list(
            scan.scan_file_resumable(
                str(source),
                str(checkpoint),
                batch_size=32,
            ),
        )
        expected = _direct_collection(str(source))

    assert len(recovered) == len(expected)
    assert {secret.secret_hash for secret in recovered} == {
        item['hashed_secret']
        for items in expected.json().values()
        for item in items
    }


@pytest.mark.parametrize(
    'crash_option',
    ['crash_before_checkpoint_at', 'crash_after_checkpoint_at'],
)
def test_built_in_checkpoint_interruption_knobs(tmp_path, crash_option):
    source, checkpoint, result_log = _read_source_fixture(tmp_path)

    with transient_settings(PLUGIN_SETTINGS):
        with pytest.raises(SimulatedCheckpointInterruption):
            run_resumable_scan(
                str(source),
                str(checkpoint),
                batch_size=32,
                result_path=str(result_log),
                **{crash_option: 1},
            )

        recovered = run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=32,
            result_path=str(result_log),
        )
        expected = _direct_collection(str(source))

    assert recovered.json() == expected.json()
    assert len(_result_log_lines(str(result_log))) == len(expected)


def test_missing_source_reports_source_missing(tmp_path):
    source, checkpoint, result_log = _read_source_fixture(tmp_path)

    with transient_settings(PLUGIN_SETTINGS):
        run_resumable_scan(
            str(source),
            str(checkpoint),
            batch_size=32,
            result_path=str(result_log),
        )

    source.unlink()
    assert get_checkpoint_invalidation_reason(
        str(checkpoint),
        str(source),
    ) == 'source_missing'
