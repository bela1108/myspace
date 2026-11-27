import os
import textwrap
from pathlib import Path

import pytest

from detect_secrets.core import scan
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from detect_secrets.util import git
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


class TestGetFilesToScan:
    @staticmethod
    def test_should_scan_specific_non_tracked_file(non_tracked_file):
        assert list(scan.get_files_to_scan(non_tracked_file.name, should_scan_all_files=False))

    @staticmethod
    def test_should_scan_tracked_files_in_directory(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) not in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=False,
                ),
            )
        )

    @staticmethod
    def test_should_scan_all_files_in_directory_if_flag_is_provided(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=True,
                ),
            )
        )

    @staticmethod
    def test_handles_each_path_separately(non_tracked_file):
        results = list(
            scan.get_files_to_scan(
                non_tracked_file.name,
                'test_data/short_files',
            ),
        )

        # This implies that the test_data/short_files directory is scanned, because otherwise,
        # it would only be one file. However, at the same time, this test case isn't fragile to
        # additions to this directory.
        assert len(results) > 2

    @staticmethod
    def test_handles_multiple_directories():
        directories = [Path('test_data/short_files'), Path('test_data/files')]
        results = list(scan.get_files_to_scan(*directories))

        for prefix in directories:
            assert len(list(filter(lambda x: x.startswith(str(prefix)), results))) > 1

    @staticmethod
    @pytest.fixture(autouse=True, scope='class')
    def non_tracked_file():
        with mock_named_temporary_file(
            prefix=os.path.join(git.get_root_directory(), 'test_data/'),
        ) as f:
            f.write(b'content does not matter')
            f.seek(0)

            yield f


class TestScanFile:
    @staticmethod
    def test_handles_broken_yaml_gracefully():
        with mock_named_temporary_file(suffix='.yaml') as f:
            f.write(
                textwrap.dedent("""
                metadata:
                    name: {{ .values.name }}
                """)[1:].encode(),
            )
            f.seek(0)

            assert not list(scan.scan_file(f.name))

    @staticmethod
    def test_handles_binary_files_gracefully():
        # NOTE: This suffix needs to be something that isn't in the known file types, as determined
        # by `detect_secrets.util.filetype.determine_file_type`.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86')
            f.seek(0)

            assert not list(scan.scan_file(f.name))


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {
                'name': 'BasicAuthDetector',
            },
        ],
    }):
        yield


class TestScanDiff:
    diff = textwrap.dedent("""\
        diff --git a/config.py b/config.py
        index 1111111..2222222 100644
        --- a/config.py
        +++ b/config.py
        @@ -1,3 +1,3 @@
         stable = 'stable-value'
        -removed = 'AKIAREMOVE0000000002'
        +added = 'AKIAADDED00000000003'
         trailing = 'another-value'
        """)

    def test_scans_added_lines_with_target_line_numbers(self):
        with transient_settings({
            'plugins_used': [{'name': 'AWSKeyDetector'}],
            'filters_used': [],
        }):
            get_settings().disable_filters('detect_secrets.filters.common.is_invalid_file')
            secrets = list(scan.scan_diff(self.diff))

        assert len(secrets) == 1
        assert secrets[0].line_number == 2
        assert secrets[0].secret_value == 'AKIAADDED00000000003'

    def test_scans_removed_lines_with_source_line_numbers(self):
        with transient_settings({
            'plugins_used': [{'name': 'AWSKeyDetector'}],
            'filters_used': [],
        }):
            get_settings().disable_filters('detect_secrets.filters.common.is_invalid_file')
            secrets = list(scan.scan_diff(self.diff, only_added=False))

        assert len(secrets) == 1
        assert secrets[0].line_number == 2
        assert secrets[0].secret_value == 'AKIAREMOVE0000000002'
