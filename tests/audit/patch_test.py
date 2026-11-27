import json
import textwrap

from detect_secrets import main as main_module
from detect_secrets.core import baseline
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory
from testing.mocks import mock_named_temporary_file
from testing.mocks import mock_printer


def test_audit_patch_cli_reports_movement_and_new_alert_count():
    patch = textwrap.dedent("""\
        diff --git a/config.py b/config.py
        index 1111111..2222222 100644
        --- a/config.py
        +++ b/config.py
        @@ -1,4 +1,5 @@
         unrelated = 'value'
        -moved = 'AKIAMOVED00000000001'
         stable = 'stable-value'
         trailing = 'another-value'
        +moved = 'AKIAMOVED00000000001'
        +added = 'AKIANEW0000000000002'
        """)
    secret = potential_secret_factory(
        type='AWS Access Key',
        filename='config.py',
        secret='AKIAMOVED00000000001',
        line_number=2,
    )

    with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}], 'filters_used': []}), \
        mock_named_temporary_file(suffix='.diff') as patch_file, \
        mock_named_temporary_file() as baseline_file, \
        mock_printer(main_module) as printer:
        patch_file.write(patch.encode())
        patch_file.seek(0)
        baseline_data = {
            'version': '1.5.0',
            'plugins_used': [{'name': 'AWSKeyDetector'}],
            'filters_used': [],
            'results': {'config.py': [secret.json()]},
        }
        baseline.save_to_file(baseline_data, baseline_file.name)
        baseline_file.seek(0)

        exit_code = main_module.main([
            'audit',
            baseline_file.name,
            '--patch',
            patch_file.name,
            '--json',
        ])

    assert exit_code == 1
    output = json.loads(printer.message)
    assert output['total_new_secrets'] == 1
    assert output['results']['new'][0]['hashed_secret'] == secret.hash_secret(
        'AKIANEW0000000000002',
    )
    assert output['results']['moved'][0]['moved_from']['line_number'] == 2
