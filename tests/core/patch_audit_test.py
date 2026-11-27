import textwrap

from detect_secrets.core import baseline
from detect_secrets.core.patch_audit import audit_patch
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory
from testing.mocks import mock_named_temporary_file


MOVED_SECRET = 'AKIAMOVED00000000001'
NEW_SECRET = 'AKIANEW0000000000002'
DUPLICATE_SECRET = 'AKIADUPLIC0000000001'


def test_audit_patch_counts_only_added_secret_and_records_movement():
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

    with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}], 'filters_used': []}):
        known_secret = potential_secret_factory(
            type='AWS Access Key',
            filename='config.py',
            secret=MOVED_SECRET,
            line_number=2,
        )
        known_secrets = SecretsCollection()
        known_secrets['config.py'].add(known_secret)
        report = audit_patch(patch, baseline=known_secrets)

    assert report.total_new_secrets == 1
    assert [item.secret.secret_hash for item in report.new_secrets] == [
        potential_secret_factory(
            type='AWS Access Key',
            filename='config.py',
            secret=NEW_SECRET,
        ).secret_hash,
    ]
    assert len(report.moved_secrets) == 1
    moved = report.moved_secrets[0]
    assert moved.secret.line_number == 4
    assert moved.old_location is not None
    assert moved.old_location.line_number == 2
    assert moved.secret.secret_hash == moved.old_location.secret_hash
    assert not report.ambiguous_secrets


def test_audit_patch_keeps_duplicate_matches_ambiguous():
    patch = textwrap.dedent("""\
        diff --git a/config.py b/config.py
        index 1111111..2222222 100644
        --- a/config.py
        +++ b/config.py
        @@ -1,5 +1,5 @@
        -first = 'AKIADUPLIC0000000001'
        -second = 'AKIADUPLIC0000000001'
         stable = 'stable-value'
         trailing = 'another-value'
         final = 'last-value'
        +first = 'AKIADUPLIC0000000001'
        +second = 'AKIADUPLIC0000000001'
        """)

    with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}], 'filters_used': []}):
        report = audit_patch(patch)

    assert report.total_new_secrets == 0
    assert not report.moved_secrets
    assert len(report.ambiguous_secrets) == 2
    assert {
        item.secret.line_number
        for item in report.ambiguous_secrets
    } == {4, 5}
    for item in report.ambiguous_secrets:
        assert [candidate.line_number for candidate in item.candidates] == [1, 2]


def test_audit_patch_reports_removed_occurrence_without_new_alert():
    patch = textwrap.dedent("""\
        diff --git a/config.py b/config.py
        index 1111111..2222222 100644
        --- a/config.py
        +++ b/config.py
        @@ -1,3 +1,2 @@
         unrelated = 'value'
        -removed = 'AKIAREMOVE0000000002'
         stable = 'stable-value'
        """)

    with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}], 'filters_used': []}):
        report = audit_patch(patch)

    assert report.total_new_secrets == 0
    assert len(report.removed_secrets) == 1
    assert report.removed_secrets[0].secret.line_number == 2


def test_audit_patch_does_not_match_across_hunk_ranges():
    patch = textwrap.dedent("""\
        diff --git a/config.py b/config.py
        index 1111111..2222222 100644
        --- a/config.py
        +++ b/config.py
        @@ -1,3 +1,3 @@
         stable = 'stable-value'
        -old = 'AKIASECRET0000000001'
         other = 'other-value'
        @@ -20,3 +20,3 @@
         after = 'after-value'
         ending = 'ending-value'
        +new = 'AKIASECRET0000000001'
        """)

    with transient_settings({'plugins_used': [{'name': 'AWSKeyDetector'}], 'filters_used': []}):
        report = audit_patch(patch)

    assert report.total_new_secrets == 1
    assert not report.moved_secrets
    assert len(report.removed_secrets) == 1


def test_baseline_format_remains_readable_without_patch_fields():
    secret = potential_secret_factory(
        type='AWS Access Key',
        filename='config.py',
        secret=MOVED_SECRET,
        line_number=2,
    )
    data = {
        'version': '1.5.0',
        'plugins_used': [{'name': 'AWSKeyDetector'}],
        'filters_used': [],
        'results': {'config.py': [secret.json()]},
    }

    with mock_named_temporary_file() as f:
        baseline.save_to_file(data, f.name)
        f.seek(0)
        loaded = baseline.load(baseline.load_from_file(f.name), f.name)

    assert secret in loaded['config.py']
    loaded_secret = next(iter(loaded['config.py']))
    assert set(loaded_secret.json()) == {
        'type',
        'filename',
        'hashed_secret',
        'is_verified',
        'line_number',
    }
