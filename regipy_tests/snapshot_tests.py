import datetime as dt
import json
import os
from tempfile import mktemp
from types import SimpleNamespace

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.plugins.ntuser.recentdocs import RECENT_DOCS_PATH, RecentDocsPlugin
from regipy.plugins.ntuser.typed_paths import TYPED_PATHS_KEY_PATH, TypedPathsPlugin
from regipy.registry import RegistryHive
from regipy.snapshots import Snapshot, compare_snapshots
from regipy_tests.validation.utils import extract_lzma

UTC = dt.timezone.utc
T0 = dt.datetime(2023, 1, 1, tzinfo=UTC)
T1 = dt.datetime(2023, 2, 1, tzinfo=UTC)
T2 = dt.datetime(2023, 3, 1, tzinfo=UTC)


class FakeValue:
    def __init__(self, name, value, value_type="REG_SZ"):
        self.name = name
        self.value = value
        self.value_type = value_type
        self.is_corrupted = False


class FakeKey:
    def __init__(self, last_write_raw, values):
        self.header = SimpleNamespace(last_modified=last_write_raw)
        self._values = values

    def iter_values(self, **kwargs):
        return iter(self._values)


class FakeHive:
    partial_hive_path = None
    hive_type = "ntuser"

    def __init__(self, key=None):
        self._key = key

    def get_key(self, key_path):
        if self._key is None:
            raise RegistryKeyNotFoundException(key_path)
        return self._key


def _snapshot(path, timestamp, name):
    return Snapshot.from_hive(RegistryHive(path), timestamp=timestamp, name=name)


def _one_value(output, key_path, value_name, key_instance=0):
    matches = [
        item
        for item in output["value_timelines"]
        if item["key_path"] == key_path and item["value_name"] == value_name and item["key_instance"] == key_instance
    ]
    assert len(matches) == 1, matches
    return matches[0]


def test_typed_paths_separates_key_clock_from_value_content(shellbags_ntuser, ntuser_hive_2):
    output = compare_snapshots(
        [
            _snapshot(shellbags_ntuser, T0, "bagmru"),
            _snapshot(ntuser_hive_2, T1, "winscp"),
        ]
    )

    url1 = _one_value(output, TYPED_PATHS_KEY_PATH, "url1")
    assert url1["range"]["first_seen"] == T0.isoformat()
    assert url1["range"]["last_seen"] == T1.isoformat()
    assert len(url1["transitions"]) == 1

    transition = url1["transitions"][0]
    assert transition["kind"] == "modified"
    assert transition["from_content"] == "cmd"
    assert transition["to_content"].endswith("w3wp")
    assert transition["interval"]["not_before"] == T0.isoformat()
    assert transition["interval"]["not_after"] == T1.isoformat()
    assert transition["key_clock_context"]["used_as_value_timestamp"] is False
    assert url1["key_clock"]["used_as_value_timestamp"] is False

    key_evidence = [item for item in output["key_evidence"] if item["key_path"] == TYPED_PATHS_KEY_PATH][0]
    assert len(key_evidence["key_clock"]) == 2
    assert key_evidence["key_clock"][0]["evidence"] == "key_nk_last_write"
    assert key_evidence["key_clock_changes"][0]["evidence"] == "key_last_write_changed"


def test_recentdocs_decodes_each_value_and_keeps_transition_interval(shellbags_ntuser, ntuser_hive_2):
    output = compare_snapshots(
        [
            _snapshot(shellbags_ntuser, T0, "bagmru"),
            _snapshot(ntuser_hive_2, T1, "winscp"),
        ]
    )

    document_slot = _one_value(output, RECENT_DOCS_PATH, "1")
    assert document_slot["transitions"][0]["from_content"] == "Python27"
    assert document_slot["transitions"][0]["to_content"] == "סביבת טסטים.docx"
    assert document_slot["transitions"][0]["interval"]["not_after"] == T1.isoformat()

    mru = _one_value(output, RECENT_DOCS_PATH, "MRUListEx")
    assert mru["transitions"][0]["from_content"]["mru_order"][0] == 105
    assert mru["transitions"][0]["to_content"]["mru_order"][0] == 82


def test_delete_and_recreate_produces_breakpoint_and_never_merges_values(shellbags_ntuser, test_data_dir):
    wsl_path = extract_lzma(os.path.join(test_data_dir, "NTUSER-WSL.DAT.xz"))
    try:
        output = compare_snapshots(
            [
                _snapshot(shellbags_ntuser, T0, "before-delete"),
                Snapshot.from_hive(RegistryHive(wsl_path), timestamp=T1, name="deleted"),
                _snapshot(shellbags_ntuser, T2, "after-recreate"),
            ],
            key_paths=[TYPED_PATHS_KEY_PATH],
        )
    finally:
        os.remove(wsl_path)

    assert len(output["breakpoints"]) == 1
    breakpoint = output["breakpoints"][0]
    assert breakpoint["kind"] == "key_deleted_and_recreated"
    assert [item["index"] for item in breakpoint["missing_snapshots"]] == [1]
    assert breakpoint["interval"]["not_before"] == T0.isoformat()
    assert breakpoint["interval"]["not_after"] == T2.isoformat()

    url1_timelines = [
        item for item in output["value_timelines"] if item["key_path"] == TYPED_PATHS_KEY_PATH and item["value_name"] == "url1"
    ]
    assert len(url1_timelines) == 2
    assert [item["key_instance"] for item in url1_timelines] == [0, 1]
    assert url1_timelines[0]["range"]["last_seen"] == T0.isoformat()
    assert url1_timelines[1]["range"]["first_seen"] == T2.isoformat()
    assert url1_timelines[0]["transitions"] == []
    assert url1_timelines[1]["transitions"] == []
    assert url1_timelines[0]["breaks"][0]["kind"] == "before_key_recreation"
    assert url1_timelines[1]["breaks"][0]["kind"] == "after_key_recreation"


def test_parent_only_clock_change_is_a_control_and_does_not_time_the_child():
    parent_only_path = r"\Software\Control\ParentOnly"
    same_timestamp = dt.datetime(2024, 1, 1, tzinfo=UTC)
    later_timestamp = dt.datetime(2024, 2, 1, tzinfo=UTC)

    first = Snapshot.from_hive(
        FakeHive(FakeKey(132000000000000000, [FakeValue("url1", "same")])),
        timestamp=same_timestamp,
        name="control-0",
    )
    second = Snapshot.from_hive(
        FakeHive(FakeKey(133000000000000000, [FakeValue("url1", "same")])),
        timestamp=later_timestamp,
        name="control-1",
    )

    output = compare_snapshots([first, second], key_paths=[parent_only_path])

    assert len(output["key_only_changes"]) == 1
    control = output["key_only_changes"][0]
    assert control["control"] is True
    assert control["value_changes"] == []
    assert control["proves"] == ["the_parent_key_last_write_changed"]
    assert "that_any_tracked_value_changed" in control["does_not_prove"]
    assert control["interval"]["not_before"] == same_timestamp.isoformat()
    assert control["interval"]["not_after"] == later_timestamp.isoformat()

    value = output["value_timelines"][0]
    assert len(value["segments"]) == 1
    assert value["transitions"] == []
    assert value["range"]["first_seen"] == same_timestamp.isoformat()
    assert value["range"]["last_seen"] == later_timestamp.isoformat()
    assert value["range"]["unchanged"] is True
    assert value["key_clock"]["changed"] is True
    assert value["key_clock"]["used_as_value_timestamp"] is False


def test_single_hive_plugin_queries_still_work(shellbags_ntuser):
    hive = RegistryHive(shellbags_ntuser)

    typed_paths = TypedPathsPlugin(hive, as_json=True)
    typed_paths.run()
    assert set(typed_paths.entries) == {"last_write", "entries"}
    assert len(typed_paths.entries["entries"]) == 16
    assert typed_paths.entries["entries"][0] == {"url1": "cmd"}

    recent_docs = RecentDocsPlugin(hive, as_json=True)
    recent_docs.run()
    assert isinstance(recent_docs.entries, list)
    assert recent_docs.entries[0]["key_path"] == RECENT_DOCS_PATH
    assert "last_write" in recent_docs.entries[0]
    assert "documents" in recent_docs.entries[0]
    assert "value_timelines" not in recent_docs.entries[0]


def test_single_snapshot_is_observation_only(shellbags_ntuser):
    output = compare_snapshots(
        [_snapshot(shellbags_ntuser, T0, "only")],
        key_paths=[TYPED_PATHS_KEY_PATH],
    )

    assert len(output["snapshots"]) == 1
    url1 = _one_value(output, TYPED_PATHS_KEY_PATH, "url1")
    assert len(url1["segments"]) == 1
    assert url1["segments"][0]["observation_count"] == 1
    assert url1["transitions"] == []
    assert url1["range"]["unchanged"] is True


def test_cli_snapshot_timeline(shellbags_ntuser, ntuser_hive_2):
    from click.testing import CliRunner

    from regipy.cli import snapshot_timeline

    output_path = mktemp()
    try:
        result = CliRunner().invoke(
            snapshot_timeline,
            [
                f"{shellbags_ntuser}@{T0.isoformat()}",
                f"{ntuser_hive_2}@{T1.isoformat()}",
                "-p",
                "typed_paths",
                "-o",
                output_path,
            ],
        )
        assert result.exit_code == 0
        with open(output_path) as output_file:
            evidence = json.load(output_file)
        assert evidence["schema_version"] == 1
        assert len(evidence["value_timelines"]) == 16
        assert evidence["snapshots"][0]["observed_at"] == T0.isoformat()
    finally:
        os.remove(output_path)
