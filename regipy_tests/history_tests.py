import datetime as dt
from types import SimpleNamespace

from regipy.history import (
    analyze_key_history,
    analyze_recentdocs_history,
    analyze_typed_paths_history,
    compare_snapshots,
)
from regipy.plugins.ntuser.recentdocs import RECENT_DOCS_PATH, RecentDocsPlugin
from regipy.plugins.ntuser.typed_paths import TYPED_PATHS_KEY_PATH, TypedPathsPlugin
from regipy.registry import RegistryHive

KEY = r"\Demo\Key"
T1 = "2024-01-01T00:00:00+00:00"
T2 = "2024-01-02T00:00:00+00:00"
T3 = "2024-01-03T00:00:00+00:00"
KEY_TIME_1 = "2023-12-31T00:00:00+00:00"
KEY_TIME_2 = "2024-01-01T12:00:00+00:00"


def _dt(value):
    return dt.datetime.fromisoformat(value)


def _snapshot(observed_at, record, key_path=KEY):
    return {"observed_at": observed_at, "keys": {key_path: record}}


def test_parent_key_change_does_not_create_a_value_time():
    snapshots = [
        _snapshot(T1, {"last_write": KEY_TIME_1, "values": {"0": "alpha"}}),
        _snapshot(T2, {"last_write": KEY_TIME_2, "values": {"0": "alpha"}}),
    ]

    history = analyze_key_history(snapshots, KEY)

    assert len(history.generations) == 1
    assert len(history.value_timelines) == 1
    timeline = history.value_timelines[0]
    assert timeline.first_observed == _dt(T1)
    assert timeline.last_observed == _dt(T2)
    # The value content was already observed at T1. The new key LastWrite at
    # T2 is key-level evidence only and must not become the value start time.
    assert timeline.valid_from_latest == _dt(T1)
    assert timeline.valid_from != _dt(T2)
    assert timeline.parent_key_changed_only is True
    assert [clock["last_write"] for clock in history.key_clock] == [KEY_TIME_1, KEY_TIME_2]

    comparisons = history.parent_only_changes
    assert len(comparisons) == 1
    assert comparisons[0]["type"] == "parent_key_only"
    assert comparisons[0]["value_content_changed"] is False
    assert comparisons[0]["proves"] == ["parent_key_last_write_changed_between_observations"]


def test_delete_and_recreate_same_name_key_breaks_the_timeline():
    snapshots = [
        _snapshot(T1, {"last_write": KEY_TIME_1, "values": {"0": "old"}}),
        {"observed_at": T2, "keys": {}},
        _snapshot(T3, {"last_write": T3, "values": {"0": "new"}}),
    ]

    history = analyze_key_history(snapshots, KEY)

    assert len(history.generations) == 2
    assert len(history.breakpoints) == 1
    assert history.breakpoints[0]["reason"] == "key_absent"
    assert history.breakpoints[0]["classification"] == "key_deleted_and_recreated"

    old = next(item for item in history.value_timelines if item.content == "old")
    new = next(item for item in history.value_timelines if item.content == "new")
    assert old.generation == 0
    assert new.generation == 1
    assert old.valid_to_latest == _dt(T2)
    assert new.valid_from_earliest == _dt(T2)
    assert new.valid_from_latest == _dt(T3)
    # The old incarnation must not be joined to the new value.
    assert old.content_hash != new.content_hash


def test_last_write_regression_is_a_recreation_breakpoint():
    snapshots = [
        _snapshot(T1, {"last_write": "2024-01-01T00:00:00+00:00", "values": {"0": "alpha"}}),
        _snapshot(T2, {"last_write": "2023-01-01T00:00:00+00:00", "values": {"0": "alpha"}}),
    ]

    history = analyze_key_history(snapshots, KEY)

    assert len(history.generations) == 2
    assert history.breakpoints[0]["reason"] == "last_write_regressed"
    assert len(history.value_timelines) == 2
    assert [item.generation for item in history.value_timelines] == [0, 1]


def test_recentdocs_value_evidence_keeps_key_clock_separate():
    document_a = "alpha.txt".encode("utf-16-le") + bytes([0, 0])
    document_b = "beta.txt".encode("utf-16-le") + bytes([0, 0])
    snapshots = [
        _snapshot(T1, {"last_write": KEY_TIME_1, "values": {"0": document_a}}, RECENT_DOCS_PATH),
        _snapshot(T2, {"last_write": KEY_TIME_2, "values": {"0": document_b}}, RECENT_DOCS_PATH),
    ]

    report = analyze_recentdocs_history(snapshots)
    timelines = report.value_timelines
    assert len(timelines) == 2
    assert [item.metadata["document_name"] for item in timelines] == ["alpha.txt", "beta.txt"]
    assert [item.generation for item in timelines] == [0, 0]
    assert timelines[0].valid_to_latest == _dt(T2)
    assert timelines[1].valid_from_earliest == _dt(T1)
    assert timelines[1].valid_from_latest == _dt(T2)
    assert report.key_histories[RECENT_DOCS_PATH].key_clock[1]["last_write"] == KEY_TIME_2


def test_typed_paths_history_report():
    snapshots = [
        _snapshot(T1, {"last_write": KEY_TIME_1, "values": {"url1": "cmd"}}, TYPED_PATHS_KEY_PATH),
        _snapshot(T2, {"last_write": KEY_TIME_2, "values": {"url1": "cmd", "url2": "powershell"}}, TYPED_PATHS_KEY_PATH),
    ]

    report = analyze_typed_paths_history(snapshots)

    assert report.key_paths == [TYPED_PATHS_KEY_PATH]
    url1 = next(item for item in report.value_timelines if item.value_name == "url1")
    url2 = next(item for item in report.value_timelines if item.value_name == "url2")
    assert url1.metadata["artifact"] == "typed_paths"
    assert url1.content == "cmd"
    assert url1.valid_from_latest == _dt(T1)
    assert url2.content == "powershell"
    assert url2.valid_from_earliest == _dt(T1)
    assert url2.valid_from_latest == _dt(T2)


def test_snapshot_mapping_with_observation_times_is_supported():
    snapshots = {
        T1: {KEY: {"last_write": KEY_TIME_1, "values": {"0": "alpha"}}},
        T2: {KEY: {"last_write": KEY_TIME_2, "values": {"0": "alpha"}}},
    }

    report = compare_snapshots(snapshots, [KEY])
    assert report.value_timelines[0].first_observed == _dt(T1)
    assert report.value_timelines[0].last_observed == _dt(T2)


def test_plugin_history_mode_exposes_value_timelines_without_snapshots():
    dummy_hive = SimpleNamespace(partial_hive_path=None)
    plugin = RecentDocsPlugin(
        dummy_hive,
        as_json=True,
        observed_at=T1,
        include_history=True,
        snapshots=[_snapshot(T1, {"last_write": KEY_TIME_1, "values": {"0": "alpha"}}, RECENT_DOCS_PATH)],
    )

    output = plugin.run()
    assert "value_timelines" in output
    assert output[0]["value_name"] == "0"
    assert plugin.value_timelines
    assert plugin.value_timelines[0].key_path == RECENT_DOCS_PATH


def test_single_hive_typed_paths_default_output_is_unchanged(shellbags_ntuser):
    registry_hive = RegistryHive(shellbags_ntuser)
    plugin = TypedPathsPlugin(registry_hive, as_json=True)
    plugin.run()

    assert plugin.entries["last_write"] == "2022-02-06T13:46:04.945080+00:00"
    assert plugin.entries["entries"][0] == {"url1": "cmd"}
    assert len(plugin.entries["entries"]) == 16
    assert plugin.value_timelines == []


def test_single_hive_typed_paths_can_opt_into_history(shellbags_ntuser):
    registry_hive = RegistryHive(shellbags_ntuser)
    plugin = TypedPathsPlugin(registry_hive, as_json=True, include_history=True, observed_at=T1)
    output = plugin.run()

    assert output["value_timelines"]
    assert output["keys"][TYPED_PATHS_KEY_PATH]["key_clock"][0]["observed_at"] == T1
