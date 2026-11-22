"""Persistent state, three-snapshot retention and the CLI."""

import json


from signedjson.acceptance.cli import main as cli_main
from signedjson.acceptance.store import SNAPSHOT_LIMIT, AcceptanceStore


def _register(store, key_config, materials):
    store.register_keys(key_config)
    store.register_materials(materials)
    store.save()


def test_store_keeps_last_three_summaries(
    tmp_path, key_config, materials, make_event, originals, material_ids
):
    path = str(tmp_path / "state.json")
    store = AcceptanceStore(path)
    _register(store, key_config, materials)

    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    store.run([root])
    for index in range(2, 6):
        event = make_event(
            "e%d" % index,
            originals["contract"],
            predecessor="e%d" % (index - 1),
            declared=material_ids["contract"],
        )
        store.run([event])

    assert len(store.snapshots) == SNAPSHOT_LIMIT
    assert [snapshot["run"] for snapshot in store.snapshots] == [3, 4, 5]

    reopened = AcceptanceStore.open(path)
    assert len(reopened.snapshots) == SNAPSHOT_LIMIT
    assert set(reopened.data["events"]) == {"e1", "e2", "e3", "e4", "e5"}


def test_late_predecessor_recovers_after_reopen(
    tmp_path, key_config, materials, make_event, originals, material_ids
):
    path = str(tmp_path / "state.json")
    store = AcceptanceStore(path)
    _register(store, key_config, materials)
    pending = make_event(
        "e2",
        originals["rider"],
        predecessor="e1",
        declared=material_ids["rider"],
    )
    first = store.run([pending])
    assert first["nodes"][0]["status"] == "awaiting_predecessor"

    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    second = AcceptanceStore.open(path).run([root])
    statuses = {node["event_id"]: node["status"] for node in second["nodes"]}
    assert statuses == {"e1": "confirmed", "e2": "confirmed"}


def test_replay_report_never_admits_twice(
    tmp_path, key_config, materials, make_event, originals, material_ids
):
    path = str(tmp_path / "state.json")
    store = AcceptanceStore(path)
    _register(store, key_config, materials)
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    store.run([root])
    snapshot = store.run([dict(root)])
    assert snapshot["ingest_report"]["duplicates"] == ["e1"]
    assert snapshot["event_count"] == 1


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_cli_ingest_and_snapshots(
    tmp_path, key_config, materials, make_event, originals, material_ids, capsys
):
    state = str(tmp_path / "state.json")
    keys_path = _write(tmp_path, "keys.json", key_config)
    materials_path = _write(tmp_path, "materials.json", materials)
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    events_path = _write(tmp_path, "events.json", [root])

    code = cli_main([
        "init",
        "--state", state,
        "--keys", keys_path,
        "--materials", materials_path,
    ])
    assert code == 0
    capsys.readouterr()
    code = cli_main([
        "ingest",
        "--state", state,
        "--events", events_path,
        "--allow-review",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_count"] == 1

    code = cli_main(["snapshots", "--state", state, "--latest"])
    assert code == 0
    latest = json.loads(capsys.readouterr().out)
    assert len(latest) == 1 and latest[0]["run"] == 1


def test_cli_ingest_returns_review_exit_code(
    tmp_path, key_config, materials, make_event, originals, material_ids
):
    state = str(tmp_path / "state.json")
    store = AcceptanceStore(state)
    _register(store, key_config, materials)
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    fork_a = make_event(
        "e2",
        originals["appendix-a"],
        predecessor="e1",
        declared=material_ids["appendix-a"],
    )
    fork_b = make_event(
        "e3",
        originals["appendix-b"],
        predecessor="e1",
        declared=material_ids["appendix-b"],
    )
    events_path = _write(tmp_path, "events.json", [root, fork_a, fork_b])
    assert cli_main(["ingest", "--state", state, "--events", events_path]) == 3


def test_replay_still_blocked_after_reopen(
    tmp_path, key_config, materials, make_event, originals, material_ids
):
    import copy

    path = str(tmp_path / "state.json")
    store = AcceptanceStore(path)
    store.register_keys(key_config)
    store.register_materials(materials)
    root = make_event("e1", originals["contract"], declared=material_ids["contract"])
    store.save()
    store.run([root])

    reopened = AcceptanceStore.open(path)
    snapshot = reopened.run([copy.deepcopy(root)])
    assert snapshot["ingest_report"]["duplicates"] == ["e1"]
    assert snapshot["event_count"] == 1
