import json

from click.testing import CliRunner

from regipy.cli import run_plugins
from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin
from regipy.plugins.utils import run_relevant_plugins
from regipy.registry import RegistryHive


def _typed_path_records(result):
    value = result.get("typed_paths")
    if isinstance(value, dict):
        return value.get("entries", [])
    return value or []


def _coverage_for(result, plugin_name):
    return result["_coverage"]["plugins"][plugin_name]


def _open_hive(extracted_hive_path):
    return RegistryHive(extracted_hive_path)


def test_full_scope_empty_result_is_checked_and_conclusive(synthetic_empty_typed_paths_backups):
    hive = synthetic_empty_typed_paths_backups["full_scope"].load_hive()
    result = run_relevant_plugins(hive, as_json=True, plugins=["typed_paths"], include_coverage=True)

    assert result["typed_paths"] == {
        "last_write": "2012-04-04T15:35:08.895090+00:00",
        "entries": [],
    }
    assert _typed_path_records(result) == []

    coverage = _coverage_for(result, "typed_paths")
    assert coverage["status"] == "no_results"
    assert coverage["reason_code"] == "no_records_in_full_scope"
    assert coverage["checked"] is True
    assert coverage["conclusive"] is True
    assert coverage["entries_found"] is False
    assert coverage["scope"] == "full"
    assert coverage["partial_hive_path"] is None
    assert coverage["hive_type"] == "ntuser"


def test_partial_scope_empty_result_is_not_conclusive(synthetic_empty_typed_paths_backups):
    hive = synthetic_empty_typed_paths_backups["partial_scope"].load_hive()
    result = run_relevant_plugins(hive, as_json=True, plugins=["typed_paths"], include_coverage=True)

    assert result["typed_paths"] == []
    assert _typed_path_records(result) == []

    coverage = _coverage_for(result, "typed_paths")
    assert coverage["status"] == "partial_scope"
    assert coverage["reason_code"] == "partial_hive_scope"
    assert coverage["checked"] is True
    assert coverage["conclusive"] is False
    assert coverage["entries_found"] is False
    assert coverage["scope"] == "partial"
    assert coverage["partial_hive_path"] == r"\Software"


def test_unrecognized_hive_has_no_precondition_to_check(synthetic_empty_typed_paths_backups):
    backup = synthetic_empty_typed_paths_backups["unrecognized_type"]
    hive = backup.load_hive()
    assert hive.hive_type is None

    result = run_relevant_plugins(hive, as_json=True, plugins=["typed_paths"], include_coverage=True)

    assert "typed_paths" not in result
    assert _typed_path_records(result) == []

    coverage = _coverage_for(result, "typed_paths")
    assert coverage["status"] == "not_checked"
    assert coverage["reason_code"] == "unrecognized_hive_type"
    assert coverage["checked"] is False
    assert coverage["conclusive"] is False
    assert coverage["entries_found"] is False
    assert coverage["hive_type"] is None
    assert coverage["compatible_hive"] == "ntuser"


def test_incompatible_hive_type_has_no_precondition_to_check(system_hive):
    hive = _open_hive(system_hive)
    result = run_relevant_plugins(hive, as_json=True, plugins=["typed_paths"], include_coverage=True)

    assert "typed_paths" not in result
    coverage = _coverage_for(result, "typed_paths")
    assert coverage["status"] == "not_checked"
    assert coverage["reason_code"] == "incompatible_hive_type"
    assert coverage["hive_type"] == "system"
    assert coverage["compatible_hive"] == "ntuser"


def test_two_empty_backups_differ_only_by_scope_and_output_shows_it(synthetic_empty_typed_paths_backups):
    full = synthetic_empty_typed_paths_backups["full_scope"]
    partial = synthetic_empty_typed_paths_backups["partial_scope"]

    # The hive bytes are identical; only the declared acquisition scope changed.
    assert full.sha256() == partial.sha256()
    assert full.manifest()["collection_scope"] == {"kind": "full", "partial_hive_path": None}
    assert partial.manifest()["collection_scope"] == {"kind": "partial", "partial_hive_path": r"\Software"}

    full_result = run_relevant_plugins(full.load_hive(), as_json=True, plugins=["typed_paths"], include_coverage=True)
    partial_result = run_relevant_plugins(partial.load_hive(), as_json=True, plugins=["typed_paths"], include_coverage=True)

    assert _typed_path_records(full_result) == []
    assert _typed_path_records(partial_result) == []
    assert full_result["_coverage"]["hive"]["scope"] == "full"
    assert partial_result["_coverage"]["hive"]["scope"] == "partial"
    assert _coverage_for(full_result, "typed_paths")["status"] == "no_results"
    assert _coverage_for(partial_result, "typed_paths")["status"] == "partial_scope"


def test_existing_records_are_unchanged_when_coverage_is_enabled(shellbags_ntuser):
    baseline = run_relevant_plugins(_open_hive(shellbags_ntuser), as_json=True, plugins=["typed_paths"])
    with_coverage = run_relevant_plugins(
        _open_hive(shellbags_ntuser), as_json=True, plugins=["typed_paths"], include_coverage=True
    )

    assert {name: value for name, value in with_coverage.items() if name != "_coverage"} == baseline
    assert len(baseline["typed_paths"]["entries"]) == 16
    assert len(with_coverage["typed_paths"]["entries"]) == 16

    coverage = _coverage_for(with_coverage, "typed_paths")
    assert coverage["status"] == "results"
    assert coverage["reason_code"] == "records_found"
    assert coverage["checked"] is True
    assert coverage["conclusive"] is True
    assert coverage["entries_found"] is True


def test_direct_plugin_coverage_after_execute(synthetic_empty_typed_paths_backups):
    hive = synthetic_empty_typed_paths_backups["full_scope"].load_hive()
    plugin = TypedPathsPlugin(hive, as_json=True)
    plugin.execute()

    coverage = plugin.get_coverage()
    assert coverage["status"] == "no_results"
    assert coverage["checked"] is True
    assert coverage["conclusive"] is True


def test_default_result_shape_has_no_coverage_key(synthetic_empty_typed_paths_backups):
    hive = synthetic_empty_typed_paths_backups["full_scope"].load_hive()
    result = run_relevant_plugins(hive, as_json=True, plugins=["typed_paths"])
    assert "_coverage" not in result
    assert result["typed_paths"]["entries"] == []


def test_cli_full_scope_reports_checked_empty(synthetic_empty_typed_paths_backups, tmp_path):
    runner = CliRunner()
    output_path = tmp_path / "full.json"
    result = runner.invoke(
        run_plugins,
        [
            str(synthetic_empty_typed_paths_backups["full_scope"].hive_path),
            "-p",
            "typed_paths",
            "-o",
            str(output_path),
            "--include-coverage",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Coverage:" in result.output
    output = json.loads(output_path.read_text())
    assert output["typed_paths"]["entries"] == []
    assert output["_coverage"]["plugins"]["typed_paths"]["status"] == "no_results"
    assert output["_coverage"]["plugins"]["typed_paths"]["conclusive"] is True


def test_cli_partial_scope_reports_partial(synthetic_empty_typed_paths_backups, tmp_path):
    runner = CliRunner()
    output_path = tmp_path / "partial.json"
    result = runner.invoke(
        run_plugins,
        [
            str(synthetic_empty_typed_paths_backups["partial_scope"].hive_path),
            "-p",
            "typed_paths",
            "-o",
            str(output_path),
            "-r",
            r"\Software",
            "--coverage",
        ],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(output_path.read_text())
    assert output["typed_paths"] == []
    assert output["_coverage"]["plugins"]["typed_paths"]["status"] == "partial_scope"
    assert output["_coverage"]["plugins"]["typed_paths"]["conclusive"] is False
    assert output["_coverage"]["plugins"]["typed_paths"]["partial_hive_path"] == r"\Software"


def test_cli_unrecognized_hive_reports_not_checked(synthetic_empty_typed_paths_backups, tmp_path):
    runner = CliRunner()
    output_path = tmp_path / "unknown.json"
    result = runner.invoke(
        run_plugins,
        [
            str(synthetic_empty_typed_paths_backups["unrecognized_type"].hive_path),
            "-p",
            "typed_paths",
            "-o",
            str(output_path),
            "--include-coverage",
        ],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(output_path.read_text())
    assert "typed_paths" not in output
    assert output["_coverage"]["plugins"]["typed_paths"]["status"] == "not_checked"
    assert output["_coverage"]["plugins"]["typed_paths"]["reason_code"] == "unrecognized_hive_type"


def test_cli_without_coverage_flag_keeps_original_shape(synthetic_empty_typed_paths_backups, tmp_path):
    runner = CliRunner()
    output_path = tmp_path / "default.json"
    result = runner.invoke(
        run_plugins,
        [str(synthetic_empty_typed_paths_backups["full_scope"].hive_path), "-p", "typed_paths", "-o", str(output_path)],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(output_path.read_text())
    assert set(output) == {"typed_paths"}
