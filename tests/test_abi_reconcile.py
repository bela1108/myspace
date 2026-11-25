"""Tests for the offline pefile-based ABI reconciliation tooling."""

from __future__ import annotations

import json
from pathlib import Path

import pefile
import pytest

from abi_check.checker import (
    ALIAS_AMBIGUOUS,
    FORWARDED_CONFIRMED,
    FORWARDED_UNCONFIRMED,
    ORDINAL_STABLE,
    REMOVED,
    RENAMED_ORDINAL_KEPT,
    STABLE,
    UNRESOLVED,
    load_exports,
    load_manifest,
    reconcile,
    render_report,
    split_forwarder,
)
from abi_check.fixtures.fixture import write_fixtures
from abi_check.pe_builder import ExportSpec, build_dll

MANIFEST_DIR = Path(__file__).parent.parent / "abi_check" / "fixtures" / "manifests"


@pytest.fixture(scope="module")
def fixture_paths(tmp_path_factory):
    output_dir = tmp_path_factory.mktemp("abi_fixtures")
    return write_fixtures(output_dir)


def _load(path):
    return pefile.PE(str(path))


def test_builder_produces_named_ordinal_only_and_forwarder_exports():
    data = build_dll(
        [
            ExportSpec(ordinal=1, name="Alpha"),
            ExportSpec(ordinal=2, name="Alpha"),
            ExportSpec(ordinal=3, name=None),
            ExportSpec(ordinal=4, name="Fwd", forwarder="other.#2"),
        ],
        dll_name="sample.dll",
    )
    pe = _load_from_bytes(data)
    symbols = {(s.ordinal, s.name): s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}

    assert pe.DIRECTORY_ENTRY_EXPORT.struct.Base == 1
    assert symbols[(1, b"Alpha")].forwarder is None
    assert symbols[(2, b"Alpha")].forwarder is None
    assert symbols[(3, None)].name is None
    assert symbols[(4, b"Fwd")].forwarder == b"other.#2"
    pe.close()


def _load_from_bytes(data):
    return pefile.PE(data=data)


def test_duplicate_name_is_indexed_to_multiple_ordinals(fixture_paths):
    old = load_exports(fixture_paths["old"])
    alias = old.by_name["WidgetAlias"]
    assert sorted(entry.ordinal for entry in alias) == [2, 3]


def test_ordinal_only_export_has_no_name_table_entry(fixture_paths):
    old = load_exports(fixture_paths["old"])
    entry = old.by_ordinal[7]
    assert entry.name is None
    assert "WidgetCompute" in old.by_name


def test_split_forwarder_handles_symbol_and_ordinal_targets():
    assert split_forwarder("legacy.OldFunc") == ("legacy", "OldFunc")
    assert split_forwarder("extmissing.#9") == ("extmissing", "#9")


def test_renamed_ordinal_kept_gives_opposite_name_vs_ordinal_verdicts(fixture_paths):
    legacy = [fixture_paths["legacy"]]

    by_name = reconcile(
        fixture_paths["old"],
        fixture_paths["new"],
        MANIFEST_DIR / "by_name.json",
        extra_module_paths=legacy,
    )
    name_verdict = next(
        v for v in by_name.verdicts if v.caller == "compute_plugin_by_name"
    )
    assert name_verdict.status == RENAMED_ORDINAL_KEPT
    assert name_verdict.usable_on_old is False
    assert name_verdict.new_resolved is False

    by_ordinal = reconcile(
        fixture_paths["old"],
        fixture_paths["new"],
        MANIFEST_DIR / "by_ordinal.json",
        extra_module_paths=legacy,
    )
    ordinal_verdict = next(
        v for v in by_ordinal.verdicts
        if v.caller == "compute_plugin_by_ordinal"
    )
    assert ordinal_verdict.status == ORDINAL_STABLE
    assert ordinal_verdict.usable_on_old is True
    assert ordinal_verdict.old_ordinals == [4]
    assert ordinal_verdict.new_ordinals == [4]


def test_all_name_binding_statuses(fixture_paths):
    report = reconcile(
        fixture_paths["old"],
        fixture_paths["new"],
        MANIFEST_DIR / "by_name.json",
        extra_module_paths=[fixture_paths["legacy"]],
    )
    statuses = {v.caller: v.status for v in report.verdicts}
    assert statuses == {
        "ui_panel_by_name": STABLE,
        "compute_plugin_by_name": RENAMED_ORDINAL_KEPT,
        "alias_consumer_by_name": ALIAS_AMBIGUOUS,
        "legacy_bridge_by_name": FORWARDED_CONFIRMED,
        "external_hook_by_name": FORWARDED_UNCONFIRMED,
        "removed_feature_by_name": REMOVED,
        "ghost_caller_by_name": UNRESOLVED,
    }


def test_all_ordinal_binding_statuses(fixture_paths):
    report = reconcile(
        fixture_paths["old"],
        fixture_paths["new"],
        MANIFEST_DIR / "by_ordinal.json",
        extra_module_paths=[fixture_paths["legacy"]],
    )
    statuses = {v.caller: v.status for v in report.verdicts}
    assert statuses == {
        "ui_panel_by_ordinal": STABLE,
        "compute_plugin_by_ordinal": ORDINAL_STABLE,
        "alias_consumer_by_ordinal": STABLE,
        "legacy_bridge_by_ordinal": FORWARDED_CONFIRMED,
        "external_hook_by_ordinal": FORWARDED_UNCONFIRMED,
        "ordinal_only_client": STABLE,
        "removed_feature_by_ordinal": REMOVED,
        "ghost_caller_by_ordinal": UNRESOLVED,
    }


def test_forwarder_confirmation_uses_offline_module_set(fixture_paths):
    report = reconcile(
        fixture_paths["old"],
        fixture_paths["new"],
        MANIFEST_DIR / "by_name.json",
        extra_module_paths=[fixture_paths["legacy"]],
    )
    confirmed = {
        row["forwarder"]: row["confirmed"] for row in report.forwarders
    }
    assert confirmed["legacy.OldFunc"] is True
    assert confirmed["extmissing.#9"] is False


def test_declaration_diff_lists_added_removed_and_renamed(fixture_paths):
    report = reconcile(
        fixture_paths["old"],
        fixture_paths["new"],
        MANIFEST_DIR / "by_name.json",
        extra_module_paths=[fixture_paths["legacy"]],
    )
    diff = report.declaration_diff
    assert [row["ordinal"] for row in diff["added"]] == [9]
    assert [row["ordinal"] for row in diff["removed"]] == [8]
    renamed = diff["renamed_ordinal_kept"]
    assert len(renamed) == 1
    assert renamed[0]["old_name"] == "WidgetCompute"
    assert renamed[0]["new_name"] == "WidgetComputeV2"


def test_json_report_is_serializable_and_renders(fixture_paths):
    report = reconcile(
        fixture_paths["old"],
        fixture_paths["new"],
        MANIFEST_DIR / "by_ordinal.json",
        extra_module_paths=[fixture_paths["legacy"]],
    )
    encoded = json.dumps(report.to_dict(), ensure_ascii=False)
    assert json.loads(encoded)["module"] == "widget.dll"
    text = render_report(report)
    assert "合成调用者核对结论" in text


def test_manifest_loader_validates_binding(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"caller": "x", "binding": "slot", "target": "y"}]))
    with pytest.raises(ValueError):
        load_manifest(bad)
