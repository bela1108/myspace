import csv
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(os.path.abspath(__file__)).parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dnfile.correlate import (  # noqa: E402
    STATUS_AMBIGUOUS,
    STATUS_RENUMBERED,
    STATUS_SIGNATURE_CHANGED,
    correlate_files,
    export_mapping,
    load_metadata,
    result_rows,
)

SAMPLES = ROOT / "examples" / "correlate" / "samples"
OLD = SAMPLES / "old" / "Correlate.Sample.dll"
NEW = SAMPLES / "new" / "Correlate.Sample.dll"
BUILDER = ROOT / "examples" / "correlate" / "build_samples.py"


@pytest.fixture(scope="session", autouse=True)
def ensure_samples():
    if OLD.exists() and NEW.exists():
        return
    spec = importlib.util.spec_from_file_location("correlate_sample_builder", str(BUILDER))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build_pair(str(SAMPLES))


@pytest.fixture(scope="session")
def result():
    return correlate_files(str(OLD), str(NEW))


def _find(result, suffix, kind=None):
    for match in result.matches:
        if kind is not None and match.source.kind != kind:
            continue
        if match.source.full_name.endswith(suffix):
            return match
    raise AssertionError("no entity ending with %s" % suffix)


def test_pure_token_change_is_renumbering(result):
    match = _find(result, "StableService::Compute#0", "method")
    assert match.status == STATUS_RENUMBERED
    assert match.target is not None
    assert match.source.token == 0x06000002
    assert match.target.token == 0x06000008
    assert match.candidates[0].semantic_equal is True
    assert match.candidates[0].projection_equal is True
    assert match.source.locals == match.target.locals
    assert match.source.namespace == match.target.namespace == "Contoso.Incident"


def test_real_signature_change_is_not_hidden_by_renumbering(result):
    match = _find(result, "LegacyApi::Process#0", "method")
    assert match.status == STATUS_SIGNATURE_CHANGED
    assert match.candidates[0].comparisons["signature_equal"] is False
    assert match.source.signature["return"] == "System.String"
    assert match.target.signature["return"] == "void"
    assert match.source.signature["parameters"] == ["System.String"]
    assert match.target.signature["parameters"] == ["System.Int32", "System.String"]


def test_nested_types_and_generic_constraints_do_not_use_previous_tokens(result):
    old = load_metadata(str(OLD))
    new = load_metadata(str(NEW))
    old_box = next(e for e in old.types if e.full_name.endswith("Outer+GenericBox"))
    new_box = next(e for e in new.types if e.full_name.endswith("Outer+GenericBox"))
    assert old_box.full_name == new_box.full_name == "Contoso.Incident.Outer+GenericBox"
    assert old_box.token == 0x02000004
    assert new_box.token == 0x02000006
    assert old_box.token != new_box.token

    old_map = next(e for e in old.methods if e.name == "Map")
    new_map = next(e for e in new.methods if e.name == "Map")
    assert old_map.token == 0x06000005
    assert new_map.token == 0x0600000A
    assert old_map.constraints == new_map.constraints
    assert old_map.constraints[0]["name"] == "U"
    assert old_map.constraints[0]["constraints"] == ["System.IDisposable [mscorlib]"]
    assert "IComparable" in old_box.constraints[0]["constraints"][0]
    assert old_box.constraints == new_box.constraints

    match = _find(result, "Outer+GenericBox::Map#1", "method")
    assert match.status == STATUS_RENUMBERED
    assert match.candidates[0].semantic_equal is True
    assert match.comparisons["generic_constraints_equal"] is True


def test_same_name_equivalent_candidates_remain_multi_select(result):
    matches = [m for m in result.matches if m.source.name == "Handle" and m.source.kind == "method"]
    assert len(matches) == 2
    group_ids = {m.group_id for m in matches}
    assert len(group_ids) == 1
    for match in matches:
        assert match.status == STATUS_AMBIGUOUS
        assert match.target is None
        assert len(match.candidates) == 2
        assert {c.target.token for c in match.candidates} == {0x06000005, 0x06000006}
        assert all(c.projection_equal for c in match.candidates)
        assert all(c.semantic_equal for c in match.candidates)


def test_exported_table_contains_required_cases(tmp_path):
    result = correlate_files(str(OLD), str(NEW))
    output = tmp_path / "entity-map.csv"
    export_mapping(result, output, fmt="csv")
    rows = list(csv.DictReader(output.open("r", encoding="utf-8")))
    assert any(row["status"] == STATUS_RENUMBERED and row["target_token"] != row["source_token"] for row in rows)
    ambiguous_rows = [row for row in rows if row["status"] == STATUS_AMBIGUOUS]
    assert len(ambiguous_rows) == 4
    assert {row["candidate_count"] for row in ambiguous_rows} == {"2"}
    assert len({row["group_id"] for row in ambiguous_rows}) == 1

    json_output = tmp_path / "entity-map.json"
    export_mapping(result, json_output, fmt="json")
    payload = json.loads(json_output.read_text(encoding="utf-8"))
    assert payload["summary"][STATUS_AMBIGUOUS] == 2
    assert payload["summary"][STATUS_RENUMBERED] >= 1


def test_result_rows_are_flat_and_addressable(result):
    rows = result_rows(result)
    assert rows
    assert all("source_kind" in row and "target_kind" in row for row in rows)
    assert sum(1 for row in rows if row["status"] == STATUS_AMBIGUOUS) == 4
