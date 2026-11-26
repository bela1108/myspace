import csv
import json
from tempfile import mktemp

import pytest
from click.testing import CliRunner

from regipy.cli import registry_dump
from regipy.evidence import (
    AmbiguousLegacyReferenceException,
    EvidenceReference,
    UnmappedLegacyReferenceException,
    find_reference_in_export,
    legacy_csv_reference_id,
    legacy_csv_reference_key,
    reference_from_entry,
    resolve_legacy_csv_reference,
    verify_evidence_reference,
    verify_reference_in_export,
)
from regipy.registry import RegistryHive


def _evidence_entries(hive):
    return list(hive.recurse_subkeys(as_json=True, fetch_values=False, include_evidence_reference=True))


def test_evidence_reference_is_opt_in_and_round_trips(ntuser_hive):
    hive = RegistryHive(ntuser_hive)
    plain_entry = next(hive.recurse_subkeys(as_json=True, fetch_values=False))
    assert "evidence_reference" not in plain_entry.to_dict()

    entry = next(hive.recurse_subkeys(as_json=True, fetch_values=False, include_evidence_reference=True))
    reference = entry.evidence_reference
    assert isinstance(reference, EvidenceReference)
    assert reference.to_dict() == {
        "acquisition_file": ntuser_hive,
        "record_offset": reference.record_offset,
        "sample_index": 0,
    }
    assert EvidenceReference.from_dict(reference.to_dict()) == reference
    assert EvidenceReference.from_string(reference.to_string()) == reference
    assert reference_from_entry({"evidence_reference": reference.to_string()}) == reference
    assert entry.to_dict(include_evidence_reference=True)["evidence_reference"] == reference.to_dict()
    assert hive.get_evidence_reference(entry.path, sample_index=5).record_offset == reference.record_offset

    verification = verify_evidence_reference(reference, registry_hive=hive, entry=entry)
    assert verification.locator_holds
    assert verification.all_components_hold
    assert verification.key_name == entry.subkey_name
    assert verification.key_path == entry.path
    assert verify_evidence_reference(reference, entry=entry).locator_holds


def test_reference_survives_path_sort_but_not_sampling_reorder(ntuser_hive):
    hive = RegistryHive(ntuser_hive)
    entries = _evidence_entries(hive)
    first, second = entries[0], entries[1]
    first_reference = first.evidence_reference
    second_reference = second.evidence_reference
    assert first_reference.record_offset != second_reference.record_offset

    first_row = first.to_dict(include_evidence_reference=True)
    second_row = second.to_dict(include_evidence_reference=True)

    # A value-only change must not invalidate the locator.
    value_changed_row = dict(first_row)
    value_changed_row["values"] = [{"name": "changed", "value": "after", "value_type": "REG_SZ", "is_corrupted": False}]
    value_change = verify_reference_in_export(first_reference, [value_changed_row], registry_hive=hive)
    assert value_change.all_components_hold

    # The next export was sorted differently and its sampling order was
    # recomputed.  The first key now gets the second key's old sample index, and
    # its value changed in place.  Values are not part of the locator.
    first_row["values"] = value_changed_row["values"]
    first_row["evidence_reference"]["sample_index"] = second_reference.sample_index
    second_row["evidence_reference"]["sample_index"] = first_reference.sample_index
    next_export = [second_row, first_row]

    # Joining by key name could pick the wrong duplicate; joining by the
    # physical locator still finds the same NK record regardless of row order.
    matches = find_reference_in_export(first_reference, next_export)
    assert len(matches) == 1
    assert matches[0]["path"] == first.path

    verification = verify_reference_in_export(first_reference, next_export, registry_hive=hive)
    assert verification.acquisition_file_holds is True
    assert verification.physical_record_holds is True
    assert verification.entry_matches is True
    assert verification.sample_order_holds is False
    assert verification.locator_holds is True
    assert verification.all_components_hold is False
    assert verification.row_matches is False
    assert "physical record: holds" in verification.explain()
    assert "sample order: does not hold" in verification.explain()


def test_duplicate_key_names_have_distinct_physical_references(ntuser_hive):
    hive = RegistryHive(ntuser_hive)
    by_name = {}
    duplicate_pair = None
    for entry in _evidence_entries(hive):
        previous = by_name.get(entry.subkey_name)
        if previous is not None and previous.path != entry.path:
            duplicate_pair = (previous, entry)
            break
        by_name[entry.subkey_name] = entry

    assert duplicate_pair is not None
    first, second = duplicate_pair
    assert first.subkey_name == second.subkey_name
    assert first.path != second.path
    assert first.evidence_reference.record_offset != second.evidence_reference.record_offset
    assert verify_evidence_reference(first.evidence_reference, registry_hive=hive, entry=first).row_matches
    assert verify_evidence_reference(second.evidence_reference, registry_hive=hive, entry=second).row_matches
    assert not verify_evidence_reference(first.evidence_reference, registry_hive=hive, entry=second).row_matches


def test_legacy_csv_rows_require_an_explicit_mapping(ntuser_hive):
    hive = RegistryHive(ntuser_hive)
    entry = _evidence_entries(hive)[0]
    reference = entry.evidence_reference
    legacy_row = {
        "timestamp": entry.timestamp,
        "subkey_name": entry.path,
        "values_count": entry.values_count,
        "values": entry.values,
    }

    with pytest.raises(UnmappedLegacyReferenceException):
        resolve_legacy_csv_reference(legacy_row, {})

    assert resolve_legacy_csv_reference(legacy_row, {entry.path: reference}) == reference
    assert resolve_legacy_csv_reference(legacy_row, {legacy_csv_reference_key(legacy_row): reference}) == reference
    assert resolve_legacy_csv_reference(legacy_row, {legacy_csv_reference_id(legacy_row): reference}) == reference

    # A row number can be the explicit key when several old rows share a name.
    assert resolve_legacy_csv_reference(legacy_row, {7: reference}, key=7) == reference

    with pytest.raises(AmbiguousLegacyReferenceException):
        resolve_legacy_csv_reference(
            legacy_row,
            {legacy_csv_reference_key(legacy_row): EvidenceReference(ntuser_hive, 1, 9), entry.path: reference},
        )


def test_reference_rejects_a_different_physical_record(ntuser_hive):
    hive = RegistryHive(ntuser_hive)
    entry = _evidence_entries(hive)[0]
    wrong = EvidenceReference(
        acquisition_file=entry.evidence_reference.acquisition_file,
        record_offset=entry.evidence_reference.record_offset + 1,
        sample_index=entry.evidence_reference.sample_index,
    )
    verification = verify_evidence_reference(wrong, registry_hive=hive, entry=entry)
    assert verification.acquisition_file_holds is True
    assert verification.physical_record_holds is False
    assert verification.locator_holds is False


def test_cli_json_and_timeline_evidence_output(ntuser_hive):
    runner = CliRunner()
    start_date = "2012-04-03T00:00:00.000000"
    end_date = "2012-04-03T23:59:59.999999"

    json_path = mktemp()
    result = runner.invoke(
        registry_dump,
        [ntuser_hive, "-d", "-s", start_date, "-e", end_date, "-o", json_path, "--evidence-reference"],
    )
    assert result.exit_code == 0
    with open(json_path) as f:
        first = json.loads(f.readline())
    assert set(first["evidence_reference"]) == {"acquisition_file", "record_offset", "sample_index"}
    assert verify_evidence_reference(first["evidence_reference"], hive_path=ntuser_hive, entry=first).locator_holds

    csv_path = mktemp()
    result = runner.invoke(
        registry_dump,
        [ntuser_hive, "-d", "-t", "-s", start_date, "-e", end_date, "-o", csv_path, "--evidence-reference"],
    )
    assert result.exit_code == 0
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == [
            "timestamp",
            "subkey_name",
            "values_count",
            "values",
            "acquisition_file",
            "record_offset",
            "sample_index",
        ]
        row = next(reader)
    assert row["acquisition_file"] == ntuser_hive
    assert int(row["sample_index"]) == 0
    assert int(row["record_offset"]) >= 4096
    csv_reference = reference_from_entry(row)
    assert csv_reference is not None
    assert verify_reference_in_export(csv_reference, [row], hive_path=ntuser_hive).locator_holds
