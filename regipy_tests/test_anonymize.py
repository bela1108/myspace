"""Unit tests for the case-scoped anonymization export (regipy.anonymize)"""

import json

import pytest

from regipy.anonymize import AnonymizationPolicy, CaseAnonymizer, FieldKind

POLICY = AnonymizationPolicy(
    {
        "username": FieldKind.IDENTITY,
        "sid": FieldKind.OBJECT_ID,
        "key_path": FieldKind.KEY_PATH,
        "timestamp": FieldKind.KEEP,
    }
)


def _entries(username="john"):
    return [
        {
            "username": username,
            "sid": "S-1-5-21-1000",
            "key_path": f"\\Users\\{username}\\NTUSER.DAT",
            "timestamp": "2024-01-01T00:00:00",
            "internal_note": "do not export",
        },
        {
            "username": username,
            "sid": "S-1-5-21-1000",
            "key_path": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "timestamp": "2024-01-02T00:00:00",
        },
    ]


def test_correlation_within_case():
    anonymizer = CaseAnonymizer("CASE-001", POLICY)
    result = anonymizer.anonymize_entries(_entries())
    token = result[0]["username"]
    # Same subject correlates: identical token across entries and across
    # identities embedded in key paths.
    assert token.startswith("USR-")
    assert result[1]["username"] == token
    assert result[0]["key_path"] == f"\\Users\\{token}\\NTUSER.DAT"
    # Structural path segments are preserved.
    assert result[1]["key_path"] == "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    # Object identifiers are pseudonymized consistently.
    assert result[0]["sid"].startswith("OBJ-")
    assert result[1]["sid"] == result[0]["sid"]
    # Non-identifying fields pass through.
    assert result[0]["timestamp"] == "2024-01-01T00:00:00"


def test_undeclared_fields_are_dropped():
    anonymizer = CaseAnonymizer("CASE-001", POLICY)
    result = anonymizer.anonymize_entries(_entries())
    assert "internal_note" not in result[0]
    assert "john" not in json.dumps(result)


def test_unprocessable_declared_field_is_dropped():
    anonymizer = CaseAnonymizer("CASE-001", POLICY)
    result = anonymizer.anonymize_entries([{"username": {"unexpected": "type"}, "timestamp": "t"}])
    assert result == [{"timestamp": "t"}]


def test_same_username_in_two_cases_cannot_be_merged():
    case_a = CaseAnonymizer("CASE-A", POLICY)
    case_b = CaseAnonymizer("CASE-B", POLICY)
    result_a = case_a.anonymize_entries(_entries("shared_user"))
    result_b = case_b.anonymize_entries(_entries("shared_user"))
    # The two cases deliberately use the same username, but the external
    # results must not allow merging the two people.
    assert result_a[0]["username"] != result_b[0]["username"]
    assert result_a[0]["sid"] != result_b[0]["sid"]


def test_updating_case_material_keeps_tokens_stable(tmp_path):
    case_a = CaseAnonymizer("CASE-A", POLICY)
    case_b = CaseAnonymizer("CASE-B", POLICY)
    token_b = case_b.anonymize_entries(_entries("shared_user"))[0]["username"]
    first_export = case_a.anonymize_entries(_entries("shared_user"))
    mapping_path = tmp_path / "case_a_mapping.json"
    case_a.export_internal_mapping(mapping_path)
    # Later update of case A's material, resumed from the internal mapping.
    resumed = CaseAnonymizer.from_internal_mapping(mapping_path, POLICY)
    updated_entries = _entries("shared_user") + [
        {"username": "shared_user", "sid": "S-1-5-21-2000", "timestamp": "2024-01-03T00:00:00"}
    ]
    second_export = resumed.anonymize_entries(updated_entries)
    # Existing tokens are stable across the update...
    assert second_export[0]["username"] == first_export[0]["username"]
    assert second_export[0]["key_path"] == first_export[0]["key_path"]
    # ...and the update still cannot be merged with case B's person.
    assert second_export[0]["username"] != token_b


def test_internal_mapping_reverses_tokens_but_public_export_does_not(tmp_path):
    anonymizer = CaseAnonymizer("CASE-001", POLICY)
    public_path = tmp_path / "public.json"
    public = anonymizer.export_public(_entries(), public_path)
    # Public report: only one-way tokens, no originals, no reversal data.
    public_raw = public_path.read_text(encoding="utf-8")
    assert "john" not in public_raw
    assert "S-1-5-21-1000" not in public_raw
    assert "secret" not in public_raw
    # Internal review material: maps every token back to its original.
    mapping = anonymizer.export_internal_mapping(tmp_path / "mapping.json")
    originals = {record["token"]: record["value"] for record in mapping["tokens"]}
    assert originals[public[0]["username"]] == "john"
    assert originals[public[0]["sid"]] == "S-1-5-21-1000"


def test_identity_normalization_and_aliases():
    policy = AnonymizationPolicy({"username": FieldKind.IDENTITY})
    anonymizer = CaseAnonymizer(
        "CASE-001",
        policy,
        identity_aliases={"john.doe@corp.example": "john"},
    )
    result = anonymizer.anonymize_entries(
        [
            {"username": "John"},
            {"username": "JOHN"},
            {"username": "john.doe@corp.example"},
        ]
    )
    # Case variants and declared aliases of the same subject share one token.
    assert result[0]["username"] == result[1]["username"] == result[2]["username"]


def test_dict_shaped_plugin_output():
    policy = AnonymizationPolicy({"last_write": FieldKind.KEEP, "entries": FieldKind.KEEP, "url1": FieldKind.KEEP})
    anonymizer = CaseAnonymizer("CASE-001", policy)
    result = anonymizer.anonymize_entries(
        {"last_write": "2024-01-01", "entries": [{"url1": "https://example.com"}], "extra": "dropped"}
    )
    assert result == {"last_write": "2024-01-01", "entries": [{"url1": "https://example.com"}]}


def test_register_identity_for_paths_without_identity_field():
    policy = AnonymizationPolicy({"key_path": FieldKind.KEY_PATH})
    anonymizer = CaseAnonymizer("CASE-001", policy)
    token = anonymizer.register_identity("john")
    result = anonymizer.anonymize_entries([{"key_path": "\\Users\\john\\Documents"}])
    assert result == [{"key_path": f"\\Users\\{token}\\Documents"}]


def test_unknown_field_kind_rejected():
    with pytest.raises(ValueError):
        AnonymizationPolicy({"username": "not-a-kind"})
