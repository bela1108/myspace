"""Tests for two-collection access-control evidence comparison.

The synthetic hives built here intentionally contain:
* several keys sharing one SK cell (shared descriptor);
* a second SK cell whose descriptor is semantically identical (the
  equivalent re-point control case the audit hinges on);
* a genuinely re-permissioned descriptor;
* a key whose SK offset is broken (uncollectable evidence).
"""

import os
import tempfile

import pytest

from regipy.registry import RegistryHive
from regipy.security_evidence import (
    EQUIVALENT_REPOINT,
    PERMISSION_CHANGED,
    REASON_DESCRIPTOR_UNPARSEABLE,
    REASON_KEY_MISSING,
    UNCHANGED,
    UNCOLLECTABLE,
    SIDProfile,
    collect_key_security_evidence,
    compare_access_control,
)
from regipy_tests.synthetic_hive import (
    build_ace,
    build_acl,
    build_security_descriptor,
    build_sid,
    build_synthetic_hive,
)

# Sanitized, non-sensitive test trustees.
SID_OWNER = "S-1-5-18"
SID_AUDITOR = "S-1-5-21-111-222-1001"
SID_ADMIN = "S-1-5-32-544"

ACCESS_READ = 0x80000000  # GENERIC_READ
ACCESS_FULL = 0x1F01FF  # DELETE/READ_CONTROL/WRITE_DAC/WRITE_OWNER/SYNCHRONIZE


def _write_hive(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".DAT", dir=".")
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return path


@pytest.fixture()
def collected_hives():
    owner = build_sid(1, 5, [18])
    auditor = build_sid(1, 5, [21, 111, 222, 1001])
    admin = build_sid(1, 5, [32, 544])

    # Descriptor d1: auditor with full control.
    sd_full = build_security_descriptor(owner, owner, build_acl([build_ace(0, 0x3, ACCESS_FULL, auditor)]))
    # d2 is byte-different (ACE order via padding length) but semantically equal to d1.
    sd_full_equiv = (
        build_security_descriptor(owner, owner, build_acl([build_ace(0, 0x3, ACCESS_FULL, auditor)])) + b"\x00\x00"
    )  # byte-different, semantics identical
    # d3 genuinely changes permissions: read-only auditor plus an admin ACE.
    sd_changed = build_security_descriptor(
        owner,
        owner,
        build_acl(
            [
                build_ace(0, 0x3, ACCESS_READ, auditor),
                build_ace(0, 0x3, ACCESS_FULL, admin),
            ]
        ),
    )

    first_hive = build_synthetic_hive(
        keys=[
            {"name": "SharedA", "sk": "d1"},
            {"name": "SharedB", "sk": "d1"},
            {"name": "Repointed", "sk": "d1"},
            {"name": "RePermissioned", "sk": "d1"},
            {"name": "Broken", "sk": "d1", "broken_sk": True},
            {"name": "GoneLater", "sk": "d1"},
        ],
        descriptors={"d1": (sd_full, 6)},
        file_name="first",
    )
    second_hive = build_synthetic_hive(
        keys=[
            {"name": "SharedA", "sk": "d1"},
            {"name": "SharedB", "sk": "d1"},
            # Same semantics, different SK cell and different descriptor bytes.
            {"name": "Repointed", "sk": "d2"},
            # Real permission change.
            {"name": "RePermissioned", "sk": "d3"},
            # Still broken, evidence stays uncollectable.
            {"name": "Broken", "sk": "d1", "broken_sk": True},
            {"name": "NewKey", "sk": "d1"},
        ],
        descriptors={
            "d1": (sd_full, 3),
            "d2": (sd_full_equiv, 1),
            "d3": (sd_changed, 1),
        },
        file_name="second",
    )

    first_path = _write_hive(first_hive)
    second_path = _write_hive(second_hive)
    try:
        yield first_path, second_path, sd_full, sd_full_equiv, sd_changed
    finally:
        os.remove(first_path)
        os.remove(second_path)


SID_PROFILES = {
    SID_OWNER: SIDProfile(sid=SID_OWNER, permission_summary="local system"),
    SID_AUDITOR: SIDProfile(
        sid=SID_AUDITOR,
        permission_summary="read-only auditor",
        expected_access_mask=["GENERIC_READ"],
    ),
    SID_ADMIN: SIDProfile(sid=SID_ADMIN, permission_summary="local administrators"),
}


def _outcomes(report):
    return {difference.key_path: difference.outcome for difference in report.differences}


def test_compare_classifies_all_four_outcomes(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(
        first_path,
        second_path,
        sid_profiles=SID_PROFILES,
        first_collection_name="t0",
        second_collection_name="t1",
    )

    outcomes = _outcomes(report)
    assert outcomes[r"\SharedA"] == UNCHANGED
    assert outcomes[r"\SharedB"] == UNCHANGED
    assert outcomes[r"\Repointed"] == EQUIVALENT_REPOINT
    assert outcomes[r"\RePermissioned"] == PERMISSION_CHANGED
    assert outcomes[r"\Broken"] == UNCOLLECTABLE
    # Key present in only one collection is uncollectable with the right reason.
    assert outcomes[r"\GoneLater"] == UNCOLLECTABLE
    assert outcomes[r"\NewKey"] == UNCOLLECTABLE


def test_equivalent_repoint_keeps_identical_semantics_but_moves_reference(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(first_path, second_path, SID_PROFILES)
    difference = next(item for item in report.differences if item.key_path == r"\Repointed")

    assert difference.outcome == EQUIVALENT_REPOINT
    assert not difference.descriptor_identical
    # The SK reference actually moved to another cell.
    assert difference.first.sk_file_offset != difference.second.sk_file_offset
    # But owner/group/ACL semantics match on both sides.
    assert difference.first.evidence.owner == difference.second.evidence.owner
    assert difference.first.evidence.dacl == difference.second.evidence.dacl


def test_permission_change_is_detectable_and_explained(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(first_path, second_path, SID_PROFILES)
    difference = next(item for item in report.differences if item.key_path == r"\RePermissioned")

    assert difference.outcome == PERMISSION_CHANGED
    assert not difference.descriptor_identical
    assert "added ACEs" in difference.detail
    second_sids = {ace["sid"] for ace in difference.second.evidence.dacl}
    assert SID_ADMIN in second_sids
    assert SID_ADMIN not in {ace["sid"] for ace in difference.first.evidence.dacl}


def test_uncollectable_rows_keep_reasons_and_key_locations(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(first_path, second_path, SID_PROFILES)

    broken = next(item for item in report.differences if item.key_path == r"\Broken")
    assert broken.first.error_reason == REASON_DESCRIPTOR_UNPARSEABLE
    assert broken.second.error_reason == REASON_DESCRIPTOR_UNPARSEABLE
    # Even unparseable rows retain the NK location for the jump-back table.
    assert broken.first.nk_file_offset > 0
    assert broken.second.nk_file_offset > 0

    gone = next(item for item in report.differences if item.key_path == r"\GoneLater")
    assert gone.second.error_reason == REASON_KEY_MISSING
    new_key = next(item for item in report.differences if item.key_path == r"\NewKey")
    assert new_key.first.error_reason == REASON_KEY_MISSING


def test_shared_descriptor_conclusions_remain_per_key(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    first_hive = RegistryHive(first_path)
    evidence = collect_key_security_evidence(first_hive, "t0")

    shared_a = evidence[r"\SharedA"]
    shared_b = evidence[r"\SharedB"]
    # Both keys point at the same SK cell and list each other as sharers.
    assert shared_a.sk_file_offset == shared_b.sk_file_offset
    assert r"\SharedB" in shared_a.shared_by
    assert r"\SharedA" in shared_b.shared_by

    report = compare_access_control(first_path, second_path, SID_PROFILES)
    outcomes = _outcomes(report)
    # Sharing a descriptor does not merge conclusions: every key has its own row.
    assert outcomes[r"\SharedA"] == UNCHANGED
    assert outcomes[r"\SharedB"] == UNCHANGED
    assert outcomes[r"\Repointed"] == EQUIVALENT_REPOINT


def test_reference_difference_table_jumps_back_to_both_collections(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(first_path, second_path, SID_PROFILES)
    table = {row["key_path"]: row for row in report.reference_difference_table()}

    # Unchanged keys are intentionally absent from the difference table.
    assert r"\SharedA" not in table
    repointed = table[r"\Repointed"]
    assert repointed["outcome"] == EQUIVALENT_REPOINT
    # Each side carries both the NK and SK positions inside its own hive file.
    for side in ("first", "second"):
        assert repointed[side]["nk_file_offset"] > 0
        assert repointed[side]["sk_file_offset"] > 0
        assert repointed[side]["collection"] in ("first_collection", "second_collection")
    # The shared-by lists make the sharing relationship auditable.
    assert r"\SharedB" in repointed["shared_by_first"]


def test_sid_profiles_annotate_and_verify_semantics(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(first_path, second_path, SID_PROFILES)
    changed = next(item for item in report.differences if item.key_path == r"\RePermissioned")

    # The read-only auditor expectation fails once full control is replaced by read.
    assert not changed.first_verification.verified
    assert changed.first_verification.mask_mismatches
    mismatch = changed.first_verification.mask_mismatches[0]
    assert mismatch["sid"] == SID_AUDITOR
    assert mismatch["permission_summary"] == "read-only auditor"
    assert mismatch["expected"] == ["GENERIC_READ"]

    # The changed side grants GENERIC_READ and matches the auditor expectation.
    assert changed.second_verification.verified
    assert changed.second_verification.matched[SID_AUDITOR].permission_summary == "read-only auditor"


def test_unverified_sids_are_reported_not_guessed(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    # Only the owner is profiled; the trustee SIDs must surface as unverified.
    report = compare_access_control(
        first_path,
        second_path,
        sid_profiles={SID_OWNER: {"permission_summary": "local system"}},
    )
    shared = next(item for item in report.differences if item.key_path == r"\SharedA")
    assert not shared.first_verification.verified
    assert SID_AUDITOR in shared.first_verification.unverified_sids


def test_report_is_json_serializable(collected_hives):
    import json

    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(first_path, second_path, SID_PROFILES)
    encoded = json.dumps(report.to_dict())
    decoded = json.loads(encoded)
    assert "reference_difference_table" in decoded
    assert len(decoded["differences"]) == len(report.differences)


def test_accepts_registry_hive_instances(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(RegistryHive(first_path), RegistryHive(second_path), SID_PROFILES)
    assert any(difference.outcome == PERMISSION_CHANGED for difference in report.differences)


def test_semantic_fingerprint_ignores_ace_order(collected_hives):
    from regipy.security_evidence import SecurityKeyEvidence, descriptor_semantic_fingerprint

    first_path = collected_hives[0]
    first_hive = RegistryHive(first_path)
    evidence = collect_key_security_evidence(first_hive, "t0")
    original = evidence[r"\SharedA"].evidence

    reordered_evidence = SecurityKeyEvidence(
        sk_offset=original.sk_offset,
        sk_cell_offset=original.sk_cell_offset,
        sk_file_offset=original.sk_file_offset,
        reference_count=original.reference_count,
        descriptor_bytes=original.descriptor_bytes + b"\x00",
        owner=original.owner,
        group=original.group,
        dacl=list(reversed(original.dacl)),
        sacl=original.sacl,
    )
    assert descriptor_semantic_fingerprint(original) == descriptor_semantic_fingerprint(reordered_evidence)


def test_python_backend_rows_carry_concrete_jump_back_offsets(collected_hives):
    first_path, second_path, _, _, _ = collected_hives
    report = compare_access_control(first_path, second_path, SID_PROFILES)
    # Every row on the Python backend carries concrete jump-back offsets.
    for difference in report.differences:
        if difference.first.collectable:
            assert difference.first.nk_file_offset > 0
            assert difference.first.sk_file_offset > 0
