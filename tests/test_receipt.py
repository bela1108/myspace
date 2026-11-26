"""Acceptance tests for read-only Office receipts and resume behavior."""

import hashlib
import json
from os.path import dirname, join

import pytest

import msoffcrypto
from msoffcrypto.receipt import (
    CONFIRMED,
    PENDING,
    InterruptedWriteError,
    ObservationStatus,
    Receipt,
    ReceiptReadOnlyError,
    inspect_file,
    load_receipt,
    migrate_legacy_receipt,
    resume_receipt,
    write_receipt,
)


DATA_DIR = join(dirname(__file__), "inputs")
LEGACY_DOC = join(DATA_DIR, "plain.doc")
LEGACY_XLS = join(DATA_DIR, "plain.xls")
LEGACY_PPT = join(DATA_DIR, "plain.ppt")
AGILE_DOCX = join(DATA_DIR, "example_password.docx")
AGILE_XLSX = join(DATA_DIR, "example_password.xlsx")
STANDARD_DOCX = join(DATA_DIR, "ecma376standard_password.docx")
RC4_DOC = join(DATA_DIR, "rc4cryptoapi_password.doc")
RC4_XLS = join(DATA_DIR, "rc4cryptoapi_password.xls")
RC4_PPT = join(DATA_DIR, "rc4cryptoapi_password.ppt")
XOR_XLS = join(DATA_DIR, "xor_password_123456789012345.xls")


SAMPLES = [
    (LEGACY_DOC, "doc97", False, None),
    (LEGACY_XLS, "xls97", False, None),
    (LEGACY_PPT, "ppt97", False, None),
    (AGILE_DOCX, "ooxml", True, "agile"),
    (AGILE_XLSX, "ooxml", True, "agile"),
    (STANDARD_DOCX, "ooxml", True, "standard"),
    (RC4_DOC, "doc97", True, "rc4_cryptoapi"),
    (RC4_XLS, "xls97", True, "rc4_cryptoapi"),
    (RC4_PPT, "ppt97", True, "rc4_cryptoapi"),
    (XOR_XLS, "xls97", True, "xor"),
]


@pytest.mark.parametrize("path,expected_format,encrypted,scheme", SAMPLES)
def test_initial_format_conclusion_matches_existing_detector(path, expected_format, encrypted, scheme):
    observation = inspect_file(path)

    assert observation.format == expected_format
    assert observation.encrypted is encrypted
    assert observation.encryption_scheme == scheme
    assert observation.status == CONFIRMED
    assert observation.pending is False
    assert observation.read_only is True
    assert observation.decrypted is False
    assert observation.credential_used is False
    assert observation.initial_conclusion.format == expected_format
    assert observation.initial_format == expected_format

    with open(path, "rb") as handle:
        office_file = msoffcrypto.OfficeFile(handle)
        assert office_file.format == expected_format
        assert office_file.is_encrypted() is encrypted


def test_public_properties_are_reproducible_and_independently_verifiable(tmp_path):
    path = tmp_path / "case.json"
    receipt = write_receipt([LEGACY_DOC, AGILE_DOCX], path)

    first = {item["observation_id"]: item for item in receipt.observations}
    reloaded = load_receipt(path)
    second = {item["observation_id"]: item for item in reloaded.observations}

    assert set(first) == set(second)
    for observation_id in first:
        assert first[observation_id]["sample_sha256"] == second[observation_id]["sample_sha256"]
        assert first[observation_id]["public_properties"] == second[observation_id]["public_properties"]
        assert first[observation_id]["properties_digest"] == second[observation_id]["properties_digest"]
        with open(first[observation_id]["source"], "rb") as handle:
            assert first[observation_id]["sample_sha256"] == hashlib.sha256(handle.read()).hexdigest()

    verification = reloaded.verify()
    assert verification.ok is True
    assert verification.counts["verified"] == 2
    assert verification.counts["mismatch"] == 0
    assert reloaded.to_dict()["decrypted"] is False
    assert reloaded.to_dict()["credential_used"] is False


def test_accepting_one_correction_does_not_erase_other_pending_observations(tmp_path):
    path = tmp_path / "case.json"
    receipt = Receipt(path)
    first = receipt.observe_bytes(b"not an office sample A", subject="material-a")
    second = receipt.observe_bytes(b"not an office sample B", subject="material-b")

    assert first.status == PENDING
    assert second.status == PENDING
    assert receipt.pending_count == 2

    receipt.accept_correction(first.observation_id, "format", "doc97", reason="reviewer correction")

    corrected = receipt.get(first.observation_id)
    untouched = receipt.get(second.observation_id)
    assert corrected.format == "doc97"
    assert corrected.status == CONFIRMED
    assert corrected.initial_format == "unknown"
    assert len(corrected.corrections) == 1
    assert untouched.status == PENDING
    assert untouched.format == "unknown"
    assert receipt.pending_count == 1
    assert [item["observation_id"] for item in receipt.pending_observations] == [second.observation_id]

    receipt.accept_correction(second.observation_id, "format", "xls97", status=PENDING)
    assert receipt.get(second.observation_id).status == PENDING
    assert receipt.pending_count == 1


def test_permission_review_is_a_later_correction_and_never_decrypts(tmp_path):
    path = tmp_path / "case.json"
    receipt = Receipt(path)
    observation = receipt.observe(AGILE_DOCX)

    assert observation.encrypted is True
    assert observation.handling_permission == "pending_review"
    assert observation.permission_reviewed is False
    assert observation.decrypted is False
    assert observation.credential_used is False

    receipt.accept_correction(
        observation.observation_id,
        "handling_permission",
        "granted",
        reason="custodian reviewed authorization",
    )

    reviewed = receipt.get(observation.observation_id)
    assert reviewed.handling_permission == "granted"
    assert reviewed.permission_reviewed is True
    assert reviewed.encrypted is True
    assert reviewed.decrypted is False
    assert reviewed.credential_used is False


def test_unreadable_material_is_recorded_as_pending(tmp_path):
    path = tmp_path / "case.json"
    missing = tmp_path / "missing.doc"
    receipt = write_receipt([LEGACY_DOC, str(missing)], path)

    by_subject = {item.subject: item for item in receipt.observations}
    assert by_subject["plain.doc"].status == CONFIRMED
    assert by_subject["missing.doc"].status == PENDING
    assert by_subject["missing.doc"].format == "unknown"
    assert by_subject["missing.doc"].parse_errors
    assert receipt.pending_count == 1


def test_interrupted_receipt_resumes_and_renews_confirmed_conclusion_only_once(tmp_path):
    unknown = tmp_path / "unknown-material.bin"
    unknown.write_bytes(b"material that is not an office document")
    samples = [LEGACY_DOC, LEGACY_XLS, LEGACY_PPT, str(unknown)]
    path = tmp_path / "case.json"

    with pytest.raises(InterruptedWriteError) as interrupted:
        write_receipt(samples, path, interrupt_after=2)

    assert interrupted.value.observations_written == 2
    assert interrupted.value.events_written >= 2
    partial = load_receipt(path)
    assert partial.recovered_partial is True
    assert partial.confirmed_count == 2
    assert len(partial.observations) == 2

    resumed = resume_receipt(path)
    assert resumed.recovered_partial is True
    assert resumed.confirmed_count == 3
    assert resumed.pending_count == 1
    assert resumed.last_resume["recovered_partial"] is True
    assert len(resumed.last_resume["renewed"]) == 3
    assert len(resumed.last_resume["renewed_previously_confirmed"]) == 2
    assert len({item["observation_id"] for item in resumed.observations}) == 4

    by_format = {item["format"]: item for item in resumed.observations}
    assert by_format["doc97"].renewal_count == 1
    assert by_format["xls97"].renewal_count == 1
    assert by_format["ppt97"].renewal_count == 1
    assert by_format["unknown"].status == PENDING

    resumed_again = resume_receipt(path, samples)
    assert resumed_again.last_resume["renewed"] == []
    assert len({item["observation_id"] for item in resumed_again.observations}) == 4
    assert all(item.renewal_count <= 1 for item in resumed_again.confirmed_observations)

    final = resume_receipt(path, samples)
    assert final.last_resume["renewed"] == []
    assert final.pending_count == 1
    assert all(item.renewal_count == 1 for item in final.confirmed_observations)
    assert [item.format for item in final.pending_observations] == ["unknown"]


def test_legacy_receipt_keeps_old_format_values_and_is_loadable(tmp_path):
    legacy_payload = {
        "case_id": "old-case",
        "observations": [
            {"id": "old-doc", "format": "doc97", "status": "confirmed"},
            {"id": "old-ooxml", "format": "ooxml", "status": "待查"},
        ],
    }
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy_payload, ensure_ascii=False), encoding="utf-8")

    migrated = migrate_legacy_receipt(legacy_payload)
    assert {item["format"] for item in migrated["observations"]} == {"doc97", "ooxml"}

    loaded = load_receipt(path)
    by_id = {item["observation_id"]: item for item in loaded.observations}
    assert by_id["old-doc"].format == "doc97"
    assert by_id["old-doc"].status == CONFIRMED
    assert by_id["old-ooxml"].format == "ooxml"
    assert by_id["old-ooxml"].status == PENDING


def test_partial_journal_is_recovered_and_read_only_receipt_refuses_mutation(tmp_path):
    path = tmp_path / "case.json"
    with pytest.raises(InterruptedWriteError):
        write_receipt([LEGACY_DOC, LEGACY_XLS], path, interrupt_after=1)

    recovered = load_receipt(path)
    assert recovered.recovered_partial is True
    assert recovered.confirmed_count == 1
    assert {item.format for item in recovered.observations} == {"doc97"}

    read_only = load_receipt(path, read_only=True)
    with pytest.raises(ReceiptReadOnlyError):
        read_only.correct("missing", "format", "doc97")


def test_status_aliases_are_available_to_old_callers():
    assert ObservationStatus.CONFIRMED == "confirmed"
    assert ObservationStatus.CONFIRMED == "verified"
    assert ObservationStatus.PENDING == "待查"
