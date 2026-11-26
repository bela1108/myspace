from pathlib import Path

import pytest

from protection_attestation.inspect import inspect_package
from protection_attestation.intake import run_batch
from protection_attestation.reporting import write_reports
from protection_attestation.rules import normalize_claim


ROOT = Path(__file__).resolve().parents[1]
SHA1_PACKAGE = ROOT / "tests/inputs/ecma376agile_sha1_password.xlsx"
SHA512_DOCX = ROOT / "tests/inputs/example_password.docx"
BATCH_1 = ROOT / "protection_attestation/handoff/batch-1-handoff.json"
BATCH_2 = ROOT / "protection_attestation/handoff/batch-2-recheck.json"


def test_inspect_reads_agile_parameters_without_plaintext():
    result = inspect_package(SHA1_PACKAGE)

    assert result["plaintext_accessed"] is False
    assert result["protection_format"] == "agile"
    assert result["parameters"]["key_length_bits"] == 128
    assert result["parameters"]["hash_algorithm"] == "SHA1"
    assert result["parameters"]["spin_count"] == 100000
    assert result["parameters"]["encryption_suite"] == {
        "cipher_algorithm": "AES",
        "key_length_bits": 128,
        "cipher_chaining": "ChainingModeCBC",
    }


def test_byte_length_and_historical_hash_are_accepted_by_new_rules():
    length = normalize_claim(
        "key_length_bits",
        {"value": 16, "unit": "字节"},
        "archivist-rules-2026.2",
    )
    historical_hash = normalize_claim(
        "hash_algorithm",
        "SHA-1",
        "archivist-rules-2026.2",
        historical=True,
    )
    description = normalize_claim(
        "hash_algorithm",
        "SHA-1 摘要算法",
        "archivist-rules-2026.2",
    )

    assert length.accepted
    assert length.canonical_value == 128
    assert length.rule_id == "length.bytes_to_bits"
    assert historical_hash.accepted
    assert historical_hash.canonical_value == "SHA1"
    assert historical_hash.historical_compatibility is True
    assert historical_hash.rule_id == "hash.v1_canonical_compat"
    assert description.accepted
    assert description.canonical_value == "SHA1"


def test_old_ruleset_uses_hyphen_canonical_notation():
    office_token = normalize_claim(
        "hash_algorithm",
        "SHA512",
        "archivist-rules-2024.1",
    )

    assert office_token.accepted
    assert office_token.canonical_value == "SHA-512"
    assert office_token.rule_id == "hash.office_to_archival_hyphen"


@pytest.mark.parametrize("config_path", [BATCH_1, BATCH_2])
def test_batches_identify_notation_only_and_actual_update(config_path, tmp_path):
    result = run_batch(config_path)

    assert result["plaintext_accessed"] is False
    assert result["summary"]["package_count"] == 3
    assert result["summary"]["rejected_claim_count"] == 0
    assert result["summary"]["source_conflict_count"] == 0
    assert result["summary"]["review_cases_verified"] is True
    assert result["summary"]["reapproval_required_count"] == 1

    differences = result["protection_differences"]
    assert len(differences) == 1
    assert differences[0]["package_id"] == "ARCH-002"
    assert differences[0]["field"] == "spin_count"
    assert differences[0]["approved_value"] == 50000
    assert differences[0]["observed_value"] == 100000

    notation_case = next(case for case in result["review_cases"] if case["case_id"] == "CASE-NOTATION-001")
    update_case = next(case for case in result["review_cases"] if case["case_id"] == "CASE-UPDATE-002")
    assert notation_case["verified"] is True
    assert notation_case["matching_difference_count"] == 0
    assert notation_case["matching_transcription_note_count"] == 3
    assert update_case["verified"] is True
    assert update_case["matching_difference_count"] == 1

    write_reports(result, tmp_path)
    expected_files = {
        "report.md",
        "ledger.json",
        "ledger.csv",
        "transcription-notes.md",
        "transcription-notes.json",
        "protection-differences.md",
        "protection-differences.json",
        "reapproval-queue.md",
        "reapproval-queue.json",
        "review-cases.json",
    }
    assert expected_files.issubset({path.name for path in tmp_path.iterdir()})


def test_unknown_algorithm_alias_is_rejected_not_guessed():
    claim = normalize_claim(
        "hash_algorithm",
        "MD5-ish internal notation",
        "archivist-rules-2026.2",
    )

    assert claim.accepted is False
    assert claim.canonical_value is None
