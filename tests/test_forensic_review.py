"""Acceptance tests for local Office structure reconciliation."""

import json
from os.path import dirname, join

import pytest

from msoffcrypto.forensic_review import (
    ConclusionStatus,
    compare_structures,
    inspect_macro_free,
    read_structure,
    reconcile_archive_report,
    reconcile_report,
)
from msoffcrypto.__main__ import main


DATA_DIR = join(dirname(__file__), "inputs")
DOCX = join(DATA_DIR, "example_password.docx")
XLSX = join(DATA_DIR, "example_password.xlsx")
PASSWORD = "Password1234_"


def _witness(structure, stream="EncryptedPackage", **overrides):
    descriptor = structure.stream_map["encryptedpackage"]
    witness = {
        "witness_id": "witness-1",
        "verified": True,
        "logical_stream": stream,
        "stream_sha256": descriptor.sha256,
    }
    witness.update(overrides)
    return witness


def test_logical_public_and_witness_can_match_despite_layout_difference():
    local = read_structure(DOCX)
    reference = {
        "logical_stream": "EncryptedPackage",
        "public_structure": {
            "profile": "ooxml-encrypted",
            "encryption_format": "agile",
            "required_streams": ["EncryptionInfo", "EncryptedPackage"],
        },
        "physical_layout": {
            "sector_size": 4096,
            "locations": {"EncryptedPackage": 1024},
        },
        "witness": _witness(local),
    }

    result = compare_structures(local, reference)

    assert result.logical_name_matches is True
    assert result.public_structure_matches is True
    assert result.witness_verified is True
    assert result.layout_matches is False
    assert result.relatable is True
    assert result.confirmed is True
    assert result.status == ConclusionStatus.CONFIRMED
    assert result.status == "verified"


def test_archive_report_pends_layout_claim_but_retains_stream_identity_claim():
    local = read_structure(DOCX)
    report = {
        "archive_id": "fictional-report",
        "evidence": [
            {
                "id": "E1",
                "path": DOCX,
                "logical_stream": "EncryptedPackage",
                "profile": "ooxml-encrypted",
                "original_layout": {"locations": {"EncryptedPackage": 777}},
                "witness": _witness(local),
            }
        ],
        "conclusions": [
            {
                "id": "layout",
                "evidence_id": "E1",
                "text": "The original layout at sector offset 777 proves this evidence.",
            },
            {
                "id": "stream",
                "evidence_id": "E1",
                "basis": "stream_identity",
                "text": "Although the physical layout differs, the proven logical stream identity supports this conclusion.",
            },
        ],
    }

    result = reconcile_report(report)
    by_id = {item["id"]: item for item in result.conclusions}

    assert by_id["layout"].cites_original_layout is True
    assert by_id["layout"].pending is True
    assert by_id["layout"].retained is False
    assert by_id["layout"].status == "pending_verification"
    assert by_id["layout"].status == "pending"

    assert by_id["stream"].cites_original_layout is False
    assert by_id["stream"].retained is True
    assert by_id["stream"].pending is False
    assert by_id["stream"].status == "retained"
    assert by_id["stream"].status == "verified"

    payload = json.loads(result.to_json())
    assert payload["pending_count"] == 1
    assert payload["retained_count"] == 1


def test_fictional_archive_fixture_acceptance():
    report_path = join(DATA_DIR, "cold_storage_archive_report.json")
    result = reconcile_archive_report(report_path, base_dir=DATA_DIR)
    by_id = {item["id"]: item for item in result.conclusions}

    assert by_id["CONCLUSION-ORIGINAL-LAYOUT"].status == "待核"
    assert by_id["CONCLUSION-ORIGINAL-LAYOUT"].pending_verification is True
    assert by_id["CONCLUSION-STREAM-IDENTITY"].status == "保留"
    assert by_id["CONCLUSION-STREAM-IDENTITY"].identity_proven is True


def test_review_report_cli(tmp_path):
    report_path = join(DATA_DIR, "cold_storage_archive_report.json")
    json_out = tmp_path / "review.json"

    return_code = main(
        [
            "review-report",
            report_path,
            "--base-dir",
            DATA_DIR,
            "--json-out",
            str(json_out),
        ]
    )

    assert return_code == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["pending_count"] == 1
    assert payload["retained_count"] == 1


@pytest.mark.parametrize("sample", [DOCX, XLSX])
def test_legal_samples_are_macro_free_after_decryption(sample):
    result = inspect_macro_free(sample, password=PASSWORD, verify_integrity=True)
    assert result.checked is True
    assert result.macro_free is True
    assert result.macro_parts == ()


def test_wrong_logical_stream_or_witness_digest_blocks_confirmation():
    local = read_structure(DOCX)

    wrong_name = compare_structures(
        local,
        {"logical_stream": "EncryptionPackage", "witness": _witness(local, stream="EncryptionPackage")},
    )
    wrong_digest = compare_structures(
        local,
        {
            "logical_stream": "EncryptedPackage",
            "witness": _witness(local, stream_sha256="0" * 64),
        },
    )
    missing_witness = compare_structures(local, {"logical_stream": "EncryptedPackage"})

    assert wrong_name.logical_name_matches is False
    assert wrong_name.relatable is False
    assert wrong_digest.witness_verified is False
    assert wrong_digest.relatable is False
    assert missing_witness.witness_verified is False
    assert missing_witness.relatable is False


def test_report_without_proven_identity_does_not_retain_conclusion():
    report = {
        "evidence": [
            {
                "id": "E1",
                "path": DOCX,
                "logical_stream": "EncryptedPackage",
                "witness": {"verified": False, "status": "invalid"},
            }
        ],
        "conclusions": [{"id": "C1", "evidence_id": "E1", "basis": "stream_identity"}],
    }

    result = reconcile_report(report)
    conclusion = result.conclusions[0]

    assert conclusion.identity_proven is False
    assert conclusion.retained is False
    assert conclusion.pending is True
