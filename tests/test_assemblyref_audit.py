import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import assemblyref_audit as audit  # noqa: E402
import make_forensic_samples as samples  # noqa: E402


class FakeStruct:
    def __init__(self, file_offset=700, **indexes):
        self._file_offset = file_offset
        self.Name_StringIndex = indexes.get("name_index", 11)
        self.Culture_StringIndex = indexes.get("culture_index", 0)
        self.PublicKey_BlobIndex = indexes.get("key_index", 7)
        self.HashValue_BlobIndex = indexes.get("hash_index", 0)
        self.Flags = indexes.get("flags_value", 0)

    def get_file_offset(self):
        return self._file_offset


class FakeRow:
    def __init__(self, name="Contoso.Core", culture="", public_key=b"\x01" * 8, flags=0):
        self.Name = name
        self.MajorVersion = 2
        self.MinorVersion = 0
        self.BuildNumber = 0
        self.RevisionNumber = 0
        self.Culture = culture
        self.PublicKey = public_key
        self.Flags = flags
        self.struct = FakeStruct(flags_value=flags)


def test_public_key_token_uses_ecma335_sha1_low_bytes_reversed():
    assert audit.public_key_token(b"\x00").hex() == "4f78a2edf6430e42"
    assert audit.public_key_token(b"") is None


def test_identity_reports_missing_culture_and_key_as_evidence_gaps():
    culture_missing = audit.identity_from_row(
        FakeRow(culture=None), "AssemblyRef", 3
    )
    key_missing = audit.identity_from_row(
        FakeRow(public_key=b""), "AssemblyRef", 4
    )

    assert culture_missing["culture_present"] is False
    assert "culture_missing" in culture_missing["evidence_gaps"]
    assert culture_missing["complete_identity"] is False
    assert culture_missing["table_evidence"]["table"] == "AssemblyRef"
    assert culture_missing["table_evidence"]["row"] == 3

    assert key_missing["public_key_token"] is None
    assert "public_key_identity_missing" in key_missing["evidence_gaps"]
    assert key_missing["complete_identity"] is False


def test_full_public_key_ref_is_converted_to_token_not_treated_as_token():
    full_key = b"publisher-full-public-key-blob"
    row = FakeRow(public_key=full_key, flags=1)

    identity = audit.identity_from_row(row, "AssemblyRef", 1)

    assert identity["public_key_kind"] == "full_public_key"
    assert identity["public_key_token"] == audit.public_key_token(full_key).hex()
    assert identity["complete_identity"] is True


@pytest.fixture()
def case_path(tmp_path):
    case = tmp_path / "forensic_case"
    samples.build_case(case)
    return case


def test_generated_case_has_confirmed_and_candidate_only_sealed_pairs(case_path):
    inventory = audit.build_inventory(
        [case_path / "references" / "Dispatch.exe"],
        [case_path / "delivery"],
        case_path / "sealing-manifest.json",
    )

    by_name = {
        entry["reference_identity"]["name"]: entry for entry in inventory["entries"]
    }
    assert inventory["summary"]["confirmed_pairs"] == 1
    assert inventory["summary"]["candidate_only_groups"] == 2

    widgets = by_name["Contoso.Widgets"]
    assert widgets["status"] == "confirmed_pair"
    assert widgets["confirmed_pair"]["seal_id"] == "SEAL-WIDGETS-310"
    assert widgets["confirmed_pair"]["seal_verified"] is True
    assert widgets["confirmed_pair"]["manifest"]["sha256_status"] == "verified"

    regional = by_name["Regional.Resources"]
    assert regional["status"] == "candidate_only"
    assert "culture_missing" in regional["evidence_gaps"]
    assert {pair["seal_id"] for pair in regional["all_pairings"]} == {
        "SEAL-REGIONAL-EN",
        "SEAL-REGIONAL-FR",
    }
    assert all(pair["sealed_artifact"] for pair in regional["all_pairings"])

    imaging = by_name["Imaging.Codec"]
    assert imaging["status"] == "candidate_only"
    assert "public_key_identity_missing" in imaging["evidence_gaps"]
    assert {pair["seal_id"] for pair in imaging["all_pairings"]} == {
        "SEAL-IMAGING-KEYA",
        "SEAL-IMAGING-KEYB",
    }

    markdown = audit.render_markdown(inventory)
    assert "## 一、确定配对" in markdown
    assert "## 二、只能提供候选的配对" in markdown
    assert "SEAL-WIDGETS-310" in markdown
    assert "SEAL-REGIONAL-EN" in markdown
    assert "SEAL-REGIONAL-FR" in markdown
    assert "证据缺项" in markdown

    json.dumps(inventory, ensure_ascii=False)


def test_manifest_digest_mismatch_demotes_confirmed_pair(case_path):
    target = case_path / "delivery" / "Contoso.Widgets_3.1.0.0.dll"
    data = bytearray(target.read_bytes())
    data[-1] ^= 0x01
    target.write_bytes(data)

    inventory = audit.build_inventory(
        [case_path / "references" / "Dispatch.exe"],
        [case_path / "delivery"],
        case_path / "sealing-manifest.json",
    )
    widgets = next(
        entry
        for entry in inventory["entries"]
        if entry["reference_identity"]["name"] == "Contoso.Widgets"
    )

    assert widgets["status"] == "candidate_only"
    pair = widgets["all_pairings"][0]
    assert pair["manifest"]["sha256_status"] == "mismatch"
    assert "manifest.sha256_mismatch" in pair["evidence_gaps"]
