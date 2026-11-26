"""End-to-end tests for the evidence-chain audit.

All managed samples are synthesized offline with
evidence_chain.sample_builder; no external test files are needed.
"""

import json

import pytest

from evidence_chain import (
    Classification,
    GenerationUnreadable,
    audit,
    normalize_mvid,
    read_module_identity,
)
from evidence_chain.__main__ import main as cli_main
from evidence_chain.audit import (
    ReleaseItem,
    ReleaseManifest,
    SupplementRecord,
    load_manifest,
    load_records,
)
from evidence_chain.sample_builder import write_sample

A1 = "11111111-1111-1111-1111-111111111111"
B1 = "22222222-2222-2222-2222-222222222222"
B9 = "22222222-9999-2222-2222-222222222222"
D1 = "44444444-4444-4444-4444-444444444444"
D2 = "44444444-5555-4444-4444-444444444444"
G0 = "66666666-6666-6666-6666-666666666666"
G1 = "77777777-7777-7777-7777-777777777777"
S1 = "88888888-8888-8888-8888-888888888888"
S9 = "99999999-9999-9999-9999-999999999999"


# ---------------------------------------------------------------------------
# generation identifier consumption
# ---------------------------------------------------------------------------


def test_read_module_identity_roundtrip(tmp_path):
    sample = write_sample(tmp_path / "Widget.Core.dll", "Widget.Core.dll", A1)
    identity = read_module_identity(sample)
    assert identity.name == "Widget.Core.dll"
    assert identity.mvid == A1


def test_read_module_identity_rejects_non_pe(tmp_path):
    bogus = tmp_path / "bogus.dll"
    bogus.write_bytes(b"this is not a PE image")
    with pytest.raises(GenerationUnreadable):
        read_module_identity(bogus)


def test_read_module_identity_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_module_identity(tmp_path / "absent.dll")


@pytest.mark.parametrize(
    "raw",
    [
        A1,
        A1.upper(),
        "{" + A1 + "}",
        "{" + A1.upper() + "}",
        "  " + A1 + "  ",
    ],
)
def test_normalize_mvid_equivalent_forms(raw):
    assert normalize_mvid(raw) == A1


@pytest.mark.parametrize("raw", [None, "", "not-a-guid", "1234"])
def test_normalize_mvid_rejects_garbage(raw):
    assert normalize_mvid(raw) is None


# ---------------------------------------------------------------------------
# archive fixture: an offline archive plus manifest and supplemental records
# ---------------------------------------------------------------------------


def _build_archive(root):
    write_sample(root / "artifacts" / "Alpha.Core.dll", "Alpha.Core.dll", A1)
    write_sample(root / "artifacts" / "Beta.Core.dll", "Beta.Core.dll", B1)
    # Delta's on-disk file has drifted to a different generation
    write_sample(root / "artifacts" / "Delta.Core.dll", "Delta.Core.dll", D2)
    write_sample(root / "artifacts" / "Shared.Core.dll", "Shared.Core.dll", S1)
    # artifacts/Gone.Core.dll is referenced by the manifest but absent
    write_sample(root / "incoming" / "Alpha.Core.dll", "Alpha.Core.dll", A1)
    write_sample(root / "incoming" / "Beta.Core.dll", "Beta.Core.dll", B9)
    write_sample(root / "incoming" / "Gamma.Core.dll", "Gamma.Core.dll", G1)
    write_sample(
        root / "incoming" / "shared_a" / "Shared.Core.dll",
        "Shared.Core.dll",
        S1,
    )
    write_sample(
        root / "incoming" / "shared_b" / "Shared.Core.dll",
        "Shared.Core.dll",
        S9,
    )
    write_sample(
        root / "incoming" / "alpha2" / "Alpha.Core.dll", "Alpha.Core.dll", A1
    )
    corrupt = root / "incoming" / "corrupt.dll"
    corrupt.write_bytes(b"MZ but otherwise garbage")


def _manifest():
    return ReleaseManifest(
        release="REL-2026-0042",
        items=[
            ReleaseItem(1, "Alpha.Core.dll", "artifacts/Alpha.Core.dll", A1),
            ReleaseItem(2, "Beta.Core.dll", "artifacts/Beta.Core.dll", B1),
            ReleaseItem(3, "Delta.Core.dll", "artifacts/Delta.Core.dll", D1),
            ReleaseItem(4, "Gone.Core.dll", "artifacts/Gone.Core.dll", G0),
            ReleaseItem(5, "Shared.Core.dll", "artifacts/Shared.Core.dll", S1),
        ],
    )


def _records():
    return [
        SupplementRecord("SUP-001", "Alpha.Core.dll",
                         "incoming/Alpha.Core.dll", "supplement note"),
        SupplementRecord("SUP-002", "Beta.Core.dll",
                         "incoming/Beta.Core.dll", "vendor swapped build"),
        SupplementRecord("SUP-003", "Gamma.Core.dll",
                         "incoming/Gamma.Core.dll", "no chain link"),
        SupplementRecord("SUP-004", "Gone.Core.dll",
                         "incoming/NotThere.dll", "witness absent"),
        SupplementRecord("SUP-005", "Shared.Core.dll",
                         "incoming/shared_b/Shared.Core.dll", "same name xgen"),
        SupplementRecord("SUP-006", "Shared.Core.dll",
                         "incoming/shared_a/Shared.Core.dll", "same name cont"),
        SupplementRecord("SUP-007", "Alpha.Core.dll",
                         "incoming/alpha2/Alpha.Core.dll", "duplicate"),
        SupplementRecord("SUP-008", "Delta.Core.dll",
                         "incoming/corrupt.dll", "corrupt sample"),
    ]


@pytest.fixture()
def report(tmp_path):
    archive = tmp_path / "archive"
    archive.mkdir()
    _build_archive(archive)
    before = {
        p.relative_to(archive): p.read_bytes()
        for p in sorted(archive.rglob("*"))
        if p.is_file()
    }
    result = audit(_manifest(), _records(), archive_root=archive)
    after = {
        p.relative_to(archive): p.read_bytes()
        for p in sorted(archive.rglob("*"))
        if p.is_file()
    }
    assert before == after, "audit must be strictly read-only"
    return result


def _verdict(report, record_id):
    matches = [v for v in report.submissions if v.record_id == record_id]
    assert len(matches) == 1
    return matches[0]


# ---------------------------------------------------------------------------
# old-record audit: do referenced external files still correspond?
# ---------------------------------------------------------------------------


def test_manifest_audit_location_and_generation(report):
    by_component = {e.component: e for e in report.manifest_audit}
    assert by_component["Alpha.Core.dll"].location_status == "intact"
    assert by_component["Alpha.Core.dll"].generation_status == "confirmed"
    assert by_component["Delta.Core.dll"].generation_status == "diverged"
    assert by_component["Delta.Core.dll"].observed_mvid == D2
    gone = by_component["Gone.Core.dll"]
    assert gone.location_status == "missing"
    assert gone.generation_status is None


# ---------------------------------------------------------------------------
# classification along the external archive chain
# ---------------------------------------------------------------------------


def test_supplement_same_generation_accepted(report):
    verdict = _verdict(report, "SUP-001")
    assert verdict.classification is Classification.SUPPLEMENT
    assert verdict.accepted
    assert verdict.reason == "generation-continues"
    assert verdict.observed_mvid == A1
    assert verdict.module_name == "Alpha.Core.dll"
    assert not verdict.name_mismatch


def test_cross_generation_replacement_rejected(report):
    verdict = _verdict(report, "SUP-002")
    assert verdict.classification is Classification.REPLACEMENT
    assert not verdict.accepted
    assert verdict.reason == "cross-generation"
    assert verdict.observed_mvid == B9
    assert verdict.recognized_mvid == B1


def test_missing_witness_no_recognized_generation(report):
    verdict = _verdict(report, "SUP-003")
    assert verdict.classification is Classification.MISSING_WITNESS
    assert not verdict.accepted
    assert verdict.reason == "no-recognized-generation"


def test_missing_witness_artifact_absent(report):
    verdict = _verdict(report, "SUP-004")
    assert verdict.classification is Classification.MISSING_WITNESS
    assert not verdict.accepted
    assert verdict.reason == "artifact-absent"
    assert verdict.recognized_mvid == G0


def test_unreadable_sample_is_indeterminate(report):
    verdict = _verdict(report, "SUP-008")
    assert verdict.classification is Classification.INDETERMINATE
    assert not verdict.accepted
    assert verdict.reason == "unreadable-sample"


def test_same_name_records_only_generation_continuing_accepted(report):
    cross = _verdict(report, "SUP-005")
    continuing = _verdict(report, "SUP-006")
    assert cross.classification is Classification.REPLACEMENT
    assert not cross.accepted
    assert continuing.classification is Classification.SUPPLEMENT
    assert continuing.accepted
    shared = [
        v for v in report.submissions if v.component == "Shared.Core.dll"
    ]
    assert sum(1 for v in shared if v.accepted) == 1


def test_duplicate_supplement_superseded(report):
    verdict = _verdict(report, "SUP-007")
    assert verdict.classification is Classification.DUPLICATE
    assert not verdict.accepted
    assert verdict.reason == "superseded-by-SUP-001"


# ---------------------------------------------------------------------------
# evidence catalog continues the original release order
# ---------------------------------------------------------------------------


def test_catalog_continues_release_order(report):
    catalog = report.catalog
    assert [e.seq for e in catalog] == [1, 2, 3, 4, 5, 6, 7]
    release_entries = [e for e in catalog if e.origin == "release"]
    assert [e.component for e in release_entries] == [
        "Alpha.Core.dll",
        "Beta.Core.dll",
        "Delta.Core.dll",
        "Gone.Core.dll",
        "Shared.Core.dll",
    ]
    supplements = [e for e in catalog if e.origin == "supplement"]
    assert [(e.seq, e.source_record) for e in supplements] == [
        (6, "SUP-001"),
        (7, "SUP-006"),
    ]
    shared = [e for e in supplements if e.component == "Shared.Core.dll"]
    assert len(shared) == 1
    assert shared[0].mvid == S1
    assert shared[0].location == "incoming/shared_a/Shared.Core.dll"


def test_catalog_release_entries_carry_audit_status(report):
    by_component = {e.component: e for e in report.catalog}
    assert by_component["Gone.Core.dll"].location_status == "missing"
    assert by_component["Delta.Core.dll"].generation_status == "diverged"
    assert by_component["Alpha.Core.dll"].generation_status == "confirmed"


# ---------------------------------------------------------------------------
# JSON loading and the CLI
# ---------------------------------------------------------------------------


def test_load_manifest_normalizes_mvids(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "release": "REL-X",
                "items": [
                    {
                        "seq": 1,
                        "component": "Shared.Core.dll",
                        "location": "artifacts/Shared.Core.dll",
                        "mvid": "{" + S1.upper() + "}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    assert manifest.recognized_generations == {"Shared.Core.dll": S1}


def test_load_manifest_rejects_malformed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"items": [{"seq": 1}]}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(bad)


def test_load_records_roundtrip(tmp_path):
    records_path = tmp_path / "records.json"
    records_path.write_text(
        json.dumps(
            {
                "submissions": [
                    {
                        "record_id": "SUP-1",
                        "component": "A.dll",
                        "location": "incoming/A.dll",
                        "note": "n",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (records,) = load_records(records_path)
    assert records.record_id == "SUP-1"
    assert records.note == "n"


def test_cli_end_to_end(tmp_path):
    archive = tmp_path / "archive"
    archive.mkdir()
    _build_archive(archive)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "release": "REL-2026-0042",
                "items": [
                    {
                        "seq": item.seq,
                        "component": item.component,
                        "location": item.location,
                        "mvid": item.recognized_mvid,
                    }
                    for item in _manifest().items
                ],
            }
        ),
        encoding="utf-8",
    )
    records_path = tmp_path / "records.json"
    records_path.write_text(
        json.dumps(
            {
                "submissions": [
                    {
                        "record_id": r.record_id,
                        "component": r.component,
                        "location": r.location,
                        "note": r.note,
                    }
                    for r in _records()
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "evidence_catalog.json"
    rc = cli_main(
        [
            "audit",
            "--manifest",
            str(manifest_path),
            "--records",
            str(records_path),
            "--archive-root",
            str(archive),
            "--output",
            str(output),
        ]
    )
    assert rc == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["release"] == "REL-2026-0042"
    assert [e["seq"] for e in payload["catalog"]] == [1, 2, 3, 4, 5, 6, 7]
    verdicts = {v["record_id"]: v for v in payload["submissions"]}
    assert verdicts["SUP-001"]["classification"] == "supplement"
    assert verdicts["SUP-002"]["classification"] == "replacement"
    assert verdicts["SUP-004"]["classification"] == "missing_witness"
    assert verdicts["SUP-006"]["accepted"] is True
    assert verdicts["SUP-005"]["accepted"] is False
