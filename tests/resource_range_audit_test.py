import hashlib
import json

import pefile
from resource_range_audit import (
    ALPHA_PAYLOAD,
    DUPLICATE_PAYLOAD,
    PADDED_PAYLOAD,
    build_benign_resource_pair,
)


def _findings_by_id(report):
    return {item["id"]: item for item in report["findings"]}


def test_benign_pair_parses_with_different_alignments(tmp_path):
    bundle = build_benign_resource_pair(tmp_path / "samples")

    source_pe = pefile.PE(bundle["source"]["path"])
    target_pe = pefile.PE(bundle["target"]["path"])

    assert source_pe.OPTIONAL_HEADER.FileAlignment == 0x200
    assert source_pe.OPTIONAL_HEADER.SectionAlignment == 0x1000
    assert target_pe.OPTIONAL_HEADER.FileAlignment == 0x80
    assert target_pe.OPTIONAL_HEADER.SectionAlignment == 0x80
    assert len(source_pe.DIRECTORY_ENTRY_RESOURCE.entries) == 1
    assert len(target_pe.DIRECTORY_ENTRY_RESOURCE.entries) == 1


def test_audit_classifies_verified_candidate_and_out_of_range(tmp_path):
    bundle = build_benign_resource_pair(tmp_path / "samples")
    report = pefile.audit_resource_ranges(bundle["manifest"])
    findings = _findings_by_id(report)

    assert report["read_only"] is True
    assert report["content_included"] is False
    assert report["summary"]["total"] == 5
    assert report["summary"]["verified_copy"] == 3
    assert report["summary"]["candidate_only"] == 1
    assert report["summary"]["out_of_range_source"] == 1
    assert report["counts"]["已核实拷贝"] == 3

    alpha = findings["ALPHA-TRANSFER"]
    duplicate = findings["DUPLICATE-TRANSFER"]
    cross_align = findings["CROSS-ALIGN-TRANSFER"]
    padded = findings["PADDED-TRANSFER"]
    ghost = findings["GHOST-OFFSET"]

    assert alpha["status"] == "verified_copy"
    assert alpha["classification_zh"] == "已核实拷贝"
    assert alpha["verified"] is True
    assert alpha["export_permission"]["status"] == "granted"
    assert alpha["source_section"] == ".rsrc"
    assert alpha["target_section"] == ".rsrc"
    assert alpha["source_offset"] != alpha["target_offset"]
    assert alpha["source_size"] == alpha["target_size"]

    assert duplicate["status"] == "candidate_only"
    assert duplicate["classification_zh"] == "只能定位到候选"
    assert duplicate["verified"] is False
    candidate_ids = [
        item["resource_path"]["resource_id"] for item in duplicate["candidates"]
    ]
    assert candidate_ids == [202, 203]

    raw_occurrences = duplicate["target"]["raw_occurrences"]
    assert len(raw_occurrences) == 2
    assert (
        sum(
            "exact_resource_range" in item["resource_relations"]
            for item in raw_occurrences
        )
        == 2
    )

    cross_occurrences = cross_align["target"]["raw_occurrences"]
    assert cross_align["status"] == "verified_copy"
    assert len(cross_occurrences) == 2
    assert any(
        item["location_class"] == "section_alignment_padding"
        for item in cross_occurrences
    )
    assert (
        sum(
            "exact_resource_range" in item["resource_relations"]
            for item in cross_occurrences
        )
        == 1
    )

    padding = padded["provenance"]["source"]["trailing_alignment_padding"]
    assert padded["status"] == "verified_copy"
    assert padding["byte_count"] == 16
    assert padding["all_zero"] is True
    assert padded["source_size"] == len(PADDED_PAYLOAD)

    assert ghost["status"] == "out_of_range_source"
    assert ghost["classification_zh"] == "超范围来源"
    assert ghost["verified"] is False
    assert ghost["source"]["range"]["valid_file_range"] is False


def test_verified_ranges_retain_full_provenance_without_bytes(tmp_path):
    bundle = build_benign_resource_pair(tmp_path / "samples")
    report = pefile.audit_resource_ranges(
        bundle["source"]["path"],
        bundle["target"]["path"],
        bundle["records"],
    )

    source_digest = hashlib.sha256(
        open(bundle["source"]["path"], "rb").read()
    ).hexdigest()
    target_digest = hashlib.sha256(
        open(bundle["target"]["path"], "rb").read()
    ).hexdigest()

    for item in report["verified"]:
        provenance = item["provenance"]
        source = provenance["source"]
        target = provenance["target"]["verified_range"]

        assert source["artifact"]["sha256"] == source_digest
        assert provenance["target"]["artifact"]["sha256"] == target_digest
        assert source["verified_range"]["sha256"] == item["sha256"]
        assert target["sha256"] == item["sha256"]
        assert source["verified_range"]["raw_offset"] == item["source_offset"]
        assert target["raw_offset"] == item["target_offset"]
        assert source["verified_range"]["section_name"] == ".rsrc"
        assert target["section_name"] == ".rsrc"
        assert provenance["comparison"]["byte_for_byte"] is True
        assert provenance["comparison"]["content_included"] is False

    serialized = report.to_json()
    assert "PE-AUDIT-ALPHA-RANGE" not in serialized
    assert DUPLICATE_PAYLOAD.decode("ascii") not in serialized
    assert "PE-AUDIT-CROSS-ALIGN" not in serialized
    assert "PE-AUDIT-PADDED" not in serialized

    restored = report.to_dict()
    assert restored["schema"] == pefile.RESOURCE_RANGE_AUDIT_SCHEMA
    json.dumps(report)


def test_scalar_section_offset_can_use_source_resource_boundary(tmp_path):
    bundle = build_benign_resource_pair(tmp_path / "samples")
    offset = bundle["records"][0]["section_offset"]

    report = pefile.audit_resource_ranges(
        bundle["source"]["path"], bundle["target"]["path"], [offset]
    )

    assert report.findings[0]["classification"] == "verified_copy"
    assert report.findings[0]["source_size"] == len(ALPHA_PAYLOAD)


def test_export_denial_is_separately_visible(tmp_path):
    bundle = build_benign_resource_pair(tmp_path / "samples")
    records = [dict(bundle["records"][0], export_allowed=False)]

    report = pefile.audit_resource_ranges(
        bundle["source"]["path"], bundle["target"]["path"], records
    )
    finding = report.findings[0]

    assert finding["classification"] == "verified_copy"
    assert finding["copy_verified"] is True
    assert finding["status"] == "export_denied"
    assert finding["authorized"] is False


def test_pe_instance_method_and_manifest_aliases(tmp_path):
    bundle = build_benign_resource_pair(tmp_path / "samples")
    source_pe = pefile.PE(bundle["source"]["path"])
    target_pe = pefile.PE(bundle["target"]["path"])

    report = source_pe.audit_resource_ranges(target_pe, bundle["records"])

    assert report["summary"]["verified_copy"] == 3
    assert (
        pefile.audit_resource_transfers(bundle["manifest"])["summary"]
        == (report["summary"])
    )
