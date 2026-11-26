#!/usr/bin/env python3
"""Build and structurally audit a minimal PE with placeholder sign-off segments.

This tool is intentionally offline and structural-only.  Its placeholder
``WIN_CERTIFICATE`` bytes are not PKCS#7 data and no Authenticode trust path is
evaluated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

import pefile  # noqa: E402

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADERS_SIZE = 0x200
TEXT_RAW_OFFSET = 0x200
RCP0_RAW_OFFSET = 0x400
RCP1_RAW_OFFSET = 0x600
SECURITY_OFFSET = 0x800
IMAGE_BASE = 0x140000000


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_receipt_payload(receipt_id: str, retention: str, disposition: str) -> bytes:
    return (
        b"RCPPLACEHOLDER/1\n"
        + f"receipt-id: {receipt_id}\n".encode("utf-8")
        + f"retention: {retention}\n".encode("utf-8")
        + f"project-disposition: {disposition}\n".encode("utf-8")
        + b"structure: retained-in-pe-section-raw-data\n"
        + b"notice: structural placeholder; not a cryptographic signature\n"
    )


def make_win_certificate(label: bytes) -> bytes:
    """Build one 8-byte-aligned ``WIN_CERTIFICATE`` envelope placeholder."""
    certificate_bytes = (
        b"STRUCTURAL-PLACEHOLDER-WIN_CERTIFICATE/1\n"
        + b"label: "
        + label
        + b"\nnotice: not-pkcs7-not-authenticode-trust-evidence\n"
    )
    declared_length = 8 + len(certificate_bytes)
    padding_length = (-declared_length) % 8
    header = struct.pack("<IHH", declared_length, 0x0200, 0x0002)
    return header + certificate_bytes + b"\x00" * padding_length


def build_minimal_pe() -> tuple[bytes, dict[str, Any]]:
    alpha_id = "RCPT-APPROVED-ALPHA"
    beta_id = "RCPT-COUNTERSIGN-BETA"
    alpha_payload = make_receipt_payload(alpha_id, "approved", "approved-for-retention")
    beta_payload = make_receipt_payload(beta_id, "retained", "second-leg-of-signoff")

    image = bytearray(SECURITY_OFFSET)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)

    pe_offset = 0x40
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    coff_offset = pe_offset + 4
    optional_offset = coff_offset + 20

    struct.pack_into(
        "<HHIIIHH",
        image,
        coff_offset,
        0x8664,  # IMAGE_FILE_MACHINE_AMD64
        3,  # .text, .rcp0, .rcp1
        0,
        0,
        0,
        0xF0,  # PE32+ optional header size
        0x0022,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    optional_values = [
        ("<H", 0, 0x20B),
        ("<BB", 2, 14, 0),
        ("<I", 4, FILE_ALIGNMENT),  # SizeOfCode
        ("<I", 8, 2 * FILE_ALIGNMENT),  # SizeOfInitializedData
        ("<I", 12, 0),
        ("<I", 16, SECTION_ALIGNMENT),  # AddressOfEntryPoint
        ("<I", 20, SECTION_ALIGNMENT),  # BaseOfCode
        ("<Q", 24, IMAGE_BASE),
        ("<I", 32, SECTION_ALIGNMENT),
        ("<I", 36, FILE_ALIGNMENT),
        ("<HH", 40, 6, 0),
        ("<HH", 44, 1, 0),
        ("<HH", 48, 6, 0),
        ("<I", 52, 0),
        ("<I", 56, 4 * SECTION_ALIGNMENT),  # SizeOfImage through RVA 0x3fff
        ("<I", 60, HEADERS_SIZE),
        ("<I", 64, 0),  # CheckSum
        ("<H", 68, 3),  # IMAGE_SUBSYSTEM_WINDOWS_CUI
        ("<H", 70, 0),
        ("<Q", 72, 0x100000),
        ("<Q", 80, 0x1000),
        ("<Q", 88, 0x100000),
        ("<Q", 96, 0x1000),
        ("<I", 104, 0),
        ("<I", 108, 16),
    ]
    for item in optional_values:
        fmt, relative_offset, *values = item
        struct.pack_into(fmt, image, optional_offset + relative_offset, *values)

    certificate_table = make_win_certificate(b"PKG-WIN-0001-SEG-A") + make_win_certificate(
        b"PKG-WIN-0001-SEG-B"
    )
    security_directory_offset = optional_offset + 112 + 4 * 8
    struct.pack_into(
        "<II",
        image,
        security_directory_offset,
        SECURITY_OFFSET,
        len(certificate_table),
    )
    image.extend(certificate_table)

    def write_section_header(
        index: int,
        name: bytes,
        virtual_size: int,
        virtual_address: int,
        raw_size: int,
        raw_offset: int,
        characteristics: int,
        payload: bytes,
    ) -> None:
        header_offset = optional_offset + 0xF0 + index * 40
        struct.pack_into(
            "<8sIIIIIIHHI",
            image,
            header_offset,
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            characteristics,
        )
        image[raw_offset : raw_offset + len(payload)] = payload

    write_section_header(
        0,
        b".text",
        1,
        SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        TEXT_RAW_OFFSET,
        0x60000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ
        b"\xc3",
    )
    write_section_header(
        1,
        b".rcp0",
        len(alpha_payload),
        2 * SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        RCP0_RAW_OFFSET,
        0x40000040,  # CNT_INITIALIZED_DATA | MEM_READ
        alpha_payload,
    )
    write_section_header(
        2,
        b".rcp1",
        len(beta_payload),
        3 * SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        RCP1_RAW_OFFSET,
        0x40000040,
        beta_payload,
    )

    layout = {
        "alpha_id": alpha_id,
        "beta_id": beta_id,
        "alpha_payload": alpha_payload,
        "beta_payload": beta_payload,
        "alpha_sha256": sha256_hex(alpha_payload),
        "beta_sha256": sha256_hex(beta_payload),
        "certificate_table_size": len(certificate_table),
    }
    return bytes(image), layout


def build_fixture(outdir: Path) -> dict[str, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    pe_path = outdir / "minimal-two-receipt-sections.exe"
    manifest_path = outdir / "project-signoff-manifest.json"
    order_a_path = outdir / "external-registration-order-a.json"
    order_b_path = outdir / "external-registration-order-b.json"

    pe_bytes, layout = build_minimal_pe()
    pe_path.write_bytes(pe_bytes)

    ghost_payload = b"claimed section .rcp9; never present in the PE section table\n"
    manifest = {
        "schema": "project-signoff-manifest/v1-structural-fixture",
        "scope": "Offline structural reconciliation only; no signature trust validation.",
        "pe_file": pe_path.name,
        "windows_release_report": {
            "registered_signature_package_count": 1,
            "package_numbers": ["PKG-WIN-0001"],
            "pe_data_directory": "IMAGE_DIRECTORY_ENTRY_SECURITY",
            "data_directory_index": pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            "note": "One Windows data-directory registration can contain multiple aligned WIN_CERTIFICATE records.",
        },
        "alignment_policy": {
            "section_alignment": SECTION_ALIGNMENT,
            "file_alignment": FILE_ALIGNMENT,
            "win_certificate_alignment": 8,
            "preserve_raw_padding": True,
        },
        "receipts": [
            {
                "receipt_id": layout["alpha_id"],
                "archive_accession": "SIGNBOOK-ALPHA",
                "source": "project_manifest",
                "pe_section": ".rcp0",
                "payload_offset_in_section": 0,
                "payload_size": len(layout["alpha_payload"]),
                "payload_sha256": layout["alpha_sha256"],
                "retention": "approved",
            },
            {
                "receipt_id": layout["beta_id"],
                "archive_accession": "SIGNBOOK-BETA",
                "source": "project_manifest",
                "pe_section": ".rcp1",
                "payload_offset_in_section": 0,
                "payload_size": len(layout["beta_payload"]),
                "payload_sha256": layout["beta_sha256"],
                "retention": "retained",
            },
            {
                "receipt_id": "RCPT-GHOST-MISSING-SECTION",
                "archive_accession": "SIGNBOOK-GHOST",
                "source": "project_manifest",
                "pe_section": ".rcp9",
                "payload_offset_in_section": 0,
                "payload_size": len(ghost_payload),
                "payload_sha256": sha256_hex(ghost_payload),
                "retention": "claimed",
            },
            {
                "receipt_id": "ARCHIVE-DUP-ALPHA",
                "archive_accession": "SIGNBOOK-ALPHA-DUPLICATE",
                "source": "duplicate_archive",
                "pe_section": ".rcp0",
                "duplicate_of": layout["alpha_id"],
                "payload_offset_in_section": 0,
                "payload_size": len(layout["alpha_payload"]),
                "payload_sha256": layout["alpha_sha256"],
                "retention": "duplicate-copy",
            },
        ],
    }
    write_json(manifest_path, manifest)

    order_a = {
        "schema": "external-registration/v1-order-a",
        "package_no": "PKG-WIN-0001",
        "registrations": [
            {
                "registration_no": "EXT-B-SECOND-IN-A",
                "receipt_id": layout["beta_id"],
                "payload_sha256": layout["beta_sha256"],
            },
            {
                "registration_no": "EXT-A-APPROVED-SECOND-IN-A",
                "receipt_id": layout["alpha_id"],
                "payload_sha256": layout["alpha_sha256"],
            },
        ],
    }
    order_b = dict(order_a)
    order_b["schema"] = "external-registration/v1-order-b-swapped"
    order_b["registrations"] = list(reversed(order_a["registrations"]))
    write_json(order_a_path, order_a)
    write_json(order_b_path, order_b)

    return {
        "pe": pe_path,
        "manifest": manifest_path,
        "order_a": order_a_path,
        "order_b": order_b_path,
    }


def _hex(value: int) -> str:
    return f"0x{value:x}"


def audit_security_directory(
    data: bytes, pe: pefile.PE, errors: list[str]
) -> dict[str, Any]:
    directory_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    offset = directory.VirtualAddress
    size = directory.Size

    result: dict[str, Any] = {
        "source": "pefile.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_SECURITY]",
        "directory_index": directory_index,
        "directory_entry_encoding": "For this directory only, VirtualAddress is a raw file offset, not an RVA.",
        "file_offset": _hex(offset),
        "file_offset_int": offset,
        "size_bytes": size,
        "offset_8byte_aligned": offset % 8 == 0,
        "size_8byte_aligned": size % 8 == 0,
        "win_certificates": [],
    }
    if offset == 0 or size == 0:
        errors.append("security directory is empty")
        return result
    if offset + size > len(data):
        errors.append("security directory exceeds file size")
        return result
    if offset % 8 != 0:
        errors.append("security directory offset is not 8-byte aligned")
    if size % 8 != 0:
        errors.append("security directory size is not 8-byte aligned")

    cursor = offset
    table_end = offset + size
    certificate_index = 0
    while cursor < table_end:
        if cursor + 8 > table_end:
            errors.append(f"WIN_CERTIFICATE header at {_hex(cursor)} is truncated")
            break
        declared_length, revision, certificate_type = struct.unpack_from(
            "<IHH", data, cursor
        )
        if declared_length < 8 or cursor + declared_length > table_end:
            errors.append(f"WIN_CERTIFICATE length at {_hex(cursor)} is invalid")
            break

        aligned_length = (declared_length + 7) & ~7
        if cursor + aligned_length > table_end:
            errors.append(f"WIN_CERTIFICATE alignment padding at {_hex(cursor)} exceeds directory size")
            break

        payload = data[cursor + 8 : cursor + declared_length]
        padding = data[cursor + declared_length : cursor + aligned_length]
        record = {
            "index": certificate_index,
            "header_file_offset": _hex(cursor),
            "declared_length_bytes": declared_length,
            "aligned_span_bytes": aligned_length,
            "wRevision": _hex(revision),
            "wCertificateType": _hex(certificate_type),
            "payload_file_range": {
                "start": _hex(cursor + 8),
                "end_exclusive": _hex(cursor + declared_length),
                "sha256": sha256_hex(payload),
            },
            "alignment_padding": {
                "start": _hex(cursor + declared_length),
                "end_exclusive": _hex(cursor + aligned_length),
                "byte_count": len(padding),
                "all_zero": padding == b"\x00" * len(padding),
            },
            "next_offset_8byte_aligned": (cursor + aligned_length) % 8 == 0,
            "structural_note": "Placeholder envelope only; bCertificate is not parsed as PKCS#7.",
        }
        result["win_certificates"].append(record)
        if not record["alignment_padding"]["all_zero"]:
            errors.append(f"WIN_CERTIFICATE padding at {_hex(cursor)} is not zeroed")
        cursor += aligned_length
        certificate_index += 1

    result["parsed_record_count"] = certificate_index
    result["consumes_directory_exactly"] = cursor == table_end
    if cursor != table_end:
        errors.append("security directory size does not exactly cover aligned certificate records")
    if certificate_index != 2:
        errors.append(f"expected two placeholder WIN_CERTIFICATE records, found {certificate_index}")
    return result


def audit_fixture(outdir: Path) -> dict[str, Any]:
    pe_path = outdir / "minimal-two-receipt-sections.exe"
    manifest_path = outdir / "project-signoff-manifest.json"
    order_a_path = outdir / "external-registration-order-a.json"
    order_b_path = outdir / "external-registration-order-b.json"

    data = pe_path.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    order_a = json.loads(order_a_path.read_text(encoding="utf-8"))
    order_b = json.loads(order_b_path.read_text(encoding="utf-8"))
    errors: list[str] = []

    pe = pefile.PE(str(pe_path), fast_load=False)
    file_header = pe.FILE_HEADER
    optional_header = pe.OPTIONAL_HEADER
    sections_by_name = {
        section.Name.rstrip(b"\x00").decode("ascii"): section for section in pe.sections
    }

    section_evidence: list[dict[str, Any]] = []
    payload_spec_by_section: dict[str, dict[str, Any]] = {}
    for receipt in manifest["receipts"]:
        payload_spec_by_section.setdefault(receipt["pe_section"], receipt)

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii")
        raw_start = section.PointerToRawData
        raw_size = section.SizeOfRawData
        raw_end = raw_start + raw_size
        raw_bytes = data[raw_start:raw_end]
        spec = payload_spec_by_section.get(name)
        payload_evidence = None
        if spec and raw_size:
            payload_size = spec["payload_size"]
            payload = raw_bytes[:payload_size]
            padding = raw_bytes[payload_size:]
            payload_evidence = {
                "manifest_receipt_id": spec["receipt_id"],
                "offset_in_section": 0,
                "size_bytes": payload_size,
                "sha256": sha256_hex(payload),
                "manifest_sha256": spec["payload_sha256"],
                "hash_matches_manifest": sha256_hex(payload) == spec["payload_sha256"],
                "retained_alignment_padding": {
                    "start_file_offset": _hex(raw_start + payload_size),
                    "end_exclusive_file_offset": _hex(raw_end),
                    "byte_count": len(padding),
                    "all_zero": padding == b"\x00" * len(padding),
                },
            }
            if not payload_evidence["hash_matches_manifest"]:
                errors.append(f"payload hash mismatch in section {name}")
            if not payload_evidence["retained_alignment_padding"]["all_zero"]:
                errors.append(f"raw alignment padding in section {name} is not zeroed")

        evidence = {
            "source": "pefile.sections / IMAGE_SECTION_HEADER",
            "name": name,
            "index_in_header_table": section.index_in_file,
            "virtual_address": _hex(section.VirtualAddress),
            "virtual_size_bytes": section.Misc_VirtualSize,
            "virtual_end": _hex(section.VirtualAddress + section.Misc_VirtualSize),
            "raw_offset": _hex(raw_start),
            "raw_offset_int": raw_start,
            "raw_size_bytes": raw_size,
            "raw_end_exclusive": _hex(raw_end),
            "raw_sha256_including_alignment": sha256_hex(raw_bytes),
            "characteristics": _hex(section.Characteristics),
            "raw_offset_file_alignment_remainder": raw_start % optional_header.FileAlignment,
            "raw_size_file_alignment_remainder": raw_size % optional_header.FileAlignment,
            "virtual_address_section_alignment_remainder": section.VirtualAddress
            % optional_header.SectionAlignment,
            "payload": payload_evidence,
        }
        section_evidence.append(evidence)
        if raw_start + raw_size > len(data):
            errors.append(f"section {name} raw range exceeds file")
        if raw_start % optional_header.FileAlignment != 0:
            errors.append(f"section {name} raw offset violates FileAlignment")
        if raw_size % optional_header.FileAlignment != 0:
            errors.append(f"section {name} raw size violates FileAlignment")
        if section.VirtualAddress % optional_header.SectionAlignment != 0:
            errors.append(f"section {name} VA violates SectionAlignment")

    receipt_sections = [item for item in section_evidence if item["name"].startswith(".rcp")]
    if len(receipt_sections) != 2:
        errors.append(f"expected two real .rcp* sections, found {len(receipt_sections)}")

    security = audit_security_directory(data, pe, errors)
    last_raw_end = max(
        section.PointerToRawData + section.SizeOfRawData for section in pe.sections
    )
    security["starts_after_last_raw_section"] = security["file_offset_int"] >= last_raw_end
    if not security["starts_after_last_raw_section"]:
        errors.append("security directory overlaps raw section data")

    manifest_findings: list[dict[str, Any]] = []
    seen_digests: dict[str, str] = {}
    counts = {
        "manifest_records": len(manifest["receipts"]),
        "real_receipt_sections": len(receipt_sections),
        "matched_unique_materials": 0,
        "missing_real_section": 0,
        "duplicate_archive": 0,
        "hash_mismatch": 0,
    }
    for receipt in manifest["receipts"]:
        section_name = receipt["pe_section"]
        section = sections_by_name.get(section_name)
        digest = receipt["payload_sha256"]
        flags: list[str] = []
        finding: dict[str, Any] = {
            "receipt_id": receipt["receipt_id"],
            "archive_accession": receipt["archive_accession"],
            "declared_source": receipt["source"],
            "claimed_pe_section": section_name,
            "retention": receipt["retention"],
            "payload_sha256": digest,
        }

        if section is None:
            flags.append("missing_real_section")
            finding["real_section_present"] = False
            finding["evidence_ref"] = None
            counts["missing_real_section"] += 1
        else:
            raw_start = section.PointerToRawData
            payload_size = receipt["payload_size"]
            actual_digest = sha256_hex(
                data[raw_start + receipt["payload_offset_in_section"] : raw_start + payload_size]
            )
            hash_matches = actual_digest == digest
            duplicate_of = seen_digests.get(digest)
            finding.update(
                {
                    "real_section_present": True,
                    "hash_matches_manifest": hash_matches,
                    "duplicate_of_evidence": duplicate_of,
                    "evidence_ref": {
                        "source": "pefile.sections / IMAGE_SECTION_HEADER",
                        "pe_section": section_name,
                        "file_offset": _hex(raw_start + receipt["payload_offset_in_section"]),
                        "raw_section_end_exclusive": _hex(raw_start + section.SizeOfRawData),
                        "payload_size": payload_size,
                        "payload_sha256": actual_digest,
                    },
                }
            )
            if not hash_matches:
                flags.append("hash_mismatch")
                counts["hash_mismatch"] += 1
                errors.append(f"manifest hash mismatch for {receipt['receipt_id']}")
            if duplicate_of is not None:
                flags.append("duplicate_archive")
                counts["duplicate_archive"] += 1
            else:
                counts["matched_unique_materials"] += 1
            seen_digests.setdefault(digest, receipt["receipt_id"])

        finding["classifications"] = flags or ["matched_real_section"]
        finding["primary_classification"] = flags[0] if flags else "matched_real_section"
        manifest_findings.append(finding)

    external_audit: dict[str, Any] = {"source": "external_registration", "orders": []}
    approved_locator_by_order: dict[str, dict[str, Any]] = {}
    for order_path, order_doc in [(order_a_path, order_a), (order_b_path, order_b)]:
        order_result = {
            "file": order_path.name,
            "package_no": order_doc["package_no"],
            "entries": [],
        }
        for position, entry in enumerate(order_doc["registrations"]):
            digest = entry["payload_sha256"]
            matching_findings = [
                item
                for item in manifest_findings
                if item.get("payload_sha256") == digest and item.get("real_section_present")
            ]
            physical_locators = []
            approved = False
            for item in matching_findings:
                ref = item["evidence_ref"]
                physical_locator = {
                    "pe_section": ref["pe_section"],
                    "file_offset": ref["file_offset"],
                    "payload_sha256": ref["payload_sha256"],
                }
                if physical_locator not in physical_locators:
                    physical_locators.append(physical_locator)
                if item["retention"] == "approved":
                    approved = True
            entry_result = {
                "external_position_zero_based": position,
                "registration_no": entry["registration_no"],
                "receipt_id": entry["receipt_id"],
                "matched_by": "payload_sha256",
                "physical_locators": physical_locators,
                "manifest_matches": [item["receipt_id"] for item in matching_findings],
                "is_approved_retention_material": approved,
            }
            order_result["entries"].append(entry_result)
            if approved:
                approved_locator_by_order[order_path.name] = {
                    "external_position_zero_based": position,
                    "physical_locators": physical_locators,
                }
        external_audit["orders"].append(order_result)

    locator_a = approved_locator_by_order.get(order_a_path.name)
    locator_b = approved_locator_by_order.get(order_b_path.name)
    same_physical_location = bool(
        locator_a
        and locator_b
        and locator_a["physical_locators"] == locator_b["physical_locators"]
    )
    positions_swapped = bool(
        locator_a and locator_b and locator_a["external_position_zero_based"]
        != locator_b["external_position_zero_based"]
    )
    external_audit["swap_test"] = {
        "approved_locator_order_a": locator_a,
        "approved_locator_order_b": locator_b,
        "same_physical_location_after_swap": same_physical_location,
        "external_positions_changed": positions_swapped,
        "passed": same_physical_location and positions_swapped,
        "matching_key": "payload_sha256 -> project manifest -> IMAGE_SECTION_HEADER raw range",
    }
    if not external_audit["swap_test"]["passed"]:
        errors.append("external order swap test failed")

    if counts["missing_real_section"] != 1:
        errors.append("expected one missing real section demonstration")
    if counts["duplicate_archive"] != 1:
        errors.append("expected one duplicate archive demonstration")

    whole_file_hash = sha256_hex(data)
    evidence = {
        "schema": "pe-signoff-structural-evidence/v1",
        "scope": {
            "offline": True,
            "structural_only": True,
            "signature_verification": "not_performed",
            "trust_statement": "Hashes and offsets prove archival structure only; placeholder material is not a trusted signature.",
        },
        "tool_versions": {"pefile": pefile.__version__},
        "artifact": {
            "path": str(pe_path),
            "name": pe_path.name,
            "size_bytes": len(data),
            "sha256": whole_file_hash,
        },
        "pe_header_evidence": {
            "machine": _hex(file_header.Machine),
            "number_of_sections": file_header.NumberOfSections,
            "optional_header_magic": _hex(optional_header.Magic),
            "image_base": _hex(optional_header.ImageBase),
            "section_alignment": _hex(optional_header.SectionAlignment),
            "file_alignment": _hex(optional_header.FileAlignment),
            "subsystem": optional_header.Subsystem,
            "entry_point_rva": _hex(optional_header.AddressOfEntryPoint),
        },
        "pefile_warnings": pe.get_warnings(),
        "sections": section_evidence,
        "security_directory": security,
        "manifest_audit": {"counts": counts, "findings": manifest_findings},
        "external_order_audit": external_audit,
        "verdict": {
            "expected_two_real_receipt_sections": True,
            "structural_checks_passed": not errors,
            "expected_dispositions_present": {
                "missing_real_section": counts["missing_real_section"] == 1,
                "duplicate_archive": counts["duplicate_archive"] == 1,
            },
            "errors": errors,
        },
    }
    pe.close()
    return evidence


def render_markdown(evidence: dict[str, Any]) -> str:
    artifact = evidence["artifact"]
    header = evidence["pe_header_evidence"]
    security = evidence["security_directory"]
    counts = evidence["manifest_audit"]["counts"]
    swap = evidence["external_order_audit"]["swap_test"]
    approved_locators = (
        swap["approved_locator_order_b"]["physical_locators"]
        if swap.get("approved_locator_order_b")
        else []
    )
    approved_location_text = "; ".join(
        f"`{locator['pe_section']}`@`{locator['file_offset']}`"
        for locator in approved_locators
    )
    lines = [
        "# PE 签收材料离线结构证据",
        "",
        "## 结论",
        "",
        f"- PE：`{artifact['name']}`，{artifact['size_bytes']} bytes，SHA-256 `{artifact['sha256']}`。",
        f"- pefile：`{evidence['tool_versions']['pefile']}`；结构核对：`{'通过' if evidence['verdict']['structural_checks_passed'] else '未通过'}`。",
        f"- PE 节表中有 {counts['real_receipt_sections']} 个真实 `.rcp*` 签收区段；清单另有 {counts['missing_real_section']} 个真实区段缺失项、{counts['duplicate_archive']} 个重复归档项。",
        f"- Windows 安全目录是数据目录第 {security['directory_index']} 项，文件偏移 `{security['file_offset']}`，长度 {security['size_bytes']} bytes，解析出 {security.get('parsed_record_count', 0)} 条 8 字节对齐的占位 `WIN_CERTIFICATE` 记录。",
        f"- 交换外部登记顺序后，批准保留材料仍定位到 {approved_location_text}。",
        "- 范围：仅离线结构、偏移、对齐和哈希引用；占位字节不是 PKCS#7/Authenticode 签名，不做信任结论。",
        "",
        "## PE 头与对齐",
        "",
        "| 项 | 值 |",
        "| --- | --- |",
        f"| Machine | `{header['machine']}` |",
        f"| Optional Magic | `{header['optional_header_magic']}` |",
        f"| NumberOfSections | `{header['number_of_sections']}` |",
        f"| SectionAlignment | `{header['section_alignment']}` |",
        f"| FileAlignment | `{header['file_alignment']}` |",
        f"| ImageBase | `{header['image_base']}` |",
        f"| AddressOfEntryPoint | `{header['entry_point_rva']}` |",
        "",
        "## 真实 PE 区段与保留对齐",
        "",
        "| 区段 | VA / VSize | Raw range | Raw size | 对齐余数 | 负载 SHA-256 | 保留填充 |",
        "| --- | --- | --- | ---: | ---: | --- | --- |",
    ]
    for section in evidence["sections"]:
        payload = section["payload"]
        if payload:
            payload_hash = f"`{payload['sha256'][:16]}…` / 清单匹配 `{payload['hash_matches_manifest']}`"
            padding = f"{payload['retained_alignment_padding']['byte_count']} B zero={payload['retained_alignment_padding']['all_zero']}"
        else:
            payload_hash = "(code/无清单负载)"
            padding = "-"
        lines.append(
            f"| `{section['name']}` | `{section['virtual_address']}` / {section['virtual_size_bytes']} B | "
            f"`{section['raw_offset']}–{section['raw_end_exclusive']}` | {section['raw_size_bytes']} B | "
            f"raw%FA={section['raw_offset_file_alignment_remainder']}, size%FA={section['raw_size_file_alignment_remainder']} | "
            f"{payload_hash} | {padding} |"
        )

    lines.extend(
        [
            "",
            "## 正常 PE 安全目录",
            "",
            f"- 目录引用：`OPTIONAL_HEADER.DATA_DIRECTORY[{security['directory_index']}]`；该目录的 `VirtualAddress` 按 PE 规范是原始文件偏移而非 RVA。",
            f"- 目录范围：`{security['file_offset']}`，{security['size_bytes']} bytes；8 字节对齐：offset=`{security['offset_8byte_aligned']}`, size=`{security['size_8byte_aligned']}`；恰好覆盖记录=`{security['consumes_directory_exactly']}`。",
            "",
            "| # | 头偏移 | dwLength | 对齐跨度 | Revision / Type | 负载范围 | SHA-256 | 对齐填充 |",
            "| ---: | --- | ---: | ---: | --- | --- | --- | --- |",
        ]
    )
    for certificate in security["win_certificates"]:
        lines.append(
            f"| {certificate['index']} | `{certificate['header_file_offset']}` | {certificate['declared_length_bytes']} B | "
            f"{certificate['aligned_span_bytes']} B | `{certificate['wRevision']}` / `{certificate['wCertificateType']}` | "
            f"`{certificate['payload_file_range']['start']}–{certificate['payload_file_range']['end_exclusive']}` | "
            f"`{certificate['payload_file_range']['sha256'][:16]}…` | {certificate['alignment_padding']['byte_count']} B zero={certificate['alignment_padding']['all_zero']} |"
        )

    lines.extend(["", "## 项目签收清单核对", "", "| 签收 ID | 来源 | 声称区段 | 主分类 | 物理证据引用 |", "| --- | --- | --- | --- | --- |"])
    for finding in evidence["manifest_audit"]["findings"]:
        ref = finding["evidence_ref"]
        if ref:
            evidence_ref = f"`{ref['pe_section']}` @ `{ref['file_offset']}`, `{ref['payload_sha256'][:16]}…`"
        else:
            evidence_ref = "无区段表记录、无原始范围"
        lines.append(
            f"| `{finding['receipt_id']}` | `{finding['declared_source']}` | `{finding['claimed_pe_section']}` | "
            f"`{finding['primary_classification']}` | {evidence_ref} |"
        )

    lines.extend(["", "## 外部登记顺序交换核对", ""])
    for order in evidence["external_order_audit"]["orders"]:
        lines.append(f"### `{order['file']}`")
        lines.append("")
        lines.append("| 位置 | 登记号 | 签收 ID | 哈希定位到的物理区段 | 批准保留 |")
        lines.append("| ---: | --- | --- | --- | --- |")
        for entry in order["entries"]:
            locators = "; ".join(
                f"`{locator['pe_section']}`@{locator['file_offset']}"
                for locator in entry["physical_locators"]
            ) or "(无)"
            lines.append(
                f"| {entry['external_position_zero_based']} | `{entry['registration_no']}` | `{entry['receipt_id']}` | {locators} | "
                f"`{entry['is_approved_retention_material']}` |"
            )
        lines.append("")

    lines.extend(
        [
            "## 证据边界",
            "",
            "- `pefile` 负责解析 DOS/PE 头、数据目录和节表；`WIN_CERTIFICATE` 链由本脚本按偏移做结构解析。",
            "- 所有定位均附文件偏移、范围或 SHA-256，可供离线复核；未联网、未调用证书链或时间戳验证。",
            f"- pefile 警告仅为解析启发式：{evidence['pefile_warnings']!r}；本夹具保留大量零对齐填充，`objdump -p` 可正常识别。",
            "- `missing_real_section` 表示清单声称的 `.rcp9` 在节表和原始范围中均不存在；`duplicate_archive` 是同一 SHA-256/同一物理区段的重复归档，不是第二段新材料。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", type=Path, default=SCRIPT_DIR)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    if not args.skip_build:
        build_fixture(args.outdir)
    evidence = audit_fixture(args.outdir)
    write_json(args.outdir / "evidence.json", evidence)
    (args.outdir / "evidence.md").write_text(render_markdown(evidence), encoding="utf-8")
    print(json.dumps(evidence["verdict"], ensure_ascii=False, indent=2))
    if not evidence["verdict"]["structural_checks_passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
