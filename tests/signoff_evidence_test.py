import importlib.util
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "signoff_evidence"
    / "pe_signoff_audit.py"
)
SPEC = importlib.util.spec_from_file_location("pe_signoff_audit", SCRIPT_PATH)
assert SPEC and SPEC.loader
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


def test_two_receipt_sections_survive_order_swap(tmp_path):
    audit_module.build_fixture(tmp_path)
    evidence = audit_module.audit_fixture(tmp_path)

    assert evidence["verdict"]["structural_checks_passed"] is True
    assert evidence["pe_header_evidence"]["number_of_sections"] == 3

    section_names = [section["name"] for section in evidence["sections"]]
    assert section_names == [".text", ".rcp0", ".rcp1"]

    counts = evidence["manifest_audit"]["counts"]
    assert counts["real_receipt_sections"] == 2
    assert counts["missing_real_section"] == 1
    assert counts["duplicate_archive"] == 1

    security = evidence["security_directory"]
    assert security["directory_index"] == 4
    assert security["parsed_record_count"] == 2
    assert security["consumes_directory_exactly"] is True

    swap_test = evidence["external_order_audit"]["swap_test"]
    assert swap_test["passed"] is True
    locators = swap_test["approved_locator_order_b"]["physical_locators"]
    assert locators == [
        {
            "pe_section": ".rcp0",
            "file_offset": "0x400",
            "payload_sha256": evidence["sections"][1]["payload"]["sha256"],
        }
    ]


def test_audit_reports_missing_section_without_physical_reference(tmp_path):
    audit_module.build_fixture(tmp_path)
    evidence = audit_module.audit_fixture(tmp_path)
    findings = {
        item["receipt_id"]: item for item in evidence["manifest_audit"]["findings"]
    }

    missing = findings["RCPT-GHOST-MISSING-SECTION"]
    duplicate = findings["ARCHIVE-DUP-ALPHA"]

    assert missing["primary_classification"] == "missing_real_section"
    assert missing["real_section_present"] is False
    assert missing["evidence_ref"] is None

    assert duplicate["primary_classification"] == "duplicate_archive"
    assert duplicate["real_section_present"] is True
    assert duplicate["evidence_ref"]["pe_section"] == ".rcp0"
