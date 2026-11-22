"""Export-range verdicts, byte ownership and review classification."""

from __future__ import annotations

from abi_layout_audit.audit import audit_type
from abi_layout_audit.parser import parse_c_source

from .conftest import make_abi, make_audit


SOURCE = (
    "struct block {"
    " unsigned int magic;"
    " unsigned short flags;"
    " unsigned long watchdog;"
    " unsigned long long sequence;"
    " unsigned int internal_token; };"
)


def _run(config, ranges, public):
    unit = parse_c_source(SOURCE, "block.c")
    audit = make_audit("block", public, ranges)
    return audit_type(unit, config, audit)


def test_public_only_range_is_ok(ilp32):
    report = _run(ilp32, [("head", 0, 3)], ["magic"])
    verdict = report.verdicts[0]
    assert verdict.verdict == "ok"
    assert verdict.findings[0].classification == "public"
    assert verdict.findings[0].location.line == 1


def test_internal_field_is_violation_with_location(ilp32):
    report = _run(ilp32, [("tail", 24, 27)], ["magic"])
    verdict = report.verdicts[0]
    assert verdict.verdict == "violation"
    finding = verdict.findings[0]
    assert finding.classification == "internal"
    assert "internal_token" in finding.paths
    assert finding.location.line == 1


def test_padding_only_range_is_review_not_violation(lp64):
    report = _run(lp64, [("gap", 6, 7)],
                  ["magic", "flags", "watchdog"])
    verdict = report.verdicts[0]
    assert verdict.verdict == "review"
    assert verdict.findings[0].classification == "padding"
    assert verdict.findings[0].location is not None


def test_same_range_diverges_between_abis(ilp32, lp64):
    public = ["magic", "flags", "watchdog", "sequence"]
    ilp = _run(ilp32, [("gap", 12, 15)], public)
    lp = _run(lp64, [("gap", 12, 15)], public)
    ilp_classes = {f.classification for f in ilp.verdicts[0].findings}
    lp_classes = {f.classification for f in lp.verdicts[0].findings}
    assert ilp_classes == {"padding"}
    assert lp_classes == {"public"}


def test_out_of_bounds_range_is_violation(ilp32):
    report = _run(ilp32, [("huge", 0, 99)], ["magic"])
    assert report.verdicts[0].verdict == "violation"
    assert report.verdicts[0].findings[0].classification == "out_of_bounds"


def test_bitfield_lands_in_review_items():
    config = make_abi()
    source = "struct bits { unsigned int mode; unsigned int code : 4; };"
    unit = parse_c_source(source, "bits.c")
    audit = make_audit("bits", ["mode"], [("all", 0, 7)])
    report = audit_type(unit, config, audit)
    assert report.layout.has_bitfields
    kinds = {item["kind"] for item in report.review_items}
    assert "bitfield" in kinds
    bit_finding = next(
        f for v in report.verdicts for f in v.findings
        if f.classification == "review")
    assert bit_finding.location.line == 1


def test_pack_pragma_is_review_item():
    config = make_abi()
    source = (
        "#pragma pack(1)\n"
        "struct packed { char tag; unsigned int value; };")
    unit = parse_c_source(source, "packed.c")
    audit = make_audit("packed", ["tag", "value"], [("all", 0, 4)])
    report = audit_type(unit, config, audit)
    pragma = next(item for item in report.review_items
                  if item["kind"] == "pack_pragma")
    assert pragma["location"]["line"] == 1
