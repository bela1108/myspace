from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from dissect.cstruct import (
    LayoutEvidence,
    compare_evidence,
    layout_evidence,
    reconcile_layout,
    verify_layout_paths,
)
from tests.util import verify_compiled

if TYPE_CHECKING:
    from dissect.cstruct.types import Structure

STATUS_CDEF = """
struct Reading {
    uint8  tag;
    uint32 value;
    uint16 matrix[2][2];
};

struct StatusPage {
    uint8   schema;
    Reading readings[2];
    uint32  serial;
};
"""


def make_page(align: bool, *, compiled: bool = True) -> tuple[Any, type[Structure], bytes]:
    from dissect.cstruct import cstruct

    cs = cstruct(endian="big")
    cs.load(STATUS_CDEF, align=align, compiled=compiled)
    obj = cs.StatusPage(
        schema=0x01,
        readings=[
            cs.Reading(tag=0x02, value=0x11223344, matrix=[[1, 2], [3, 4]]),
            cs.Reading(tag=0x05, value=0x55667788, matrix=[[5, 6], [7, 8]]),
        ],
        serial=0x99AABBCC,
    )
    return cs, cs.StatusPage, obj.dumps() + b"\xde\xad"


def assert_segments_partition_buffer(evidence: LayoutEvidence) -> None:
    cursor = 0
    for segment in evidence.segments:
        assert segment.start == cursor
        assert segment.end > segment.start or segment.kind == "field"
        cursor = segment.end
    assert cursor == evidence.buffer_size


@pytest.mark.parametrize("load_compiled", [True, False], ids=["compiled-load", "interpreted-load"])
@pytest.mark.parametrize("align", [False, True], ids=["packed", "aligned"])
def test_layout_evidence_ranges_padding_and_unconsumed(align: bool, load_compiled: bool) -> None:
    cs, page_cls, data = make_page(align, compiled=load_compiled)
    assert verify_compiled(page_cls, load_compiled)

    evidence = cs.layout_evidence("StatusPage", data, label="device")

    assert isinstance(evidence, LayoutEvidence)
    assert evidence.endianness == ">"
    assert evidence.declared_endianness == ">"
    assert evidence.align is align
    assert evidence.unconsumed == (40 if align else 31, 42 if align else 33)
    assert evidence.unconsumed.kind == "unconsumed"
    assert_segments_partition_buffer(evidence)

    if not align:
        assert evidence.consumed == 31
        assert evidence.declared_size == 31
        assert evidence.padding == []
        assert evidence.range_for("schema") == (0, 1)
        assert evidence.range_for("readings") == (1, 27)
        assert evidence.range_for("readings[0]") == (1, 14)
        assert evidence.range_for("readings[0].value") == (2, 6)
        assert evidence.range_for("readings[0].matrix") == (6, 14)
        assert evidence.range_for("readings[0].matrix[0][1]") == (8, 10)
        assert evidence.range_for("readings[1].value") == (15, 19)
        assert evidence.range_for("readings[1].matrix[1][1]") == (25, 27)
        assert evidence.range_for("serial") == (27, 31)
    else:
        assert evidence.consumed == 40
        assert evidence.declared_size == 40
        assert [tuple(padding.span) for padding in evidence.padding] == [(1, 4), (5, 8), (21, 24)]
        assert evidence.range_for("schema") == (0, 1)
        assert evidence.range_for("readings") == (4, 36)
        assert evidence.range_for("readings[0]") == (4, 20)
        assert evidence.range_for("readings[0].tag") == (4, 5)
        assert evidence.range_for("readings[0].value") == (8, 12)
        assert evidence.range_for("readings[0].matrix") == (12, 20)
        assert evidence.range_for("readings[0].matrix[1][1]") == (18, 20)
        assert evidence.range_for("readings[1]") == (20, 36)
        assert evidence.range_for("readings[1].value") == (24, 28)
        assert evidence.range_for("readings[1].matrix[1][1]") == (34, 36)
        assert evidence.range_for("serial") == (36, 40)


@pytest.mark.parametrize("align", [False, True], ids=["packed", "aligned"])
def test_compiled_and_interpreted_paths_reconcile(align: bool) -> None:
    _, page_cls, data = make_page(align, compiled=False)

    result = reconcile_layout(page_cls, data)
    result.assert_matches()

    assert result.matches
    assert result.values_match
    assert result.consumed_match
    assert result.compiled_backend == "compiled"
    assert result.interpreted_consumed == result.compiled_consumed == result.evidence.consumed
    assert verify_layout_paths(page_cls, data).matches


def test_same_values_do_not_mean_same_physical_range() -> None:
    _, packed_cls, packed_data = make_page(False)
    _, aligned_cls, aligned_data = make_page(True)

    packed = layout_evidence(packed_cls, packed_data, label="packed-device")
    aligned = aligned_cls.layout_evidence(aligned_data, label="aligned-device")
    comparison = compare_evidence(packed, aligned)

    assert packed.name == aligned.name == "StatusPage"
    assert comparison.same_structure_name
    assert comparison.same_values
    assert not comparison.same_ranges
    assert not comparison.can_share_physical_range
    assert "readings[0].value" in comparison.equal_value_paths
    assert "readings[0].value" in {item["path"] for item in comparison.range_differences}

    value_diff = next(item for item in comparison.range_differences if item["path"] == "readings[0].value")
    assert value_diff["left"] == (2, 6)
    assert value_diff["right"] == (8, 12)
    assert value_diff["values_equal"] is True
    assert "equal decoded value" in comparison.explanation
    assert "distinct device buffers" in comparison.explanation


def test_declared_endianness_is_reported_and_used() -> None:
    from dissect.cstruct import cstruct

    cs = cstruct(endian="little")
    cs.load("struct EndianPage { uint16 value; };")

    declared = layout_evidence(cs.EndianPage, b"\x2a\x00")
    assert declared.declared_endianness == "<"
    assert declared.endianness == "<"
    assert declared.get("value").value == 42

    overridden = layout_evidence(cs.EndianPage, b"\x00\x2a", endian="big")
    assert overridden.declared_endianness == "<"
    assert overridden.endianness == ">"
    assert overridden.get("value").value == 42


def test_explain_layout_mentions_padding_and_unconsumed() -> None:
    _, page_cls, data = make_page(True)
    text = page_cls.layout_evidence(data).explain()

    assert "StatusPage" in text
    assert "padding" in text
    assert "unconsumed" in text
    assert "readings[0].value" in text
