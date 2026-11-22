"""Struct, union, array and padding layout behaviour."""

from __future__ import annotations

from abi_layout_audit.layout import LayoutEngine
from abi_layout_audit.parser import parse_c_source


def _engine(source, config):
    return LayoutEngine(parse_c_source(source, "block.c"), config)


def test_struct_padding_and_tail(ilp32):
    source = "struct S { char a; int b; };"
    layout = _engine(source, ilp32).layout_named("S")
    assert layout.size == 8
    assert layout.alignment == 4
    kinds = [(r.offset, r.size, r.kind) for r in layout.regions]
    assert (0, 1, "field") in kinds
    assert (1, 3, "padding") in kinds
    assert (4, 4, "field") in kinds


def test_nested_struct_regions_keep_full_paths(ilp32):
    source = (
        "typedef struct { char c; int i; } inner_t;"
        "struct S { inner_t nested; int tail; };")
    layout = _engine(source, ilp32).layout_named("S")
    paths = {".".join(r.path): r.kind for r in layout.regions}
    assert paths["nested.c"] == "field"
    assert paths["nested.i"] == "padding" or "nested.i" in paths
    assert paths["tail"] == "field"
    padding = next(r for r in layout.regions if r.kind == "padding"
                   and "nested" in r.path)
    assert padding.location.line == 1


def test_array_of_structs_expands_every_element(ilp32):
    source = (
        "typedef struct { char c; int i; } inner_t;"
        "struct S { inner_t arr[2]; };")
    layout = _engine(source, ilp32).layout_named("S")
    indexed = [r for r in layout.regions if "[0]" in r.path or "[1]" in r.path]
    assert indexed
    assert any("[0]" in ".".join(r.path) for r in layout.regions)
    assert any("[1]" in ".".join(r.path) for r in layout.regions)
    assert layout.size == 16


def test_union_overlapping_members_share_offset(ilp32):
    source = (
        "union U { unsigned int word; unsigned char bytes[4]; };"
        "struct S { char tag; union U value; };")
    layout = _engine(source, ilp32).layout_named("S")
    union_regions = [r for r in layout.regions
                     if r.path and r.path[0] == "value"
                     and r.kind != "padding"]
    offsets = {r.offset for r in union_regions}
    assert offsets == {4}
    paths = {".".join(r.path) for r in union_regions}
    assert "value.word" in paths
    assert "value.bytes" in paths


def test_long_member_distinguishes_ilp32_from_lp64(ilp32, lp64):
    source = "struct S { char a; unsigned long b; };"
    small = _engine(source, ilp32).layout_named("S")
    large = _engine(source, lp64).layout_named("S")
    assert small.size == 8
    assert large.size == 16
    assert small.members[1].offset == 4
    assert large.members[1].offset == 8


def test_typedef_enum_and_primitive_sizing(ilp32):
    source = (
        "typedef enum { A, B } color_t;"
        "struct S { color_t c; unsigned short s; };")
    layout = _engine(source, ilp32).layout_named("S")
    assert layout.members[0].size == 4
    assert layout.size == 8


def test_constant_array_dimension_through_enum(ilp32):
    source = (
        "enum limits { LIMIT = 3 };"
        "struct S { unsigned char data[LIMIT + 1]; };")
    layout = _engine(source, ilp32).layout_named("S")
    assert layout.size == 4
    assert layout.members[0].size == 4


def test_alignas_increases_member_alignment(ilp32):
    source = "struct S { char a; _Alignas(16) char b; };"
    layout = _engine(source, ilp32).layout_named("S")
    assert layout.members[1].offset == 16
    assert layout.alignment == 16
    assert layout.size == 32
