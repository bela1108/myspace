"""Edge cases: pointers, anonymous composites, packed attrs, zero bits."""

from __future__ import annotations

import pytest

from abi_layout_audit.errors import LayoutUnsupportedError
from abi_layout_audit.layout import LayoutEngine
from abi_layout_audit.parser import parse_c_source

from .conftest import make_abi


def test_pointer_uses_profile_width(ilp32, lp64):
    source = "struct S { char tag; void *pointer; };"
    small = LayoutEngine(parse_c_source(source), ilp32).layout_named("S")
    large = LayoutEngine(parse_c_source(source), lp64).layout_named("S")
    assert small.members[1].size == 4
    assert large.members[1].size == 8


def test_anonymous_nested_struct_regions():
    source = (
        "struct S { char a; struct { short x; int y; } nested; };")
    layout = LayoutEngine(parse_c_source(source), make_abi()).layout_named("S")
    paths = {".".join(r.path) for r in layout.regions}
    assert "nested.x" in paths
    assert "nested.y" in paths


def test_packed_attribute_creates_review_item():
    source = "struct S { char a; int b; } [[gnu::packed]];"
    layout = LayoutEngine(parse_c_source(source), make_abi()).layout_named("S")
    assert any(item.kind == "packed_attribute"
               for item in layout.unsupported)


def test_zero_width_bitfield_is_review():
    source = "struct S { char a; int : 0; int b; };"
    layout = LayoutEngine(parse_c_source(source), make_abi()).layout_named("S")
    assert layout.has_bitfields
    bit_regions = [r for r in layout.regions if r.kind == "bitfield"]
    assert bit_regions and bit_regions[0].size == 0
    assert any(item.kind == "bitfield" for item in layout.unsupported)


def test_unsized_array_is_an_error():
    source = "struct S { char flexible[]; };"
    engine = LayoutEngine(parse_c_source(source), make_abi())
    with pytest.raises(LayoutUnsupportedError):
        engine.layout_named("S")


def test_unknown_primitive_raises_config_error():
    source = "struct S { __int128 huge; };"
    engine = LayoutEngine(parse_c_source(source), make_abi())
    with pytest.raises(Exception):
        engine.layout_named("S")
