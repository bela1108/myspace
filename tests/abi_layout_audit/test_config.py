"""ABI configuration validation and primitive canonicalization."""

from __future__ import annotations

import pytest

from abi_layout_audit.config import (
    AbiConfig,
    AbiConfigError,
    canonical_type_name,
    parse_byte_range,
)


def test_canonical_type_name_aliases():
    assert canonical_type_name(["unsigned", "long", "int"]) == "unsigned long"
    assert canonical_type_name(["long", "long", "int"]) == "long long"
    assert canonical_type_name(["bool"]) == "_Bool"


def test_primitive_lookup_requires_complete_profile():
    with pytest.raises(AbiConfigError):
        AbiConfig.from_dict({
            "name": "broken",
            "pointer_size": 4,
            "pointer_alignment": 4,
            "primitive_types": {"int": {"size": 4, "alignment": 4}},
        })


def test_pointer_geometry_is_caller_supplied(ilp32, lp64):
    assert ilp32.pointer_size == 4
    assert lp64.pointer_size == 8


def test_parse_byte_range_variants():
    assert parse_byte_range("0-15") == (0, 15)
    assert parse_byte_range("4..7") == (4, 7)
    with pytest.raises(AbiConfigError):
        parse_byte_range("9-3")
    with pytest.raises(AbiConfigError):
        parse_byte_range("garbage")
