"""Shared fixtures for the ABI layout audit tests."""

from __future__ import annotations

import pytest

from abi_layout_audit.audit import AuditConfig, ExportRange
from abi_layout_audit.config import AbiConfig


def make_abi(name: str = "test-abi", pointer: int = 4,
             long_size: int = 4) -> AbiConfig:
    primitives = {
        "_Bool": (1, 1),
        "signed char": (1, 1),
        "unsigned char": (1, 1),
        "short": (2, 2),
        "unsigned short": (2, 2),
        "int": (4, 4),
        "unsigned int": (4, 4),
        "long": (long_size, long_size),
        "unsigned long": (long_size, long_size),
        "long long": (8, 8),
        "unsigned long long": (8, 8),
        "float": (4, 4),
        "double": (8, 8),
        "long double": (8 if pointer == 4 else 16,
                        8 if pointer == 4 else 16),
    }
    return AbiConfig.from_dict({
        "name": name,
        "pointer_size": pointer,
        "pointer_alignment": pointer,
        "enum_size": 4,
        "enum_alignment": 4,
        "primitive_types": {
            key: {"size": value[0], "alignment": value[1]}
            for key, value in primitives.items()
        },
    })


def make_audit(type_name: str, public: list[str],
               ranges: list[tuple[str, int, int]]) -> AuditConfig:
    return AuditConfig(
        type_name=type_name,
        public_paths=public,
        export_ranges=[ExportRange(label, start, end)
                       for label, start, end in ranges])


@pytest.fixture
def ilp32():
    return make_abi("ilp32", pointer=4, long_size=4)


@pytest.fixture
def lp64():
    return make_abi("lp64", pointer=8, long_size=8)
