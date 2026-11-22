"""Static ABI layout audit built on pycparser.

The package reviews whether a proposed byte range of a fixed-size C state
block can safely be exported, without ever executing the audited code.

Caller-supplied inputs
----------------------
Every primitive size/alignment, pointer width and enum geometry is given
explicitly through :class:`abi_layout_audit.config.AbiConfig`. The host
interpreter is never queried, so two profiles (for example ILP32 and LP64)
can be checked against the same declarations. The audit scope additionally
names the public member paths and the inclusive export byte ranges.

What is modeled
---------------
:class:`abi_layout_audit.layout.LayoutEngine` computes struct/union sizes,
member offsets and implicit padding under ordinary ABI alignment rules.
Nested structs, unions and arrays are expanded into per-byte regions that
record the responsible member path and declaration location.

What is deliberately not guessed
--------------------------------
Bitfields only identify their underlying storage unit; bit packing order and
storage-unit overlap are ABI specific and are returned as review items.
``#pragma pack``, ``[[gnu::packed]]`` and forced-alignment attributes are
reported the same way. Each review item carries the concrete source location
so a human can finish the verification.
"""

from .config import AbiConfig, AbiConfigError, parse_byte_range
from .errors import (
    AuditError,
    ConfigError,
    LayoutUnsupportedError,
    Location,
)
from .evaluator import ConstantEvaluator
from .layout import LayoutEngine, MemberLayout, Region, TypeLayout
from .report import render_text, review_abis
from .audit import (
    AuditConfig,
    AuditReport,
    ByteFinding,
    ExportRange,
    RangeVerdict,
    audit_type,
    load_audit_config,
)
from .parser import (
    ParsedUnit,
    UnsupportedRule,
    parse_c_source,
    parse_source,
    read_c_file,
)

__all__ = [
    "AbiConfig",
    "AbiConfigError",
    "parse_byte_range",
    "AuditError",
    "ConfigError",
    "LayoutUnsupportedError",
    "Location",
    "ConstantEvaluator",
    "LayoutEngine",
    "MemberLayout",
    "Region",
    "TypeLayout",
    "ParsedUnit",
    "UnsupportedRule",
    "parse_c_source",
    "parse_source",
    "read_c_file",
    "AuditConfig",
    "AuditReport",
    "ByteFinding",
    "ExportRange",
    "RangeVerdict",
    "audit_type",
    "load_audit_config",
    "render_text",
    "review_abis",
]
