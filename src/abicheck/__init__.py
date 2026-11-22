"""Read-only managed ABI responsibility checking on top of dnfile.

The package is deliberately split into two parts:

* :mod:`abicheck.synthetic` builds small, ordinary managed assemblies from
  in-memory metadata models so tests do not depend on a .NET toolchain or on
  external binary fixtures.
* :mod:`abicheck.checker` consumes the caller-provided entry list and the
  approved type sources, then compares two assembly versions without ever
  writing to the inspected files.
"""

from .checker import (
    AbiReport,
    EntrySpec,
    EntryVerdict,
    SupportedTypeSource,
    Verdict,
    compare_assemblies,
)

__all__ = [
"AbiReport",
    "EntrySpec",
    "EntryVerdict",
    "SupportedTypeSource",
    "Verdict",
    "compare_assemblies",
]
