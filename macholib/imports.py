"""Compatibility alias for :mod:`macholib.bindings`."""

from macholib.bindings import *  # noqa: F401,F403
from macholib.bindings import (  # noqa: F401
    STATUS_BOUND,
    STATUS_SPECIAL,
    STATUS_UNKNOWN,
    STATUS_UNRESOLVED,
    STATUS_UNVERIFIED,
    STATUS_WEAK,
    analyze_imports,
    check_imports,
    inspect_bindings,
)

from macholib import bindings as _bindings

__all__ = list(_bindings.__all__)
