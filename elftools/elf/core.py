"""Core-file mapping helpers (alias of :mod:`elftools.elf.corefile`)."""

from .corefile import *  # noqa: F401,F403
from .corefile import __all__ as _corefile_all

__all__ = list(_corefile_all)
