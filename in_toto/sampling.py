"""Compatibility namespace for batch sampling verification.

The implementation lives in :mod:`in_toto.verifylib`, because the release
protocol extends verifylib's existing signature and artifact checks.
"""

from in_toto import verifylib as _verifylib

for _name in vars(_verifylib):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_verifylib, _name)

__all__ = [name for name in vars(_verifylib) if not name.startswith("_")]
