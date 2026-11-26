"""Offline acceptance plan compatibility module."""
from plyara import acceptance as _acceptance


def __getattr__(name):
    """Delegate compatibility imports to plyara.acceptance."""
    return getattr(_acceptance, name)
