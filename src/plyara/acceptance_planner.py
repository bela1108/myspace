"""Compatibility import path for the acceptance planner."""
from plyara import acceptance as _acceptance


def __getattr__(name):
    """Delegate compatibility imports to plyara.acceptance."""
    return getattr(_acceptance, name)
