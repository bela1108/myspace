"""Compatibility module for the BCD boot-selection plugin."""

from regipy.bcd import analyze_boot_selection, read_bcd_roles
from regipy.plugins.bcd.boot_selection import (
    BcdBootSelection,
    BcdBootSelectionPlugin,
    BootSelectionPlugin,
)

__all__ = [
    "BootSelectionPlugin",
    "BcdBootSelectionPlugin",
    "BcdBootSelection",
    "analyze_boot_selection",
    "read_bcd_roles",
]
