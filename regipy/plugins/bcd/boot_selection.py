"""
Windows Boot Configuration Data (BCD) boot-selection plugin.

The plugin wraps ``regipy.bcd.analyze_boot_selection`` and returns a structured,
evidence-bearing report.  By default it reports the configured default entry;
an observed selection is only claimed when the caller supplies a one-time
selection observation explicitly.
"""

from __future__ import annotations

from typing import Any

from regipy.bcd import analyze_boot_selection
from regipy.hive_types import BCD_HIVE_TYPE
from regipy.plugins.plugin import Plugin


class BootSelectionPlugin(Plugin):
    """Resolve BCD boot roles, default entry and a verifiable selection path."""

    NAME = "boot_selection"
    DESCRIPTION = "Resolve BCD boot roles and the provable boot selection path"
    COMPATIBLE_HIVE = BCD_HIVE_TYPE

    def __init__(
        self,
        registry_hive,
        as_json=False,
        trim_values=False,
        observed_selection: Any = None,
        observation: Any = None,
        selected_guid: Any = None,
        boot_manager_guid: Any = None,
        source: str | None = None,
    ):
        super().__init__(registry_hive, as_json=as_json, trim_values=trim_values)
        self.observed_selection = observed_selection
        self.observation = observation
        self.selected_guid = selected_guid
        self.boot_manager_guid = boot_manager_guid
        self.source = source

    def run(self) -> None:
        self.entries = analyze_boot_selection(
            self.registry_hive,
            observed_selection=self.observed_selection,
            observation=self.observation,
            selected_guid=self.selected_guid,
            boot_manager_guid=self.boot_manager_guid,
            source=self.source,
        )


# Compatibility aliases for callers that use a BCD-prefixed class name.
BcdBootSelectionPlugin = BootSelectionPlugin
BcdBootSelection = BootSelectionPlugin
