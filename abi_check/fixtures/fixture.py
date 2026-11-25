"""Synthetic old/new widget.dll fixtures for the offline ABI audit.

The short fixture keeps ordinal 4 in both versions while changing its
exported name (WidgetCompute -> WidgetComputeV2). A by-name caller and a
by-ordinal caller therefore reach different conclusions for the same
symbol identity.
"""

from __future__ import annotations

from pathlib import Path

from ..pe_builder import ExportSpec, build_dll

WIDGET_DLL = "widget.dll"
LEGACY_DLL = "legacy.dll"

OLD_EXPORTS = [
    ExportSpec(ordinal=1, name="WidgetAdd"),
    ExportSpec(ordinal=2, name="WidgetAlias"),
    ExportSpec(ordinal=3, name="WidgetAlias"),
    ExportSpec(ordinal=4, name="WidgetCompute"),
    ExportSpec(ordinal=5, name="WidgetLegacy", forwarder="legacy.OldFunc"),
    ExportSpec(ordinal=6, name="WidgetExternal", forwarder="extmissing.#9"),
    ExportSpec(ordinal=7, name=None),
    ExportSpec(ordinal=8, name="WidgetRemoved"),
]

NEW_EXPORTS = [
    ExportSpec(ordinal=1, name="WidgetAdd"),
    ExportSpec(ordinal=2, name="WidgetAlias"),
    ExportSpec(ordinal=3, name="WidgetAlias"),
    ExportSpec(ordinal=4, name="WidgetComputeV2"),
    ExportSpec(ordinal=5, name="WidgetLegacy", forwarder="legacy.OldFunc"),
    ExportSpec(ordinal=6, name="WidgetExternal", forwarder="extmissing.#9"),
    ExportSpec(ordinal=7, name=None),
    ExportSpec(ordinal=9, name="WidgetFresh"),
]

LEGACY_EXPORTS = [
    ExportSpec(ordinal=1, name="OldFunc"),
]


def write_fixtures(output_dir):
    """Build every fixture DLL and write them under output_dir."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "old": output_dir / "widget_v1.dll",
        "new": output_dir / "widget_v2.dll",
        "legacy": output_dir / LEGACY_DLL,
    }
    paths["old"].write_bytes(build_dll(OLD_EXPORTS, dll_name=WIDGET_DLL))
    paths["new"].write_bytes(build_dll(NEW_EXPORTS, dll_name=WIDGET_DLL))
    paths["legacy"].write_bytes(build_dll(LEGACY_EXPORTS, dll_name=LEGACY_DLL))
    return paths
