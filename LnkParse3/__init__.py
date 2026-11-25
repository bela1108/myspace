__all__ = [
    "DroidIdentity",
    "LineageEdge",
    "LineageResult",
    "Observation",
    "TrackerIdentity",
    "TrackerInfo",
    "build_lineage",
    "build_migration_lineage",
    "build_tracker_lineage",
    "export_edges",
    "export_lineage",
    "export_lineage_edges",
    "extract_distributed_link_tracker",
    "lineage",
    "lineage_edges",
    "lnk_file",
    "normalize_observations",
    "parse_tracker_identity",
    "reconcile_tracker_identities",
    "reconstruct_lineage",
    "tracker_identity",
]

import importlib

from LnkParse3.lnk_file import LnkFile as lnk_file


_LINEAGE_EXPORTS = {name: name for name in __all__ if name not in {"lineage", "lnk_file"}}


def __getattr__(name):
    if name == "lineage":
        module = importlib.import_module("LnkParse3.lineage")
        globals()[name] = module
        return module
    if name in _LINEAGE_EXPORTS:
        module = importlib.import_module("LnkParse3.lineage")
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
