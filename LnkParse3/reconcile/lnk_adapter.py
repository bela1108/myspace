"""Adapt parsed LnkFile objects into the target descriptors used offline."""

import warnings
from pathlib import Path

from LnkParse3 import lnk_file
from LnkParse3.reconcile.models import make_target
from LnkParse3.reconcile.normalization import normalize_drive_letter


def _local_location_info(link_info):
    if link_info.get("location") != "Local":
        return None
    return link_info.get("location_info") or {}


def _written_path(link_info):
    """Reconstruct the target path exactly as the LNK records it."""
    base = link_info.get("local_base_path_unicode") or link_info.get("local_base_path")
    if not base:
        return None

    suffix = link_info.get("common_path_suffix_unicode") or link_info.get("common_path_suffix")
    if not suffix:
        return base
    return base.rstrip("\\") + "\\" + suffix.lstrip("\\")


def descriptor_from_lnk(lnk, lnk_ref=None):
    """Build a normalized target descriptor from a parsed LnkFile.

    Only bytes stored inside the shortcut are consulted: the embedded VolumeID
    serial/label and the path written at creation time. Nothing about the
    current analysis machine drives the result.
    """
    link_info = lnk.get_json().get("link_info") or {}
    location_info = _local_location_info(link_info)
    source = lnk_ref or "lnk-memory"

    if location_info is None:
        return make_target(
            source=source,
            written_path=_written_path(link_info)
            or ((lnk.get_json().get("data") or {}).get("working_directory")),
            location=link_info.get("location", "Unknown"),
            note="no local VolumeID in LNK (network target or missing link info)",
        )

    written_path = _written_path(link_info)
    return make_target(
        source=source,
        written_path=written_path,
        drive_letter=normalize_drive_letter(written_path),
        volume_serial=location_info.get("drive_serial_number"),
        volume_label=(
            location_info.get("volume_label_unicode") or location_info.get("volume_label") or None
        ),
        lnk_ref=lnk_ref,
    )


def descriptors_from_path(path, cp="cp1252"):
    """Parse one LNK file and return a single-element descriptor list."""
    ref = str(path)
    with open(ref, "rb") as handle:
        lnk = lnk_file(fhandle=handle, cp=cp)
    return [descriptor_from_lnk(lnk, lnk_ref=ref)]


def descriptors_from_directory(directory, cp="cp1252"):
    """Recursively parse every readable .lnk file below directory."""
    descriptors = []
    for path in sorted(Path(directory).rglob("*")):
        if not path.is_file() or path.suffix.lower() != ".lnk":
            continue
        try:
            descriptors.extend(descriptors_from_path(path, cp=cp))
        except Exception as exc:
            warnings.warn(f"skipping unreadable LNK {path!r}: {exc!r}")
    return descriptors


def descriptors_from_inputs(inputs, cp="cp1252"):
    """Parse a mix of LNK files and directories holding LNK files."""
    descriptors = []
    for entry in inputs:
        path = Path(entry)
        if path.is_dir():
            descriptors.extend(descriptors_from_directory(path, cp=cp))
        else:
            descriptors.extend(descriptors_from_path(path, cp=cp))
    return descriptors
