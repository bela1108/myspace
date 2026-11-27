"""Helpers for building small synthetic evidence backups for regression tests.

The backups are based on bundled test hives, but their acquisition metadata is
explicit.  This lets a test hold the hive bytes constant and change only the
collection scope, which is the situation a reviewer must be able to interpret.
"""

import hashlib
import json
import lzma
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from regipy.registry import RegistryHive

REGF_FILE_NAME_OFFSET = 0x30
REGF_FILE_NAME_LENGTH = 64


@dataclass
class SyntheticBackup:
    """A synthetic hive file plus the scope it was supposedly acquired with."""

    name: str
    hive_path: Path
    manifest_path: Path
    partial_hive_path: Optional[str]
    hive_type: Optional[str] = None

    def load_hive(self) -> RegistryHive:
        return RegistryHive(
            str(self.hive_path),
            hive_type=self.hive_type,
            partial_hive_path=self.partial_hive_path,
        )

    def manifest(self) -> dict:
        with open(self.manifest_path) as f:
            return json.load(f)

    def sha256(self) -> str:
        digest = hashlib.sha256()
        with open(self.hive_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def _decompress_hive(source_xz: Path, destination: Path) -> None:
    with lzma.open(source_xz) as source, open(destination, "wb") as target:
        target.write(source.read())


def _rewrite_internal_file_name(hive_path: Path, file_name: str) -> None:
    encoded = file_name.encode("utf-16-le")
    if len(encoded) > REGF_FILE_NAME_LENGTH:
        raise ValueError(f"Internal hive name is too long: {file_name!r}")
    with open(hive_path, "r+b") as f:
        f.seek(REGF_FILE_NAME_OFFSET)
        f.write(encoded.ljust(REGF_FILE_NAME_LENGTH, b"\x00"))


def _write_manifest(
    manifest_path: Path,
    *,
    backup_name: str,
    source_hive: str,
    partial_hive_path: Optional[str],
    hive_type: Optional[str],
    internal_file_name: Optional[str],
) -> None:
    manifest = {
        "synthetic": True,
        "backup_name": backup_name,
        "source_hive": source_hive,
        "collection_scope": {
            "kind": "partial" if partial_hive_path else "full",
            "partial_hive_path": partial_hive_path,
        },
        "hive_type_override": hive_type,
        "internal_file_name": internal_file_name,
    }
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")


def make_empty_typed_paths_backups(
    test_data_dir: Path,
    output_dir: Path,
    source_file_name: str = "NTUSER.DAT.xz",
) -> dict[str, SyntheticBackup]:
    """Create synthetic backups whose ``typed_paths`` result is empty.

    The ``full_scope`` and ``partial_scope`` backups use identical hive bytes;
    only the declared collection scope differs.  ``unrecognized_type`` uses the
    same records with an internal file name that regipy cannot identify, so the
    plugin has no precondition for running.
    """
    source_xz = test_data_dir / source_file_name
    output_dir = Path(output_dir)

    full_dir = output_dir / "empty-full-scope"
    partial_dir = output_dir / "empty-partial-scope"
    unknown_dir = output_dir / "empty-unrecognized-type"
    for directory in (full_dir, partial_dir, unknown_dir):
        directory.mkdir(parents=True, exist_ok=True)

    full_hive = full_dir / "NTUSER.DAT"
    _decompress_hive(source_xz, full_hive)

    partial_hive = partial_dir / "NTUSER.DAT"
    shutil.copyfile(full_hive, partial_hive)

    unknown_hive = unknown_dir / "mystery.hive"
    shutil.copyfile(full_hive, unknown_hive)
    unknown_name = r"?\C:\Evidence\mystery.hive"
    _rewrite_internal_file_name(unknown_hive, unknown_name)

    full_manifest = full_dir / "acquisition.json"
    _write_manifest(
        full_manifest,
        backup_name="empty-full-scope",
        source_hive=source_file_name,
        partial_hive_path=None,
        hive_type=None,
        internal_file_name="?\\C:\\Users\\vibranium\\ntuser.dat",
    )

    partial_manifest = partial_dir / "acquisition.json"
    _write_manifest(
        partial_manifest,
        backup_name="empty-partial-scope",
        source_hive=source_file_name,
        partial_hive_path=r"\Software",
        hive_type=None,
        internal_file_name="?\\C:\\Users\\vibranium\\ntuser.dat",
    )

    unknown_manifest = unknown_dir / "acquisition.json"
    _write_manifest(
        unknown_manifest,
        backup_name="empty-unrecognized-type",
        source_hive=source_file_name,
        partial_hive_path=None,
        hive_type=None,
        internal_file_name=unknown_name,
    )

    return {
        "full_scope": SyntheticBackup(
            name="empty-full-scope",
            hive_path=full_hive,
            manifest_path=full_manifest,
            partial_hive_path=None,
        ),
        "partial_scope": SyntheticBackup(
            name="empty-partial-scope",
            hive_path=partial_hive,
            manifest_path=partial_manifest,
            partial_hive_path=r"\Software",
        ),
        "unrecognized_type": SyntheticBackup(
            name="empty-unrecognized-type",
            hive_path=unknown_hive,
            manifest_path=unknown_manifest,
            partial_hive_path=None,
        ),
    }
