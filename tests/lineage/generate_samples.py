"""Generate the four local LNK samples used by the lineage tests.

Scenario (an old computer was migrated, files repeat across backups):

* ``backup1_oldpc.lnk`` / ``backup2_oldpc.lnk``: the same file collected in
  two backup rounds on the old machine (identical tracker identities).
* ``migrated_newpc.lnk``: the file after migration to the new machine; its
  birth identity points back at the old current identity, so *both* backup
  copies are equally supported predecessors (parallel branches).
* ``copied_newpc.lnk``: a later copy on the new machine, descending only
  from ``migrated_newpc.lnk``.

Run ``python -m tests.lineage.generate_samples`` to regenerate the files
under ``tests/lineage/samples/``.
"""

import os
import uuid
from datetime import datetime
from datetime import timezone
from struct import pack


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")

VOLUME_OLD = "11111111-1111-1111-1111-111111111111"
FILE_ORIGINAL = "22222222-2222-2222-2222-222222222222"
VOLUME_NEW = "33333333-3333-3333-3333-333333333333"
FILE_MIGRATED = "44444444-4444-4444-4444-444444444444"
FILE_COPIED = "55555555-5555-5555-5555-555555555555"

# Caller-supplied context: collection order and hardware generation.
CONTEXT = {
    "backup1_oldpc.lnk": {"collection_order": 1, "hardware_generation": 1},
    "backup2_oldpc.lnk": {"collection_order": 2, "hardware_generation": 1},
    "migrated_newpc.lnk": {"collection_order": 3, "hardware_generation": 2},
    "copied_newpc.lnk": {"collection_order": 4, "hardware_generation": 2},
}


def _filetime(moment):
    epoch_as_filetime = 116444736000000000
    return int(moment.timestamp() * 10000000) + epoch_as_filetime


def _header(created, accessed, written):
    link_clsid = bytes.fromhex("0114020000000000C000000000000046")
    return b"".join(
        [
            pack("<I", 0x4C),  # HeaderSize
            link_clsid,
            pack("<I", 0),  # LinkFlags
            pack("<I", 0x20),  # FileAttributes: FILE_ATTRIBUTE_ARCHIVE
            pack("<Q", _filetime(created)),
            pack("<Q", _filetime(accessed)),
            pack("<Q", _filetime(written)),
            pack("<I", 0),  # FileSize
            pack("<i", 0),  # IconIndex
            pack("<I", 1),  # ShowCommand: SW_SHOWNORMAL
            pack("<H", 0),  # HotKey
            pack("<H", 0),  # Reserved1
            pack("<I", 0),  # Reserved2
            pack("<I", 0),  # Reserved3
        ]
    )


def _tracker_block(machine_id, volume_id, file_id, birth_volume_id, birth_file_id):
    machine = machine_id.encode("ascii")[:15].ljust(16, b"\x00")
    return b"".join(
        [
            pack("<I", 0x60),  # BlockSize
            pack("<I", 0xA0000003),  # BlockSignature
            pack("<I", 0x58),  # Length
            pack("<I", 0),  # Version
            machine,
            uuid.UUID(volume_id).bytes_le,
            uuid.UUID(file_id).bytes_le,
            uuid.UUID(birth_volume_id).bytes_le,
            uuid.UUID(birth_file_id).bytes_le,
        ]
    )


def build_sample(machine_id, volume_id, file_id, birth_volume_id, birth_file_id, moment):
    created = accessed = written = moment
    return b"".join(
        [
            _header(created, accessed, written),
            _tracker_block(machine_id, volume_id, file_id, birth_volume_id, birth_file_id),
            pack("<I", 0),  # TerminalBlock
        ]
    )


def samples():
    old_moment = datetime(2023, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    migrated_moment = datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    copied_moment = datetime(2024, 5, 20, 12, 0, 0, tzinfo=timezone.utc)
    return {
        "backup1_oldpc.lnk": build_sample(
            "PC-OLD", VOLUME_OLD, FILE_ORIGINAL, VOLUME_OLD, FILE_ORIGINAL, old_moment
        ),
        "backup2_oldpc.lnk": build_sample(
            "PC-OLD", VOLUME_OLD, FILE_ORIGINAL, VOLUME_OLD, FILE_ORIGINAL, old_moment
        ),
        "migrated_newpc.lnk": build_sample(
            "PC-NEW", VOLUME_NEW, FILE_MIGRATED, VOLUME_OLD, FILE_ORIGINAL, migrated_moment
        ),
        "copied_newpc.lnk": build_sample(
            "PC-NEW", VOLUME_NEW, FILE_COPIED, VOLUME_NEW, FILE_MIGRATED, copied_moment
        ),
    }


def main():
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    for name, data in samples().items():
        path = os.path.join(SAMPLE_DIR, name)
        with open(path, "wb") as fp:
            fp.write(data)
        print(f"wrote {path} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
