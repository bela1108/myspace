#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Tests for the read-only deleted-cell recovery interface.

The fixtures are built by patching tests/reg_samples/issue22.hive:
  - live key data is never modified,
  - the trailing free cell is split and populated with carved key cells,
  - one deliberately malformed cell exercises the structural validation.
"""

from __future__ import unicode_literals

import os
import struct
import datetime

import pytest

from Registry import Registry
from Registry import RegistryParse


FIRST_HBIN = 0x1000
SAMPLE_PATH = os.path.join(os.path.dirname(__file__), "reg_samples", "issue22.hive")

DELETED_TIMESTAMP = datetime.datetime(2019, 3, 4, 5, 6, 7)
DUP_TIMESTAMP = datetime.datetime(2018, 1, 2, 3, 4, 5)


def _filetime(dt):
    epoch = datetime.datetime(1601, 1, 1)
    delta = dt - epoch
    return (delta.days * 86400 + delta.seconds) * 10000000 + delta.microseconds * 10


def _nk_cell(cell_offset, name, timestamp, parent_relative, ascii_name=False):
    """
    Build an HBIN cell containing an NKRecord with the given name.
    The cell size is positive, as encountered in a freed cell.
    """
    encoding = "windows-1252" if ascii_name else "utf-16le"
    name_bytes = name.encode(encoding)
    # The size dword covers the NK data (0x4C header plus the name), not itself.
    data_size = (0x4C + len(name_bytes) + 7) & ~7
    size = data_size + 0x4

    cell = bytearray(size)
    cell[0:4] = struct.pack("<i", size)
    cell[4:6] = b"nk"
    flags = 0x20 if ascii_name else 0x0
    cell[6:8] = struct.pack("<H", flags)
    cell[0x8:0x10] = struct.pack("<Q", _filetime(timestamp))
    cell[0x14:0x18] = struct.pack("<I", parent_relative)
    cell[0x1C:0x20] = struct.pack("<I", 0xFFFFFFFF)
    cell[0x2C:0x30] = struct.pack("<I", 0xFFFFFFFF)
    cell[0x34:0x38] = struct.pack("<I", 0xFFFFFFFF)
    cell[0x4C:0x4E] = struct.pack("<H", len(name_bytes))
    cell[0x50:0x50 + len(name_bytes)] = name_bytes
    return bytes(cell)


def _write_free_cell(buf, offset, size, next_relative=0xFFFFFFFF):
    buf[offset:offset + 4] = struct.pack("<i", size)
    buf[offset + 4:offset + 8] = struct.pack("<I", next_relative)


@pytest.fixture
def pristine_hive():
    with open(SAMPLE_PATH, "rb") as f:
        return bytearray(f.read())


@pytest.fixture
def deleted_hive(pristine_hive):
    """
    Layout inside the original trailing free cell at 0x1428 (3032 bytes):
      0x1428  released cell (0xBD8 bytes) whose free payload carries carved NK cells
      0x1628  carved NK cell (direct child of the live root, unicode name)
      0x16b8  carved NK cell (direct child of the live root, ascii name)
      0x1748  carved NK cell whose parent reference is unresolvable
      0x17d8  duplicate copy of the first carved key (conflicting candidate)
      0x1868  malformed cell that must be rejected
      0x18b0  residual space still owned by the same released cell (0x2000)
    """
    buf = bytearray(pristine_hive)

    carved = [
        (0x1628, "EvictedKey", DELETED_TIMESTAMP, 0x24, False),
        (0x16b8, "AsciiEvicted", DELETED_TIMESTAMP, 0x24, True),
        (0x1748, "OrphanedKey", DELETED_TIMESTAMP, 0x77777, False),
        (0x17d8, "EvictedKey", DUP_TIMESTAMP, 0x24, False),
        # 0x62c is the NK data offset of the EvictedKey cell at 0x1628.
        (0x18b0, "ChildOfDeleted", DELETED_TIMESTAMP, 0x62c, False),
    ]

    for offset, name, ts, parent, ascii_name in carved:
        cell = _nk_cell(offset, name, ts, parent, ascii_name)
        buf[offset:offset + len(cell)] = cell

    malformed = bytearray(0x50)
    malformed[0:4] = struct.pack("<i", 0x50)
    malformed[4:6] = b"nk"
    malformed[0x8:0x10] = struct.pack("<Q", _filetime(DELETED_TIMESTAMP))
    malformed[0x14:0x18] = struct.pack("<I", 0x24)
    malformed[0x4C:0x4E] = struct.pack("<H", 0x400)
    buf[0x1868:0x18b0] = bytes(malformed)[:0x48]

    _write_free_cell(buf, 0x1428, 0xBD8)
    return bytes(buf)


@pytest.fixture
def slack_hive(pristine_hive):
    """
    The trailing free cell claims less space than it actually owns, so the
    region from 0x1628 to the end of the HBIN can only be classified as slack.
    """
    buf = bytearray(pristine_hive)
    cell = _nk_cell(0x1628, "SlackKey", DELETED_TIMESTAMP, 0x24)
    buf[0x1628:0x1628 + len(cell)] = cell
    _write_free_cell(buf, 0x1428, 0x200)
    # Break the cell chain at 0x1628: the size field is invalid, so the
    # remaining HBIN space can only be recovered as slack, even though the
    # NK signature and inline fields further inside remain intact.
    struct.pack_into(str("<i"), buf, 0x1628, 0)
    return bytes(buf)


def test_scanner_recovers_free_and_slack_candidates(deleted_hive):
    recovery = RegistryParse.DeletedKeyRecovery(deleted_hive)
    candidates = recovery.recover()

    names = [c.name for c in candidates]
    assert names == ["EvictedKey", "AsciiEvicted", "OrphanedKey",
                      "EvictedKey", "ChildOfDeleted"]

    by_offset = dict((c.source_cell_offset, c) for c in candidates)
    assert set(by_offset) == {0x1628, 0x16b8, 0x1748, 0x17d8, 0x18b0}

    first = by_offset[0x1628]
    assert first.cell_type == RegistryParse.DELETED_CELL_TYPE_KEY
    assert first.cell_state in (RegistryParse.DELETED_CELL_STATE_FREE,
                                RegistryParse.DELETED_CELL_STATE_SLACK)
    assert first.timestamp == DELETED_TIMESTAMP
    assert first.has_ascii_name is False
    assert first.parent_relative_offset == 0x24
    assert first.parent_state == RegistryParse.DELETED_PARENT_LIVE
    assert first.parent_name == "TimeZoneInformation"

    ascii_candidate = by_offset[0x16b8]
    assert ascii_candidate.has_ascii_name is True
    assert ascii_candidate.name == "AsciiEvicted"
    assert ascii_candidate.parent_state == RegistryParse.DELETED_PARENT_LIVE

    orphan = by_offset[0x1748]
    assert orphan.parent_state == RegistryParse.DELETED_PARENT_UNRESOLVED
    assert orphan.parent_name is None

    child = by_offset[0x18b0]
    assert child.name == "ChildOfDeleted"
    assert child.parent_state == RegistryParse.DELETED_PARENT_DELETED
    assert child.parent_name == "EvictedKey"
    assert child.parent_offset == 0x162c


def test_conflicting_candidates_keep_source_offsets(deleted_hive):
    recovery = RegistryParse.DeletedKeyRecovery(deleted_hive)
    candidates = recovery.recover()

    evicted = [c for c in candidates if c.name == "EvictedKey"]
    assert len(evicted) == 2
    assert [c.source_cell_offset for c in evicted] == [0x1628, 0x17d8]
    assert [c.timestamp for c in evicted] == [DELETED_TIMESTAMP, DUP_TIMESTAMP]


def test_candidates_are_sorted_by_source_offset_and_time(deleted_hive):
    recovery = RegistryParse.DeletedKeyRecovery(deleted_hive)
    candidates = recovery.recover()

    keys = [(c.source_cell_offset, c.timestamp, c.name) for c in candidates]
    assert keys == sorted(keys)


def test_recovery_is_deterministic(deleted_hive):
    first = RegistryParse.DeletedKeyRecovery(deleted_hive).recover()
    second = RegistryParse.DeletedKeyRecovery(deleted_hive).recover()
    assert first == second


def test_malformed_cell_is_rejected(deleted_hive):
    recovery = RegistryParse.DeletedKeyRecovery(deleted_hive)
    candidates = recovery.recover()
    assert all(c.source_cell_offset != 0x1868 for c in candidates)


def test_slack_detection(slack_hive):
    recovery = RegistryParse.DeletedKeyRecovery(slack_hive)
    candidates = recovery.recover()

    slack = [c for c in candidates
             if c.source_cell_offset == 0x1628 and c.name == "SlackKey"]
    assert len(slack) == 1
    assert slack[0].cell_state == RegistryParse.DELETED_CELL_STATE_SLACK


def test_pristine_hive_has_no_deleted_candidates(pristine_hive):
    recovery = RegistryParse.DeletedKeyRecovery(RegistryParse.REGFBlock(bytes(pristine_hive), 0, False))
    assert recovery.recover() == []


def test_high_level_interface(deleted_hive):
    hive = Registry.Registry(__import__("io").BytesIO(deleted_hive))
    keys = hive.recover_deleted_keys()

    assert [k.name() for k in keys] == \
        ["EvictedKey", "AsciiEvicted", "OrphanedKey",
         "EvictedKey", "ChildOfDeleted"]
    assert all(isinstance(k, Registry.DeletedKey) for k in keys)

    first = keys[0]
    assert first.timestamp() == DELETED_TIMESTAMP
    assert first.source_offset() == 0x1628
    assert first.cell_state() in (RegistryParse.DELETED_CELL_STATE_FREE,
                                  RegistryParse.DELETED_CELL_STATE_SLACK)
    assert first.cell_type() == RegistryParse.DELETED_CELL_TYPE_KEY
    assert first.parent_name() == "TimeZoneInformation"


def test_live_browsing_is_unchanged(deleted_hive, pristine_hive):
    original = Registry.Registry(__import__("io").BytesIO(bytes(pristine_hive)))
    patched = Registry.Registry(__import__("io").BytesIO(deleted_hive))

    def snapshot(key):
        return (
            key.name(),
            key.timestamp(),
            tuple(sorted(v.name() for v in key.values())),
            tuple(snapshot(s) for s in key.subkeys()),
        )

    assert snapshot(patched.root()) == snapshot(original.root())
    assert patched.root().subkeys_number() == original.root().subkeys_number()
    assert patched.root().values_number() == original.root().values_number()


def test_scan_does_not_mutate_buffer(deleted_hive):
    before = bytes(deleted_hive)
    RegistryParse.DeletedKeyRecovery(deleted_hive).recover()
    assert deleted_hive == before


def test_live_cells_are_not_reported(pristine_hive):
    recovery = RegistryParse.DeletedKeyRecovery(RegistryParse.REGFBlock(bytes(pristine_hive), 0, False))
    live_nk_offsets = set()

    def collect(key):
        live_nk_offsets.add(key._nkrecord.offset() - 4)
        for subkey in key.subkeys():
            collect(subkey)

    collect(Registry.Registry(SAMPLE_PATH).root())
    assert live_nk_offsets

    recovered = {c.source_cell_offset for c in recovery.recover()}
    assert recovered.isdisjoint(live_nk_offsets)
