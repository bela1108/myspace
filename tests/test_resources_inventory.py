import hashlib

import pytest
import fixtures

import dnfile
from dnfile.resource import (
    InternalResource,
    ResourceCarrier,
    ResourceInventoryEntry,
    ResourceStatus,
)


class StubFlags(object):
    def __init__(self, public=False, private=False):
        self.mrPublic = public
        self.mrPrivate = private


class StubImplementation(object):
    def __init__(self, table_name=None, target_name=None):
        self.table = None
        if table_name is not None:
            self.table = type("StubTable", (), {"name": table_name})()
        self._target_name = target_name

    @property
    def row(self):
        if self._target_name is None:
            return None
        return type("StubRow", (), {"Name": self._target_name})()


class StubManifestResourceRow(object):
    def __init__(self, name, offset=0, public=True, private=False, implementation=None):
        self.Name = name
        self.Offset = offset
        self.Flags = StubFlags(public=public, private=private)
        self.Implementation = implementation


def test_inventory_entry_embedded_ok():
    row = StubManifestResourceRow("dup.resources", offset=0x10)
    data = b"\x01\x02\x03"
    res = InternalResource("dup.resources", True, False)

    entry = ResourceInventoryEntry.from_row(row, 1, resources_rva=0x4000, resource=res, data=data)

    assert entry.row_index == 1
    assert entry.name == "dup.resources"
    assert entry.offset == 0x10
    assert entry.rva == 0x4000 + 0x10 + 4
    assert entry.visibility == "public"
    assert entry.carrier is ResourceCarrier.EMBEDDED
    assert entry.implementation is None
    assert entry.status is ResourceStatus.OK
    assert entry.size == 3
    assert entry.sha256 == hashlib.sha256(data).hexdigest()
    assert entry.resource is res
    assert entry.error is None


def test_inventory_entry_embedded_empty_is_not_missing():
    row = StubManifestResourceRow("empty.bin")

    entry = ResourceInventoryEntry.from_row(row, 1, resources_rva=0x4000, data=b"")

    assert entry.status is ResourceStatus.EMPTY
    assert entry.size == 0
    assert entry.sha256 == hashlib.sha256(b"").hexdigest()

    missing = ResourceInventoryEntry.from_row(row, 2, resources_rva=0x4000, error="read failed")

    assert missing.status is ResourceStatus.MISSING
    assert missing.size is None
    assert missing.sha256 is None
    assert missing.error == "read failed"
    # the two failure modes must be distinguishable at a glance
    assert missing.status is not entry.status
    assert repr(missing) != repr(entry)


def test_inventory_entry_external_carriers():
    file_row = StubManifestResourceRow(
        "linked.bin",
        implementation=StubImplementation("File", "linked.bin"),
    )
    entry = ResourceInventoryEntry.from_row(file_row, 1)
    assert entry.carrier is ResourceCarrier.FILE
    assert entry.implementation == "linked.bin"
    assert entry.status is ResourceStatus.EXTERNAL
    assert entry.size is None
    assert entry.rva is None

    asm_row = StubManifestResourceRow(
        "ref.resources",
        implementation=StubImplementation("AssemblyRef", "Other.Assembly"),
    )
    entry = ResourceInventoryEntry.from_row(asm_row, 2)
    assert entry.carrier is ResourceCarrier.ASSEMBLY
    assert entry.implementation == "Other.Assembly"
    assert entry.status is ResourceStatus.EXTERNAL


def test_inventory_entry_unknown_carrier():
    # ExportedType is not a valid ManifestResource implementation per ECMA-335
    row = StubManifestResourceRow(
        "weird",
        implementation=StubImplementation("ExportedType", "Some.Type"),
    )
    entry = ResourceInventoryEntry.from_row(row, 1)
    assert entry.carrier is ResourceCarrier.UNKNOWN
    assert entry.implementation is None
    assert entry.status is ResourceStatus.EXTERNAL

    # coded index that could not be resolved to any table
    row = StubManifestResourceRow("orphan", implementation=StubImplementation())
    entry = ResourceInventoryEntry.from_row(row, 2)
    assert entry.carrier is ResourceCarrier.UNKNOWN


def test_inventory_entries_keep_same_name_rows_distinct():
    rows = [
        StubManifestResourceRow("dup.resources", offset=0x0),
        StubManifestResourceRow("dup.resources", offset=0x20),
    ]
    res_a = InternalResource("dup.resources", True, False)
    res_b = InternalResource("dup.resources", True, False)

    entries = [
        ResourceInventoryEntry.from_row(row, i, resources_rva=0x4000, resource=res, data=b"x" * i)
        for i, (row, res) in enumerate(zip(rows, (res_a, res_b)), start=1)
    ]

    assert [e.name for e in entries] == ["dup.resources", "dup.resources"]
    assert [e.row_index for e in entries] == [1, 2]
    assert entries[0].resource is res_a
    assert entries[1].resource is res_b
    assert entries[0].resource is not entries[1].resource
    assert entries[0].rva != entries[1].rva


def test_inventory_entry_visibility():
    public = ResourceInventoryEntry.from_row(StubManifestResourceRow("a", public=True), 1)
    private = ResourceInventoryEntry.from_row(
        StubManifestResourceRow("b", public=False, private=True), 2
    )
    assert public.visibility == "public"
    assert public.public is True
    assert private.visibility == "private"
    assert private.private is True


def _load_or_xfail(name):
    path = fixtures.get_data_path_by_name(name)
    if not path.exists():
        raise pytest.xfail("test file {} not found in test fixtures".format(name))
    return path


def test_inventory_matches_on_demand_resources():
    path = _load_or_xfail("minimal-res.exe")

    dn = dnfile.dnPE(path)
    inventory = dn.net.resources_inventory

    assert len(inventory) == 1
    entry = inventory[0]
    assert entry.row_index == 1
    assert entry.name == "sample.resources"
    assert entry.carrier is ResourceCarrier.EMBEDDED
    assert entry.status is ResourceStatus.OK
    assert entry.visibility == "public"
    # the inventory entry and the on-demand resource list refer to the same object
    assert len(dn.net.resources) == 1
    assert entry.resource is dn.net.resources[0]
    assert entry.resource.row_index == entry.row_index
    # content summary matches the raw bytes on disk
    raw = dn.get_data(entry.resource.rva, entry.resource.size)
    assert entry.size == len(raw)
    assert entry.sha256 == hashlib.sha256(raw).hexdigest()


def test_inventory_matches_resources_with_lazy_loading():
    path = _load_or_xfail("minimal-res.exe")

    dn = dnfile.dnPE(path, clr_lazy_load=True)
    inventory = dn.net.resources_inventory

    assert len(inventory) == 1
    assert inventory[0].resource is dn.net.resources[0]


def test_inventory_distinguishes_zero_byte_resource(tmp_path):
    path = _load_or_xfail("minimal-res.exe")
    patched = fixtures.copy_fixture_to_tmp(tmp_path, "minimal-res.exe")

    baseline = dnfile.dnPE(path)
    rsrc = baseline.net.resources[0]
    # zero out the 4-byte size prefix that precedes the resource data
    fixtures.patch_bytes(patched, baseline.get_offset_from_rva(rsrc.rva - 4), b"\x00" * 4)

    dn = dnfile.dnPE(patched)
    inventory = dn.net.resources_inventory

    assert len(inventory) == 1
    entry = inventory[0]
    assert entry.status is ResourceStatus.EMPTY
    assert entry.size == 0
    assert entry.sha256 == hashlib.sha256(b"").hexdigest()
    # a zero-byte resource is still readable on demand
    assert len(dn.net.resources) == 1
    assert entry.resource is dn.net.resources[0]
    assert entry.resource.data == b""


def test_inventory_reports_missing_resource(tmp_path):
    path = _load_or_xfail("minimal-res.exe")
    patched = fixtures.copy_fixture_to_tmp(tmp_path, "minimal-res.exe")

    baseline = dnfile.dnPE(path)
    row_offset = baseline.net.mdtables.ManifestResource[0].struct.get_file_offset()
    # point the row's Offset field far beyond the resources directory
    fixtures.patch_bytes(patched, row_offset, b"\xff\xff\xff\x7f")

    dn = dnfile.dnPE(patched)
    inventory = dn.net.resources_inventory

    # the unreadable resource is gone from the on-demand list...
    assert dn.net.resources == []
    # ...but the inventory still records the declared row
    assert len(inventory) == 1
    entry = inventory[0]
    assert entry.name == "sample.resources"
    assert entry.carrier is ResourceCarrier.EMBEDDED
    assert entry.status is ResourceStatus.MISSING
    assert entry.resource is None
    assert entry.size is None
    assert entry.sha256 is None
    assert entry.error is not None
