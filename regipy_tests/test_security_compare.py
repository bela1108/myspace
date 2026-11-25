import struct

from regipy.registry import REGF_HEADER_SIZE, RegistryHive
from regipy.security_compare import compare_security_descriptors

BACKSLASH = chr(92)
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
GENERIC_READ = 0x80000000


def sid_system():
    return bytes([1, 1, 0, 0, 0, 0, 0, 5]) + struct.pack("<I", 18)


def security_descriptor(access_mask):
    sid = sid_system()
    ace = struct.pack("<BBHI", 0, 0, 8 + len(sid), access_mask) + sid
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(ace), 1, 0) + ace
    owner_offset = 20
    dacl_offset = owner_offset + len(sid)
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, owner_offset, owner_offset, 0, dacl_offset)
    return header + sid + acl


class SyntheticHiveBuilder:
    def __init__(self):
        self.hbin = bytearray(32)

    def add_cell(self, body):
        offset = len(self.hbin)
        total = 4 + len(body)
        padded = (total + 7) & ~7
        cell = struct.pack("<i", -padded) + body
        cell += b"\x00" * (padded - len(cell))
        self.hbin.extend(cell)
        return offset

    def add_security_key(self, access_mask, reference_count=1):
        descriptor = security_descriptor(access_mask)
        body = b"sk" + b"\x00\x00"
        body += struct.pack("<IIII", 0xFFFFFFFF, 0xFFFFFFFF, reference_count, len(descriptor))
        body += descriptor
        return self.add_cell(body)

    def add_root_placeholder(self, subkey_count):
        return self.add_nk("Root", 0xFFFFFFFF, subkey_count=subkey_count)

    def add_nk(self, name, security_offset, subkey_count=0, subkey_list=0xFFFFFFFF, parent=0xFFFFFFFF):
        name_bytes = name.encode("ascii")
        body = b"nk" + struct.pack("<HQ4s", 0x0020, 133000000000000000, b"\x02\x00\x00\x00")
        fields = (
            parent,
            subkey_count,
            0,
            subkey_list,
            0,
            0,
            0xFFFFFFFF,
            security_offset,
            0xFFFFFFFF,
            len(name_bytes),
            0,
            0,
            0,
        )
        body += struct.pack("<13I", *fields)
        body += b"\x00" * 4
        body += struct.pack("<HH", len(name_bytes), 0)
        body += name_bytes
        return self.add_cell(body)

    def add_lh_leaf(self, nk_offsets):
        body = b"lh" + struct.pack("<H", len(nk_offsets))
        for offset in nk_offsets:
            body += struct.pack("<II", offset, 0)
        return self.add_cell(body)

    def patch_root(self, root_offset, leaf_offset, security_offset):
        struct.pack_into("<I", self.hbin, root_offset + 32, leaf_offset)
        struct.pack_into("<I", self.hbin, root_offset + 48, security_offset)

    def save(self, path):
        struct.pack_into("<4sIIIIQI", self.hbin, 0, b"hbin", 0, 4096, 0, 0, 0, 0)
        regf = bytearray(REGF_HEADER_SIZE)
        regf[0:4] = b"regf"
        struct.pack_into(
            "<IIQIIIIIII",
            regf,
            4,
            101,
            101,
            133000000000000000,
            1,
            3,
            0,
            1,
            32,
            4096,
            1,
        )
        file_name = "SYNTHETIC_HIVE".encode("utf-16-le")
        regf[48 : 48 + len(file_name)] = file_name
        hbin = bytes(self.hbin).ljust(4096, b"\x00")
        with open(path, "wb") as handle:
            handle.write(bytes(regf) + hbin)


def build_pair(first_path, second_path):
    key_names = [
        "RealChange",
        "SwapA",
        "SwapB",
        "SharedGroupA",
        "SharedGroupB",
        "MovedReference",
        "NotCollected",
    ]

    first = SyntheticHiveBuilder()
    first_root = first.add_root_placeholder(len(key_names))
    root_security_first = first.add_security_key(READ_CONTROL)
    shared_one_first = first.add_security_key(GENERIC_READ, reference_count=1)
    shared_two_first = first.add_security_key(GENERIC_READ, reference_count=1)
    shared_group_first = first.add_security_key(GENERIC_READ | READ_CONTROL, reference_count=2)
    real_low = first.add_security_key(READ_CONTROL)
    moved_first = first.add_security_key(WRITE_DAC)
    collected_security = first.add_security_key(READ_CONTROL)

    first_assignments = {
        "RealChange": real_low,
        "SwapA": shared_one_first,
        "SwapB": shared_two_first,
        "SharedGroupA": shared_group_first,
        "SharedGroupB": shared_group_first,
        "MovedReference": moved_first,
        "NotCollected": collected_security,
    }
    first_children = [first.add_nk(name, first_assignments[name], parent=first_root) for name in key_names]
    first_leaf = first.add_lh_leaf(first_children)
    first.patch_root(first_root, first_leaf, root_security_first)
    first.save(first_path)

    second = SyntheticHiveBuilder()
    second_root = second.add_root_placeholder(len(key_names))
    root_security_second = second.add_security_key(READ_CONTROL)
    shared_one_second = second.add_security_key(GENERIC_READ, reference_count=1)
    shared_two_second = second.add_security_key(GENERIC_READ, reference_count=1)
    second.add_security_key(READ_CONTROL)
    shared_group_second = second.add_security_key(GENERIC_READ | READ_CONTROL, reference_count=2)
    real_high = second.add_security_key(READ_CONTROL | WRITE_DAC)
    moved_second = second.add_security_key(WRITE_DAC)

    second_assignments = {
        "RealChange": real_high,
        "SwapA": shared_two_second,
        "SwapB": shared_one_second,
        "SharedGroupA": shared_group_second,
        "SharedGroupB": shared_group_second,
        "MovedReference": moved_second,
        "NotCollected": 0xFFFFFFFF,
    }
    second_children = [second.add_nk(name, second_assignments[name], parent=second_root) for name in key_names]
    second_leaf = second.add_lh_leaf(second_children)
    second.patch_root(second_root, second_leaf, root_security_second)
    second.save(second_path)


def test_synthetic_security_comparison_distinguishes_change_rereference_and_gap(tmp_path):
    first_path = tmp_path / "synthetic-first.hive"
    second_path = tmp_path / "synthetic-second.hive"
    build_pair(str(first_path), str(second_path))

    RegistryHive(str(first_path)).get_key(BACKSLASH + "SwapA")
    report = compare_security_descriptors(
        str(first_path),
        str(second_path),
        first_name="material-A",
        second_name="material-B",
    )
    findings = {item["key_path"]: item for item in report["key_findings"]}

    real_change = findings[BACKSLASH + "RealChange"]
    assert real_change["conclusion"] == "real_change"
    assert real_change["real_change"] is True
    assert real_change["semantic_equal"] is False
    assert real_change["first"]["hive_path"] == str(first_path)
    assert real_change["second"]["hive_path"] == str(second_path)
    assert real_change["citations"][0]["key_path"] == BACKSLASH + "RealChange"

    moved = findings[BACKSLASH + "MovedReference"]
    assert moved["conclusion"] == "equivalent_rereference"
    assert moved["equivalent_re_reference"] is True
    assert moved["semantic_equal"] is True
    assert moved["reference_location_equal"] is False
    assert moved["first"]["security_key_offset"] != moved["second"]["security_key_offset"]

    swap_a = findings[BACKSLASH + "SwapA"]
    swap_b = findings[BACKSLASH + "SwapB"]
    assert swap_a["conclusion"] == "equivalent_rereference"
    assert swap_a["reference_relation"] == "swapped"
    assert swap_a["is_reference_swap"] is True
    assert swap_a["swap_partner_key"] == BACKSLASH + "SwapB"
    assert swap_b["swap_partner_key"] == BACKSLASH + "SwapA"

    shared_a = findings[BACKSLASH + "SharedGroupA"]
    shared_b = findings[BACKSLASH + "SharedGroupB"]
    assert shared_a["conclusion"] == "equivalent_rereference"
    assert shared_a["first"]["reference_is_shared"] is True
    assert shared_a["second"]["reference_is_shared"] is True
    assert shared_a["first"]["shared_reference_keys"] == [
        BACKSLASH + "SharedGroupA",
        BACKSLASH + "SharedGroupB",
    ]
    assert shared_b["first"]["security_key_offset"] == shared_a["first"]["security_key_offset"]
    assert shared_b["second"]["security_key_offset"] == shared_a["second"]["security_key_offset"]
    assert shared_a["first"]["reference_count"] == 2

    missing = findings[BACKSLASH + "NotCollected"]
    assert missing["conclusion"] == "not_collected"
    assert missing["not_collected"] is True
    assert missing["first"]["collected"] is True
    assert missing["second"]["collected"] is False
    assert missing["second"]["collection_status"] == "not_collected"

    assert report["summary"]["real_change"] >= 1
    assert report["summary"]["equivalent_rereference"] >= 3
    assert report["summary"]["not_collected"] >= 1
    assert report["summary"]["equivalent_reference_swap"] == 2


def test_missing_material_is_reported_as_uncollected(tmp_path):
    first_path = tmp_path / "only.hive"
    second_path = tmp_path / "unused.hive"
    build_pair(str(first_path), str(second_path))

    report = compare_security_descriptors(str(first_path), None)
    finding = report["key_findings"][0]
    assert finding["conclusion"] == "not_collected"
    assert finding["second"]["hive_path"] is None
    assert report["materials"][1]["collected"] is False
