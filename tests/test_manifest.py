import io
import json

import pytest

import pcapng.blocks as blocks
from pcapng import FileWriter
from pcapng.manifest import (
    Manifest,
    build_manifest,
    compare_manifests,
)

RAW_PACKET = (
    b"\xff\xff\xff\xff\xff\xff"  # dst mac
    b"\x00\x11\x22\x33\x44\x55"  # src mac
    b"\x08\x00"  # ethertype
    b"synthetic-payload-0123456789"
)


class ReadOnlyStream(object):
    """A stream that only supports read(); any write attempt fails."""

    def __init__(self, data):
        self._buffer = io.BytesIO(data)

    def read(self, size=-1):
        return self._buffer.read(size)

    def write(self, data):  # pragma: no cover
        raise AssertionError("manifest backend must not write to the source")


def build_record(
    if_name="eth0",
    if_description="Uplink interface",
    comments=("captured by unit A", "exported for review"),
    shb_userappl="tool-alpha",
    epb_options=None,
    endianness="<",
):
    """Build a synthetic capture record; returns (data, epb_offset)."""
    shb = blocks.SectionHeader(
        endianness=endianness,
        options={"shb_userappl": shb_userappl},
    )
    idb_options = {}
    if if_name is not None:
        idb_options["if_name"] = if_name
    if if_description is not None:
        idb_options["if_description"] = if_description
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options=idb_options,
    )

    fake_file = io.BytesIO()
    writer = FileWriter(fake_file, shb)

    epb = shb.new_member(
        blocks.EnhancedPacket,
        timestamp_high=0,
        timestamp_low=123456,
        packet_data=RAW_PACKET,
    )
    for comment in comments:
        epb.options.add("opt_comment", comment)
    if epb_options:
        for name, value in epb_options.items():
            epb.options[name] = value
    epb_offset = fake_file.tell()
    writer.write_block(epb)

    return fake_file.getvalue(), epb_offset


def scan(data, **kwargs):
    return build_manifest(io.BytesIO(data), **kwargs)


def test_manifest_records_capture_position_and_attribution():
    data, epb_offset = build_record()
    manifest = scan(data)
    section = manifest.content["sections"][0]
    assert section["offset"] == 0

    interface = section["interfaces"][0]
    assert interface["interface_id"] == 0
    assert interface["link_type"] == 1
    assert interface["options"]["if_name"] == ["eth0"]
    assert interface["options"]["if_description"] == ["Uplink interface"]
    assert interface["missing_descriptions"] == []

    packet = section["packets"][0]
    assert packet["offset"] == epb_offset
    assert packet["interface_id"] == 0
    assert packet["interface_digest"] == interface["identity_digest"]
    assert packet["unresolved_interface"] is False
    assert packet["captured_len"] == len(RAW_PACKET)
    assert manifest.content["packets_missing_context"] == []


def test_manifest_is_recomputable():
    data, _ = build_record()
    first = scan(data)
    second = scan(data)
    assert first.digest == second.digest
    assert first == second

    # Round-trip through the serialized electronic sheet
    restored = Manifest.from_json(first.to_json())
    assert restored.digest == first.digest
    json.dumps(first.to_dict())  # must stay JSON-serializable


def test_manifest_backend_is_read_only():
    data, _ = build_record()
    manifest = build_manifest(ReadOnlyStream(data))
    assert manifest.digest == scan(data).digest


def test_option_reordering_does_not_change_digest():
    # Same descriptive material, written in a different order by the
    # re-exporting tool: attribution is unaffected, digests must match.
    data_a, _ = build_record(comments=("first note", "second note"))
    data_b, _ = build_record(comments=("second note", "first note"))
    assert data_a != data_b  # the files really differ byte-wise
    trusted = {"packet": ["opt_comment"]}
    assert scan(data_a, trusted_options=trusted).digest == scan(
        data_b, trusted_options=trusted
    ).digest


def test_same_raw_packet_different_context_different_signoff():
    # The two synthetic records from the handover: identical raw packet
    # bytes, but the re-export changed the interface description.
    signed_data, _ = build_record(if_description="Uplink interface")
    reexported_data, _ = build_record(if_description="Backup line (re-export)")

    signed = scan(signed_data)
    reexported = scan(reexported_data)

    report = compare_manifests(signed, reexported)
    assert report["verdict"] == "reject"
    assert report["digests_match"] is False
    assert report["raw_packets_identical"] is True
    assert len(report["attribution_changes"]) == 1

    change = report["attribution_changes"][0]
    packet = reexported.content["sections"][0]["packets"][0]
    assert change["packet_index"] == packet["index"]
    assert change["new_offset"] == packet["offset"]
    assert change["packet_sha256"] == packet["packet_sha256"]
    assert change["old_interface_digest"] != change["new_interface_digest"]


def test_identical_records_sign_off():
    data, _ = build_record()
    report = compare_manifests(scan(data), scan(data))
    assert report["verdict"] == "accept"
    assert report["digests_match"] is True
    assert report["attribution_changes"] == []


def test_missing_key_description_points_out_packets():
    data, epb_offset = build_record(if_description=None)
    manifest = scan(data)

    interface = manifest.content["sections"][0]["interfaces"][0]
    assert interface["missing_descriptions"] == ["if_description"]

    flagged = manifest.content["packets_missing_context"]
    assert len(flagged) == 1
    assert flagged[0]["offset"] == epb_offset
    assert flagged[0]["interface_id"] == 0
    assert flagged[0]["missing"] == ["if_description"]

    packet = manifest.content["sections"][0]["packets"][0]
    assert packet["missing_context"] == ["if_description"]


def test_untrusted_option_change_does_not_change_digest():
    # shb_userappl changed (different exporting tool) but is not trusted
    data_a, _ = build_record(shb_userappl="tool-alpha")
    data_b, _ = build_record(shb_userappl="tool-beta")
    assert scan(data_a).digest == scan(data_b).digest

    # Once the caller explicitly trusts it, the change becomes visible
    trusted = {"section": ["shb_userappl"]}
    assert scan(data_a, trusted_options=trusted).digest != scan(
        data_b, trusted_options=trusted
    ).digest


def test_trusted_packet_options_are_recorded():
    trusted = {"packet": ["epb_dropcount"]}
    data_a, _ = build_record(epb_options={"epb_dropcount": 3})
    data_b, _ = build_record(epb_options={"epb_dropcount": 4})
    data_c, _ = build_record(epb_options={"epb_dropcount": 3, "epb_queue": 1})

    manifest_a = scan(data_a, trusted_options=trusted)
    packet = manifest_a.content["sections"][0]["packets"][0]
    assert packet["options"]["epb_dropcount"] == [3]
    assert "epb_queue" not in packet["options"]  # not trusted -> not recorded

    assert manifest_a.digest != scan(data_b, trusted_options=trusted).digest
    # epb_queue is not trusted, so adding it changes nothing
    assert manifest_a.digest == scan(data_c, trusted_options=trusted).digest


def test_unresolved_interface_is_flagged():
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    fake_file = io.BytesIO()
    FileWriter(fake_file, shb)
    epb = shb.new_member(blocks.EnhancedPacket, packet_data=RAW_PACKET)
    epb.interface_id = 5  # no such interface in the section
    epb._write(fake_file)

    manifest = scan(fake_file.getvalue())
    packet = manifest.content["sections"][0]["packets"][0]
    assert packet["unresolved_interface"] is True
    assert packet["interface_digest"] is None


def test_manifest_from_dict_detects_tampering():
    data, _ = build_record()
    exported = scan(data).to_dict()
    exported["sections"][0]["packets"][0]["captured_len"] += 1
    with pytest.raises(ValueError, match="digest mismatch"):
        Manifest.from_dict(exported)
