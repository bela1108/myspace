"""Minimal synthetic registry-hive builder for access-control tests.

The generated hives contain only what regipy needs to navigate keys and parse
their sk security cells: a REGF header, a single HBin holding an NK tree
(an LF subkey list under the root NK) and a pool of SK cells. They are written
to temporary files by the tests, so no binary fixtures are committed.

The builder deliberately supports:
* several keys referencing the same SK cell (shared descriptor);
* two distinct SK cells carrying semantically identical descriptors (the
  equivalent re-point control case);
* a key with a deliberately broken SK offset (uncollectable evidence).
"""

import struct

REGF_HEADER_SIZE = 4096
HBIN_HEADER_SIZE = 32
_CELL_SIZE_SIZE = 4


def _pad4(data: bytes) -> bytes:
    remainder = len(data) % 4
    return data + (b"\x00" * (4 - remainder) if remainder else b"")


def build_sid(revision: int, identifier_authority: int, sub_authorities) -> bytes:
    body = struct.pack("<BB6s", revision, len(sub_authorities), identifier_authority.to_bytes(6, "big"))
    for sub_authority in sub_authorities:
        body += struct.pack("<I", sub_authority)
    return body


def build_ace(ace_type: int, flags: int, access_mask: int, sid: bytes) -> bytes:
    size = 8 + len(sid)
    return struct.pack("<BBHI", ace_type, flags, size, access_mask) + sid


def build_acl(aces) -> bytes:
    acl_body = b"".join(aces)
    header = struct.pack("<BBHHH", 2, 0, 8 + len(acl_body), len(aces), 0)
    return _pad4(header + acl_body)


def build_security_descriptor(owner_sid: bytes, group_sid: bytes, dacl: bytes, sacl: bytes = b"") -> bytes:
    """Build a self-relative SECURITY_DESCRIPTOR; offsets are relative to start."""
    header_size = 20
    offset_owner = header_size
    offset_group = offset_owner + len(owner_sid)
    offset_sacl = offset_group + len(group_sid)
    offset_dacl = offset_sacl + len(sacl)
    control = 0x8000 | 0x0004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    header = struct.pack(
        "<BBHIIII",
        1,
        0,
        control,
        offset_owner,
        offset_group,
        offset_sacl if sacl else 0,
        offset_dacl,
    )
    return header + owner_sid + group_sid + sacl + dacl


def _cell(payload: bytes) -> bytes:
    padded = _pad4(payload)
    cell_size = _CELL_SIZE_SIZE + len(padded)
    return struct.pack("<i", -cell_size) + padded


def _nk_payload(
    name: str,
    parent_offset: int,
    subkeys_list_offset: int,
    security_key_offset: int,
    subkey_count: int,
) -> bytes:
    # CM_KEY_NODE begins right after the 2-byte "nk" signature (prepended by
    # the caller). Byte layout verified against the parser: flags at 0,
    # FILETIME at 2, access_bits at 10, parent offset at 14, SK offset at 42
    # and the key/class name sizes at 70/72; fixed header is 74 bytes followed by the name.
    name_bytes = name.encode("ascii")
    flags = 0x0020  # KEY_COMP_NAME (ASCII compressed name)
    fields = struct.pack(
        "<HQ4sIIIIIIIIIIIII4sHH",
        flags,
        0,  # last_modified (FILETIME, 8 bytes)
        b"\x00\x00\x00\x00",  # access_bits (4 bytes)
        parent_offset,
        subkey_count,
        0,  # volatile subkey count
        subkeys_list_offset,
        0xFFFFFFFF,  # volatile subkeys list offset
        0,  # values count
        0xFFFFFFFF,  # values list offset
        security_key_offset,
        0xFFFFFFFF,  # class name offset
        0,  # largest sk name
        0,  # largest sk class name
        0,  # largest value name
        0,  # largest value data
        b"\x00\x00\x00\x00",  # unknown 4 bytes
        len(name_bytes),  # key name size
        0,  # class name size
    )
    return fields + name_bytes


def _nk_cell(name, parent_offset, subkeys_list_offset, security_key_offset, subkey_count) -> bytes:
    return _cell(b"nk" + _nk_payload(name, parent_offset, subkeys_list_offset, security_key_offset, subkey_count))


def _lf_cell(key_node_offsets) -> bytes:
    # LF body: 2-byte signature, 2-byte element count, then 8-byte elements.
    # regipy reads the signature first and parses the remaining struct from
    # the very next byte, so there is no padding between count and elements.
    elements = b"".join(struct.pack("<II", offset, 0) for offset in key_node_offsets)
    payload = b"lf" + struct.pack("<H", len(key_node_offsets)) + elements
    return _cell(payload)


def _sk_cell(descriptor: bytes, reference_count: int) -> bytes:
    # NK security_key_offset points at the 4 reserved bytes right before "sk".
    payload = (
        b"\x00\x00\x00\x00"
        + b"sk"
        + b"\x00\x00"
        + struct.pack("<iii", 0, 0, reference_count)
        + struct.pack("<I", len(descriptor))
        + descriptor
    )
    return _cell(payload)


def _regf_header(file_name: str, hbin_size: int) -> bytes:
    header = struct.pack(
        "<4sIIQQIIIIII",
        b"regf",
        1,  # primary sequence num
        1,  # secondary sequence num
        0,  # last modification time
        1,  # major version
        3,  # minor version
        0,  # file type
        1,  # file format
        32,  # root key offset
        hbin_size,  # hive bins data size
        1,  # clustering factor
    )
    name_field = file_name.encode("utf-16-le")[:64].ljust(64, b"\x00")
    padding = b"\x00" * 396
    checksum = struct.pack("<I", 0)
    return (header + name_field + padding + checksum).ljust(REGF_HEADER_SIZE, b"\x00")


def build_synthetic_hive(keys, descriptors, file_name: str = "synthetic") -> bytes:
    """Assemble a minimal hive whose root NK owns one flat level of subkeys.

    :param keys: list of dicts {"name": str, "sk": descriptor id | None,
        "broken_sk": bool} describing the root subkeys.
    :param descriptors: mapping of descriptor id to (descriptor bytes,
        reference count) for the SK pool.
    """
    hbin_size = 0x4000

    root_probe = _nk_cell(
        name="CMI-Root",
        parent_offset=0,
        subkeys_list_offset=0,
        security_key_offset=0,
        subkey_count=len(keys),
    )
    sk_sizes = {
        descriptor_id: len(_sk_cell(descriptor_bytes, reference_count))
        for descriptor_id, (descriptor_bytes, reference_count) in descriptors.items()
    }
    nk_sizes = {
        key["name"]: len(
            _nk_cell(
                name=key["name"],
                parent_offset=0,
                subkeys_list_offset=0,
                security_key_offset=0,
                subkey_count=0,
            )
        )
        for key in keys
    }
    lf_probe = _lf_cell([0] * len(keys))

    # Layout: root NK must be the first HBin cell, then SK pool, LF list, child NKs.
    root_offset = HBIN_HEADER_SIZE
    cursor = root_offset + len(root_probe)

    sk_offsets = {}
    for descriptor_id in descriptors:
        sk_offsets[descriptor_id] = cursor + 4
        cursor += sk_sizes[descriptor_id]

    lf_offset = cursor
    cursor += len(lf_probe)

    nk_offsets = {}
    for key in keys:
        nk_offsets[key["name"]] = cursor
        cursor += nk_sizes[key["name"]]

    root_sk = sk_offsets[next(iter(sk_offsets))]
    root_cell = _nk_cell(
        name="CMI-Root",
        parent_offset=root_offset,
        subkeys_list_offset=lf_offset,
        security_key_offset=root_sk,
        subkey_count=len(keys),
    )

    sk_cells = b""
    for descriptor_id, (descriptor_bytes, reference_count) in descriptors.items():
        sk_cells += _sk_cell(descriptor_bytes, reference_count)

    lf_cell = _lf_cell([nk_offsets[key["name"]] for key in keys])

    nk_cells = b""
    for key in keys:
        if key.get("broken_sk"):
            security_key_offset = 0x7FFFFFFF
        else:
            security_key_offset = sk_offsets[key["sk"]]
        nk_cells += _nk_cell(
            name=key["name"],
            parent_offset=root_offset,
            subkeys_list_offset=0,
            security_key_offset=security_key_offset,
            subkey_count=0,
        )

    hbin_header = b"hbin" + struct.pack("<IIIIQI", 0, hbin_size, 0, 0, 0, 0)
    hbin_payload = root_cell + sk_cells + lf_cell + nk_cells
    hbin = (hbin_header + hbin_payload).ljust(hbin_size, b"\x00")
    return _regf_header(file_name, hbin_size) + hbin
