"""
Synthetic OLE2 compound-document generator for sparse-image regression tests.

Builds a small, fully valid CFB container from raw sectors so that individual
pages can be removed deterministically. The layout uses 512-byte sectors and
contains both FAT-backed streams and MiniFAT-backed streams, including two
mini streams that share an underlying normal sector.
"""

import struct

SECTOR_SIZE = 512
MINI_SIZE = 64
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

def _dir_entry(name, entry_type, color=1, left=NOSTREAM, right=NOSTREAM,
               child=NOSTREAM, isect=0, size=0):
    encoded = name.encode("UTF-16LE")
    name_bytes = encoded + b"\x00\x00"
    name_length = len(name_bytes)
    name_field = name_bytes.ljust(64, b"\x00")[:64]
    return struct.pack(
        "<64sHBBIII16sIQQIII",
        name_field, name_length, entry_type, color, left, right, child,
        b"\x00" * 16, 0, 0, 0, isect, size & 0xFFFFFFFF,
        (size >> 32) & 0xFFFFFFFF)

def _payload(label, length, start_byte=0x41):
    return bytes(((start_byte + i) % 251) + 1 for i in range(length))


def build_container():
    """Return (data, layout) for a valid synthetic CFB container."""
    big_a = _payload("A", 4096, 0x11)
    big_b = _payload("B", 4096, 0x71)
    mini_x = _payload("X", 200, 0x21)
    mini_y = _payload("Y", 200, 0x91)
    mini_stream = (mini_x + b"\x00" * (MINI_SIZE * 4 - len(mini_x))
                   + mini_y + b"\x00" * (MINI_SIZE * 4 - len(mini_y)))
    # sector indexes
    FAT, DIRECTORY, DIRECTORY2, MINIFAT = 0, 1, 2, 3
    MINI_ROOT = 4
    BIG_A = [5, 6, 7, 8, 9, 10, 11, 12]
    BIG_B = [13, 14, 15, 16, 17, 18, 19, 20]
    nb_sect = 21
    fat = [FREESECT] * nb_sect
    fat[FAT] = FATSECT
    fat[DIRECTORY] = DIRECTORY2
    fat[DIRECTORY2] = ENDOFCHAIN
    fat[MINIFAT] = ENDOFCHAIN
    fat[MINI_ROOT] = ENDOFCHAIN
    for chain in (BIG_A, BIG_B):
        for index, sect in enumerate(chain):
            fat[sect] = chain[index + 1] if index + 1 < len(chain) else ENDOFCHAIN
    minifat = [FREESECT] * (SECTOR_SIZE // 4)
    mini_x_chain = [0, 1, 2, 3]
    mini_y_chain = [4, 5, 6, 7]
    for chain in (mini_x_chain, mini_y_chain):
        for index, sect in enumerate(chain):
            minifat[sect] = chain[index + 1] if index + 1 < len(chain) else ENDOFCHAIN
    fat_sector = b"".join(struct.pack("<I", v) for v in fat)
    fat_sector = fat_sector.ljust(SECTOR_SIZE, b"\x00")
    minifat_sector = b"".join(struct.pack("<I", v) for v in minifat)
    minifat_sector = minifat_sector.ljust(SECTOR_SIZE, b"\x00")
    root = _dir_entry("Root Entry", 5, color=0, child=1,
                      isect=MINI_ROOT, size=len(mini_stream))
    entry_x = _dir_entry("MiniX", 2, color=0, isect=0, size=len(mini_x))
    entry_y = _dir_entry("MiniY", 2, color=1, isect=4, size=len(mini_y))
    entry_a = _dir_entry("BigA", 2, color=0, isect=BIG_A[0], size=len(big_a))
    entry_b = _dir_entry("BigB", 2, color=1, isect=BIG_B[0], size=len(big_b))
    # red-black tree of root children: BigA(1) left->BigB(2); BigB right->MiniX(3);
    # MiniX right->MiniY(4)
    entry_a = _dir_entry("BigA", 2, color=0, left=2, isect=BIG_A[0], size=len(big_a))
    entry_b = _dir_entry("BigB", 2, color=1, right=3, isect=BIG_B[0], size=len(big_b))
    entry_x = _dir_entry("MiniX", 2, color=0, right=4, isect=0, size=len(mini_x))
    entry_y = _dir_entry("MiniY", 2, color=1, isect=4, size=len(mini_y))
    directory_blob = (root + entry_a + entry_b + entry_x + entry_y)
    directory_sector = directory_blob[:SECTOR_SIZE]
    directory_sector2 = directory_blob[SECTOR_SIZE:].ljust(SECTOR_SIZE, b"\x00")
    mini_root_sector = mini_stream.ljust(SECTOR_SIZE, b"\x00")
    sectors = [
        fat_sector,
        directory_sector,
        directory_sector2,
        minifat_sector,
        mini_root_sector,
    ]
    for sect in BIG_A:
        index = sect - BIG_A[0]
        sectors.append(big_a[index * SECTOR_SIZE:(index + 1) * SECTOR_SIZE])
    for sect in BIG_B:
        index = sect - BIG_B[0]
        sectors.append(big_b[index * SECTOR_SIZE:(index + 1) * SECTOR_SIZE])
    assert len(sectors) == nb_sect
    header = bytearray(512)
    header[0:8] = MAGIC
    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, 3)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 9)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<I", header, 40, 0)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<I", header, 48, DIRECTORY)
    struct.pack_into("<I", header, 56, 0x1000)
    struct.pack_into("<I", header, 60, MINIFAT)
    struct.pack_into("<I", header, 64, 1)
    struct.pack_into("<I", header, 68, ENDOFCHAIN)
    struct.pack_into("<I", header, 72, 0)
    struct.pack_into("<I", header, 76, FAT)
    for index in range(1, 109):
        struct.pack_into("<I", header, 76 + index * 4, FREESECT)
    data = bytes(header) + b"".join(sectors)
    layout = {
        "fat": FAT, "directory": DIRECTORY, "minifat": MINIFAT,
        "mini_root": MINI_ROOT,
        "big_a": list(BIG_A), "big_b": list(BIG_B),
        "mini_x_chain": list(mini_x_chain),
        "mini_y_chain": list(mini_y_chain),
        "nb_sect": nb_sect,
        "streams": {
            "BigA": big_a, "BigB": big_b,
            "MiniX": mini_x, "MiniY": mini_y,
        },
    }
    return data, layout
