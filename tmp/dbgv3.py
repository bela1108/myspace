import struct
data = open("tmp/v2.evtx","rb").read()
chunk = data[0x1000:0x11000]
for ofs in (0x251, 0x2f8):
    nxt, hsh, slen = struct.unpack_from("<IHH", chunk, ofs)
    print(hex(ofs), "next", hex(nxt), "hash", hex(hsh), "slen", slen, chunk[ofs:ofs+8].hex())
