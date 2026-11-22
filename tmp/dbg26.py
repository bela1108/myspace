import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
nro = struct.unpack_from("<I", chunk, 0x30)[0]
print("nro", hex(nro))
print("data region end; scan first name-node-like (next=0, hash)")
for ofs in range(0x388, 0x420, 2):
    nxt, hsh, slen = struct.unpack_from("<IHH", chunk, ofs)
    if nxt == 0 and 0 < slen < 30 and hsh != 0:
        print("candidate node", hex(ofs), "slen", slen, "head", chunk[ofs:ofs+8].hex())
        break
