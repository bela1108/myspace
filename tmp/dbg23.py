import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
b47 = struct.unpack_from("<I", chunk, 0x80+47*4)[0]
print("bucket47 ptr", hex(b47))
base = b47
nxt, hsh, slen = struct.unpack_from("<IHH", chunk, base)
print("next", hex(nxt), "hash", hex(hsh), "slen", slen)
print("raw string bytes", chunk[base+8: base+8+slen*2].hex())
