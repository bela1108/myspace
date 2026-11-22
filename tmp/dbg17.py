import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
nro = struct.unpack_from("<I", chunk, 0x30)[0]
print("next_record_offset", hex(nro))
vals = [(i, hex(struct.unpack_from("<I", chunk, 0x80+i*4)[0])) for i in range(64) if struct.unpack_from("<I", chunk, 0x80+i*4)[0]]
print("buckets", vals[:5])
print("bytes at nro", chunk[nro:nro+16].hex())
