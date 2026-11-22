import struct
data = open("tmp/v2.evtx","rb").read()
chunk = data[0x1000:0x11000]
vals = [(i, hex(struct.unpack_from("<I", chunk, 0x80+i*4)[0])) for i in range(64) if struct.unpack_from("<I", chunk, 0x80+i*4)[0]]
print("buckets", vals)
