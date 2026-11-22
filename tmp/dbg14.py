data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
import struct
nz = [(i, hex(struct.unpack_from("<I", chunk, 0x80+i*4)[0])) for i in range(64) if struct.unpack_from("<I", chunk, 0x80+i*4)[0]]
print("nonempty buckets", nz)
print("next_record_offset", hex(struct.unpack_from("<I", chunk, 0x30)[0]))
