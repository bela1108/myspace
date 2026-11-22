data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
ofs = 0x226
print("ofs-10 token", hex(chunk[ofs-10]))
import struct
print("ofs-4 dword", hex(struct.unpack_from("<I", chunk, ofs-4)[0]))
print("node head", chunk[ofs:ofs+24].hex())
