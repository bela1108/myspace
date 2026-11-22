import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
t = 0x226
print("dlen @0x14", hex(struct.unpack_from("<I", chunk, t+0x14)[0]))
print("body token t+0x18", hex(chunk[t+0x18]))
