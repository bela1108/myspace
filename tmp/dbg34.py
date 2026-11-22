import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
t = 0x226
nxt, tid = struct.unpack_from("<II", chunk, t)
dlen = struct.unpack_from("<I", chunk, t+0x14)[0]
print("next", hex(nxt), "id", hex(tid), "dlen", hex(dlen))
print("head", chunk[t:t+0x18].hex())
