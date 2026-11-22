import struct
data = open("tmp/v2.evtx","rb").read()
chunk = data[0x1000:0x11000]
p0 = 0x200 + 0x18
print("stream", chunk[p0:p0+4].hex())
inst = p0+4
toff = struct.unpack_from("<I", chunk, inst+6)[0]
print("instance", chunk[inst:inst+10].hex(), "trel", hex(toff))
print("tnode", chunk[toff:toff+0x18].hex())
body = toff+0x18
print("body stream", chunk[body:body+4].hex(), "elem token", hex(chunk[body+4]))
