import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
t = 0x226
dlen = struct.unpack_from("<I", chunk, t+0x14)[0]
body = t+0x18
end = body + dlen
print("body end region", chunk[end-8:end].hex())
print("last token", hex(chunk[end-1]))
