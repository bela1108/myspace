import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
v = 0x242 + 11 + 5
slen = struct.unpack_from("<H", chunk, v+2)[0]
print("token", hex(chunk[v]), "type", hex(chunk[v+1]), "slen", slen)
print("text", chunk[v+4:v+4+slen*2].decode("utf-16-le"))
after = v+4+slen*2
print("token after value", hex(chunk[after]))
