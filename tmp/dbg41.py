import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
body = 0x226 + 0x18
print("root elem 11 bytes", chunk[body:body+11].hex())
print("token", hex(chunk[body]), "flags", hex(chunk[body]>>4))
