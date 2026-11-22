import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
body = 0x226 + 0x18
print("template body head", chunk[body:body+24].hex())
print("first token", hex(chunk[body]))
