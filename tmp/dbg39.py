import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
t = 0x226
body = t + 0x18
print("body first 32", chunk[body:body+32].hex())
print("token", hex(chunk[body]))
