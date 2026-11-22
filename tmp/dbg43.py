data = open("tests/data/system.evtx","rb").read()
import struct
chunk = data[0x1000:0x11000]
r0 = 0x200
payload = r0 + 0x18
inst = payload + 4
toff = struct.unpack_from("<I", chunk, inst+6)[0]
body = toff + 0x18
print("real root open element", chunk[body:body+11].hex())
print("token", hex(chunk[body]))
