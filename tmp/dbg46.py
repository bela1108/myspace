import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
body = 0x226 + 0x18
ss = body + 4
print("after inner streamstart, root elem at", hex(ss))
print("root 11 bytes", chunk[ss:ss+11].hex())
print("byte after root tag (should be 02 CloseStart)", hex(chunk[ss+11]))
