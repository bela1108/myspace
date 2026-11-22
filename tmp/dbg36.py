import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
print("instance at 0x21c", chunk[0x21c:0x226].hex())
print("bytes 0x226..0x240", chunk[0x226:0x240].hex())
print("expect tnode: next(4) id(4) guid(16) dlen(4)")
