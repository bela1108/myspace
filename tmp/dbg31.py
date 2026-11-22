data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
print("magic", chunk[0:8])
import struct
print("magic2a at", hex(chunk.find(bytes.fromhex("2a2a0000"))))
print("ElfChnk present", b"ElfChnk" in chunk)
