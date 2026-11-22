import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
for ofs in (0x3b0,):
    print(hex(ofs), chunk[ofs:ofs+12].hex())
