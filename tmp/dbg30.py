import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
print("record head", chunk[0x200:0x218].hex())
magic, size, num = struct.unpack_from("<IIQ", chunk, 0x200)
print("magic", hex(magic), "size", size, "num", num)
print("record end", hex(0x200+size))
nro = struct.unpack_from("<I", chunk, 0x30)[0]
print("nro", hex(nro))
