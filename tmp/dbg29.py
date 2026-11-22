import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
nro = struct.unpack_from("<I", chunk, 0x30)[0]
rec_size = struct.unpack_from("<I", chunk, 0x204)[0]
print("nro", hex(nro), "record size", rec_size, "record end abs", hex(0x200+rec_size))
