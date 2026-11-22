import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
nro = struct.unpack_from("<I", chunk, 0x30)[0]
print("blob first 24 at nro", chunk[nro:nro+24].hex())
print("Event node at 0x408", chunk[0x408:0x408+20].hex())
