import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
nro = struct.unpack_from("<I", chunk, 0x30)[0]
print("nro", hex(nro))
for probe in range(nro, nro+0x120, 8):
    print(hex(probe), chunk[probe:probe+8].hex())
