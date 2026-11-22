import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
a = 0x242 + 11
print("attr bytes", chunk[a:a+24].hex())
print("token", hex(chunk[a]), "name_off", hex(struct.unpack_from("<I", chunk, a+1)[0]))
print("value token +5", hex(chunk[a+5]), "type +6", hex(chunk[a+6]))
