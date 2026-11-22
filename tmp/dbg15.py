data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
print("at 0x388:", chunk[0x388:0x388+32].hex())
print("at 0x200 table region sample 0x80:", chunk[0x80:0x90].hex())
print("size of chunk region 0x200..0x388 all records; strings expected at 0x388")
