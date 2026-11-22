data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
rec = chunk[0x200:]
payload = rec[0x18:0x18+40]
print("payload head", payload.hex())
print("stream token", hex(rec[0x18]))
inst = 0x18 + 4
print("instance bytes", rec[inst:inst+10].hex())
print("template table @0x180:", chunk[0x180:0x190].hex())
