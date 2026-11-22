data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
rec = chunk[0x200:]
size = int.from_bytes(rec[4:8], "little")
print("record size", size)
payload = rec[0x18:size-4]
print("payload len", len(payload))
print(payload.hex())
