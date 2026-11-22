data = open("tmp/smoke3.evtx", "rb").read()
chunk = data[0x1000:0x11000]
print("magic", chunk[0:8])
print("next_record_offset field @0x28:", chunk[0x28:0x2C].hex())
print("data cks @0x38:", chunk[0x38:0x3C].hex())
print("hdr cks @0x1F8:", chunk[0x1F8:0x1FC].hex())
print("last 8:", chunk[0x1F8:0x200].hex())
