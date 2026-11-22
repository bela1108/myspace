data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
rec = chunk[0x200:]
payload = rec[0x18:]
for i in range(14):
    print(i, hex(payload[i]))
