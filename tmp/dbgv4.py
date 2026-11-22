import struct
data = open("tmp/v2.evtx","rb").read()
chunk = data[0x1000:0x11000]
print("rec head", chunk[0x200:0x218].hex())
for probe in range(0x24b, 0x258):
    print(hex(probe), chunk[probe:probe+6].hex())
