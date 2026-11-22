import struct
data = open("tmp/smoke3.evtx","rb").read()
chunk = data[0x1000:0x11000]
nro = struct.unpack_from("<I", chunk, 0x30)[0]
blob = chunk[nro:]
target = "Event".encode("utf-16-le")
idx = blob.find(target)
print("Event wstring at chunk offset", hex(nro+idx))
node = nro + idx - 8
print("node start", hex(node), "head", chunk[node:node+8].hex())
print("first bucket ptr", hex(struct.unpack_from("<I", chunk, 0x80+47*4)[0]))
