p = "correlator/evtx_writer.py"
s = open(p).read()
old = "            return stream + bytes(10 + 0x18 + len(body) + 4 + 4)"
new = "            return stream + bytes(10 + 0x18 + len(body) + 4)"
assert old in s
open(p, "w").write(s.replace(old, new))
print("measure formula fixed")
