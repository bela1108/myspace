p = "correlator/evtx_writer.py"
s = open(p).read()
old = "        guid = bytes(range(16))"
new = "        guid = struct.pack(\"<I\", template_id) + bytes(range(12))"
assert old in s
open(p, "w").write(s.replace(old, new))
print("guid fixed")
