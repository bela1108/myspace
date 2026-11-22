p = "correlator/evtx_writer.py"
s = open(p).read()
old = "        tnode = struct.pack(\"<II\", 0, template_id) + guid + struct.pack(\"<I\", len(body)) + body"
new = "        tnode = struct.pack(\"<I\", 0) + guid + struct.pack(\"<I\", len(body)) + body"
assert old in s
open(p, "w").write(s.replace(old, new))
print("tnode fixed")
