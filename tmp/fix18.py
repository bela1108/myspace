p = "correlator/evtx_writer.py"
s = open(p).read()
old = "        body = self.element(root, measure=measure) + bytes([T_END_OF_STREAM])"
new = "        stream_start = bytes([T_START_OF_STREAM, 0x01, 0x01, 0x00])\n        body = stream_start + self.element(root, measure=measure) + bytes([T_END_OF_STREAM])"
assert old in s
open(p, "w").write(s.replace(old, new))
print("inner stream start added")
