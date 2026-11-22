p = "correlator/evtx_writer.py"
lines = open(p).read().splitlines()
start = None
end = None
for i, line in enumerate(lines):
    if line.startswith("    def record_payload("):
        start = i
    if start is not None and i > start and line and not line[0].isspace():
        end = i
        break
NL = chr(10)
m = [
    "    def record_payload(self, root: XmlElement, measure: bool = False) -> bytes:",
    "        self.collect(root)",
    "        stream = bytes([T_START_OF_STREAM, 0x01, 0x01, 0x00])",
    "        body = self.element(root, measure=measure) + bytes([T_END_OF_STREAM])",
    "        if measure:",
    "            return stream + bytes(10 + 0x18 + len(body) + 4)",
    "        template_id = 0x0BADC0DE",
    "        guid = bytes(range(16))",
    "        instance = struct.pack(\"<BBII\", T_TEMPLATE_INSTANCE, 0, template_id, 0)",
    "        tnode = struct.pack(\"<II\", 0, template_id) + guid + struct.pack(\"<I\", len(body)) + body",
    "        return stream + instance + tnode + struct.pack(\"<I\", 0)",
]
lines = lines[:start] + m + lines[end:]
open(p, "w").write(NL.join(lines) + NL)
print("ok")
