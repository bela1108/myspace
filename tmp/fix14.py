p = "correlator/evtx_writer.py"
lines = open(p).read().splitlines()
NL = chr(10)
start = end = None
for i, line in enumerate(lines):
    if line.startswith("    def layout("):
        start = i
    if start is not None and i > start and line.startswith("    def bucket_table"):
        end = i
        break
m = [
    "    def layout(self, start_offset: int) -> bytes:",
    "        encoded_lengths = [len(self._encode_node(name, 0)) for name in self.order]",
    "        cursor = start_offset",
    "        for name, length in zip(self.order, encoded_lengths):",
    "            self.offsets[name] = cursor",
    "            cursor += length",
    "        buckets = [[] for _ in range(self.BUCKETS)]",
    "        for name in self.order:",
    "            buckets[self.hash_name(name) % self.BUCKETS].append(name)",
    "        self._buckets = buckets",
    "        next_in_bucket = {}",
    "        for bucket in buckets:",
    "            for position, name in enumerate(bucket):",
    "                if position + 1 < len(bucket):",
    "                    next_in_bucket[name] = self.offsets[bucket[position + 1]]",
    "                else:",
    "                    next_in_bucket[name] = 0",
    "        nodes = bytearray()",
    "        for name in self.order:",
    "            nodes += self._encode_node(name, next_in_bucket[name])",
    "        return bytes(nodes)",
    "",
]
new = lines[:start] + m + lines[end:]
open(p, "w").write(NL.join(new) + NL)
print("layout corrected")
