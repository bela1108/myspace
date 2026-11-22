p = "correlator/evtx_writer.py"
lines = open(p).read().splitlines()
NL = chr(10)
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
    "        nodes = bytearray()",
    "        for bucket in buckets:",
    "            for position, name in enumerate(bucket):",
    "                if position + 1 < len(bucket):",
    "                    next_offset = self.offsets[bucket[position + 1]]",
    "                else:",
    "                    next_offset = 0",
    "                nodes += self._encode_node(name, next_offset)",
    "        return bytes(nodes)",
    "",
    "    def bucket_table(self) -> bytes:",
    "        table = bytearray(0x200)",
    "        for index, bucket in enumerate(self._buckets):",
    "            if bucket:",
    "                struct.pack_into(\"<I\", table, index * 4, self.offsets[bucket[0]])",
    "        return bytes(table)",
]
new = lines[:108] + m + lines[135:]
open(p, "w").write(NL.join(new) + NL)
print("layout split")
