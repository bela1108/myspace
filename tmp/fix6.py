p = "correlator/evtx_writer.py"
lines = open(p).read().splitlines()
NL = chr(10)
m = [
    "    def render(self) -> bytes:",
    "        self._collect_names()",
    "        next_record_offset = CHUNK_HEADER_SIZE + self._measure_records()",
    "        strings_blob = self.names.layout(next_record_offset)",
    "        records = bytearray()",
    "        template_offsets = []",
    "        for record_num, timestamp, root in self._roots:",
    "            payload = bytearray(self.builder.record_payload(root))",
    "            record_start = CHUNK_HEADER_SIZE + len(records)",
    "            instance_abs = record_start + 0x18 + 4",
    "            template_abs = instance_abs + 10",
    "            struct.pack_into(\"<I\", payload, 4 + 6, template_abs)",
    "            template_offsets.append(template_abs)",
    "            records += build_record(record_num, timestamp, bytes(payload))",
    "        data = bytes(records)",
    "        if CHUNK_HEADER_SIZE + len(data) != next_record_offset:",
    "            raise RuntimeError(\"record size measurement mismatch\")",
    "        if next_record_offset + len(strings_blob) > CHUNK_SIZE:",
    "            raise ValueError(\"chunk capacity exceeded\")",
    "        header = bytearray(0x200)",
    "        first = self._roots[0][0] if self._roots else 0",
    "        last = self._roots[-1][0] if self._roots else 0",
    "        header[0:8] = b\"ElfChnk\" + bytes(1)",
    "        struct.pack_into(\"<QQQQ\", header, 0x08, first, last, first, last)",
    "        struct.pack_into(\"<I\", header, 0x28, 0x80)",
    "        struct.pack_into(\"<I\", header, 0x2C, 0)",
    "        struct.pack_into(\"<I\", header, 0x30, next_record_offset)",
    "        struct.pack_into(\"<I\", header, 0x34, crc32(data))",
    "        for slot, toff in enumerate(template_offsets[:32]):",
    "            struct.pack_into(\"<I\", header, 0x180 + slot * 4, toff)",
    "        chunk = bytearray(header) + bytearray(data) + bytearray(strings_blob)",
    "        if len(chunk) < CHUNK_SIZE:",
    "            chunk += bytes(CHUNK_SIZE - len(chunk))",
    "        struct.pack_into(\"<I\", chunk, 0x7C, crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])))",
    "        return bytes(chunk)",
]
new = lines[:217] + m + lines[246:]
open(p, "w").write(NL.join(new) + NL)
print("render replaced")
