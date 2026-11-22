p = "correlator/evtx_writer.py"
lines = open(p).read().splitlines()
out = []
for line in lines:
    if line.strip() == "struct.pack_into(\"<II\", header, 0x28, 0x80, next_record_offset)":
        out.append("        struct.pack_into(\"<I\", header, 0x28, 0x80)")
        out.append("        struct.pack_into(\"<I\", header, 0x2C, 0)")
        out.append("        struct.pack_into(\"<I\", header, 0x30, next_record_offset)")
        continue
    if "header, 0x38, crc32(data)" in line:
        out.append("        struct.pack_into(\"<I\", header, 0x34, crc32(data))")
        continue
    if "chunk, 0x1F8, crc32(" in line:
        out.append("        struct.pack_into(\"<I\", chunk, 0x7C, crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])))")
        continue
    out.append(line)
open(p, "w").write(chr(10).join(out) + chr(10))
print("chunk header offsets fixed")
