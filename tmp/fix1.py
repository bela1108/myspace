p = "correlator/evtx_writer.py"
lines = open(p, encoding="utf-8").read().splitlines(keepends=True)
out = []
i = 0
while i < len(lines):
    line = lines[i]
    if line.startswith("        chunk = bytes(header) + data + strings_blob"):
        out.append("        chunk = bytearray(header) + bytearray(data) + bytearray(strings_blob)\n")
        out.append("        if len(chunk) < CHUNK_SIZE:\n")
        out.append("            chunk += bytes(CHUNK_SIZE - len(chunk))\n")
        i += 1
        nxt = lines[i]
        if "ljust" in nxt:
            i += 1
        out.append("        struct.pack_into(\"<I\", chunk, 0x1FC, crc32(bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])))\n")
        i += 1
        out.append("        return bytes(chunk)\n")
        i += 1
    else:
        out.append(line)
        i += 1
open(p, "w", encoding="utf-8").write("".join(out))
print("rewrote render tail")
