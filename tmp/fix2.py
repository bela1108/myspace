p = "correlator/evtx_writer.py"
s = open(p).read()
s = s.replace(", 0x34, crc32(data))", ", 0x38, crc32(data))")
s = s.replace(", 0x1FC, crc32(", ", 0x1F8, crc32(")
s = s.replace(", 0x78, crc32(bytes(file_header", ", 0x7C, crc32(bytes(file_header")
open(p, "w").write(s)
print("done")
