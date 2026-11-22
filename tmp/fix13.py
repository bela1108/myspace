p = "correlator/evtx_writer.py"
s = open(p).read()
s = s.replace("        strings_blob = self.names.layout(next_record_offset)", "        strings_blob = self.names.layout(next_record_offset)\n        string_table = self.names.bucket_table()")
anchor = "        header = bytearray(0x200)\n"
s = s.replace(anchor, anchor + "        header[0x80:0x200] = self.names.bucket_table()\n")
open(p, "w").write(s)
print("render uses bucket table")
