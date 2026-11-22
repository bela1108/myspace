p = "correlator/evtx_writer.py"
s = open(p).read()
s = s.replace("struct.pack_into(\"<I\", payload, 10, template_rel)", "struct.pack_into(\"<I\", payload, 6, template_rel)")
open(p, "w").write(s)
print("ok")
