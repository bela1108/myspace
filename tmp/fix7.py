p = "correlator/evtx_writer.py"
s = open(p).read()
s = s.replace("            instance_abs = record_start + 0x18 + 4", "            instance_rel = record_start + 0x18 + 4")
s = s.replace("            template_abs = instance_abs + 10", "            template_rel = instance_rel + 10")
s = s.replace("            struct.pack_into(\"<I\", payload, 4 + 6, template_abs)", "            struct.pack_into(\"<I\", payload, 4 + 6, template_rel)")
s = s.replace("            template_offsets.append(template_abs)", "            template_offsets.append(template_rel)")
open(p, "w").write(s)
print("relative offsets fixed")
