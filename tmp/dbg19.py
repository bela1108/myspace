from correlator.evtx_writer import EvtxChunkWriter, XmlElement
w = EvtxChunkWriter()
root = XmlElement("Event", {"xmlns": "x"}, [XmlElement("System", {}, [XmlElement("Computer", {}, [], "H")])])
w.add_event(1, 0, root)
w._collect_names()
measured = w._measure_records()
real = len(w.builder.record_payload(root))
print("measured", measured, "real payload", real, "padded record", ((0x18+real+4)+7)//8*8)
