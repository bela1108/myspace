from correlator.evtx_writer import EvtxChunkWriter, XmlElement, filetime, build_record, _pad_to_8
import datetime as dt
w = EvtxChunkWriter()
root = XmlElement("Event", {"xmlns": "x"}, [XmlElement("System", {}, [XmlElement("Computer", {}, [], "HOST1")])])
w.add_event(1, 0, root)
w._collect_names()
m = w._measure_records()
from correlator.evtx_writer import CHUNK_HEADER_SIZE
nro = CHUNK_HEADER_SIZE + m
blob = w.names.layout(nro)
print("measured record region", m, "nro", hex(nro), "strings len", len(blob))
real_payload = w.builder.record_payload(root)
real_record = len(_pad_to_8(build_record(1,0,real_payload)))
print("real record", real_record)
print("first name offset", list(w.names.offsets.items())[:3])
