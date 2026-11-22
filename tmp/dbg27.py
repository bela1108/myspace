import struct
from correlator.evtx_writer import EvtxChunkWriter, XmlElement, filetime, CHUNK_HEADER_SIZE
import datetime as dt
w = EvtxChunkWriter()
root = XmlElement("Event", {"xmlns": "x"}, [XmlElement("System", {}, [XmlElement("Computer", {}, [], "HOST1")])])
w.add_event(1, 0, root)
w._collect_names()
nro = CHUNK_HEADER_SIZE + w._measure_records()
blob = w.names.layout(nro)
print("order", w.names.order)
print("offsets", {k: hex(v) for k,v in w.names.offsets.items()})
