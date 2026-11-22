from correlator.evtx_writer import EvtxChunkWriter, XmlElement, filetime, CHUNK_HEADER_SIZE, build_record, _pad_to_8
import datetime as dt
w = EvtxChunkWriter()
root = XmlElement("Event", {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}, [
  XmlElement("System", {}, [XmlElement("Provider", {"Name": "AdminApproval"}, []), XmlElement("EventID", {}, [], "1001"), XmlElement("Computer", {}, [], "HOST1")]),
  XmlElement("EventData", {}, [XmlElement("ApprovalChainId", {}, [], "CHAIN-7"), XmlElement("Stage", {}, [], "Request")]),
])
w.add_event(1, filetime(dt.datetime(2026,11,20,8,5,0)), root)
w._collect_names()
m = w._measure_records()
print("measure", m, "nro would be", hex(CHUNK_HEADER_SIZE+m))
blob = w.names.layout(CHUNK_HEADER_SIZE+m)
print("blob len", len(blob))
real = w.builder.record_payload(root)
print("real payload", len(real), "real padded rec", len(_pad_to_8(build_record(1,0,real))))
