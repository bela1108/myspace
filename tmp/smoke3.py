from correlator.evtx_writer import EvtxChunkWriter, XmlElement, write_evtx, filetime
import datetime as dt
import Evtx.Evtx as ev
w = EvtxChunkWriter()
root = XmlElement("Event", {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}, [
  XmlElement("System", {}, [
    XmlElement("Provider", {"Name": "AdminApproval"}, []),
    XmlElement("EventID", {}, [], "1001"),
    XmlElement("Computer", {}, [], "HOST1"),
  ]),
  XmlElement("EventData", {}, [
    XmlElement("ApprovalChainId", {}, [], "CHAIN-7"),
    XmlElement("Stage", {}, [], "Request"),
  ]),
])
ts = filetime(dt.datetime(2026, 11, 20, 8, 5, 0))
w.add_event(1, ts, root)
write_evtx("tmp/smoke3.evtx", w)
with ev.Evtx("tmp/smoke3.evtx") as log:
    fh = log.get_file_header()
    print("file verify:", fh.verify())
    for ch in fh.chunks():
        print("chunk verify:", ch.verify())
        for r in ch.records():
            print("record", r.record_num(), "ts", r.timestamp())
            print(r.xml())
