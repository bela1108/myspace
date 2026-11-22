from correlator.evtx_writer import EvtxChunkWriter, XmlElement, write_evtx
import Evtx.Evtx as ev

w = EvtxChunkWriter()
root = XmlElement(
    "Event",
    {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
    [
        XmlElement("System", {}, [
            XmlElement("EventID", {}, [], "1001"),
            XmlElement("Computer", {}, [], "HOST1"),
        ]),
    ],
)
w.add_event(1, 0, root)
write_evtx("tmp/smoke.evtx", w)
with ev.Evtx("tmp/smoke.evtx") as log:
    fh = log.get_file_header()
    print("file verify:", fh.verify())
    for ch in fh.chunks():
        print("chunk verify:", ch.verify())
        for r in ch.records():
            print(r.xml())
