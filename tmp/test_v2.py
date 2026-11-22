from correlator.evtx_writer2 import EvtxChunkWriter, build_event_root, write_evtx, filetime
import datetime as dt
import Evtx.Evtx as ev
w = EvtxChunkWriter()
events = [
    {"event_id": 6005, "provider": "EventLog", "computer": "H1$", "data": {}},
    {"event_id": 1001, "provider": "AdminApproval", "computer": "H1$", "data": {"ApprovalChainId": "CHAIN-7", "Stage": "Request"}},
    {"event_id": 1002, "provider": "AdminApproval", "computer": "H1$", "data": {"ApprovalChainId": "CHAIN-7", "Stage": "Decision"}},
]
for i, e in enumerate(events, 1):
    w.add_event(i, filetime(dt.datetime(2026,11,20,8,i)), build_event_root(e))
write_evtx("tmp/v2.evtx", w)
with ev.Evtx("tmp/v2.evtx") as log:
    fh = log.get_file_header()
    print("file", fh.verify())
    for ch in fh.chunks():
        print("chunk", ch.verify(), "strings", len(ch.strings()), "templates", len(ch.templates()))
        for r in ch.records():
            print("REC", r.record_num())
            print(r.xml())
