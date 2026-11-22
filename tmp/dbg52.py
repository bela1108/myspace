import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    print("next_record_offset", hex(ch.next_record_offset()))
    recs = list(ch.records())
    print("num records", len(recs))
    for r in recs:
        print(r.xml())
