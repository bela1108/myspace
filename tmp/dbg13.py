import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    print("num strings", len(ch.strings()))
    items = sorted(ch.strings().items())
    print("first 3", [(hex(k), v.string()) for k,v in items[:3]])
