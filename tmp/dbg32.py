import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = ch.templates()[0x226]
    print("data_length", hex(t.data_length()), "node length", hex(t.length()))
    print("children count", len(t.children()))
