import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = next(iter(ch.templates().values()))
    print("dlen", hex(t.data_length()))
