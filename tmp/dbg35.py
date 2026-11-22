import Evtx.Evtx as ev
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = next(iter(ch.templates().values()))
    for f in ["next_offset","template_id","data_length"]:
        print(f, hex(getattr(t, "_off_"+f)))
