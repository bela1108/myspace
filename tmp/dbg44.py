import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = next(iter(ch.templates().values()))
    for c in t.children():
        print(type(c).__name__)
        if isinstance(c, n.OpenStartElementNode):
            print("  name", c.tag_name(), "kids", [type(x).__name__ for x in c.children()])
