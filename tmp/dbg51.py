import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = next(iter(ch.templates().values()))
    def walk(x):
        if isinstance(x, n.OpenStartElementNode):
            noff = x.offset() - ch.offset()
            print("node", hex(noff), "str", hex(x.string_offset()), "inline?", x.string_offset() > noff, "taglen", hex(x.tag_length()))
        for c in x.children():
            walk(c)
    walk(t)
