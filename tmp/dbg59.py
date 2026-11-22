import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = ch.first_record().root().template()
    def find(x):
        for c in x.children():
            if isinstance(c, n.OpenStartElementNode):
                return c
            z = find(c)
            if z:
                return z
    el = find(t)
    print("tag_length", hex(el.tag_length()), "str", hex(el.string_offset()), "name", el.tag_name())
