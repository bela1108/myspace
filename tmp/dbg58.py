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
    raw = el._buf[el.offset():el.offset()+11]
    noff = el.offset() - ch.offset()
    print("bytes", raw.hex(), "flags", hex(el.flags()), "str", hex(el.string_offset()), "node", hex(noff), "gt?", el.string_offset() > noff)
