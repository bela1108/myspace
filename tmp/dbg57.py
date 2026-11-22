import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    r = ch.first_record()
    t = r.root().template()
    body0 = t.offset() - ch.offset() + 0x18
    def fe(x):
        for c in x.children():
            if isinstance(c, n.OpenStartElementNode):
                return c.offset() - ch.offset()
            z = fe(c)
            if z:
                return z
        return None
    print("body", hex(body0), "first element", hex(fe(t)), "first string", hex(min(ch.strings().keys())))
