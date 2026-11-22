import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = ch.first_record().root().template()
    def find(x, want):
        for c in x.children():
            if isinstance(c, want):
                return c
            z = find(c, want)
            if z:
                return z
    el = find(t, n.OpenStartElementNode)
    noff = el.offset()-ch.offset()
    sn = ch.strings()[el.string_offset()]
    print("elem", hex(noff), "taglen", hex(el.tag_length()), "nameat", hex(sn.offset()-ch.offset()), "namelen", sn.length(), "after11", hex(noff+11))
