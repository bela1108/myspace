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
    print("ELEM 15", el._buf[el.offset():el.offset()+15].hex())
    at = find(t, n.AttributeNode)
    print("ATTR 10", at._buf[at.offset():at.offset()+10].hex(), "taglen", hex(at.tag_length()))
