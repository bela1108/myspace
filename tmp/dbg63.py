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
    at = find(t, n.AttributeNode)
    aoff = at.offset() - ch.offset()
    raw = ch._buf[ch.offset()+aoff: ch.offset()+aoff+25]
    print("attr raw", raw.hex())
    print("token", hex(at.token()), "taglen", hex(at.tag_length()), "str", hex(at.string_offset()))
