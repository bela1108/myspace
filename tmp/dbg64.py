import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = ch.first_record().root().template()
    seen = set()
    def walk(x):
        if isinstance(x, n.OpenStartElementNode):
            key = x.token() & 0xF0
            if key not in seen:
                seen.add(key)
                noff = x.offset()-ch.offset()
                print("flag", hex(x.token()>>4), "node", hex(noff), "str", hex(x.string_offset()), "gt?", x.string_offset()>noff, "taglen", hex(x.tag_length()))
        for c in x.children():
            walk(c)
    walk(t)
