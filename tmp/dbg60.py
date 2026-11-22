import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = ch.first_record().root().template()
    def walk(x, d=0):
        if isinstance(x, n.OpenStartElementNode):
            noff = x.offset()-ch.offset()
            print("ELEM", x.tag_name(), hex(x.token()), hex(noff), hex(x.string_offset()))
        if isinstance(x, n.AttributeNode):
            noff = x.offset()-ch.offset()
            print("  ATTR", x.attribute_name().string(), hex(x.token()), hex(noff), hex(x.string_offset()))
        for c in x.children():
            walk(c, d+1)
    walk(t)
