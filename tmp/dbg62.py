import Evtx.Evtx as ev, Evtx.Nodes as n, struct
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
    b = el._buf[el.offset():el.offset()+15]
    print("size dword", hex(struct.unpack_from("<I", b, 3)[0]), "extra", hex(struct.unpack_from("<I", b, 7)[0]), "str", hex(el.string_offset()))
