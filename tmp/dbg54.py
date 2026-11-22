import Evtx.Evtx as ev
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    r = ch.first_record()
    rs = r.offset() - ch.offset()
    so = sorted(ch.strings().keys())
    inside = [hex(x) for x in so if rs <= x < rs + r.size()]
    print("first record", hex(rs), "size", r.size())
    print("strings inside", inside)
