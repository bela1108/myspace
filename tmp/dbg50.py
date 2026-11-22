import Evtx.Evtx as ev
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    so = sorted(ch.strings().keys())
    print("string offset range", hex(so[0]), hex(so[-1]))
    print("next_record_offset", hex(ch.next_record_offset()))
    r = next(ch.records())
    print("first record at chunk off", hex(r.offset() - ch.offset()))
