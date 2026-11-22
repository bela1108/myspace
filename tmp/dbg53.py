import Evtx.Evtx as ev
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    print("first record", hex(ch.first_record().offset() - ch.offset()))
    print("strings", hex(min(ch.strings().keys())), hex(max(ch.strings().keys())))
    print("nro", hex(ch.next_record_offset()))
