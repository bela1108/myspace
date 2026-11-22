import Evtx.Evtx as ev
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    print("header_size", hex(ch.header_size()))
    print("last_record_offset", hex(ch.last_record_offset()))
    print("next_record_offset", hex(ch.next_record_offset()))
    print("data_checksum", hex(ch.data_checksum()))
    print("header_checksum", hex(ch.header_checksum()))
