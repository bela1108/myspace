import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    print("hdr", hex(ch.header_checksum()), hex(ch.calculate_header_checksum()), ch.header_checksum()==ch.calculate_header_checksum())
    print("data", hex(ch.data_checksum()), hex(ch.calculate_data_checksum()), ch.data_checksum()==ch.calculate_data_checksum())
    print("strings", len(ch.strings()))
