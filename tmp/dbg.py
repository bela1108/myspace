import Evtx.Evtx as ev, binascii
with ev.Evtx("tmp/smoke3.evtx") as log:
    fh = log.get_file_header()
    print("file stored", hex(fh.checksum()), "calc", hex(fh.calculate_checksum()))
    ch = next(fh.chunks())
    print("hdr stored", hex(ch.header_checksum()), "calc", hex(ch.calculate_header_checksum()))
    print("data stored", hex(ch.data_checksum()), "calc", hex(ch.calculate_data_checksum()))
    print("next off", hex(ch.next_record_offset()))
