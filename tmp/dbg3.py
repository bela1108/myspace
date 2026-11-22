import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    for name in ["magic","file_first_record_number","file_last_record_number","log_first_record_number","log_last_record_number","header_size","last_record_offset","next_record_offset","data_checksum","header_checksum"]:
        print(name, hex(getattr(ch, "_off_" + name)))
