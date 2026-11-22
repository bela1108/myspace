import Evtx.Evtx as ev, struct
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    r = ch.first_record()
    rs = r.offset() - ch.offset()
    data = r.data()
    print("head", data[:24].hex())
    inst = 0x1c
    toff = struct.unpack_from("<I", data, inst+6)[0]
    print("template chunk-rel", hex(toff), "record-rel", hex(toff-rs))
