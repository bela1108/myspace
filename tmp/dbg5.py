import Evtx.Evtx as ev, binascii
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    raw = ch._buf[ch._offset:ch._offset+0x200]
    calc = binascii.crc32(raw[0:0x78] + raw[0x80:0x200]) & 0xffffffff
    print("calc hdr cks", hex(calc), "stored", hex(ch.header_checksum()))
    print("verify", ch.verify())
