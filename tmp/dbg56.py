import Evtx.Evtx as ev
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    r = ch.first_record()
    t = r.root().template()
    body = t.offset() - ch.offset() + 0x18
    first_str = min(ch.strings().keys())
    print("template body", hex(body), "first string", hex(first_str), "str<body?", first_str < body)
