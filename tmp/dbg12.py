import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    r = next(ch.records())
    root = r.root()
    inst = root.template_instance()
    print("inst template_offset", hex(inst.template_offset()))
    print(r.xml())
