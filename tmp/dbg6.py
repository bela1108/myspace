import Evtx.Evtx as ev
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    r = next(ch.records())
    root = r.root()
    inst = root.template_instance()
    print("inst off", hex(inst.offset() - ch.offset()))
    print("template_id", hex(inst.template_id()), "tmpl_off", hex(inst.template_offset()))
    t = root.template()
    print("tmpl node off", hex(t.offset() - ch.offset()), "data_length", hex(t.data_length()), "guid", t.guid())
    print("sub count", len(root.substitutions()))
