import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = next(iter(ch.templates().values()))
    root_el = t.children()[0]
    print("root type", type(root_el).__name__, "name", root_el.tag_name())
    print("num children", len(root_el.children()))
    for c in root_el.children():
        print(" -", type(c).__name__)
