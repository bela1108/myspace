import Evtx.Evtx as ev, Evtx.Nodes as n, traceback
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = next(iter(ch.templates().values()))
    ev_node = [c for c in t.children() if isinstance(c, n.OpenStartElementNode)][0]
    print("tag_length", hex(ev_node.tag_length()))
    try:
        kids = ev_node.children()
        for k in kids:
            print(type(k).__name__)
    except Exception:
        traceback.print_exc()
