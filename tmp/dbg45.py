import Evtx.Evtx as ev, Evtx.Nodes as n
with ev.Evtx("tests/data/system.evtx") as log:
    ch = next(log.get_file_header().chunks())
    t = next(iter(ch.templates().values()))
    def walk(node, d=0):
        print("  "*d, type(node).__name__, getattr(node, "tag_name", lambda: "")() if isinstance(node, n.OpenStartElementNode) else "")
        for c in getattr(node, "children", lambda: [])():
            walk(c, d+1)
    walk(t)
