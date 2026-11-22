import Evtx.Evtx as ev
with ev.Evtx("tmp/smoke3.evtx") as log:
    ch = next(log.get_file_header().chunks())
    print("verify", ch.verify())
    try:
        tpls = ch.templates()
        print("templates", {hex(k): type(v).__name__ for k,v in tpls.items()})
    except Exception as exc:
        print("template load error", repr(exc))
