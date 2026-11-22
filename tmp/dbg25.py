from correlator.evtx_writer import NameTable
nt = NameTable()
for n in ["Event", "xmlns", "System"]:
    b = nt._encode_node(n, 0)
    print(n, "encoded len", len(b), "expected parser len", 8+2*len(n)+2)
