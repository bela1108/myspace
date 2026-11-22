p = "correlator/evtx_writer.py"
lines = open(p).read().splitlines()
start = end = None
for i, line in enumerate(lines):
    if line.startswith("    def layout("):
        start = i
    if start is not None and i > start and line and not line[0].isspace():
        end = i
        break
print(start, end)
