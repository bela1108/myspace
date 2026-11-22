p = "correlator/evtx_writer.py"
lines = open(p).read().splitlines()
start = None
end = None
for i, line in enumerate(lines):
    if line.startswith("    def render(self) -> bytes:"):
        start = i
    if start is not None and i > start and line.startswith("def write_evtx"):
        end = i
        break
print("render span", start, end)
