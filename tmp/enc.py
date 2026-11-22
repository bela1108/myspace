import base64, sys
src = open("tmp/new_writer_src.py").read()
open("tmp/new_writer.b64","w").write(base64.b64encode(src.encode()).decode())
print("encoded", len(src))
