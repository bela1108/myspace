#!/usr/bin/env python3
#
# Reproduces the on-call mis-attribution scenario and prints the forensic
# report. Run with the project virtualenv:
#
#   .venv/bin/python tests/review_demo.py
#
import os

from minidump.minidumpfile import MinidumpFile
from minidump.forensic_report import build_report
from tests.dumpbuilder import DumpBuilder


OUT_PATH = os.path.join(os.path.dirname(__file__), 'review_crash.dmp')


def build_dump():
	builder = DumpBuilder()
	builder.add_thread(0x100)
	# Currently loaded image: [0x10000, 0x13000).
	builder.add_module(r"C:\app\plugin.dll", 0x10000, 0x3000,
					   timestamp=0xAAAA)
	# Same-named module that was unloaded, living at a different range.
	builder.add_unloaded_module(r"C:\app\plugin.dll", 0x90000, 0x2000,
								timestamp=0x3333)
	# Exception 1: address is exactly the module tail (raw endaddress).
	builder.add_exception(0x100, 0x13000)
	# Exception 2: address only has historical (unloaded) coverage.
	builder.add_exception(0x100, 0x90100)
	data = builder.build()
	with open(OUT_PATH, 'wb') as handle:
		handle.write(data)
	return MinidumpFile.parse_bytes(data)


def main():
	dump = build_dump()
	print('Synthetic dump written to %s' % OUT_PATH)
	print('')
	print(build_report(dump))


if __name__ == '__main__':
	main()
