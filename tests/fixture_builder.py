#!/usr/bin/env python3
#
# Builds the two small, format-valid minidump files used by the regression
# tests and the ready-made "same PID, different process generation" scenario
# under tests/fixtures/.
#
# Scenario: an incident left a light snapshot and a full snapshot behind.
# Both dumps record the same process id (4242), but the process was
# restarted between the two captures, so the caller recorded generation 1
# for the light snapshot and generation 2 for the full one. Thread id
# 0x104 exists in both generations and must NOT be stitched into a single
# timeline.

import json
import os
import struct
from datetime import datetime, timezone

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')

SCENARIO_PID = 4242
SHARED_THREAD_ID = 0x104

LIGHT_GENERATION = 1
LIGHT_TIMESTAMP = 1782000005  # header TimeDateStamp of the light snapshot
LIGHT_WINDOW = (1781999900, 1782000100)

FULL_GENERATION = 2
FULL_TIMESTAMP = 1782000905  # header TimeDateStamp of the full snapshot
FULL_WINDOW = (1782000800, 1782001000)

STREAM_THREAD_LIST = 3
STREAM_MISC_INFO = 15
STREAM_PROCESS_VM_COUNTERS = 22


def _iso(epoch):
	return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def build_thread_list(thread_ids):
	data = struct.pack('<I', len(thread_ids))
	for tid in thread_ids:
		data += struct.pack('<IIII', tid, 0, 0, 0)   # ThreadId, SuspendCount, PriorityClass, Priority
		data += struct.pack('<Q', 0)                # Teb
		data += struct.pack('<QII', 0, 0, 0)        # Stack memory descriptor
		data += struct.pack('<II', 0, 0)            # ThreadContext location descriptor
	return data


def build_misc_info(pid):
	flags = 0x1 | 0x2  # MINIDUMP_MISC1_PROCESS_ID | MINIDUMP_MISC1_PROCESS_TIMES
	return struct.pack('<IIIIII', 24, flags, pid, 0, 0, 0)


def build_vm_counters():
	# 64-bit VM_COUNTERS_EX (96 bytes)
	data = struct.pack('<QQ', 0x1000000, 0x0F00000)  # PeakVirtualSize, VirtualSize
	data += struct.pack('<II', 1234, 0)  # PageFaultCount + alignment padding
	data += struct.pack('<QQQQQQQQQ',
		0x50000,   # PeakWorkingSetSize
		0x40000,   # WorkingSetSize
		0x1000,    # QuotaPeakPagedPoolUsage
		0x0F00,    # QuotaPagedPoolUsage
		0x0800,    # QuotaPeakNonPagedPoolUsage
		0x0700,    # QuotaNonPagedPoolUsage
		0x20000,   # PagefileUsage
		0x28000,   # PeakPagefileUsage
		0x18000,   # PrivateUsage
	)
	return data


def build_minidump(streams, timestamp, flags):
	"""
	streams: list of (stream_type, stream_bytes). Returns the dump file bytes.
	"""
	header_size = 32
	directory_rva = header_size
	data_rva = directory_rva + 12 * len(streams)

	directory = b''
	body = b''
	for stream_type, stream_data in streams:
		directory += struct.pack('<III', stream_type, len(stream_data), data_rva)
		body += stream_data
		data_rva += len(stream_data)

	header = b'MDMP'
	header += struct.pack('<HH', 1, 0)                 # Version, ImplementationVersion
	header += struct.pack('<I', len(streams))          # NumberOfStreams
	header += struct.pack('<I', directory_rva)         # StreamDirectoryRva
	header += struct.pack('<I', 0)                     # CheckSum
	header += struct.pack('<I', timestamp)             # TimeDateStamp
	header += struct.pack('<Q', flags)                 # Flags (MINIDUMP_TYPE)
	return header + directory + body


def build_light_snapshot():
	return build_minidump(
		[
			(STREAM_THREAD_LIST, build_thread_list([0x100, SHARED_THREAD_ID])),
			(STREAM_MISC_INFO, build_misc_info(SCENARIO_PID)),
		],
		timestamp=LIGHT_TIMESTAMP,
		flags=0x0,  # MiniDumpNormal
	)


def build_full_snapshot():
	return build_minidump(
		[
			(STREAM_THREAD_LIST, build_thread_list([SHARED_THREAD_ID, 0x108])),
			(STREAM_MISC_INFO, build_misc_info(SCENARIO_PID)),
			(STREAM_PROCESS_VM_COUNTERS, build_vm_counters()),
		],
		timestamp=FULL_TIMESTAMP,
		flags=0x2 | 0x100,  # MiniDumpWithFullMemory | MiniDumpWithProcessThreadData
	)


def build_manifest():
	return {
		'captures': [
			{
				'label': 'light-snapshot',
				'path': 'light_snapshot.dmp',
				'generation': LIGHT_GENERATION,
				'window': {'start': _iso(LIGHT_WINDOW[0]), 'end': _iso(LIGHT_WINDOW[1])},
				'intent': ['threads', 'vm_counters'],
			},
			{
				'label': 'full-snapshot',
				'path': 'full_snapshot.dmp',
				'generation': FULL_GENERATION,
				'window': {'start': _iso(FULL_WINDOW[0]), 'end': _iso(FULL_WINDOW[1])},
				'intent': ['threads', 'vm_counters'],
			},
		]
	}


def main():
	os.makedirs(FIXTURE_DIR, exist_ok=True)
	with open(os.path.join(FIXTURE_DIR, 'light_snapshot.dmp'), 'wb') as f:
		f.write(build_light_snapshot())
	with open(os.path.join(FIXTURE_DIR, 'full_snapshot.dmp'), 'wb') as f:
		f.write(build_full_snapshot())
	with open(os.path.join(FIXTURE_DIR, 'manifest.json'), 'w') as f:
		json.dump(build_manifest(), f, indent=2)
	print('fixtures written to %s' % FIXTURE_DIR)


if __name__ == '__main__':
	main()
