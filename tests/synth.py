"""Small synthetic minidumps used by the evidence-view tests."""

import struct


def _u16(value):
	return struct.pack("<H", value)


def _u32(value):
	return struct.pack("<I", value)


def _u64(value):
	return struct.pack("<Q", value)


def _system_info():
	data = _u16(9) + _u16(6) + _u16(0)
	data += struct.pack("<BB", 1, 1)
	data += _u32(10) + _u32(0) + _u32(19045) + _u32(2)
	data += _u32(0) + _u16(0) + _u16(0)
	data += _u64(0) + _u64(0)
	return data


def _directory(stream_type, rva, size):
	return _u32(stream_type) + _u32(size) + _u32(rva)


def build_memory_list_dump(ranges=None):
	"""Build a dump with SystemInfo, MemoryList and ThreadList streams."""
	if ranges is None:
		ranges = [
			(0x1000, bytes(range(0x80))),
			(0x1080, bytes((0x80 + i) & 0xFF for i in range(0x80))),
			(0x1100, b"\xaa" * 0x100),
			(0x1200, b"\xbb" * 0x100),
		]

	stream_count = 3
	directory_rva = 28
	body = bytearray()
	cursor = directory_rva + stream_count * 12

	sysinfo = _system_info()
	sysinfo_rva = cursor
	body += sysinfo
	cursor += len(sysinfo)

	memlist_rva = cursor
	memlist = bytearray(_u32(len(ranges)))
	for start, _ in ranges:
		memlist += _u64(start) + _u32(0) + _u32(0)
	body += memlist
	cursor += len(memlist)
	memlist_size = len(memlist)

	thread_rva = cursor
	thread = bytearray(_u32(1))
	thread += _u32(1) + _u32(0) + _u32(0) + _u32(0) + _u64(0x7000)
	thread += _u64(0x1100) + _u32(0x100) + _u32(0)
	thread += _u32(0x4D0) + _u32(0)
	body += thread
	cursor += len(thread)
	thread_size = len(thread)

	context_rva = cursor
	context = bytearray(0x4D0)
	context[152:160] = _u64(0x1110)
	body += context
	cursor += len(context)

	data_rvas = []
	for _, data in ranges:
		data_rvas.append(cursor)
		body += data
		cursor += len(data)

	for index, (start, data) in enumerate(ranges):
		offset = 4 + index * 16
		struct.pack_into("<Q", body, memlist_rva + offset - (directory_rva + stream_count * 12), start)
		struct.pack_into("<I", body, memlist_rva + offset + 8 - (directory_rva + stream_count * 12), len(data))
		struct.pack_into("<I", body, memlist_rva + offset + 12 - (directory_rva + stream_count * 12), data_rvas[index])

	struct.pack_into("<I", body, thread_rva + 40 - (directory_rva + stream_count * 12), data_rvas[2])
	struct.pack_into("<I", body, thread_rva + 48 - (directory_rva + stream_count * 12), context_rva)

	directory = (
		_directory(7, sysinfo_rva, len(sysinfo))
		+ _directory(5, memlist_rva, memlist_size)
		+ _directory(3, thread_rva, thread_size)
	)

	header = bytearray()
	header += b"MDMP"
	header += _u16(0xA793) + _u16(0)
	header += _u32(stream_count) + _u32(directory_rva)
	header += _u32(0) + _u32(0) + _u32(0)
	assert len(header) == directory_rva
	return bytes(header + directory + body)


def build_memory64_dump(ranges=None):
	"""Build a dump with a Memory64ListStream and no thread list."""
	if ranges is None:
		ranges = [
			(0x2000, b"raw-data-" * 8),
			(0x2100, b"summary-" * 16),
		]

	stream_count = 2
	directory_rva = 28
	body = bytearray()
	cursor = directory_rva + stream_count * 12

	sysinfo = _system_info()
	sysinfo_rva = cursor
	body += sysinfo
	cursor += len(sysinfo)

	mem64_rva = cursor
	mem64 = bytearray(_u64(len(ranges)))
	mem64 += _u64(cursor + 8 + 8 + len(ranges) * 16)
	for start, data in ranges:
		mem64 += _u64(start) + _u64(len(data))
	body += mem64
	cursor += len(mem64)
	mem64_size = len(mem64)

	for _, data in ranges:
		body += data
		cursor += len(data)

	directory = (
		_directory(7, sysinfo_rva, len(sysinfo))
		+ _directory(9, mem64_rva, mem64_size)
	)
	header = bytearray()
	header += b"MDMP"
	header += _u16(0xA793) + _u16(0)
	header += _u32(stream_count) + _u32(directory_rva)
	header += _u32(0) + _u32(0) + _u32(0)
	assert len(header) == directory_rva
	return bytes(header + directory + body)
