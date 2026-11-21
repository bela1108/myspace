import struct

from minidump.constants import MINIDUMP_STREAM_TYPE


BASE = 0x10000

# Three memory streams with overlapping virtual ranges. Where all three cover
# the same address they carry different bytes (three distinct candidates); the
# pairwise overlaps produce two-candidate disputes, and the single-source tails
# are agreed. Stream A also has two touching segments to exercise stitching.
# Re-ordering the directory entries must not change any reported candidate.
STREAM_SPECS = [
	{
		"name": "A",
		"stream_type": MINIDUMP_STREAM_TYPE.MemoryListStream,
		"segments": [
			(BASE + 0x00, 16, bytes(range(0x10, 0x20))),
			(BASE + 0x10, 8, bytes(range(0x30, 0x38))),
		],
	},
	{
		"name": "B",
		"stream_type": MINIDUMP_STREAM_TYPE.MemoryListStream,
		"segments": [
			(BASE + 0x08, 16, b"B" * 16),
		],
	},
	{
		"name": "C",
		"stream_type": MINIDUMP_STREAM_TYPE.Memory64ListStream,
		"segments": [
			(BASE + 0x04, 24, bytes((0xC0 + (i % 16)) for i in range(24))),
		],
	},
]


def _system_info_bytes():
	processor_architecture = 9  # AMD64
	processor_level = 6
	processor_revision = 0x8E09
	number_of_processors = 1
	product_type = 1
	major_version = 10
	minor_version = 0
	build_number = 19045
	platform_id = 2
	csd_version_rva = 0
	suite_mask = 0x100
	reserved2 = 0
	processor_features = [0, 0]
	return struct.pack(
		"<HHHBBIIIIIHH2Q",
		processor_architecture,
		processor_level,
		processor_revision,
		number_of_processors,
		product_type,
		major_version,
		minor_version,
		build_number,
		platform_id,
		csd_version_rva,
		suite_mask,
		reserved2,
		processor_features[0],
		processor_features[1],
	)


def _memory_list_blob(segments, data_rva):
	chunks = [struct.pack("<I", len(segments))]
	cursor = data_rva
	for start, size, data in segments:
		chunks.append(struct.pack("<QII", start, size, cursor))
		cursor += size
	return b"".join(chunks)


def _memory64_list_bytes(segments, base_rva, data_blob):
	chunks = [struct.pack("<QQ", len(segments), base_rva)]
	for start, size, data in segments:
		chunks.append(struct.pack("<QQ", start, size))
	return b"".join(chunks), data_blob


def build_minidump(stream_order):
	"""
	Builds a minimal but valid minidump containing a system info stream, an
	empty module list and the three overlapping memory streams.
	``stream_order`` selects the directory ordering, so swapping it must not
	change the reported candidates.
	"""
	specs = [STREAM_SPECS[index] for index in stream_order]

	header_size = 28
	directory_entry_size = 12
	directory_rva = header_size
	number_of_streams = 1 + 1 + len(specs)
	directory_size = number_of_streams * directory_entry_size

	cursor = directory_rva + directory_size

	directories = []
	stream_blobs = []

	sysinfo_blob = _system_info_bytes()
	directories.append((MINIDUMP_STREAM_TYPE.SystemInfoStream.value, cursor, len(sysinfo_blob)))
	stream_blobs.append(sysinfo_blob)
	cursor += len(sysinfo_blob)

	module_list_blob = struct.pack("<I", 0)
	directories.append((MINIDUMP_STREAM_TYPE.ModuleListStream.value, cursor, len(module_list_blob)))
	stream_blobs.append(module_list_blob)
	cursor += len(module_list_blob)

	for spec in specs:
		segments = spec["segments"]
		if spec["stream_type"] == MINIDUMP_STREAM_TYPE.MemoryListStream:
			descriptor_blob = _memory_list_blob(segments, 0)
			data_rva = cursor + len(descriptor_blob)
			blob = _memory_list_blob(segments, data_rva)
			stream_data = blob + b"".join(data for _, _, data in segments)
		else:
			data_blob = b"".join(data for _, _, data in segments)
			descriptor_blob, _ = _memory64_list_bytes(segments, 0, data_blob)
			base_rva = cursor + len(descriptor_blob)
			blob, _ = _memory64_list_bytes(segments, base_rva, data_blob)
			stream_data = blob + data_blob
		directories.append((spec["stream_type"].value, cursor, len(blob)))
		stream_blobs.append(stream_data)
		cursor += len(stream_data)

	header = b"MDMP"
	header += struct.pack("<HH", 1, 1)
	header += struct.pack("<I", number_of_streams)
	header += struct.pack("<I", directory_rva)
	header += struct.pack("<II", 0, 0)
	header += struct.pack("<I", 0)

	directory_blob = b"".join(
		struct.pack("<III", entry[0], entry[2], entry[1])
		for entry in directories
	)

	return header + directory_blob + b"".join(stream_blobs)


def write_fixtures(path_a, path_b):
	order_a = (0, 1, 2)
	order_b = (2, 0, 1)
	with open(path_a, "wb") as handle:
		handle.write(build_minidump(order_a))
	with open(path_b, "wb") as handle:
		handle.write(build_minidump(order_b))
