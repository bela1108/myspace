"""Minimal, in-memory minidump builder used by the stack-index regression.

The bytes produced here are parseable by the minidump package itself, so the
tests exercise the real ThreadListStream, ModuleListStream and
SystemInfoStream parsers instead of mock objects.  Nothing is written to disk
by the builder.
"""
import struct

from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE, PRODUCT_TYPE, PLATFORM_ID


AMD64_CONTEXT_SIZE = 1232


def _u16(value):
	return struct.pack('<H', value)


def _u32(value):
	return struct.pack('<I', value)


def _u64(value):
	return struct.pack('<Q', value)


def _amd64_context(rsp, rip):
	"""A zeroed AMD64 CONTEXT with only Rsp and Rip meaningful."""
	data = bytearray(AMD64_CONTEXT_SIZE)
	struct.pack_into('<Q', data, 152, rsp)
	struct.pack_into('<Q', data, 248, rip)
	return bytes(data)


def _system_info_stream():
	data = b''
	data += _u16(PROCESSOR_ARCHITECTURE.AMD64.value)
	data += _u16(9)
	data += _u16(0xffff)
	data += bytes([4, PRODUCT_TYPE.VER_NT_WORKSTATION.value])
	data += _u32(10)
	data += _u32(0)
	data += _u32(19045)
	data += _u32(PLATFORM_ID.VER_PLATFORM_WIN32_NT.value)
	data += _u32(0)
	data += _u16(0)
	data += _u16(0)
	data += _u64(0)
	data += _u64(0)
	return data


def _fixed_file_info(version_ms, version_ls):
	values = [
		0xfeef04bd,
		0,
		version_ms,
		version_ls,
		1,
		2,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
	]
	return b''.join(_u32(value) for value in values)


class SyntheticModule:
	def __init__(self, name, base, size, timestamp, version_ms, version_ls):
		self.name = name
		self.base = base
		self.size = size
		self.timestamp = timestamp
		self.version_ms = version_ms
		self.version_ls = version_ls


def _module_stream(modules):
	record_size = 108
	payload = bytearray(_u32(len(modules)))
	payload += b'\x00' * (record_size * len(modules))

	name_blob = b''
	layout = []
	for index, module in enumerate(modules):
		encoded_name = module.name.encode('utf-16-le')
		name_offset = len(name_blob)
		name_blob += _u32(len(encoded_name)) + encoded_name
		layout.append((index, name_offset))

		record = 4 + index * record_size
		payload[record:record + 8] = _u64(module.base)
		payload[record + 8:record + 12] = _u32(module.size)
		payload[record + 12:record + 16] = _u32(0)
		payload[record + 16:record + 20] = _u32(module.timestamp)
		payload[record + 20:record + 24] = _u32(0)
		version_info = _fixed_file_info(module.version_ms, module.version_ls)
		payload[record + 24:record + 76] = version_info

	return bytes(payload) + name_blob, layout


class SyntheticThread:
	def __init__(self, thread_id, stack_start, stack_size, rip, stack_data, teb=0):
		self.thread_id = thread_id
		self.stack_start = stack_start
		self.stack_size = stack_size
		self.rip = rip
		self.rsp = stack_start + stack_size - 8
		self.stack_data = stack_data
		self.teb = teb


def build_minidump(threads, modules):
	"""Assemble a full minidump byte string from synthetic threads and modules."""
	stream_payloads = []

	stream_payloads.append((MINIDUMP_STREAM_TYPE.SystemInfoStream, _system_info_stream()))

	module_payload, module_layout = _module_stream(modules)
	stream_payloads.append((MINIDUMP_STREAM_TYPE.ModuleListStream, module_payload))

	thread_stream, context_blob, stack_blob, thread_layout = _thread_layout(threads)
	stream_payloads.append((MINIDUMP_STREAM_TYPE.ThreadListStream, thread_stream))

	return _assemble(
		stream_payloads, context_blob, stack_blob,
		threads, thread_layout, modules, module_layout,
	)


def _thread_layout(threads):
	# RVAs inside the records depend on the final file layout and are patched
	# later by _assemble.
	record_size = 48
	stream = bytearray(_u32(len(threads)))
	stream += b'\x00' * (record_size * len(threads))

	context_blob = b''
	stack_blob = b''
	layout = []

	for index, thread in enumerate(threads):
		context = _amd64_context(thread.rsp, thread.rip)
		context_offset = len(context_blob)
		context_blob += context
		stack_offset = len(stack_blob)
		stack_blob += thread.stack_data
		layout.append((index, thread, context_offset, len(context), stack_offset))

	return bytes(stream), context_blob, stack_blob, layout


def _assemble(stream_payloads, context_blob, stack_blob, threads,
		thread_layout, modules, module_layout):
	number_of_streams = len(stream_payloads)
	header_size = 32
	directory_rva = header_size
	offset = header_size + number_of_streams * 12

	directories = b''
	stream_ranges = {}
	for stream_type, payload in stream_payloads:
		directories += _u32(stream_type.value)
		directories += _u32(len(payload))
		directories += _u32(offset)
		stream_ranges[stream_type] = (offset, payload)
		offset += len(payload)

	module_type = MINIDUMP_STREAM_TYPE.ModuleListStream
	module_stream_offset, module_payload = stream_ranges[module_type]
	module_stream = bytearray(module_payload)
	record_size = 108
	records_end = 4 + record_size * len(modules)
	for index, name_offset in module_layout:
		name_rva = module_stream_offset + records_end + name_offset
		record = 4 + index * record_size
		module_stream[record + 20:record + 24] = _u32(name_rva)

	context_base_rva = offset
	offset += len(context_blob)
	stack_base_rva = offset

	thread_type = MINIDUMP_STREAM_TYPE.ThreadListStream
	_, thread_payload = stream_ranges[thread_type]
	thread_stream = bytearray(thread_payload)

	for index, thread, context_offset, context_size, stack_offset in thread_layout:
		record = 4 + index * 48
		thread_stream[record:record + 4] = _u32(thread.thread_id)
		thread_stream[record + 16:record + 24] = _u64(thread.teb)
		thread_stream[record + 24:record + 32] = _u64(thread.stack_start)
		thread_stream[record + 32:record + 36] = _u32(thread.stack_size)
		thread_stream[record + 36:record + 40] = _u32(stack_base_rva + stack_offset)
		thread_stream[record + 40:record + 44] = _u32(context_size)
		thread_stream[record + 44:record + 48] = _u32(context_base_rva + context_offset)

	header = b'MDMP'
	header += _u16(1)
	header += _u16(1)
	header += _u32(number_of_streams)
	header += _u32(directory_rva)
	header += _u32(0)
	header += _u32(0)
	header += _u32(0)
	header += _u32(0)

	body = b''
	for stream_type, payload in stream_payloads:
		if stream_type == thread_type:
			body += bytes(thread_stream)
		elif stream_type == module_type:
			body += bytes(module_stream)
		else:
			body += payload

	return header + directories + body + context_blob + stack_blob
