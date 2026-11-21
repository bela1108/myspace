#!/usr/bin/env python3
#
# Minimal synthetic minidump builder used by the attribution tests.
#
# Only the streams consumed by the forensic attributor are emitted:
# header + directory, module list, unloaded module list, exception list
# and (optionally) a thread list. Everything is laid out by hand so the
# fixtures stay independent of any Windows-only writing code.
#
import struct


SIGNATURE = b'MDMP'

STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_EXCEPTION = 6
STREAM_UNLOADED_MODULE_LIST = 14

EXCEPTION_ACCESS_VIOLATION = 0xC0000005

# Raw on-disk sizes of the fixed-size records.
_MODULE_ENTRY_SIZE = 108       # MINIDUMP_MODULE
_UNLOADED_ENTRY_SIZE = 24      # MINIDUMP_UNLOADED_MODULE
_UNLOADED_HEADER_SIZE = 12


class DumpBuilder:
	def __init__(self):
		self.modules = []
		self.unloaded_modules = []
		self.exceptions = []
		self.thread_ids = []

	def add_module(self, name, base, size, timestamp=0, checksum=0):
		self.modules.append((name, base, size, timestamp, checksum))
		return self

	def add_unloaded_module(self, name, base, size, timestamp=0, checksum=0):
		self.unloaded_modules.append((name, base, size, timestamp, checksum))
		return self

	def add_exception(self, thread_id, address,
					  code=EXCEPTION_ACCESS_VIOLATION, information=None):
		self.exceptions.append((thread_id, address, code, information or []))
		return self

	def add_thread(self, thread_id):
		self.thread_ids.append(thread_id)
		return self

	def build(self):
		# First pass: build every stream without name RVAs, so their file
		# offsets can be computed from the real blob sizes.
		stream_specs = []
		if self.thread_ids:
			stream_specs.append((STREAM_THREAD_LIST,
								 self._thread_list_blob()))
		if self.modules:
			stream_specs.append((STREAM_MODULE_LIST,
								 self._module_list_blob(None)))
		if self.exceptions:
			stream_specs.append((STREAM_EXCEPTION,
								 self._exception_blob()))
		if self.unloaded_modules:
			stream_specs.append((
				STREAM_UNLOADED_MODULE_LIST,
				self._unloaded_module_list_blob(None)))

		# The library parses a 28-byte header (the 4-byte Flags field is
		# consumed without advancing the stream), so the directory follows at 28.
		header_size = 28
		directory_size = len(stream_specs) * 12
		next_rva = header_size + directory_size

		directories = []
		stream_rvas = {}
		for stream_type, blob in stream_specs:
			directories.append((stream_type, len(blob), next_rva))
			stream_rvas[stream_type] = next_rva
			next_rva += len(blob)

		# Second pass: rebuild the streams that carry name strings now that
		# their own stream RVA is known.
		final_streams = []
		for stream_type, blob in stream_specs:
			if stream_type == STREAM_MODULE_LIST:
				blob = self._module_list_blob(
					stream_rvas[STREAM_MODULE_LIST])
			elif stream_type == STREAM_UNLOADED_MODULE_LIST:
				blob = self._unloaded_module_list_blob(
					stream_rvas[STREAM_UNLOADED_MODULE_LIST])
			final_streams.append((stream_type, blob))

		out = bytearray()
		out += SIGNATURE
		out += struct.pack('<HH', 1, 1)                 # version fields
		out += struct.pack('<I', len(final_streams))
		out += struct.pack('<I', header_size)          # StreamDirectoryRva
		out += struct.pack('<I', 0)                    # CheckSum
		out += struct.pack('<I', 0)                    # TimeDateStamp
		out += struct.pack('<I', 0)                    # Flags

		for stream_type, size, rva in directories:
			out += struct.pack('<III', stream_type, size, rva)

		for _, blob in final_streams:
			out += blob

		return bytes(out)

	def _module_list_blob(self, stream_rva):
		body_size = 4 + _MODULE_ENTRY_SIZE * len(self.modules)
		name_rva = (stream_rva + body_size) if stream_rva is not None else 0

		out = bytearray()
		out += struct.pack('<I', len(self.modules))
		name_blobs = []
		for name, base, size, timestamp, checksum in self.modules:
			encoded = name.encode('utf-16-le')
			name_blobs.append(encoded)
			out += struct.pack('<Q', base)             # BaseOfImage
			out += struct.pack('<I', size)             # SizeOfImage
			out += struct.pack('<I', checksum)         # CheckSum
			out += struct.pack('<I', timestamp)        # TimeDateStamp
			out += struct.pack('<I', name_rva)         # ModuleNameRva
			out += b'\x00' * 52                        # VS_FIXEDFILEINFO
			out += struct.pack('<II', 0, 0)            # CvRecord
			out += struct.pack('<II', 0, 0)            # MiscRecord
			out += struct.pack('<QQ', 0, 0)            # Reserved0/1
			name_rva += 4 + len(encoded)

		for encoded in name_blobs:
			out += struct.pack('<I', len(encoded))
			out += encoded
		return bytes(out)

	def _unloaded_module_list_blob(self, stream_rva):
		body_size = (_UNLOADED_HEADER_SIZE
					 + _UNLOADED_ENTRY_SIZE * len(self.unloaded_modules))
		name_rva = (stream_rva + body_size) if stream_rva is not None else 0

		out = bytearray()
		out += struct.pack('<III', _UNLOADED_HEADER_SIZE,
						   _UNLOADED_ENTRY_SIZE,
						   len(self.unloaded_modules))
		name_blobs = []
		for name, base, size, timestamp, checksum in self.unloaded_modules:
			encoded = name.encode('utf-16-le')
			name_blobs.append(encoded)
			out += struct.pack('<Q', base)
			out += struct.pack('<I', size)
			out += struct.pack('<I', checksum)
			out += struct.pack('<I', timestamp)
			out += struct.pack('<I', name_rva)
			name_rva += 4 + len(encoded)

		for encoded in name_blobs:
			out += struct.pack('<I', len(encoded))
			out += encoded
		return bytes(out)

	def _exception_blob(self):
		out = bytearray()
		for thread_id, address, code, information in self.exceptions:
			params = list(information)[:15]
			out += struct.pack('<II', thread_id, 0)    # ThreadId, alignment
			out += struct.pack('<I', code)             # ExceptionCode
			out += struct.pack('<I', 0)                # ExceptionFlags
			out += struct.pack('<Q', 0)                # ExceptionRecord
			out += struct.pack('<Q', address)          # ExceptionAddress
			out += struct.pack('<II', len(params), 0)  # NumberParameters
			for index in range(15):
				value = params[index] if index < len(params) else 0
				out += struct.pack('<Q', value)
			out += struct.pack('<II', 0, 0)            # ThreadContext
		return bytes(out)

	def _thread_list_blob(self):
		out = bytearray()
		out += struct.pack('<I', len(self.thread_ids))
		for thread_id in self.thread_ids:
			out += struct.pack('<I', thread_id)
			out += struct.pack('<III', 0, 0, 0)        # suspend/priority
			out += struct.pack('<Q', 0)                # Teb
			out += struct.pack('<QII', 0, 0, 0)        # Stack descriptor
			out += struct.pack('<II', 0, 0)            # ThreadContext
		return bytes(out)
