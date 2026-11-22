#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import struct
import ntpath
from .common_structs import *
from .memory_range import MemoryRangeEvidence, MemoryRangeKind
from .streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

class VirtualSegment:
	def __init__(self, start, end, start_file_address):
		self.start = start
		self.end = end
		self.start_file_address = start_file_address



		self.data = None

	def inrange(self, start, end):
		return self.start <= start and end<= self.end

class MinidumpBufferedMemorySegment:
	def __init__(self, memory_segment, file_handle, chunksize = 10*1024):
		self.start_address = memory_segment.start_virtual_address
		self.end_address = memory_segment.end_virtual_address
		self.total_size = memory_segment.end_virtual_address - memory_segment.start_virtual_address
		self.start_file_address = memory_segment.start_file_address
		self.chunksize = chunksize
		self.chunks = []

	def inrange(self, position):
		return self.start_address <= position < self.end_address

	def remaining_len(self, position):
		if not self.inrange(position):
			return None
		return self.end_address - position

	def find(self, file_handle, pattern, startpos):
		data = self.read(file_handle, 0, -1)
		return data.find(pattern, startpos)

	def read(self, file_handle, start, end):
		if end is None:
			file_handle.seek(self.start_file_address + start)
			return file_handle.read(self.end_address - (self.start_file_address + start))

		for chunk in self.chunks:
			if chunk.inrange(start, end):
				return chunk.data[start - chunk.start: end - chunk.start]

		if self.total_size <= 2*self.chunksize:
			chunksize = self.total_size
			vs = VirtualSegment(0, chunksize, self.start_file_address)
			file_handle.seek(self.start_file_address)
			vs.data = file_handle.read(chunksize)
			self.chunks.append(vs)
			return vs.data[start - vs.start: end - vs.start]

		chunksize = max((end-start), self.chunksize)
		if start + chunksize > self.end_address:
			chunksize = self.end_address - start

		vs = VirtualSegment(start, start+chunksize, self.start_file_address + start)
		file_handle.seek(vs.start_file_address)
		vs.data = file_handle.read(chunksize)
		self.chunks.append(vs)

		return vs.data[start - vs.start: end - vs.start]



class MinidumpBufferedReader:
	def __init__(self, reader, segment_chunk_size = 10*1024):
		self.reader = reader
		self.segment_chunk_size = segment_chunk_size
		self.memory_segments = []

		self.current_segment = None
		self.current_position = None

	def _select_segment(self, requested_position):
		"""

		"""
		# check if we have semgnet for requested address in cache
		for memory_segment in self.memory_segments:
			if memory_segment.inrange(requested_position):
				self.current_segment = memory_segment
				self.current_position = requested_position
				return

		# not in cache, check if it's present in memory space. if yes then create a new buffered memeory object, and copy data
		for memory_segment in self.reader.memory_segments:
			if memory_segment.inrange(requested_position):
				newsegment = MinidumpBufferedMemorySegment(memory_segment, self.reader.file_handle, chunksize=self.segment_chunk_size)
				self.memory_segments.append(newsegment)
				self.current_segment = newsegment
				self.current_position = requested_position
				return

		raise Exception('Memory address 0x%08x is not in process memory space' % requested_position)

	def get_reader(self):
		return self.reader

	def read_range_with_evidence(self, start, end = None, size = None, length = None):
		"""Query an address range without moving the buffered reader's cursor."""
		return self.reader.read_range_with_evidence(start, end = end, size = size, length = length)

	def query_range(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def seek(self, offset, whence = 0):
		"""
		Changes the current address to an offset of offset. The whence parameter controls from which position should we count the offsets.
		0: beginning of the current memory segment
		1: from current position
		2: from the end of the current memory segment
		If you wish to move out from the segment, use the 'move' function
		"""
		if whence == 0:
			t = self.current_segment.start_address + offset
		elif whence == 1:
			t = self.current_position + offset
		elif whence == 2:
			t = self.current_segment.end_address - offset
		else:
			raise Exception('Seek function whence value must be between 0-2')

		if not self.current_segment.inrange(t):
			raise Exception('Seek would cross memory segment boundaries (use move)')

		self.current_position = t
		return

	def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		self._select_segment(address)
		return

	def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
				alignment = 8
			else:
				alignment = 4
		offset = self.current_position % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		self.seek(offset_to_aligned, 1)
		return

	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.current_position

	def peek(self, length):
		"""
		Returns up to length bytes from the current memory segment
		"""
		t = self.current_position + length
		if not self.current_segment.inrange(t - 1):
			raise Exception('Would read over segment boundaries!')
		return self.current_segment.read(self.reader.file_handle, self.current_position - self.current_segment.start_address , t - self.current_segment.start_address)

	def read(self, size = -1):
		"""
		Returns data bytes of size size from the current segment. If size is -1 it returns all the remaining data bytes from memory segment
		"""
		if size < -1:
			raise Exception('You shouldnt be doing this')
		if size == -1:
			t = self.current_segment.remaining_len(self.current_position)
			if not t:
				return None

			old_new_pos = self.current_position
			self.current_position = self.current_segment.end_address
			return self.current_segment.read(self.reader.file_handle, old_new_pos - self.current_segment.start_address, None)

		t = self.current_position + size
		if not self.current_segment.inrange(t - 1):
			raise Exception('Would read over segment boundaries!')

		old_new_pos = self.current_position
		self.current_position = t
		return self.current_segment.read(self.reader.file_handle, old_new_pos - self.current_segment.start_address, t - self.current_segment.start_address)

	def read_int(self):
		"""
		Reads an integer. The size depends on the architecture.
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = True)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = True)

	def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture.
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			return int.from_bytes(self.read(8), byteorder = 'little', signed = False)
		else:
			return int.from_bytes(self.read(4), byteorder = 'little', signed = False)

	def find(self, pattern):
		"""
		Searches for a pattern in the current memory segment
		"""
		pos = self.current_segment.find(self.reader.file_handle, pattern)
		if pos == -1:
			return -1
		return pos + self.current_position

	def find_all(self, pattern):
		"""
		Searches for all occurrences of a pattern in the current memory segment, returns all occurrences as a list
		"""
		pos = []
		last_found = -1
		while True:
			last_found = self.current_segment.find(self.reader.file_handle, pattern, last_found + 1)
			if last_found == -1:
				break
			pos.append(last_found + self.current_segment.start_address)

		return pos

	def find_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns the first occurrence.
		This is exhaustive!
		"""
		pos_s = self.reader.search(pattern)
		if len(pos_s) == 0:
			return -1

		return pos_s[0]

	def find_all_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns a list of addresses where the pattern begins.
		This is exhaustive!
		"""
		return self.reader.search(pattern)

	def get_ptr(self, pos):
		self.move(pos)
		return self.read_uint()
		#raw_data = self.read(pos, self.sizeof_ptr)
		#return struct.unpack(self.unpack_ptr, raw_data)[0]

	def get_ptr_with_offset(self, pos):
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			self.move(pos)
			ptr = int.from_bytes(self.read(4), byteorder = 'little', signed = True)
			return pos + 4 + ptr
		else:
			self.move(pos)
			return self.read_uint()

	def find_in_module(self, module_name, pattern, find_first = False, reverse_order = False):
		t = self.reader.search_module(module_name, pattern, find_first = find_first, reverse_order = reverse_order, chunksize = self.segment_chunk_size)
		return t

class MinidumpFileReader:
	def __init__(self, minidumpfile):
		self.modules = minidumpfile.modules.modules if minidumpfile.modules is not None else []
		self.unloaded_modules = []
		if minidumpfile.unloaded_modules is not None:
			self.unloaded_modules = minidumpfile.unloaded_modules.modules

		self.sysinfo = minidumpfile.sysinfo
		self.memory_info = minidumpfile.memory_info

		if minidumpfile.memory_segments_64 is not None:
			self.memory_segments = minidumpfile.memory_segments_64.memory_segments
			self.is_fulldump = True

		elif minidumpfile.memory_segments is not None:
			self.memory_segments = minidumpfile.memory_segments.memory_segments
			self.is_fulldump = False
		else:
			self.memory_segments = []
			self.is_fulldump = False

		self.filename = minidumpfile.filename
		self.file_handle = minidumpfile.file_handle

		#reader params
		self.sizeof_long = 4
		self.unpack_long = '<L'
		if self.sysinfo is None:
			# Range/evidence queries do not need architecture information.
			self.sizeof_ptr = 8
			self.unpack_ptr = '<Q'
		elif self.sysinfo.ProcessorArchitecture in [PROCESSOR_ARCHITECTURE.AMD64, PROCESSOR_ARCHITECTURE.AARCH64]:
			self.sizeof_ptr = 8
			self.unpack_ptr = '<Q'
		elif self.sysinfo.ProcessorArchitecture in [PROCESSOR_ARCHITECTURE.INTEL,
				PROCESSOR_ARCHITECTURE.ARM]:
			self.sizeof_ptr = 4
			self.unpack_ptr = '<L'
		else:
			raise Exception('Unknown processor architecture %s! Please fix and submit PR!' % self.sysinfo.ProcessorArchitecture)

	def get_handler(self):
		return self.file_handle

	def get_memory(self):
		return self.memory_segments

	def _get_memory_info_entries(self):
		if self.memory_info is None:
			return []
		return self.memory_info.infos

	def _overlapping_data_segments(self, start, end):
		return [
			segment for segment in self.memory_segments
			if segment.start_virtual_address < end and segment.end_virtual_address > start
		]

	def _overlapping_memory_info(self, start, end):
		t = []
		for entry in self._get_memory_info_entries():
			if entry.BaseAddress is None or entry.RegionSize is None:
				continue
			entry_end = entry.BaseAddress + entry.RegionSize
			if entry.BaseAddress < end and entry_end > start:
				t.append(entry)
		return t

	@staticmethod
	def _normalise_range(start, end = None, size = None, length = None):
		if length is not None:
			if size is not None:
				raise ValueError('Specify either size or length, not both')
			size = length

		if size is not None:
			if end is not None:
				raise ValueError('Specify either end or size, not both')
			if size < 0:
				raise ValueError('Range size must not be negative')
			end = start + size
		elif end is None:
			raise ValueError('A range end or size is required')
		elif end < start:
			# Also accept the read(addr, size) convention. It is unambiguous for
			# normal virtual addresses; callers should prefer size= for others.
			end = start + end

		if end < start:
			raise ValueError('Range end must not precede range start')
		return start, end

	@staticmethod
	def _memory_info_signature(entry):
		if entry is None:
			return (None, None, None)
		return (entry.State, entry.Protect, entry.Type)

	@staticmethod
	def _signature(item):
		data_segment = item.data_segment
		data_source = None
		if data_segment is not None:
			data_source = (
				data_segment.start_file_address,
				data_segment.start_virtual_address,
			)
		return (
			item.kind,
			item.memory_info,
			item.data_stream,
			MinidumpFileReader._memory_info_signature(item.memory_info_entry),
			data_source,
			item.truncated,
		)

	@classmethod
	def _merge_evidence(cls, items):
		t = []
		for item in items:
			if item.end <= item.start:
				continue
			if t and t[-1].end == item.start and cls._signature(t[-1]) == cls._signature(item):
				t[-1].end = item.end
				t[-1].data += item.data
				continue
			t.append(item)
		return t

	def _read_sampled_interval(self, start, end, segment):
		data = segment.read(start, end - start, self.file_handle)
		size = end - start
		truncated = len(data) != size
		if truncated:
			data += b'\x00' * (size - len(data))
		return data, truncated

	def read_range_with_evidence(self, start, end = None, size = None, length = None):
		"""
		Read a virtual-address range and return an interval-sorted evidence list.

		The range is half-open (``start <= address < end``). Each returned
		:class:`MemoryRangeEvidence` says whether its bytes came from the memory
		data stream, only from the memory-info table (display-layer zero fill), or
		from neither source (uncovered).

		Adjacent intervals are merged only when their evidence is identical.
		Intervals with the same byte value but different evidence stay separate.
		"""
		start, end = self._normalise_range(start, end = end, size = size, length = length)
		if start == end:
			return []

		data_segments = self._overlapping_data_segments(start, end)
		memory_infos = self._overlapping_memory_info(start, end)

		boundaries = {start, end}
		for segment in data_segments:
			boundaries.add(max(start, segment.start_virtual_address))
			boundaries.add(min(end, segment.end_virtual_address))
		for entry in memory_infos:
			boundaries.add(max(start, entry.BaseAddress))
			boundaries.add(min(end, entry.BaseAddress + entry.RegionSize))

		points = sorted(boundaries)
		items = []
		for interval_start, interval_end in zip(points, points[1:]):
			if interval_start == interval_end:
				continue

			segment = next((
				s for s in data_segments
				if s.start_virtual_address <= interval_start and interval_end <= s.end_virtual_address
			), None)
			info = next((
				i for i in memory_infos
				if i.BaseAddress <= interval_start and interval_end <= i.BaseAddress + i.RegionSize
			), None)

			if segment is not None:
				data, truncated = self._read_sampled_interval(interval_start, interval_end, segment)
				# Keep captured zero and captured non-zero data distinct without
				# changing the boundaries of the underlying evidence.
				run_start = 0
				run_is_zero = data[0] == 0 if data else None
				for offset in range(1, len(data) + 1):
					if offset == len(data) or (data[offset] == 0) != run_is_zero:
						run_data = data[run_start:offset]
						item_start = interval_start + run_start
						item_end = interval_start + offset
						kind = MemoryRangeKind.SAMPLED_ZERO if run_is_zero else MemoryRangeKind.SAMPLED
						items.append(MemoryRangeEvidence(
							item_start,
							item_end,
							run_data,
							kind,
							True,
							info is not None,
							data_segment = segment,
							memory_info_entry = info,
							truncated = truncated,
						))
						run_start = offset
						if offset < len(data):
							run_is_zero = data[offset] == 0
				continue

			zero_data = b'\x00' * (interval_end - interval_start)
			if info is not None:
				kind = MemoryRangeKind.DISPLAY_ZERO
			else:
				kind = MemoryRangeKind.UNCOVERED
			items.append(MemoryRangeEvidence(
				interval_start,
				interval_end,
				zero_data,
				kind,
				False,
				info is not None,
				memory_info_entry = info,
			))

		return self._merge_evidence(items)

	def query_range(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def query_range_with_evidence(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def read_range(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def query_memory_range(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def read_range_evidence(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def get_range_evidence(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def evidence_ranges(self, start, end = None, size = None, length = None):
		"""Alias for :meth:`read_range_with_evidence`."""
		return self.read_range_with_evidence(start, end = end, size = size, length = length)

	def get_buffered_reader(self, segment_chunk_size = 10*1024):
		return MinidumpBufferedReader(self, segment_chunk_size = segment_chunk_size)

	def get_module_by_name(self, module_name):
		for mod in self.modules:
			if ntpath.basename(mod.name).lower().find(module_name.lower()) != -1:
				return mod
		return None

	def get_unloaded_by_name(self, module_name):
		for mod in self.unloaded_modules:
			if ntpath.basename(mod.name).find(module_name) != -1:
				return mod
		return None

	def search_module(self, module_name, pattern, find_first = False, reverse_order = False, chunksize = 10*1024):
		mod = self.get_module_by_name(module_name)
		if mod is None:
			mod = self.get_unloaded_by_name(module_name)
			if mod is None:
				raise Exception('Could not find module! %s' % module_name)

		needles = []
		for ms in self.memory_segments:
			if mod.baseaddress <= ms.start_virtual_address < mod.endaddress:
				needles+= ms.search(pattern, self.file_handle, find_first = find_first, chunksize = chunksize)
				if len(needles) > 0 and find_first is True:
					return needles


		return needles

	def search(self, pattern, find_first = False, chunksize = 10*1024):
		t = []
		for ms in self.memory_segments:
			t+= ms.search(pattern, self.file_handle, find_first = find_first, chunksize = chunksize)

		return t

	def read(self, virt_addr, size):
		for segment in self.memory_segments:
			if segment.inrange(virt_addr):
				return segment.read(virt_addr, size, self.file_handle)
		raise Exception('Address not in memory range! %s' % hex(virt_addr))
