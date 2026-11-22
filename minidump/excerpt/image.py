#!/usr/bin/env python3
#
# Memory image abstraction used by the excerpt manifest backend.
#
# A MemoryImage is an ordered set of known virtual-address segments.
# Anything not covered by a segment is "unknown" and must never be
# synthesized (e.g. zero-filled) by the manifest layer.

class MemorySegment:
	def __init__(self, start, data):
		self.start = start
		self.data = bytes(data)

	@property
	def end(self):
		return self.start + len(self.data)

	def __repr__(self):
		return 'MemorySegment(%s, %d bytes)' % (hex(self.start), len(self.data))

class MemoryImage:
	def __init__(self, segments):
		self.segments = sorted(segments, key=lambda s: s.start)
		prev = None
		for seg in self.segments:
			if prev is not None and seg.start < prev.end:
				raise ValueError('Overlapping segments at %s' % hex(seg.start))
			prev = seg

	@staticmethod
	def from_minidump_file(minidumpfile):
		"""
		Builds a MemoryImage from a parsed minidump.minidumpfile.MinidumpFile
		by reading every memory segment's bytes from the dump file.
		"""
		segments = []
		lists = []
		if minidumpfile.memory_segments is not None:
			lists.append(minidumpfile.memory_segments)
		if minidumpfile.memory_segments_64 is not None:
			lists.append(minidumpfile.memory_segments_64)
		for memlist in lists:
			for seg in memlist.memory_segments:
				minidumpfile.file_handle.seek(seg.start_file_address, 0)
				data = minidumpfile.file_handle.read(seg.size)
				segments.append(MemorySegment(seg.start_virtual_address, data))
		return MemoryImage(segments)

	def coverage(self, start, end):
		"""
		Walks [start, end) and yields tuples describing what is known:
			('data', run_start, bytes)  for contiguous known runs
			('gap',  gap_start, size)   for unknown address space
		Unknown space is reported, never fabricated.
		"""
		if end <= start:
			raise ValueError('Empty range')
		pos = start
		for seg in self.segments:
			if seg.end <= pos:
				continue
			if seg.start >= end:
				break
			if seg.start > pos:
				yield ('gap', pos, seg.start - pos)
				pos = seg.start
			run_start = max(pos, seg.start)
			run_end = min(end, seg.end)
			off_lo = run_start - seg.start
			off_hi = run_end - seg.start
			yield ('data', run_start, seg.data[off_lo:off_hi])
			pos = run_end
		if pos < end:
			yield ('gap', pos, end - pos)

	def read(self, start, size):
		"""
		Returns the bytes for [start, start+size). Raises KeyError if any
		part of the range is unknown - callers must not substitute zeros.
		"""
		end = start + size
		chunks = []
		for kind, cstart, payload in self.coverage(start, end):
			if kind == 'gap':
				raise KeyError(
					'Unknown pages in range %s-%s' % (hex(cstart), hex(cstart + payload))
				)
			chunks.append(payload)
		return b''.join(chunks)
