#!/usr/bin/env python3

"""
Evidence-aware views of ranges read from a minidump.

A minidump does not contain every byte of the process' virtual address space.
Consumers commonly zero-fill the parts which were not captured, which makes a
captured zero byte indistinguishable from a gap unless the source of the byte
is kept next to the value.
"""


class MemoryRangeKind:
	"""Values used by :class:`MemoryRangeEvidence.kind`."""

	SAMPLED = 'sampled'
	SAMPLED_ZERO = 'sampled_zero'
	DISPLAY_ZERO = 'display_zero'
	UNCOVERED = 'uncovered'

	# Descriptive aliases for callers which use the terminology of the dump.
	CAPTURED = SAMPLED
	ZERO = SAMPLED_ZERO
	TRUE_ZERO = SAMPLED_ZERO
	DISPLAY_PADDING = DISPLAY_ZERO
	FILLER_ZERO = DISPLAY_ZERO
	GAP = UNCOVERED
	NO_SAMPLE = UNCOVERED
	UNSAMPLED = UNCOVERED


class MemoryRangeEvidence:
	"""
	A half-open virtual-memory interval together with the evidence which
	produced its bytes.

	``data_stream`` is true only when the bytes came from a MemoryListStream or
	Memory64ListStream. ``memory_info`` is true when a MemoryInfoListStream
	describes the interval. A zero-filled interval with memory-info support is
	display-layer padding; an interval without either source is uncovered.
	"""

	def __init__(
			self,
			start,
			end,
			data,
			kind,
			data_stream,
			memory_info,
			data_segment = None,
			memory_info_entry = None,
			truncated = False):
		self.start = start
		self.end = end
		self.data = data
		self.kind = kind
		self.data_stream = bool(data_stream)
		self.memory_info = bool(memory_info)
		self.data_segment = data_segment
		self.memory_info_entry = memory_info_entry
		self.truncated = bool(truncated)

	@property
	def size(self):
		return self.end - self.start

	@property
	def memory_info_support(self):
		return self.memory_info

	@property
	def data_stream_support(self):
		return self.data_stream

	@property
	def memory_info_supported(self):
		return self.memory_info

	@property
	def data_stream_supported(self):
		return self.data_stream

	@property
	def has_memory_info(self):
		return self.memory_info

	@property
	def has_data_stream(self):
		return self.data_stream

	@property
	def in_memory_info(self):
		return self.memory_info

	@property
	def in_data_stream(self):
		return self.data_stream

	@property
	def sampled(self):
		return self.data_stream

	@property
	def captured(self):
		return self.data_stream

	@property
	def synthesized(self):
		return not self.data_stream

	@property
	def zero_filled(self):
		return not self.data_stream

	@property
	def is_zero(self):
		return self.kind in (
			MemoryRangeKind.SAMPLED_ZERO,
			MemoryRangeKind.DISPLAY_ZERO,
			MemoryRangeKind.UNCOVERED,
		)

	@property
	def is_sampled_zero(self):
		return self.kind == MemoryRangeKind.SAMPLED_ZERO

	@property
	def is_true_zero(self):
		return self.is_sampled_zero

	@property
	def is_display_zero(self):
		return self.kind == MemoryRangeKind.DISPLAY_ZERO

	@property
	def is_display_padding(self):
		return self.is_display_zero

	@property
	def is_uncovered(self):
		return self.kind == MemoryRangeKind.UNCOVERED

	@property
	def is_gap(self):
		return self.is_uncovered

	@property
	def source(self):
		if self.data_stream:
			return 'data_stream'
		if self.memory_info:
			return 'memory_info'
		return 'uncovered'

	@property
	def origin(self):
		return self.source

	@property
	def classification(self):
		return self.kind

	@property
	def evidence_type(self):
		return self.kind

	@property
	def support(self):
		return {
			'memory_info': self.memory_info,
			'data_stream': self.data_stream,
		}

	@property
	def state(self):
		if self.memory_info_entry is None:
			return None
		return self.memory_info_entry.State

	@property
	def protect(self):
		if self.memory_info_entry is None:
			return None
		return self.memory_info_entry.Protect

	@property
	def memory_type(self):
		if self.memory_info_entry is None:
			return None
		return self.memory_info_entry.Type

	@property
	def evidence(self):
		return {
			'kind': self.kind,
			'data_stream': self.data_stream,
			'memory_info': self.memory_info,
			'sampled': self.sampled,
			'synthesized': self.synthesized,
		}

	def to_dict(self):
		t = self.evidence
		t.update({
			'start': self.start,
			'end': self.end,
			'data': self.data,
			'truncated': self.truncated,
		})
		return t

	def as_dict(self):
		return self.to_dict()

	def _as_tuple(self):
		return (
			self.start,
			self.end,
			self.data,
			self.kind,
			self.memory_info,
			self.data_stream,
		)

	def __iter__(self):
		return iter(self._as_tuple())

	def __len__(self):
		return len(self._as_tuple())

	def __getitem__(self, item):
		if isinstance(item, str):
			return getattr(self, item)
		return self._as_tuple()[item]

	def get(self, item, default = None):
		try:
			return self[item]
		except (AttributeError, IndexError):
			return default

	def __repr__(self):
		return (
			'MemoryRangeEvidence(start=0x%x, end=0x%x, kind=%r, '
			'memory_info=%r, data_stream=%r)'
		) % (
			self.start,
			self.end,
			self.kind,
			self.memory_info,
			self.data_stream,
		)
