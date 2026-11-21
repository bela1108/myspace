#!/usr/bin/env python3
#
# Sourced virtual-memory reads.
#
# A minidump may contain more than one memory stream (multiple memory list
# directories or a mix of 32/64 bit memory lists). When their ranges overlap,
# the same virtual address can be backed by different bytes depending on which
# stream is consulted. The objects in this module describe such a read without
# silently picking one source over the other.
#
import enum


class RegionKind(enum.Enum):
	AGREED = 'agreed'
	DISPUTED = 'disputed'
	HOLE = 'hole'


class MemorySource:
	"""One memory stream found in the minidump together with its segments."""

	def __init__(self, stream_type, stream_rva, segments, index = None):
		self.stream_type = stream_type
		self.stream_rva = stream_rva
		self.segments = segments
		self.index = index

	@property
	def source_id(self):
		return '%s@%x' % (self.stream_type.name, self.stream_rva)

	@staticmethod
	def from_stream(stream_type, directory, memory_list, index = None):
		return MemorySource(
			stream_type,
			directory.Location.Rva,
			list(memory_list.memory_segments),
			index = index,
		)

	def covering_segments(self, start_address, end_address):
		candidates = []
		for segment in self.segments:
			overlap_start = max(start_address, segment.start_virtual_address)
			overlap_end = min(end_address, segment.end_virtual_address)
			if overlap_start < overlap_end:
				candidates.append((overlap_start, overlap_end, segment))
		candidates.sort(key = lambda item: (item[0], item[1], item[2].start_file_address))
		return candidates

	def __str__(self):
		return 'MemorySource(%s, segments=%d)' % (self.source_id, len(self.segments))


class MemoryByteRange:
	"""A contiguous [start, end) byte range coming from a single source."""

	def __init__(self, start_address, end_address, source, data):
		self.start_address = start_address
		self.end_address = end_address
		self.source = source
		self.data = data

	@property
	def size(self):
		return self.end_address - self.start_address

	def __len__(self):
		return self.size

	def __str__(self):
		return 'MemoryByteRange(0x%x-0x%x, %s)' % (
			self.start_address,
			self.end_address,
			self.source.source_id if self.source else None,
		)


class MemoryReadRegion:
	"""
	One maximal sub-range of a read, classified as:

	AGREED: every covering source yields the same bytes.
	DISPUTED: at least two sources disagree; ``candidates`` holds the
		distinct byte values instead of pretending there is one answer.
	HOLE: no memory stream covers the address, so there is no evidence.
	"""

	def __init__(self, kind, start_address, end_address, candidates = None, sources = None):
		self.kind = kind
		self.start_address = start_address
		self.end_address = end_address
		self.candidates = candidates if candidates is not None else []
		self.sources = sources if sources is not None else []

	@property
	def size(self):
		return self.end_address - self.start_address

	@property
	def data(self):
		if self.kind == RegionKind.HOLE:
			return None
		if self.kind == RegionKind.AGREED:
			return self.candidates[0]
		return None

	def __str__(self):
		if self.kind == RegionKind.HOLE:
			detail = 'no evidence'
		elif self.kind == RegionKind.AGREED:
			detail = 'value=%s' % _preview(self.candidates[0])
		else:
			detail = 'candidates=[%s]' % ', '.join(_preview(candidate) for candidate in self.candidates)
		return 'MemoryReadRegion(%s, 0x%x-0x%x, %s)' % (
			self.kind.name,
			self.start_address,
			self.end_address,
			detail,
		)


class SourceCoverage:
	"""Everything a single source contributes to the read, stitched per range."""

	def __init__(self, source):
		self.source = source
		self.parts = []

	@property
	def covered_ranges(self):
		return [(part.start_address, part.end_address) for part in self.parts]

	@property
	def data(self):
		chunks = []
		for part in self.parts:
			chunks.append(part.data)
		return b''.join(chunks)

	def __str__(self):
		return 'SourceCoverage(%s, parts=%d)' % (self.source.source_id, len(self.parts))


class MemoryReadReport:
	"""Result of a sourced read over [start_address, start_address + size)."""

	def __init__(self, start_address, size):
		self.start_address = start_address
		self.size = size
		self.end_address = start_address + size
		self.regions = []
		self.source_coverage = {}

	@property
	def agreed_regions(self):
		return [region for region in self.regions if region.kind == RegionKind.AGREED]

	@property
	def disputed_regions(self):
		return [region for region in self.regions if region.kind == RegionKind.DISPUTED]

	@property
	def holes(self):
		return [region for region in self.regions if region.kind == RegionKind.HOLE]

	@property
	def is_fully_resolved(self):
		return all(region.kind == RegionKind.AGREED for region in self.regions)

	@property
	def has_dispute(self):
		return any(region.kind == RegionKind.DISPUTED for region in self.regions)

	def resolved_data(self, hole_fill = b'\x00'):
		"""
		Convenience view of the full requested span. Agreed bytes are used,
		disputed bytes fall back to the first candidate and holes to ``hole_fill``.
		"""
		chunks = []
		for region in self.regions:
			if region.kind == RegionKind.HOLE:
				chunks.append(hole_fill * region.size)
			elif region.kind == RegionKind.AGREED:
				chunks.append(region.candidates[0])
			else:
				chunks.append(region.candidates[0])
		return b''.join(chunks)

	def __str__(self):
		lines = [
			'MemoryReadReport(0x%x-0x%x)' % (self.start_address, self.end_address),
		]
		for region in self.regions:
			lines.append('  ' + str(region))
		for coverage in self.source_coverage.values():
			lines.append('  ' + str(coverage))
		return '\n'.join(lines)


def build_boundaries(start_address, end_address, sources):
	"""All elementary interval boundaries produced by the source segments."""
	boundaries = {start_address, end_address}
	for source in sources:
		for segment in source.segments:
			if segment.end_virtual_address <= start_address or segment.start_virtual_address >= end_address:
				continue
			boundaries.add(max(start_address, segment.start_virtual_address))
			boundaries.add(min(end_address, segment.end_virtual_address))
	return sorted(boundaries)


def classify_element(boundary_start, boundary_end, sources):
	"""
	Returns (kind, ordered distinct candidates, covering sources) for one
	elementary interval without performing any IO.
	"""
	candidates = []
	covering_sources = []
	for source in sources:
		for overlap_start, overlap_end, segment in source.covering_segments(boundary_start, boundary_end):
			if overlap_start == boundary_start and overlap_end == boundary_end:
				covering_sources.append((source, segment))
				break

	if not covering_sources:
		return RegionKind.HOLE, [], []

	# Order by intrinsic source identity (stream type and location), not by
	# directory position, so swapping directory entries never changes the
	# reported candidate sequence.
	ordered = sorted(
		covering_sources,
		key = lambda item: (item[0].stream_type.name, item[0].stream_rva, item[1].start_file_address),
	)
	seen = set()
	distinct_candidates = []
	for source, segment in ordered:
		value = (source, segment)
		if value not in seen:
			seen.add(value)
			distinct_candidates.append(value)

	return None, distinct_candidates, [source for source, _ in ordered]


def merge_regions(elementary_regions):
	"""Merge adjacent elementary intervals that carry the same classification."""
	merged = []
	for region in elementary_regions:
		if merged and _can_merge(merged[-1], region):
			previous = merged[-1]
			previous.end_address = region.end_address
			previous.candidates = [
				previous.candidates[i] + region.candidates[i]
				for i in range(len(previous.candidates))
			]
			for source in region.sources:
				if source not in previous.sources:
					previous.sources.append(source)
			continue
		merged.append(MemoryReadRegion(
			region.kind,
			region.start_address,
			region.end_address,
			list(region.candidates),
			list(region.sources),
		))
	return merged


def _can_merge(left, right):
	if left.kind != right.kind or left.end_address != right.start_address:
		return False
	if left.kind == RegionKind.HOLE:
		return True
	if len(left.candidates) != len(right.candidates):
		return False
	if [source.source_id for source in left.sources] != [source.source_id for source in right.sources]:
		return False
	return True


def plan_sourced_read(start_address, size, sources):
	"""
	Pure planning step shared by the sync and async entry points.

	Returns a list of elementary intervals, each described as
	(kind_or_None, start, end, [(source, segment), ...]) where ``kind_or_None``
	is HOLE and the segment list is empty for uncovered addresses.
	"""
	if size < 0:
		raise Exception('Read size must not be negative')

	end_address = start_address + size
	boundaries = build_boundaries(start_address, end_address, sources)
	plan = []
	for i in range(len(boundaries) - 1):
		boundary_start = boundaries[i]
		boundary_end = boundaries[i + 1]
		if boundary_start == boundary_end:
			continue
		kind, candidate_refs, covering_sources = classify_element(
			boundary_start,
			boundary_end,
			sources,
		)
		plan.append((kind, boundary_start, boundary_end, candidate_refs, covering_sources))
	return plan


def stitch_source_parts(read_ranges):
	"""
	Group per-source (address, data) fragments into contiguous parts.
	Fragments that merely sit next to each other are stitched together;
	an address gap keeps them as separate parts (the gap stays a hole).
	"""
	grouped = {}
	for start_address, end_address, source, data in read_ranges:
		grouped.setdefault(source, []).append((start_address, end_address, data))

	coverage = {}
	for source, fragments in grouped.items():
		fragments.sort(key = lambda item: item[0])
		source_coverage = SourceCoverage(source)
		for fragment_start, fragment_end, data in fragments:
			if source_coverage.parts and source_coverage.parts[-1].end_address == fragment_start:
				part = source_coverage.parts[-1]
				part.end_address = fragment_end
				part.data += data
			else:
				source_coverage.parts.append(MemoryByteRange(fragment_start, fragment_end, source, data))
		coverage[source.source_id] = source_coverage
	return coverage


def build_report_from_values(start_address, size, plan, value_getter):
	"""
	Assembles the report. ``value_getter(source, segment, start, end)`` returns
	the bytes for one elementary interval (coroutine results are awaited by the
	async wrapper), so the classification rules live in exactly one place.
	"""
	read_ranges = []
	elementary_regions = []

	for kind, boundary_start, boundary_end, candidate_refs, covering_sources in plan:
		if kind == RegionKind.HOLE:
			elementary_regions.append(MemoryReadRegion(
				RegionKind.HOLE,
				boundary_start,
				boundary_end,
			))
			continue

		ordered_values = []
		seen_values = set()
		region_sources = []
		for source, segment in candidate_refs:
			data = value_getter(source, segment, boundary_start, boundary_end)
			read_ranges.append((boundary_start, boundary_end, source, data))
			if source not in region_sources:
				region_sources.append(source)
			if data not in seen_values:
				seen_values.add(data)
				ordered_values.append(data)

		region_kind = RegionKind.AGREED if len(ordered_values) == 1 else RegionKind.DISPUTED
		elementary_regions.append(MemoryReadRegion(
			region_kind,
			boundary_start,
			boundary_end,
			ordered_values,
			region_sources,
		))

	report = MemoryReadReport(start_address, size)
	report.regions = merge_regions(elementary_regions)
	report.source_coverage = stitch_source_parts(read_ranges)
	return report


async def build_report_from_values_async(start_address, size, plan, value_getter):
	"""
	Async mirror of :func:`build_report_from_values`. The planning, ordering
	and merging are identical; only the byte fetching is awaited.
	"""
	read_ranges = []
	elementary_regions = []

	for kind, boundary_start, boundary_end, candidate_refs, covering_sources in plan:
		if kind == RegionKind.HOLE:
			elementary_regions.append(MemoryReadRegion(
				RegionKind.HOLE,
				boundary_start,
				boundary_end,
			))
			continue

		ordered_values = []
		seen_values = set()
		region_sources = []
		for source, segment in candidate_refs:
			data = await value_getter(source, segment, boundary_start, boundary_end)
			read_ranges.append((boundary_start, boundary_end, source, data))
			if source not in region_sources:
				region_sources.append(source)
			if data not in seen_values:
				seen_values.add(data)
				ordered_values.append(data)

		region_kind = RegionKind.AGREED if len(ordered_values) == 1 else RegionKind.DISPUTED
		elementary_regions.append(MemoryReadRegion(
			region_kind,
			boundary_start,
			boundary_end,
			ordered_values,
			region_sources,
		))

	report = MemoryReadReport(start_address, size)
	report.regions = merge_regions(elementary_regions)
	report.source_coverage = stitch_source_parts(read_ranges)
	return report


def _preview(data, limit = 8):
	if data is None:
		return 'None'
	if len(data) <= limit:
		return repr(data)
	return repr(data[:limit]) + '...'
