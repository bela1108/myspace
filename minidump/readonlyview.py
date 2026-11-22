#!/usr/bin/env python3
#
# Embeddable read-only evidence views over a single shared read handle.
#
# Use case: a minidump is stored inside an archive container that exposes
# exactly one read handle. Multiple forensic components take turns reviewing
# different regions of that dump. This module lets each component work through
# its own EvidenceView while all physical reads are serialized through one
# SharedReadOnlyHandle. Logical progress (per-view cursor), underlying reads
# (provenance log on the shared handle) and evidence locations (per-view
# covered intervals) are tracked separately, so a review can be paused,
# resumed or interleaved and still produce the same evidence manifest.
# The wrapped handle is only ever seeked and read - the original stays
# untouched.

import hashlib
from typing import Dict, List, Optional, Tuple


def _merge_intervals(intervals):
	"""Merges a list of (start, end) half-open intervals into a sorted,
	non-overlapping list."""
	merged = []
	for start, end in sorted(intervals):
		if end <= start:
			continue
		if merged and start <= merged[-1][1]:
			if end > merged[-1][1]:
				merged[-1] = (merged[-1][0], end)
		else:
			merged.append((start, end))
	return merged


def _subtract_intervals(regions, covered):
	"""Returns the parts of `regions` not present in `covered`."""
	gaps = []
	for rstart, rend in sorted(regions):
		cursor = rstart
		for cstart, cend in sorted(covered):
			if cend <= cursor or cstart >= rend:
				continue
			if cstart > cursor:
				gaps.append((cursor, min(cstart, rend)))
			cursor = max(cursor, cend)
			if cursor >= rend:
				break
		if cursor < rend:
			gaps.append((cursor, rend))
	return gaps


class UnderlyingRead:
	"""
	Provenance record for one physical read issued on the shared handle.
	"""
	def __init__(self, seq:int, reader_id:str, offset:int, requested:int, returned:int):
		self.seq = seq
		self.reader_id = reader_id
		self.offset = offset
		self.requested = requested
		self.returned = returned

	@property
	def end(self):
		return self.offset + self.returned

	@property
	def short(self):
		return self.returned < self.requested

	def to_dict(self):
		return {
			'seq': self.seq,
			'reader_id': self.reader_id,
			'offset': self.offset,
			'requested': self.requested,
			'returned': self.returned,
			'short': self.short,
		}

	def __repr__(self):
		return '<UnderlyingRead #%d %s @%#x req=%d got=%d>' % (
			self.seq, self.reader_id, self.offset, self.requested, self.returned)


class SharedReadOnlyHandle:
	"""
	Serializes all access to the single read handle exposed by an archive
	container. Every physical read is appended to `read_log` as an
	UnderlyingRead provenance record. The wrapped handle is never written.
	"""
	def __init__(self, handle, size:Optional[int] = None):
		self._handle = handle
		if size is None:
			pos = handle.tell()
			handle.seek(0, 2)
			size = handle.tell()
			handle.seek(pos, 0)
		self.size = size
		self.read_log: List[UnderlyingRead] = []

	def read_at(self, offset:int, size:int, reader_id:str) -> Tuple[bytes, UnderlyingRead]:
		if offset < 0:
			raise ValueError('offset must be >= 0')
		if size < 0:
			raise ValueError('size must be >= 0')
		self._handle.seek(offset)
		data = self._handle.read(size)
		rec = UnderlyingRead(len(self.read_log), reader_id, offset, size, len(data))
		self.read_log.append(rec)
		return data, rec

	@staticmethod
	def coverage_of(read_log, reader_id:Optional[str] = None):
		"""
		Recomputes the covered intervals straight from provenance records,
		optionally restricted to one reader. Accepts any iterable of
		UnderlyingRead records, so logs of several sessions (e.g. before
		and after a pause) can be combined for the cross-check.
		"""
		intervals = [
			(rec.offset, rec.end)
			for rec in read_log
			if rec.returned > 0 and (reader_id is None or rec.reader_id == reader_id)
		]
		return _merge_intervals(intervals)

	def coverage(self, reader_id:Optional[str] = None):
		"""
		Recomputes the covered intervals straight from this handle's
		provenance log, optionally restricted to one reader. Used to
		cross-check the evidence locations reported by the views.
		"""
		return SharedReadOnlyHandle.coverage_of(self.read_log, reader_id)

	def write(self, *args, **kwargs):
		raise IOError('SharedReadOnlyHandle is read-only')

	def writelines(self, *args, **kwargs):
		raise IOError('SharedReadOnlyHandle is read-only')

	def truncate(self, *args, **kwargs):
		raise IOError('SharedReadOnlyHandle is read-only')


class ReadResult:
	"""
	Auditable outcome of one logical read issued by an EvidenceView.
	Short reads (returned < requested) and empty reads are visible here,
	together with the provenance sequence numbers that served the read.
	"""
	def __init__(self, reader_id, offset, requested, returned, underlying_seqs, data=None, exhausted=False):
		self.reader_id = reader_id
		self.offset = offset
		self.requested = requested
		self.returned = returned
		self.underlying_seqs = list(underlying_seqs)
		self.data = data
		self.exhausted = exhausted

	@property
	def end(self):
		return self.offset + self.returned

	@property
	def short(self):
		return self.returned < self.requested

	def to_dict(self):
		return {
			'reader_id': self.reader_id,
			'offset': self.offset,
			'requested': self.requested,
			'returned': self.returned,
			'short': self.short,
			'exhausted': self.exhausted,
			'underlying_seqs': list(self.underlying_seqs),
		}

	@staticmethod
	def from_dict(d):
		return ReadResult(
			d['reader_id'], d['offset'], d['requested'], d['returned'],
			d['underlying_seqs'], data=None, exhausted=d['exhausted'])

	def __repr__(self):
		return '<ReadResult %s @%#x req=%d got=%d>' % (
			self.reader_id, self.offset, self.requested, self.returned)


class EvidenceView:
	"""
	Embeddable read-only view for one forensic component. The view owns a
	private logical cursor that may only move inside the regions assigned to
	this reader; all bytes are fetched through the shared handle. Successfully
	collected ranges are tracked as evidence locations; whatever remains
	uncollected inside the assigned regions is reported as gaps.
	"""
	def __init__(self, shared:SharedReadOnlyHandle, reader_id:str,
			regions:List[Tuple[int, int]], materialize:bool = True):
		regions = tuple(sorted((int(s), int(e)) for s, e in regions))
		if not regions:
			raise ValueError('EvidenceView needs at least one region')
		for start, end in regions:
			if end <= start:
				raise ValueError('Region end must be greater than region start')
		for prev, nxt in zip(regions, regions[1:]):
			if nxt[0] < prev[1]:
				raise ValueError('Regions of one reader must not overlap')
		self._shared = shared
		self.reader_id = reader_id
		self.regions = regions
		self._materialize = materialize
		self._cursor = regions[0][0]
		self._covered: List[Tuple[int, int]] = []
		self._spans: List[Tuple[int, bytes]] = []
		self._results: List[ReadResult] = []

	# --- logical progress -------------------------------------------------

	def tell(self):
		"""Returns the reader's own logical position (file offset)."""
		return self._cursor

	def seek(self, offset:int, whence:int = 0):
		"""
		Moves this reader's own cursor. The target must stay inside one of
		the regions assigned to this reader.
		"""
		if whence == 0:
			target = offset
		elif whence == 1:
			target = self._cursor + offset
		elif whence == 2:
			target = self.regions[-1][1] - offset
		else:
			raise ValueError('whence must be 0, 1 or 2')
		if not any(start <= target < end for start, end in self.regions):
			raise ValueError(
				'Seek target %#x is outside the regions assigned to reader %s'
				% (target, self.reader_id))
		self._cursor = target

	def _current_region_index(self):
		idx = 0
		for idx, (start, end) in enumerate(self.regions):
			if self._cursor < end:
				return idx
		return len(self.regions)

	# --- reading ------------------------------------------------------------

	def read(self, size:int = -1) -> ReadResult:
		"""
		Reads up to `size` bytes at the reader's own cursor (-1: until the end
		of the current region). Reads never cross a region boundary; when a
		region is finished the cursor continues at the next assigned region.
		The returned ReadResult records requested vs. returned bytes and the
		provenance sequence numbers of the underlying reads.
		"""
		if size < -1:
			raise ValueError('size must be >= -1')
		idx = self._current_region_index()
		if idx >= len(self.regions):
			return ReadResult(self.reader_id, self._cursor, 0, 0, [], exhausted=True)
		start, end = self.regions[idx]
		if self._cursor < start:
			self._cursor = start
		available = end - self._cursor
		to_read = available if size == -1 else min(size, available)
		if to_read == 0:
			return ReadResult(self.reader_id, self._cursor, 0, 0, [])
		offset = self._cursor
		data, rec = self._shared.read_at(offset, to_read, self.reader_id)
		self._cursor += len(data)
		if len(data) == 0:
			# the underlying handle cannot provide more bytes for this region
			# (e.g. truncated original) - skip the rest so the review can
			# continue with the next region; the uncollected part stays
			# visible as a gap.
			self._cursor = end
		if data:
			self._covered.append((offset, offset + len(data)))
			if self._materialize:
				self._spans.append((offset, bytes(data)))
		result = ReadResult(
			self.reader_id, offset, to_read, len(data), [rec.seq],
			data=data if self._materialize else None)
		self._results.append(result)
		return result

	def collect(self, chunk_size:int = 8192) -> 'EvidenceView':
		"""Reads all remaining assigned regions in chunk_size steps."""
		while True:
			result = self.read(chunk_size)
			if result.exhausted:
				break
		return self

	# --- evidence locations -------------------------------------------------

	@property
	def results(self) -> List[ReadResult]:
		"""Auditable log of every logical read this reader performed."""
		return list(self._results)

	@property
	def evidence(self) -> List[Tuple[int, int]]:
		"""Merged (start, end) intervals actually collected by this reader."""
		return _merge_intervals(self._covered)

	@property
	def gaps(self) -> List[Tuple[int, int]]:
		"""Assigned ranges that were not collected (short reads / missed)."""
		return _subtract_intervals(self.regions, self.evidence)

	def _merged_spans(self) -> List[Tuple[int, bytes]]:
		spans = []
		for start, data in sorted(self._spans):
			if spans and start <= spans[-1][0] + len(spans[-1][1]):
				pstart, pdata = spans[-1]
				overlap_end = pstart + len(pdata)
				if start + len(data) > overlap_end:
					spans[-1] = (pstart, pdata + data[overlap_end - start:])
			else:
				spans.append((start, data))
		return spans

	def manifest(self) -> Dict:
		"""
		Chunking-independent evidence list for this reader: collected
		intervals with content hashes plus the uncollected gaps. Two runs
		that reviewed the same original produce identical manifests
		regardless of read order or chunk sizes.
		"""
		if self._materialize:
			evidence = [
				(start, start + len(data), hashlib.sha256(data).hexdigest())
				for start, data in self._merged_spans()
			]
		else:
			evidence = [(start, end, None) for start, end in self.evidence]
		return {
			'reader_id': self.reader_id,
			'regions': list(self.regions),
			'evidence': evidence,
			'gaps': list(self.gaps),
		}

	def audit(self, read_log=None) -> Dict:
		"""
		Cross-checks this reader's evidence locations against the provenance
		log and lists every short read. By default the log of this reader's
		shared handle is used; when a review spanned several sessions (pause
		and resume on a fresh handle), the combined logs can be passed in.
		"""
		if read_log is None:
			read_log = self._shared.read_log
		provenance = SharedReadOnlyHandle.coverage_of(read_log, self.reader_id)
		return {
			'reader_id': self.reader_id,
			'regions': list(self.regions),
			'evidence': self.evidence,
			'gaps': self.gaps,
			'short_reads': [r.to_dict() for r in self._results if r.short],
			'provenance': provenance,
			'provenance_matches': provenance == self.evidence,
		}

	# --- pause / resume -----------------------------------------------------

	def save_progress(self) -> Dict:
		"""
		Snapshots the logical progress, the evidence locations and the
		auditable results so the review can be continued later, possibly on
		a freshly opened handle of the same original.
		"""
		return {
			'reader_id': self.reader_id,
			'regions': [list(r) for r in self.regions],
			'cursor': self._cursor,
			'covered': [list(r) for r in self._covered],
			'spans': [(start, bytes(data)) for start, data in self._spans],
			'results': [r.to_dict() for r in self._results],
			'materialize': self._materialize,
		}

	@classmethod
	def resume(cls, shared:SharedReadOnlyHandle, state:Dict, reader_id:Optional[str] = None) -> 'EvidenceView':
		"""
		Continues a review from a saved progress state. A reader can only
		continue its own review: if `reader_id` is given and does not match
		the saved state, a ValueError is raised.
		"""
		if reader_id is not None and reader_id != state['reader_id']:
			raise ValueError(
				'Reader %s cannot continue the review of reader %s'
				% (reader_id, state['reader_id']))
		view = cls(shared, state['reader_id'],
			[tuple(r) for r in state['regions']],
			materialize=state.get('materialize', True))
		view._cursor = state['cursor']
		view._covered = [tuple(r) for r in state['covered']]
		view._spans = [(start, bytes(data)) for start, data in state['spans']]
		view._results = [ReadResult.from_dict(d) for d in state['results']]
		return view
