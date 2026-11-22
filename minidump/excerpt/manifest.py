#!/usr/bin/env python3
#
# Excerpt manifest: binds caller-authorized memory content of an
# original dump to (a) the original's digest and (b) virtual address
# ranges. The manifest is the public artifact - it carries coverage
# relations and hashes only, never memory content.
#
# Unknown pages inside an authorized range are recorded as explicit
# gaps. They are never zero-filled and never signed, so a gap can
# neither leak into a digest nor be "verified" later.

import hashlib
import json

HASH_DOMAIN = b'MINIDUMP-EXCERPT-v1\x00'
FORMAT_VERSION = 1


def hash_segment(start, data):
	"""
	Content hash of one known run, bound to its virtual address and
	length so bytes cannot be relocated or resized undetected.
	"""
	h = hashlib.sha256()
	h.update(HASH_DOMAIN)
	h.update(start.to_bytes(8, byteorder='little', signed=False))
	h.update(len(data).to_bytes(8, byteorder='little', signed=False))
	h.update(data)
	return h.hexdigest()


class SegmentRecord:
	"""Hash binding for one contiguous known run inside an authorized range."""
	def __init__(self, start, size, sha256):
		self.start = start
		self.size = size
		self.sha256 = sha256

	@property
	def end(self):
		return self.start + self.size

	def to_dict(self):
		return {
			'start': self.start,
			'end': self.end,
			'size': self.size,
			'sha256': self.sha256,
		}

	@staticmethod
	def from_dict(d):
		return SegmentRecord(d['start'], d['size'], d['sha256'])


class GapRecord:
	"""Unknown pages inside an authorized range. Recorded, never signed."""
	def __init__(self, start, size, reason='unknown-pages'):
		self.start = start
		self.size = size
		self.reason = reason

	@property
	def end(self):
		return self.start + self.size

	def to_dict(self):
		return {
			'start': self.start,
			'end': self.end,
			'size': self.size,
			'reason': self.reason,
			'signed': False,
		}

	@staticmethod
	def from_dict(d):
		return GapRecord(d['start'], d['size'], d.get('reason', 'unknown-pages'))


class ManifestEntry:
	"""
	One description of an authorized virtual address range.
	derived_from links a re-description to the entry it refines, so
	multiple descriptions of the same region stay traceable.
	"""
	def __init__(self, entry_id, label, range_start, range_end,
			segments=None, gaps=None, derived_from=None):
		self.entry_id = entry_id
		self.label = label
		self.range_start = range_start
		self.range_end = range_end
		self.segments = segments if segments is not None else []
		self.gaps = gaps if gaps is not None else []
		self.derived_from = derived_from

	def to_dict(self):
		return {
			'entry_id': self.entry_id,
			'label': self.label,
			'range': {'start': self.range_start, 'end': self.range_end},
			'derived_from': self.derived_from,
			'segments': [s.to_dict() for s in self.segments],
			'gaps': [g.to_dict() for g in self.gaps],
		}

	@staticmethod
	def from_dict(d):
		return ManifestEntry(
			d['entry_id'],
			d['label'],
			d['range']['start'],
			d['range']['end'],
			segments=[SegmentRecord.from_dict(s) for s in d['segments']],
			gaps=[GapRecord.from_dict(g) for g in d['gaps']],
			derived_from=d.get('derived_from'),
		)


class ExcerptManifest:
	"""
	Public manifest for one original dump. Contains no memory content;
	the serialized form is exactly the "public view" (coverage + hashes).
	"""
	def __init__(self, origin_digest, entries=None, origin_description=None):
		self.origin_digest = origin_digest
		self.origin_description = origin_description
		self.entries = entries if entries is not None else []

	def directory(self):
		"""
		Index of authorized regions to the entries describing them.
		Several entries covering the same region are listed together so
		the relationship between descriptions stays traceable.
		"""
		directory = []
		for entry in self.entries:
			directory.append({
				'range': {'start': entry.range_start, 'end': entry.range_end},
				'entry_id': entry.entry_id,
				'label': entry.label,
				'derived_from': entry.derived_from,
			})
		return directory

	def trace(self, start, end):
		"""
		Returns every entry describing [start, end) (overlap), each with
		its derivation chain, so overlapping or refined descriptions of
		the same region can be followed back to their origin.
		"""
		by_id = {}
		for entry in self.entries:
			by_id[entry.entry_id] = entry
		hits = []
		for entry in self.entries:
			if entry.range_start < end and start < entry.range_end:
				lineage = []
				cursor = entry
				while cursor is not None:
					lineage.append(cursor.entry_id)
					cursor = by_id.get(cursor.derived_from)
				hits.append({'entry': entry, 'lineage': lineage})
		return hits

	def find_segment_records(self, start, end):
		"""All signed segment records intersecting [start, end)."""
		records = []
		for entry in self.entries:
			for seg in entry.segments:
				if seg.start < end and start < seg.end:
					records.append(seg)
		return records

	def authorized_coverage(self, start, end):
		"""
		Walks [start, end) against every entry and yields tuples:
			('segment', SegmentRecord, covered_end)
			('gap', GapRecord, covered_end)
			(None, gap_start, gap_end)  not covered by any authorization
		"""
		pos = start
		while pos < end:
			best = None
			best_end = None
			for entry in self.entries:
				for seg in entry.segments:
					if seg.start <= pos < seg.end:
						if best_end is None or seg.end > best_end:
							best = ('segment', seg)
							best_end = seg.end
				for gap in entry.gaps:
					if gap.start <= pos < gap.end:
						if best_end is None or gap.end > best_end:
							best = ('gap', gap)
							best_end = gap.end
			if best is None:
				next_edge = end
				for entry in self.entries:
					for rec in entry.segments + entry.gaps:
						if pos < rec.start < next_edge:
							next_edge = rec.start
				yield (None, pos, next_edge)
				pos = next_edge
			else:
				yield (best[0], best[1], min(best_end, end))
				pos = best_end

	def to_public_dict(self):
		return {
			'format': 'minidump-excerpt-manifest',
			'version': FORMAT_VERSION,
			'origin_digest': self.origin_digest,
			'origin_description': self.origin_description,
			'directory': self.directory(),
			'entries': [e.to_dict() for e in self.entries],
		}

	def to_json(self):
		return json.dumps(self.to_public_dict(), indent=2, sort_keys=True)

	@staticmethod
	def from_dict(d):
		if d.get('format') != 'minidump-excerpt-manifest':
			raise ValueError('Not an excerpt manifest')
		return ExcerptManifest(
			d['origin_digest'],
			entries=[ManifestEntry.from_dict(e) for e in d['entries']],
			origin_description=d.get('origin_description'),
		)

	@staticmethod
	def from_json(text):
		return ExcerptManifest.from_dict(json.loads(text))


def build_manifest(image, origin_digest, authorized_ranges, origin_description=None):
	"""
	Builds a manifest for `image` (MemoryImage).

	authorized_ranges: iterable of (start, end, label) or
	(start, end, label, derived_from) tuples explicitly approved by the
	caller. Known runs become signed SegmentRecords; unknown pages
	inside the range become GapRecords and are never zero-filled or
	signed.
	"""
	entries = []
	for idx, spec in enumerate(authorized_ranges):
		start, end, label = spec[0], spec[1], spec[2]
		derived_from = spec[3] if len(spec) > 3 else None
		segments = []
		gaps = []
		for kind, cstart, payload in image.coverage(start, end):
			if kind == 'data':
				segments.append(SegmentRecord(cstart, len(payload), hash_segment(cstart, payload)))
			else:
				gaps.append(GapRecord(cstart, payload))
		entries.append(ManifestEntry(
			'entry-%d' % idx, label, start, end,
			segments=segments, gaps=gaps, derived_from=derived_from,
		))
	return ExcerptManifest(origin_digest, entries, origin_description)
