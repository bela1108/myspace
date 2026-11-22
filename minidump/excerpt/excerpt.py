#!/usr/bin/env python3
#
# Excerpt: the actual memory bytes carved out of the original dump for
# the authorized party. This is the private counterpart of the
# manifest - it is the only artifact that carries content, and it is
# pinned to the same origin digest so it cannot be replayed against a
# different dump.
import base64
import json


class ExcerptSegment:
	def __init__(self, start, data):
		self.start = start
		self.data = bytes(data)

	@property
	def end(self):
		return self.start + len(self.data)

	def to_dict(self):
		return {
			'start': self.start,
			'size': len(self.data),
			'data_b64': base64.b64encode(self.data).decode('ascii'),
		}

	@staticmethod
	def from_dict(d):
		return ExcerptSegment(d['start'], base64.b64decode(d['data_b64']))


class Excerpt:
	def __init__(self, origin_digest, segments=None, note=None):
		self.origin_digest = origin_digest
		self.segments = segments if segments is not None else []
		self.note = note

	def to_dict(self):
		return {
			'format': 'minidump-excerpt',
			'origin_digest': self.origin_digest,
			'note': self.note,
			'segments': [s.to_dict() for s in self.segments],
		}

	def to_json(self):
		return json.dumps(self.to_dict(), indent=2, sort_keys=True)

	@staticmethod
	def from_dict(d):
		if d.get('format') != 'minidump-excerpt':
			raise ValueError('Not an excerpt')
		return Excerpt(
			d['origin_digest'],
			segments=[ExcerptSegment.from_dict(s) for s in d['segments']],
			note=d.get('note'),
		)

	@staticmethod
	def from_json(text):
		return Excerpt.from_dict(json.loads(text))


def build_excerpt(image, origin_digest, ranges, note=None):
	"""
	Carves `ranges` (iterable of (start, size)) out of `image`.
	Refuses to fabricate bytes: any range touching unknown pages raises
	KeyError instead of zero-filling.
	"""
	segments = []
	for start, size in ranges:
		segments.append(ExcerptSegment(start, image.read(start, size)))
	return Excerpt(origin_digest, segments=segments, note=note)
