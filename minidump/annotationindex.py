#!/usr/bin/env python3
#
# Forensic annotation index for minidump comment streams.
#
# Records every CommentStreamA/CommentStreamW annotation as a sealed
# observation whose identity is proven by its encoding, its legal content
# boundaries and the stream directory position it was recovered from.
# External evidence receipts (authorized copy observations) can be
# registered alongside and corroborated against the sealed observations.
# Identical text across streams or dumps stays retrievable, but sources
# are never merged: each observation keeps its own provenance.
#
import enum
import hashlib

from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.directory import MINIDUMP_DIRECTORY

COMMENT_STREAM_ENCODINGS = {
	MINIDUMP_STREAM_TYPE.CommentStreamA: 'ascii',
	MINIDUMP_STREAM_TYPE.CommentStreamW: 'utf-16-le',
}


class UnauthorizedComparisonError(Exception):
	pass


class AnnotationIdentityIssue(enum.Enum):
	BOUNDS_VIOLATION = 'bounds_violation'      # content falls outside the file
	ENCODING_SIZE_MISMATCH = 'encoding_size'   # byte count incompatible with encoding
	DECODE_FAILURE = 'decode_failure'          # bytes do not decode as the stream encoding


class CorroborationStatus(enum.Enum):
	CONFIRMED = 'confirmed'              # text, encoding and origin match a sealed observation
	TEXT_ONLY = 'text_only'              # text matches but the declared origin does not
	LEGACY_UNLOCATED = 'legacy_unlocated'  # receipt carries no origin, cannot be tied to a location
	NO_MATCH = 'no_match'                # no sealed observation carries this text


class AnnotationObservation:
	"""
	A sealed forensic record of one annotation recovered from a minidump
	comment stream. Identity evidence: encoding derived from the stream
	type, legal content boundaries (RVA + size within the file) and the
	stream directory position. Once sealed the record cannot be modified
	or merged with other sources.
	"""
	def __init__(self):
		self.source_id:str = None
		self.directory_index:int = None
		self.directory_rva:int = None
		self.stream_type:MINIDUMP_STREAM_TYPE = None
		self.encoding:str = None
		self.rva:int = None
		self.data_size:int = None
		self.file_size:int = None
		self.text:str = None
		self.raw_sha256:str = None
		self.issues = []
		self.authorized:bool = True  # originals recovered from the dump itself
		self._sealed = False

	def __setattr__(self, name, value):
		if getattr(self, '_sealed', False) is True:
			raise AttributeError('AnnotationObservation is sealed and cannot be modified')
		object.__setattr__(self, name, value)

	def seal(self):
		self.issues = tuple(self.issues)
		object.__setattr__(self, '_sealed', True)

	@property
	def is_sealed(self):
		return self._sealed

	@property
	def is_verified(self):
		return len(self.issues) == 0

	def __str__(self):
		t = '== AnnotationObservation ==\n'
		t += 'Source: %s\n' % self.source_id
		t += 'Stream: %s (directory #%s @0x%x)\n' % (self.stream_type.name, self.directory_index, self.directory_rva)
		t += 'Encoding: %s\n' % self.encoding
		t += 'Content: RVA 0x%x, size %d (file size %d)\n' % (self.rva, self.data_size, self.file_size)
		t += 'SHA256: %s\n' % self.raw_sha256
		t += 'Verified: %s\n' % self.is_verified
		if self.issues:
			t += 'Issues: %s\n' % ', '.join(issue.name for issue in self.issues)
		t += 'Text: %s\n' % self.text
		return t


class EvidenceReceipt:
	"""
	An external evidence receipt: a copy observation of annotation text
	registered from outside the dump. Only receipts marked authorized may
	take part in text comparison. Receipts lacking the original encoding
	and location are legacy reports and are explicitly identifiable.
	"""
	def __init__(self, receipt_id, text, authorized=False, encoding=None, stream_type=None, rva=None, data_size=None):
		self.receipt_id:str = receipt_id
		self.text:str = text
		self.authorized:bool = authorized
		self.encoding:str = encoding
		self.stream_type:MINIDUMP_STREAM_TYPE = stream_type
		self.rva:int = rva
		self.data_size:int = data_size

	@property
	def has_origin(self):
		return self.stream_type is not None and self.rva is not None and self.data_size is not None

	@property
	def is_legacy(self):
		return not self.has_origin

	def __str__(self):
		t = '== EvidenceReceipt %s ==\n' % self.receipt_id
		t += 'Authorized: %s\n' % self.authorized
		t += 'Legacy (no origin): %s\n' % self.is_legacy
		if self.has_origin:
			t += 'Origin: %s @0x%x size %d (%s)\n' % (self.stream_type.name, self.rva, self.data_size, self.encoding)
		t += 'Text: %s\n' % self.text
		return t


class Corroboration:
	def __init__(self, status, matches):
		self.status:CorroborationStatus = status
		self.matches = matches  # sealed observations backing the receipt

	def __str__(self):
		return 'Corroboration: %s (%d matching observation(s))' % (self.status.name, len(self.matches))


class AnnotationTextMatches:
	"""
	Result of a text lookup. Every matching record is returned with its
	own provenance; sources are never merged.
	"""
	def __init__(self, observations, receipts):
		self.observations = observations
		self.receipts = receipts

	@property
	def sources(self):
		return sorted(set(o.source_id for o in self.observations))

	def __len__(self):
		return len(self.observations) + len(self.receipts)

	def __str__(self):
		t = '%d sealed observation(s), %d receipt(s)\n' % (len(self.observations), len(self.receipts))
		for obs in self.observations:
			t += '  [%s] %s dir#%s @0x%x (%s)\n' % (obs.source_id, obs.stream_type.name, obs.directory_index, obs.rva, obs.encoding)
		for rec in self.receipts:
			t += '  [receipt %s] authorized=%s legacy=%s\n' % (rec.receipt_id, rec.authorized, rec.is_legacy)
		return t


class AnnotationIndex:
	"""
	Forensic annotation index. Sealed observations are recovered from
	minidump comment streams; external evidence receipts can be registered
	and corroborated against them.
	"""
	def __init__(self):
		self.observations = []  # sealed AnnotationObservation records, never merged
		self.receipts = []      # EvidenceReceipt records

	@staticmethod
	def from_minidump(mf, source_id=None):
		idx = AnnotationIndex()
		idx.add_minidump(mf, source_id=source_id)
		return idx

	def add_minidump(self, mf, source_id=None):
		if source_id is None:
			source_id = mf.filename if mf.filename else '<unnamed>'
		fh = mf.file_handle
		pos = fh.tell()
		fh.seek(0, 2)
		file_size = fh.tell()
		for i in range(mf.header.NumberOfStreams):
			directory_rva = mf.header.StreamDirectoryRva + i * 12
			fh.seek(directory_rva)
			mdir = MINIDUMP_DIRECTORY.parse(fh)
			if mdir is None:
				continue
			if mdir.StreamType not in COMMENT_STREAM_ENCODINGS:
				continue
			obs = AnnotationObservation()
			obs.source_id = source_id
			obs.directory_index = i
			obs.directory_rva = directory_rva
			obs.stream_type = mdir.StreamType
			obs.encoding = COMMENT_STREAM_ENCODINGS[mdir.StreamType]
			obs.rva = mdir.Location.Rva
			obs.data_size = mdir.Location.DataSize
			obs.file_size = file_size
			if obs.rva < 0 or obs.data_size <= 0 or obs.rva + obs.data_size > file_size:
				obs.issues.append(AnnotationIdentityIssue.BOUNDS_VIOLATION)
			else:
				fh.seek(obs.rva)
				raw = fh.read(obs.data_size)
				obs.raw_sha256 = hashlib.sha256(raw).hexdigest()
				if obs.encoding == 'utf-16-le' and obs.data_size % 2 != 0:
					obs.issues.append(AnnotationIdentityIssue.ENCODING_SIZE_MISMATCH)
				try:
					obs.text = raw.decode(obs.encoding)
				except UnicodeDecodeError:
					obs.issues.append(AnnotationIdentityIssue.DECODE_FAILURE)
			obs.seal()
			self.observations.append(obs)
		fh.seek(pos)
		return self

	def add_receipt(self, receipt):
		self.receipts.append(receipt)
		return self

	def find_text(self, text):
		"""
		Returns every sealed observation and receipt carrying the exact
		text, across all streams and sources. Sources are never merged.
		"""
		return AnnotationTextMatches(
			[o for o in self.observations if o.text == text],
			[r for r in self.receipts if r.text == text],
		)

	def compare(self, first, second):
		"""
		Compares the text of two copy observations. Both sides must be
		marked authorized, otherwise the comparison is refused.
		"""
		for entry in (first, second):
			if getattr(entry, 'authorized', False) is not True:
				raise UnauthorizedComparisonError('Text comparison requires authorized copy observations on both sides')
		return first.text == second.text

	def corroborate(self, receipt):
		"""
		Ties a receipt to sealed observations. Legacy receipts without
		origin information are explicitly identified as unlocatable.
		"""
		if receipt.is_legacy:
			return Corroboration(CorroborationStatus.LEGACY_UNLOCATED, [])
		text_matches = [o for o in self.observations if o.text == receipt.text]
		origin_matches = [
			o for o in text_matches
			if o.stream_type == receipt.stream_type
			and o.rva == receipt.rva
			and o.data_size == receipt.data_size
			and (receipt.encoding is None or o.encoding == receipt.encoding)
		]
		if origin_matches:
			return Corroboration(CorroborationStatus.CONFIRMED, origin_matches)
		if text_matches:
			return Corroboration(CorroborationStatus.TEXT_ONLY, text_matches)
		return Corroboration(CorroborationStatus.NO_MATCH, [])

	def legacy_reports(self):
		"""Receipts that lack the original location and encoding."""
		return [r for r in self.receipts if r.is_legacy]

	def __str__(self):
		t = '== AnnotationIndex ==\n'
		t += 'Sealed observations: %d\n' % len(self.observations)
		for obs in self.observations:
			t += str(obs)
		t += 'Receipts: %d (%d legacy)\n' % (len(self.receipts), len(self.legacy_reports()))
		return t
