"""Authorized, provenance-aware reading over minidump memory sources."""

import hashlib
import inspect


COMPLETE = "complete"
SUCCESS = "success"
PARTIAL = "partial"
UNAUTHORIZED = "unauthorized"
NOT_AUTHORIZED = "not_authorized"
DENIED = "denied"
UNCOLLECTED = "uncollected"
NOT_COLLECTED = "not_collected"
MULTIPLE_SOURCES = "multiple_authorized_sources"
MULTIPLE_AUTHORIZED_SOURCES = MULTIPLE_SOURCES
MULTIPLE_LICENSED_SOURCES = "multiple_licensed_sources"
OVERLAPPING_SOURCES = "overlapping_authorized_sources"
AMBIGUOUS_SOURCE = "ambiguous_source"
OUTSIDE_SCOPE = "outside_scope"
READ_ERROR = "read_error"
ERROR = "error"
INCOMPLETE = "incomplete"

_UNSET = object()


class AddressRange:
	"""A half-open ``[start, end)`` address interval."""

	def __init__(self, start=0, end=None, size=None, length=None, stop=None):
		if isinstance(start, AddressRange):
			self.start = start.start
			self.end = start.end
			return

		if end is None and size is None and length is None and stop is None:
			if isinstance(start, (tuple, list)) and len(start) == 2:
				start, end = start
			elif start is not None and hasattr(start, "start") and hasattr(start, "end"):
				end = start.end
				start = start.start

		self.start = int(0 if start is None else start)

		if end is not None:
			self.end = int(end)
		elif stop is not None:
			self.end = int(stop)
		elif size is not None:
			self.end = self.start + int(size)
		elif length is not None:
			self.end = self.start + int(length)
		else:
			self.end = self.start

		if self.end < self.start:
			raise ValueError("range end precedes start: %r" % ((self.start, self.end),))

	@property
	def size(self):
		return self.end - self.start

	length = size

	def contains(self, address):
		return self.start <= int(address) < self.end

	def contains_range(self, other):
		other = coerce_range(other)
		return self.start <= other.start and other.end <= self.end

	def overlaps(self, other):
		other = coerce_range(other)
		return self.start < other.end and other.start < self.end

	def intersection(self, other):
		other = coerce_range(other)
		start = max(self.start, other.start)
		end = min(self.end, other.end)
		if start >= end:
			return None
		return AddressRange(start, end)

	def union(self, other):
		other = coerce_range(other)
		if not self.overlaps(other) and self.end != other.start and other.end != self.start:
			return None
		return AddressRange(min(self.start, other.start), max(self.end, other.end))

	def adjacent_to(self, other):
		other = coerce_range(other)
		return self.end == other.start or other.end == self.start

	def to_tuple(self):
		return (self.start, self.end)

	def to_dict(self):
		return {"start": self.start, "end": self.end, "size": self.size}

	def __iter__(self):
		yield self.start
		yield self.end

	def __len__(self):
		return self.size

	def __eq__(self, other):
		try:
			other = coerce_range(other)
		except Exception:
			return NotImplemented
		return self.start == other.start and self.end == other.end

	def __hash__(self):
		return hash((self.start, self.end))

	def __repr__(self):
		return "AddressRange(0x%x, 0x%x)" % (self.start, self.end)


Range = AddressRange
MemoryRange = AddressRange


def coerce_range(value=None, end=None, size=None, length=None):
	if isinstance(value, AddressRange) and end is None and size is None and length is None:
		return value
	if end is not None or size is not None or length is not None:
		return AddressRange(value, end=end, size=size, length=length)
	if value is None:
		return AddressRange()
	if isinstance(value, (tuple, list)):
		return AddressRange(*value)
	if isinstance(value, dict):
		return AddressRange(
			value.get("start", value.get("start_address", 0)),
			end=value.get("end", value.get("end_address")),
			size=value.get("size", value.get("length", value.get("DataSize"))),
		)
	return AddressRange(value)


class ForensicError(Exception):
	"""Base error for forensic access violations."""


class ForensicReadError(ForensicError):
	def __init__(self, message, receipt=None):
		super().__init__(message)
		self.receipt = receipt


class IncompleteForensicRead(ForensicReadError):
	pass


class CrossFragmentReadError(IncompleteForensicRead):
	pass


class AuthorizationDeniedError(IncompleteForensicRead):
	pass


class UnauthorizedReadError(AuthorizationDeniedError):
	pass


class UncollectedDataError(IncompleteForensicRead):
	pass


class MultipleAuthorizedSourcesError(IncompleteForensicRead):
	pass


class ReadTruncatedError(CrossFragmentReadError):
	pass


class PartialReadError(CrossFragmentReadError):
	pass


class AuthorizationGrant:
	def __init__(self, ranges=None, source_id=None, snapshot_id=None, group_id=None,
			principal=None, name=None, grant_id=None, authorized_ranges=None):
		self.source_id = source_id or snapshot_id
		self.group_id = group_id or principal
		self.principal = self.group_id
		self.grant_id = grant_id or name
		raw_ranges = ranges if ranges is not None else authorized_ranges
		self.ranges = _normalize_ranges(raw_ranges)

	def allows(self, interval):
		interval = coerce_range(interval)
		return any(grant_range.contains_range(interval) for grant_range in self.ranges)

	def to_dict(self):
		return {
			"grant_id": self.grant_id,
			"source_id": self.source_id,
			"group_id": self.group_id,
			"ranges": [item.to_dict() for item in self.ranges],
		}


Grant = AuthorizationGrant
AuthorizedRange = AuthorizationGrant


def _normalize_ranges(value):
	if value is None:
		return []
	if isinstance(value, AddressRange):
		return [value]
	if isinstance(value, dict) and ("start" in value or "start_address" in value):
		return [coerce_range(value)]
	if isinstance(value, (str, bytes)):
		raise TypeError("address ranges must not be strings or bytes")
	if (
		isinstance(value, (tuple, list))
		and len(value) == 2
		and isinstance(value[0], int)
		and isinstance(value[1], int)
	):
		return [coerce_range(value)]

	result = []
	for item in value:
		if isinstance(item, AuthorizationGrant):
			result.extend(item.ranges)
		else:
			result.append(coerce_range(item))
	return result


class AuthorizationPolicy:
	def __init__(self, ranges=None, grants=None, authorized_ranges=None, allowed_ranges=None,
			local_ranges=None, allow_all=False, **kwargs):
		self.allow_all = allow_all
		self.grants = []

		for value in (ranges, authorized_ranges, allowed_ranges, local_ranges):
			self._add_value(value)

		if grants is not None:
			self._add_value(grants)

		for value in kwargs.values():
			if isinstance(value, AuthorizationGrant):
				self.grants.append(value)

	def _add_value(self, value):
		if value is None:
			return
		if isinstance(value, AuthorizationGrant):
			self.grants.append(value)
			return
		if isinstance(value, AuthorizationPolicy):
			self.grants.extend(value.grants)
			self.allow_all = self.allow_all or value.allow_all
			return
		if isinstance(value, dict):
			for key, item in value.items():
				if isinstance(item, AuthorizationGrant):
					grant = item
					if grant.source_id is None:
						grant.source_id = key
					self.grants.append(grant)
				else:
					self.grants.append(AuthorizationGrant(source_id=key, ranges=item))
			return
		if isinstance(value, AddressRange):
			self.grants.append(AuthorizationGrant(ranges=[value]))
			return
		if isinstance(value, (tuple, list)):
			if value and all(isinstance(item, AuthorizationGrant) for item in value):
				self.grants.extend(value)
			else:
				try:
					self.grants.append(AuthorizationGrant(ranges=value))
				except TypeError:
					for item in value:
						self._add_value(item)
			return
		raise TypeError("unsupported authorization value: %r" % (type(value),))

	def add_grant(self, grant=None, **kwargs):
		if grant is None:
			grant = AuthorizationGrant(**kwargs)
		elif kwargs:
			raise TypeError("pass either a grant or grant keyword arguments")
		self.grants.append(grant)
		return grant

	def grants_for(self, source, interval):
		interval = coerce_range(interval)
		if self.allow_all:
			return [AuthorizationGrant(ranges=[interval], grant_id="allow-all")]

		source_id = getattr(source, "source_id", source)
		group_id = getattr(source, "group_id", None)
		matches = []
		for grant in self.grants:
			source_matches = grant.source_id in (None, "*", source_id)
			group_matches = grant.group_id in (None, "*", group_id)
			if not source_matches or not group_matches:
				continue
			if grant.allows(interval):
				matches.append(grant)
		return matches

	def allows(self, source, interval):
		return bool(self.grants_for(source, interval))


class SourceSegment:
	def __init__(self, start_address=0, data=None, end_address=None, size=None, length=None,
			read=None, reader=None, file_offset=None, start_file_address=None,
			segment_id=None, index=None, metadata=None, source_id=None):
		if isinstance(start_address, (bytes, bytearray)) and data is None:
			data = bytes(start_address)
			start_address = 0

		self.start_address = int(start_address)
		self.data = bytes(data) if data is not None else None
		self._read_callback = read
		self.reader = reader
		self.file_offset = file_offset if file_offset is not None else start_file_address
		self.segment_id = segment_id if segment_id is not None else index
		self.index = index
		self.metadata = dict(metadata or {})
		self.source_id = source_id

		if self.data is not None:
			self.size = len(self.data)
		elif size is not None:
			self.size = int(size)
		elif length is not None:
			self.size = int(length)
		elif end_address is not None:
			self.size = int(end_address) - self.start_address
		else:
			self.size = 0

		self.end_address = self.start_address + self.size

	def inrange(self, address):
		return self.start_address <= int(address) < self.end_address

	def range(self):
		return AddressRange(self.start_address, self.end_address)

	def covers(self, interval):
		return self.range().contains_range(interval)

	def read(self, start_address, size):
		start_address = int(start_address)
		size = int(size)
		if size < 0:
			raise ValueError("read size must not be negative")

		if self.data is not None:
			offset = start_address - self.start_address
			value = self.data[offset:offset + size]
		else:
			callback = self._read_callback
			if callback is None and self.reader is not None:
				callback = getattr(self.reader, "read", None)
			if callback is None:
				raise ReadTruncatedError("segment %r has no data reader" % (self.segment_id,))

			value = self._invoke_callback(callback, start_address, size)

		if not isinstance(value, (bytes, bytearray, memoryview)):
			raise TypeError("segment reader returned %s, expected bytes" % type(value).__name__)
		value = bytes(value)
		if len(value) != size:
			raise ReadTruncatedError(
				"segment read returned %d of %d bytes at 0x%x"
				% (len(value), size, start_address)
			)
		return value

	@staticmethod
	def _invoke_callback(callback, start_address, size):
		try:
			signature = inspect.signature(callback)
			var_positional = any(
				parameter.kind == inspect.Parameter.VAR_POSITIONAL
				for parameter in signature.parameters.values()
			)
			positional = [
				parameter for parameter in signature.parameters.values()
				if parameter.kind in (
					inspect.Parameter.POSITIONAL_ONLY,
					inspect.Parameter.POSITIONAL_OR_KEYWORD,
				)
			]
			if var_positional or len(positional) >= 2:
				return callback(start_address, size)
		except (TypeError, ValueError):
			pass
		return callback(start_address, size)


class EvidenceSource:
	def __init__(self, source_id=None, data=None, start_address=0, segments=None, ranges=None,
			read=None, reader=None, authorized_ranges=None, grants=None, group_id=None,
			principal=None, snapshot_id=None, name=None, metadata=None, **kwargs):
		self.source_id = source_id or snapshot_id or name or "source-%x" % id(self)
		self.snapshot_id = snapshot_id or self.source_id
		self.name = name or self.source_id
		self.group_id = group_id or principal
		self.principal = self.group_id
		self.metadata = dict(metadata or {})
		self.segments = []
		self.authorization = AuthorizationPolicy(
			ranges=authorized_ranges if authorized_ranges is not None else ranges,
			grants=grants,
		)

		if data is not None:
			self.add_segment(start_address=start_address, data=data, read=read, reader=reader)

		if segments is not None:
			for segment in segments:
				self.add_segment(segment)

		if kwargs.get("pages") is not None:
			pages = kwargs["pages"]
			if isinstance(pages, dict):
				for address in sorted(pages):
					self.add_segment(int(address), pages[address])
			else:
				page_size = kwargs.get("page_size")
				for index, page in enumerate(pages):
					self.add_segment(index * int(page_size or len(page)), page)

	def add_segment(self, segment=None, start_address=None, data=None, **kwargs):
		if segment is None:
			segment = SourceSegment(start_address=start_address, data=data, **kwargs)
		elif isinstance(segment, (tuple, list)):
			if len(segment) == 2 and isinstance(segment[1], (bytes, bytearray)):
				segment = SourceSegment(segment[0], segment[1])
			else:
				segment = SourceSegment(*segment)
		elif isinstance(segment, dict):
			segment = SourceSegment(**segment)

		if not isinstance(segment, SourceSegment):
			raise TypeError("unsupported segment: %r" % type(segment))
		segment.source_id = self.source_id
		if segment.index is None:
			segment.index = len(self.segments)
		self.segments.append(segment)
		return segment

	add_fragment = add_segment
	add_page = add_segment

	def grant(self, ranges=None, **kwargs):
		if isinstance(ranges, AuthorizationGrant):
			self.authorization.add_grant(ranges)
		else:
			self.authorization.add_grant(AuthorizationGrant(ranges=ranges, **kwargs))
		return self

	def collected_segments(self, interval):
		interval = coerce_range(interval)
		return [segment for segment in self.segments if segment.covers(interval)]

	def all_ranges(self):
		return [segment.range() for segment in self.segments]

	@classmethod
	def from_minidump_reader(cls, reader, source_id="minidump", authorized_ranges=None, **kwargs):
		source = cls(source_id=source_id, authorized_ranges=authorized_ranges, **kwargs)
		file_handle = getattr(reader, "file_handle", None)
		memory_segments = getattr(reader, "memory_segments", []) or []
		for index, memory_segment in enumerate(memory_segments):
			start = memory_segment.start_virtual_address
			size = getattr(memory_segment, "size", None)
			if size is None:
				size = memory_segment.end_virtual_address - start

			def read_callback(address, read_size, segment=memory_segment):
				return segment.read(address, read_size, file_handle)

			source.add_segment(SourceSegment(
				start_address=start,
				size=size,
				read=read_callback,
				file_offset=getattr(memory_segment, "start_file_address", None),
				segment_id=index,
				index=index,
				metadata={"minidump_segment": memory_segment},
			))
		return source


Snapshot = EvidenceSource
DataSource = EvidenceSource
LicensedSource = EvidenceSource


class FragmentReceipt:
	def __init__(self, source_id, start_address, end_address, data, segment_id=None,
			group_id=None, grant_ids=None, file_offset=None, index=None, metadata=None):
		self.source_id = source_id
		self.snapshot_id = source_id
		self.start_address = int(start_address)
		self.end_address = int(end_address)
		self.data = bytes(data)
		self.segment_id = segment_id
		self.group_id = group_id
		self.grant_ids = list(grant_ids or [])
		self.file_offset = file_offset
		self.index = index
		self.metadata = dict(metadata or {})

	@property
	def size(self):
		return self.end_address - self.start_address

	length = size

	@property
	def range(self):
		return AddressRange(self.start_address, self.end_address)

	@property
	def sha256(self):
		return hashlib.sha256(self.data).hexdigest()

	def digest(self):
		return hashlib.sha256(self.data).digest()

	def to_dict(self, include_data=True):
		result = {
			"source_id": self.source_id,
			"snapshot_id": self.snapshot_id,
			"segment_id": self.segment_id,
			"start_address": self.start_address,
			"end_address": self.end_address,
			"size": self.size,
			"sha256": self.sha256,
		}
		if include_data:
			result["data_hex"] = self.data.hex()
		return result


ReadFragment = FragmentReceipt
ReadSegment = FragmentReceipt


class RangeFinding:
	def __init__(self, kind, start_address, end_address, source_ids=None, snapshot_ids=None,
			segment_ids=None, reason=None, authorized_source_ids=None,
			collected_source_ids=None, grant_ids=None, error=None, blocking=True):
		self.kind = kind
		self.status = kind
		self.start_address = int(start_address)
		self.end_address = int(end_address)
		self.source_ids = list(source_ids or [])
		self.snapshot_ids = list(snapshot_ids if snapshot_ids is not None else self.source_ids)
		self.segment_ids = list(segment_ids or [])
		self.reason = reason or kind
		self.authorized_source_ids = list(authorized_source_ids or [])
		self.collected_source_ids = list(collected_source_ids or self.source_ids)
		self.grant_ids = list(grant_ids or [])
		self.error = error
		self.blocking = blocking

	@property
	def range(self):
		return AddressRange(self.start_address, self.end_address)

	@property
	def size(self):
		return self.end_address - self.start_address

	def to_dict(self):
		return {
			"kind": self.kind,
			"status": self.status,
			"reason": self.reason,
			"start_address": self.start_address,
			"end_address": self.end_address,
			"size": self.size,
			"source_ids": self.source_ids,
			"snapshot_ids": self.snapshot_ids,
			"segment_ids": self.segment_ids,
			"authorized_source_ids": self.authorized_source_ids,
			"collected_source_ids": self.collected_source_ids,
			"grant_ids": self.grant_ids,
			"error": repr(self.error) if self.error is not None else None,
			"blocking": self.blocking,
		}


UnauthorizedRange = RangeFinding
UncollectedRange = RangeFinding
MultipleSourcesFinding = RangeFinding
ReadErrorFinding = RangeFinding


class ForensicReadResult:
	def __init__(self, request_range, status=PARTIAL):
		self.request_range = coerce_range(request_range)
		self.requested_range = self.request_range
		self.request = self.request_range
		self.status = status
		self.fragments = []
		self.verification_fragments = []
		self.unauthorized = []
		self.uncollected = []
		self.multiple_sources = []
		self.errors = []
		self.findings = []
		self.data = None

	@property
	def segments(self):
		return self.fragments

	@property
	def intervals(self):
		return self.fragments

	@property
	def range(self):
		return self.request_range

	@property
	def reads(self):
		return self.fragments

	@property
	def actual_fragments(self):
		return self.fragments

	@property
	def provenance(self):
		return self.fragments

	@property
	def denied(self):
		return self.unauthorized

	@property
	def not_authorized(self):
		return self.unauthorized

	@property
	def authorization_failures(self):
		return self.unauthorized

	@property
	def missing(self):
		return self.uncollected

	@property
	def not_collected(self):
		return self.uncollected

	@property
	def overlaps(self):
		return self.multiple_sources

	@property
	def ambiguous_sources(self):
		return self.multiple_sources

	@property
	def request_size(self):
		return self.request_range.size

	@property
	def bytes_read(self):
		return sum(fragment.size for fragment in self.fragments)

	@property
	def source_ids(self):
		result = []
		for fragment in self.fragments:
			if fragment.source_id not in result:
				result.append(fragment.source_id)
		for finding in self.multiple_sources:
			for source_id in finding.source_ids:
				if source_id not in result:
					result.append(source_id)
		return result

	@property
	def sources(self):
		return self.source_ids

	@property
	def spans_multiple_sources(self):
		return len(set(self.source_ids)) > 1

	@property
	def fragment_count(self):
		return len(self.fragments)

	@property
	def has_unauthorized(self):
		return bool(self.unauthorized)

	@property
	def blocking_unauthorized(self):
		return [item for item in self.unauthorized if item.blocking]

	@property
	def blocking_multiple_sources(self):
		return [item for item in self.multiple_sources if item.blocking]

	@property
	def has_uncollected(self):
		return bool(self.uncollected)

	@property
	def has_multiple_sources(self):
		return bool(self.multiple_sources)

	@property
	def has_errors(self):
		return bool(self.errors)

	@property
	def error(self):
		return self.errors[0].error if self.errors else None

	@property
	def exception(self):
		return self.error

	@property
	def gaps(self):
		return list(self.unauthorized) + list(self.uncollected)

	@property
	def records(self):
		return self.findings

	@property
	def statuses(self):
		statuses = []
		for value in [self.status] + [item.kind for item in self.findings] + [ERROR if self.errors else None]:
			if value and value not in statuses:
				statuses.append(value)
		return statuses

	@property
	def complete(self):
		return (
			not self.blocking_unauthorized
			and not self.uncollected
			and not self.blocking_multiple_sources
			and not self.errors
			and self.bytes_read == self.request_size
		)

	@property
	def ok(self):
		return self.complete

	@property
	def allowed(self):
		return self.complete

	@property
	def authorised(self):
		return self.complete

	@property
	def success(self):
		return self.complete

	@property
	def is_partial(self):
		return not self.complete and self.bytes_read > 0

	@property
	def partial(self):
		return self.is_partial

	@property
	def partial_data(self):
		return b"".join(fragment.data for fragment in sorted(
			self.fragments, key=lambda item: (item.start_address, item.index or 0)
		))

	@property
	def incomplete_data(self):
		return self.partial_data

	@property
	def buffer(self):
		return self.data

	def complete_data(self):
		self.raise_for_status()
		return self.data

	def to_bytes(self):
		return self.complete_data()

	def __bytes__(self):
		return self.complete_data()

	def raise_for_status(self):
		if self.complete:
			return
		if self.errors:
			error = self.errors[0].error
			raise CrossFragmentReadError("forensic read failed: %r" % (error,), self) from error
		if self.blocking_multiple_sources:
			raise MultipleAuthorizedSourcesError("requested range has multiple authorized sources", self)
		if self.blocking_unauthorized:
			raise AuthorizationDeniedError("requested range includes unauthorized bytes", self)
		raise UncollectedDataError("requested range includes uncollected bytes", self)

	def finalize(self):
		self.unauthorized = _coalesce_findings(self.unauthorized)
		self.uncollected = _coalesce_findings(self.uncollected)
		self.multiple_sources = _coalesce_findings(self.multiple_sources)
		self.findings = list(self.unauthorized) + list(self.uncollected) + list(self.multiple_sources)

		if self.errors:
			self.status = ERROR
		elif self.blocking_multiple_sources:
			self.status = MULTIPLE_SOURCES
		elif self.blocking_unauthorized and self.bytes_read:
			self.status = PARTIAL
		elif self.blocking_unauthorized:
			self.status = UNAUTHORIZED
		elif self.uncollected and self.bytes_read:
			self.status = PARTIAL
		elif self.uncollected:
			self.status = UNCOLLECTED
		elif self.bytes_read == self.request_size:
			self.status = COMPLETE
			self.data = b"".join(
				fragment.data for fragment in sorted(self.fragments, key=lambda item: item.start_address)
			)
		else:
			self.status = INCOMPLETE
		return self

	def to_dict(self, include_data=True):
		return {
			"status": self.status,
			"complete": self.complete,
			"ok": self.ok,
			"requested_range": self.request_range.to_dict(),
			"bytes_read": self.bytes_read,
			"source_ids": self.source_ids,
			"fragments": [item.to_dict(include_data=include_data) for item in self.fragments],
			"unauthorized": [item.to_dict() for item in self.unauthorized],
			"uncollected": [item.to_dict() for item in self.uncollected],
			"multiple_sources": [item.to_dict() for item in self.multiple_sources],
			"errors": [item.to_dict() for item in self.errors],
			"data_hex": self.data.hex() if include_data and self.data is not None else None,
		}


ReadReceipt = ForensicReadResult
ForensicReceipt = ForensicReadResult
ForensicReadReceipt = ForensicReadResult


def _coalesce_findings(findings):
	ordered = sorted(findings, key=lambda item: (item.start_address, item.end_address))
	result = []
	for finding in ordered:
		if not result:
			result.append(finding)
			continue
		previous = result[-1]
		same_sources = previous.source_ids == finding.source_ids
		same_kind = previous.kind == finding.kind
		adjacent = previous.end_address == finding.start_address
		if same_kind and same_sources and adjacent:
			merged = RangeFinding(
				finding.kind,
				previous.start_address,
				finding.end_address,
				source_ids=previous.source_ids,
				snapshot_ids=previous.snapshot_ids,
				segment_ids=previous.segment_ids + finding.segment_ids,
				reason=previous.reason,
				authorized_source_ids=previous.authorized_source_ids,
				collected_source_ids=previous.collected_source_ids,
				grant_ids=previous.grant_ids + finding.grant_ids,
				blocking=previous.blocking or finding.blocking,
			)
			result[-1] = merged
		else:
			result.append(finding)
	return result


class ForensicView:
	def __init__(self, *args, sources=None, reader=None, minidumpfile=None, policy=None,
			authorization=None, grants=None, authorized_ranges=None, allowed_ranges=None,
			local_ranges=None, strict=False, raise_on_denied=None, raise_on_error=True,
			multiple_source_mode=None, on_multiple_sources="error",
			allow_identical_overlaps=False, page_size=None, **options):
		self.sources = []
		self.page_size = page_size
		self.strict = strict
		self.raise_on_denied = strict if raise_on_denied is None else raise_on_denied
		self.raise_on_error = raise_on_error
		self.multiple_source_mode = multiple_source_mode or on_multiple_sources
		self.allow_identical_overlaps = allow_identical_overlaps
		self.options = dict(options)

		if isinstance(policy, AuthorizationPolicy):
			self.policy = policy
		else:
			self.policy = AuthorizationPolicy(
				policy,
				grants=grants,
				authorized_ranges=authorized_ranges,
				allowed_ranges=allowed_ranges,
				local_ranges=local_ranges,
			)

		if authorization is not None:
			self.policy._add_value(authorization)

		if sources is not None:
			if isinstance(sources, EvidenceSource):
				sources = [sources]
			elif hasattr(sources, "memory_segments") and hasattr(sources, "file_handle"):
				self.add_minidump_reader(sources)
				sources = None
			elif hasattr(sources, "get_reader"):
				self.add_minidump_file(sources)
				sources = None
			if sources is not None:
				for source in sources:
					self.add_source(source)

		if reader is not None:
			self.add_minidump_reader(reader)
		if minidumpfile is not None:
			self.add_minidump_file(minidumpfile)

		for arg in args:
			self._add_positional(arg)

	def _add_positional(self, value):
		if isinstance(value, EvidenceSource):
			self.add_source(value)
		elif isinstance(value, AuthorizationPolicy):
			self.policy = value
		elif hasattr(value, "memory_segments") and hasattr(value, "file_handle"):
			self.add_minidump_reader(value)
		elif hasattr(value, "get_reader"):
			self.add_minidump_file(value)
		elif isinstance(value, (list, tuple)):
			if value and isinstance(value[0], EvidenceSource):
				for source in value:
					self.add_source(source)
			else:
				self.policy._add_value(value)
		elif isinstance(value, (AddressRange, dict)):
			self.policy._add_value(value)
		else:
			raise TypeError("unsupported forensic view argument: %r" % type(value))

	def add_source(self, source=None, **kwargs):
		if source is None:
			source = EvidenceSource(**kwargs)
		elif isinstance(source, dict):
			source = EvidenceSource(**source)
		elif not isinstance(source, EvidenceSource):
			raise TypeError("unsupported source: %r" % type(source))
		self.sources.append(source)
		return source

	add_snapshot = add_source
	add_data_source = add_source

	def add_bytes(self, start_address, data, source_id="synthetic", **kwargs):
		return self.add_source(EvidenceSource(
			source_id=source_id,
			start_address=start_address,
			data=data,
			**kwargs
		))

	def add_minidump_reader(self, reader, source_id="minidump", **kwargs):
		source = EvidenceSource.from_minidump_reader(reader, source_id=source_id, **kwargs)
		self.add_source(source)
		return source

	def add_minidump_file(self, minidumpfile, source_id="minidump", **kwargs):
		reader = minidumpfile.get_reader() if hasattr(minidumpfile, "get_reader") else minidumpfile
		return self.add_minidump_reader(reader, source_id=source_id, **kwargs)

	def grant(self, ranges=None, source_id=None, **kwargs):
		grant = ranges if isinstance(ranges, AuthorizationGrant) else AuthorizationGrant(
			ranges=ranges, source_id=source_id, **kwargs
		)
		self.policy.add_grant(grant)
		for source in self.sources:
			if grant.source_id in (None, "*", source.source_id):
				source.authorization.add_grant(grant)
		return self

	authorize = grant
	add_authorized_range = grant

	def _policy_for_source(self, source):
		combined = AuthorizationPolicy()
		combined.grants.extend(self.policy.grants)
		combined.grants.extend(source.authorization.grants)
		combined.allow_all = self.policy.allow_all or source.authorization.allow_all
		return combined

	def read(self, start=None, size=_UNSET, end=None, length=None, address=None,
			virt_addr=None, virtual_address=None, strict=None, **kwargs):
		request_range = self._coerce_request(start, size, end, length, address, virt_addr, virtual_address, kwargs)
		strict = self.strict if strict is None else strict
		result = ForensicReadResult(request_range)

		if request_range.size == 0:
			result.status = COMPLETE
			result.data = b""
			return result

		boundaries = self._boundaries(request_range)
		planned_reads = []

		for left, right in zip(boundaries, boundaries[1:]):
			interval = AddressRange(left, right)
			collected_hits = []
			authorized_hits = []
			unauthorized_hits = []

			for source in self.sources:
				for segment in source.collected_segments(interval):
					collected_hits.append((source, segment))
					grants = self._policy_for_source(source).grants_for(source, interval)
					if grants:
						authorized_hits.append((source, segment, grants))
					else:
						unauthorized_hits.append((source, segment))

			authorized_sources = {}
			for hit in authorized_hits:
				authorized_sources.setdefault(hit[0].source_id, hit)

			for source, segment in unauthorized_hits:
				has_authorized_alternative = bool(authorized_sources)
				result.unauthorized.append(RangeFinding(
					UNAUTHORIZED,
					interval.start,
					interval.end,
					source_ids=[source.source_id],
					segment_ids=[segment.segment_id],
					reason=NOT_AUTHORIZED,
					blocking=not has_authorized_alternative,
				))

			if len(authorized_sources) > 1:
				overlap_hits = self._ordered_hits(list(authorized_sources.values()))
				if self._identical_overlaps_allowed():
					handled = self._read_identical_overlap(interval, overlap_hits, result)
					if handled is not None:
						return handled
					continue
				result.multiple_sources.append(self._multiple_finding(interval, overlap_hits))
				continue

			if len(authorized_sources) == 1:
				source, segment, grants = next(iter(authorized_sources.values()))
				planned_reads.append((interval, source, segment, grants))
				continue

			if collected_hits:
				continue
			else:
				authorized_ids = []
				for source in self.sources:
					if self._policy_for_source(source).allows(source, interval):
						authorized_ids.append(source.source_id)
				result.uncollected.append(RangeFinding(
					UNCOLLECTED,
					interval.start,
					interval.end,
					authorized_source_ids=authorized_ids,
					reason=NOT_COLLECTED,
				))

		for planned in self._merge_planned_reads(planned_reads):
			interval, source, segment, grants = planned
			try:
				data = segment.read(interval.start, interval.size)
				receipt = FragmentReceipt(
					source.source_id,
					interval.start,
					interval.end,
					data,
					segment_id=segment.segment_id,
					group_id=source.group_id,
					grant_ids=[grant.grant_id for grant in grants if grant.grant_id],
					file_offset=segment.file_offset,
					index=len(result.fragments),
				)
				result.fragments.append(receipt)
			except Exception as error:
				finding = RangeFinding(
					ERROR, interval.start, interval.end,
					source_ids=[source.source_id],
					segment_ids=[segment.segment_id],
					reason=READ_ERROR, error=error,
				)
				result.errors.append(finding)
				result.finalize()
				if self.raise_on_error:
					raise CrossFragmentReadError(
						"cross-fragment read failed at 0x%x" % interval.start, result
					) from error
				return result

		result.finalize()

		if strict or self.raise_on_denied:
			result.raise_for_status()
		return result

	def _coerce_request(self, start, size, end, length, address, virt_addr, virtual_address, extra):
		if start is None:
			start = address if address is not None else virt_addr if virt_addr is not None else virtual_address

		if isinstance(start, AddressRange):
			return start
		if isinstance(start, (tuple, list)) and size is _UNSET and end is None:
			return coerce_range(start)
		if isinstance(start, dict):
			return coerce_range(start)
		if size is _UNSET:
			size = extra.get("length", extra.get("nbytes", extra.get("byte_count")))
		if size is _UNSET:
			size = None
		if end is None and length is not None:
			size = length
		if end is None and extra.get("stop") is not None:
			end = extra["stop"]
		return coerce_range(start or 0, end=end, size=size)

	def _boundaries(self, request_range):
		points = {request_range.start, request_range.end}
		for source in self.sources:
			for segment in source.segments:
				segment_range = segment.range().intersection(request_range)
				if segment_range:
					points.add(segment_range.start)
					points.add(segment_range.end)
			for grant in source.authorization.grants:
				for grant_range in grant.ranges:
					clipped = grant_range.intersection(request_range)
					if clipped:
						points.add(clipped.start)
						points.add(clipped.end)
		for grant in self.policy.grants:
			for grant_range in grant.ranges:
				clipped = grant_range.intersection(request_range)
				if clipped:
					points.add(clipped.start)
					points.add(clipped.end)
		return sorted(point for point in points if request_range.start <= point <= request_range.end)

	def _ordered_hits(self, hits):
		return sorted(
			hits,
			key=lambda hit: (str(hit[0].source_id), str(hit[1].segment_id)),
		)

	def _identical_overlaps_allowed(self):
		return self.allow_identical_overlaps or self.multiple_source_mode in (
			"identical",
			"same",
			"identical_overlaps",
		)

	def _read_identical_overlap(self, interval, hits, result):
		values = []
		try:
			for source, segment, grants in hits:
				data = segment.read(interval.start, interval.size)
				values.append(data)
				result.verification_fragments.append(FragmentReceipt(
					source.source_id,
					interval.start,
					interval.end,
					data,
					segment_id=segment.segment_id,
					group_id=source.group_id,
					grant_ids=[grant.grant_id for grant in grants if grant.grant_id],
					file_offset=segment.file_offset,
					index=len(result.verification_fragments),
					metadata={"role": "verification"},
				))
		except Exception as error:
			result.errors.append(RangeFinding(
				ERROR, interval.start, interval.end,
				source_ids=[hits[0][0].source_id] if hits else [],
				segment_ids=[hits[0][1].segment_id] if hits else [],
				reason=READ_ERROR, error=error,
			))
			result.finalize()
			if self.raise_on_error:
				raise CrossFragmentReadError(
					"overlapping fragment read failed at 0x%x" % interval.start, result
				) from error
			return result

		if any(value != values[0] for value in values[1:]):
			result.multiple_sources.append(self._multiple_finding(interval, hits))
			return None

		source, segment, grants = hits[0]
		result.fragments.append(FragmentReceipt(
			source.source_id,
			interval.start,
			interval.end,
			values[0],
			segment_id=segment.segment_id,
			group_id=source.group_id,
			grant_ids=[grant.grant_id for grant in grants if grant.grant_id],
			file_offset=segment.file_offset,
			index=len(result.fragments),
			metadata={
				"verified_source_ids": [hit[0].source_id for hit in hits],
				"identical_overlap": True,
			},
		))
		finding = self._multiple_finding(interval, hits)
		finding.blocking = False
		finding.reason = "identical_authorized_sources"
		result.multiple_sources.append(finding)
		return None

	def _multiple_finding(self, interval, hits, reason=MULTIPLE_LICENSED_SOURCES):
		source_ids = []
		segment_ids = []
		grant_ids = []
		for source, segment, grants in hits:
			if source.source_id not in source_ids:
				source_ids.append(source.source_id)
			if segment.segment_id not in segment_ids:
				segment_ids.append(segment.segment_id)
			grant_ids.extend(grant.grant_id for grant in grants if grant.grant_id)
		return RangeFinding(
			MULTIPLE_SOURCES,
			interval.start,
			interval.end,
			source_ids=source_ids,
			segment_ids=segment_ids,
			reason=reason,
			grant_ids=grant_ids,
		)

	def _merge_planned_reads(self, planned_reads):
		merged = []
		for item in planned_reads:
			interval, source, segment, grants = item
			if merged:
				prev_interval, prev_source, prev_segment, prev_grants = merged[-1]
				same_segment = prev_source is source and prev_segment is segment
				if same_segment and prev_interval.end == interval.start:
					merged[-1] = (
						AddressRange(prev_interval.start, interval.end),
						source,
						segment,
						prev_grants + grants,
					)
					continue
			merged.append(item)
		return merged

	def read_strict(self, *args, **kwargs):
		kwargs["strict"] = True
		return self.read(*args, **kwargs)

	read_or_raise = read_strict

	def read_authorized(self, *args, **kwargs):
		kwargs["strict"] = kwargs.get("strict", True)
		return self.read(*args, **kwargs)

	def read_bytes(self, *args, **kwargs):
		return self.read_strict(*args, **kwargs).data

	def read_data(self, *args, **kwargs):
		return self.read_bytes(*args, **kwargs)

	def read_range(self, start, end=None, **kwargs):
		if end is None:
			range_value = coerce_range(start)
		else:
			range_value = AddressRange(start, end)
		return self.read(range_value, **kwargs)

	def read_range_strict(self, start, end=None, **kwargs):
		kwargs["strict"] = True
		return self.read_range(start, end, **kwargs)


AuthorizedForensicReader = ForensicView
ForensicReader = ForensicView
ForensicViewReader = ForensicView
AuthorizedReader = ForensicView
AuthorizedMinidumpReader = ForensicView
MinidumpForensicView = ForensicView
ScopedMinidumpReader = ForensicView
EvidenceReader = ForensicView
AuditedReader = ForensicView
RestrictedForensicView = ForensicView
AuthorizedEvidenceView = ForensicView


def authorized_read(sources=None, request_range=None, authorized_ranges=None, grants=None, **kwargs):
	view = ForensicView(
		sources=sources,
		authorized_ranges=authorized_ranges,
		grants=grants,
		**kwargs
	)
	return view.read(request_range)


def forensic_read(sources=None, request_range=None, authorized_ranges=None, grants=None, **kwargs):
	return authorized_read(
		sources=sources,
		request_range=request_range,
		authorized_ranges=authorized_ranges,
		grants=grants,
		**kwargs
	)


class ForensicCoordinator(ForensicView):
	def __init__(self, snapshots=None, groups=None, grants=None, authorizations=None, **kwargs):
		super_kwargs = dict(kwargs)
		super_kwargs["grants"] = grants if grants is not None else authorizations
		super().__init__(**super_kwargs)
		if snapshots is not None:
			for snapshot in snapshots:
				self.add_snapshot(snapshot)
		if groups is not None:
			self.groups = groups
		else:
			self.groups = {}

	def assign_group(self, group_id, source_ids=None, authorized_ranges=None):
		source_ids = source_ids or []
		self.groups[group_id] = {
			"source_ids": list(source_ids),
			"authorized_ranges": _normalize_ranges(authorized_ranges),
		}
		for source_id in source_ids:
			self.grant(authorized_ranges, source_id=source_id, group_id=group_id)
		return self


CaseCoordinator = ForensicCoordinator
Coordinator = ForensicCoordinator


class ReviewGroup:
	def __init__(self, group_id, source_ids=None, authorized_ranges=None, coordinator=None):
		self.group_id = group_id
		self.source_ids = list(source_ids or [])
		self.authorized_ranges = _normalize_ranges(authorized_ranges)
		self.coordinator = coordinator

	def allows(self, interval):
		return any(item.contains_range(coerce_range(interval)) for item in self.authorized_ranges)


def synthetic_case():
	"""Return two tiny, non-process synthetic snapshots and expected receipts."""
	alpha = EvidenceSource(
		source_id="synthetic-alpha",
		snapshot_id="snapshot-alpha",
		group_id="alpha-team",
		segments=[
			SourceSegment(0x0FFC, b"ALFA"),
			SourceSegment(0x1000, b"BETA"),
		],
		authorized_ranges=[AddressRange(0x0FFC, 0x1004)],
	)
	beta = EvidenceSource(
		source_id="synthetic-beta",
		snapshot_id="snapshot-beta",
		group_id="beta-team",
		data=b"0123456789ABCDEF",
		start_address=0x2000,
		authorized_ranges=[AddressRange(0x2000, 0x2008)],
	)
	view = ForensicView(sources=[alpha, beta])
	return {
		"view": view,
		"alpha": alpha,
		"beta": beta,
		"cross_page_request": AddressRange(0x0FFC, 0x1004),
		"partial_request": AddressRange(0x2000, 0x2010),
		"cross_page_bytes": b"ALFABETA",
		"partial_authorized_bytes": b"01234567",
	}
