#!/usr/bin/env python3
"""Restricted, handoff-ready evidence views for minidump memory.

The regular :class:`minidump.minidumpfile.MinidumpFile` and its readers expose
every byte present in a dump.  Incident response frequently needs to hand a
small, explicitly approved subset of that memory to another party while
retaining a verifiable link to the original dump.

This module builds such a view from three inputs:

* a minidump (path, bytes, file handle, or parsed ``MinidumpFile``),
* a set of approved virtual-address ranges, and
* an approval ticket / work order.

A range is either ``raw`` (the approved bytes may be exported) or
``page_summary`` (only page-level metadata and digests may be exported).  The
view snapshots the permitted material once; subsequent reads do not touch the
original dump.  Reads through the evidence reader, its buffered reader, memory
segments, and thread stack helpers all use the same address policy.
"""

import base64
import copy
import datetime
import hashlib
import io
import json
import os
import threading


EVIDENCE_SCHEMA = "minidump-evidence-view/1"
RAW = "raw"
PAGE_SUMMARY = "page_summary"
DEFAULT_PAGE_SIZE = 0x1000

_RAW_MODES = {
	"raw",
	"full",
	"read",
	"readable",
	"readonly",
	"read_only",
	"raw_only",
	"bytes",
	"data",
	"allow",
	"allowed",
}
_SUMMARY_MODES = {
	"page_summary",
	"page-summary",
	"page summary",
	"summary",
	"summaries",
	"pages",
	"page",
	"digest",
	"metadata",
	"summary_only",
	"page_digest",
	"page_digests",
	"digests",
}


class _TicketId(str):
	@property
	def ticket_id(self):
		return str(self)


class EvidenceError(Exception):
	"""Base error for evidence views."""


EvidenceException = EvidenceError


class EvidencePolicyError(EvidenceError):
	"""The approval policy is invalid or incomplete."""


class EvidenceIntegrityError(EvidenceError):
	"""An evidence bundle failed its integrity check."""


class EvidenceVerificationError(EvidenceError):
	"""The original dump did not match the evidence view."""


class EvidenceAccessDenied(EvidenceError):
	"""A read was fully or partly outside the approved policy."""

	def __init__(self, message, address=None, size=None, result=None):
		EvidenceError.__init__(self, message)
		self.address = address
		self.size = size
		self.result = result


def _now_iso():
	value = datetime.datetime.now(datetime.timezone.utc)
	return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(value):
	return json.dumps(
		value,
		sort_keys=True,
		separators=(",", ":"),
		ensure_ascii=False,
	).encode("utf-8")


def _sha256(data):
	return hashlib.sha256(data).hexdigest()


def _as_int(value, field="value"):
	if isinstance(value, bool) or value is None:
		raise EvidencePolicyError("%s must be an integer" % field)
	if isinstance(value, int):
		return value
	if hasattr(value, "value") and isinstance(value.value, int):
		return value.value
	if isinstance(value, str):
		text = value.strip()
		if not text:
			raise EvidencePolicyError("%s must not be empty" % field)
		if text.lower().startswith("0x"):
			return int(text, 16)
		if text.lower().startswith("0b"):
			return int(text, 2)
		return int(text, 10)
	raise EvidencePolicyError("%s must be an integer, got %r" % (field, value))


def _looks_like_range_string(value):
	if not isinstance(value, str):
		return False
	text = value.strip().split(":", 1)[0]
	parts = text.split("-", 1)
	if len(parts) != 2:
		return False
	try:
		_as_int(parts[0], "range start")
		_as_int(parts[1], "range end")
		return True
	except (EvidencePolicyError, ValueError):
		return False


def _normalize_access(value):
	if value is None:
		return RAW
	if isinstance(value, bool):
		return RAW if value else PAGE_SUMMARY
	if hasattr(value, "name"):
		value = value.name
	elif hasattr(value, "value"):
		value = value.value
	text = str(value).strip().lower().replace("_", " ")
	compact = text.replace(" ", "_").replace("-", "_")
	if compact in _RAW_MODES:
		return RAW
	if compact in _SUMMARY_MODES:
		return PAGE_SUMMARY
	raise EvidencePolicyError(
		"unknown evidence access mode %r (expected %r or %r)"
		% (value, RAW, PAGE_SUMMARY)
	)


class _AttrDict(dict):
	"""A dict with convenient attribute access and explicit aliases."""

	_aliases = {}

	def __getattr__(self, name):
		if name.startswith("__"):
			raise AttributeError(name)
		if name in self:
			return self[name]
		alias = self._aliases.get(name)
		if alias is not None and alias in self:
			return self[alias]
		raise AttributeError(name)

	def __getitem__(self, key):
		try:
			return dict.__getitem__(self, key)
		except KeyError:
			alias = self._aliases.get(key)
			if alias is not None and alias in self:
				return dict.__getitem__(self, alias)
			raise

	def get(self, key, default=None):
		try:
			return self[key]
		except KeyError:
			return default

	def __call__(self):
		return self

	def to_dict(self):
		return copy.deepcopy(dict(self))

	def to_json(self, indent=None):
		return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class _CallableDict(_AttrDict):
	def __call__(self):
		return self


class ApprovalTicket(_AttrDict):
	"""An approval ticket / work order retained with the evidence."""

	_aliases = {
		"id": "ticket_id",
		"ticket": "ticket_id",
		"number": "ticket_id",
		"work_order": "ticket_id",
		"workorder": "ticket_id",
		"approval": "ticket_id",
		"approved_by": "issuer",
		"scope": "subject",
	}

	def __init__(
		self,
		ticket_id=None,
		issuer=None,
		subject=None,
		issued_at=None,
		expires_at=None,
		url=None,
		metadata=None,
		**kwargs
	):
		if isinstance(ticket_id, ApprovalTicket):
			ticket_id = ticket_id.ticket_id
		if isinstance(ticket_id, dict):
			source = ticket_id
			ticket_id = source.get(
				"ticket_id",
				source.get(
					"id",
					source.get(
						"ticket",
						source.get(
							"number",
							source.get("work_order", source.get("approval")),
						),
					),
				),
			)
			issuer = source.get("issuer", source.get("approved_by", issuer))
			subject = source.get("subject", source.get("scope", subject))
			issued_at = source.get("issued_at", issued_at)
			expires_at = source.get("expires_at", expires_at)
			url = source.get("url", url)
			metadata = source.get("metadata", metadata)
		if ticket_id is None:
			ticket_id = kwargs.get("id", kwargs.get("ticket", kwargs.get("number")))
		if ticket_id is None:
			raise EvidencePolicyError("an approval ticket is required")
		ticket_id = str(ticket_id).strip()
		if not ticket_id:
			raise EvidencePolicyError("approval ticket id must not be empty")
		_A = _AttrDict.__init__
		_A(self)
		self["ticket_id"] = ticket_id
		self["issuer"] = issuer
		self["subject"] = subject
		self["issued_at"] = issued_at
		self["expires_at"] = expires_at
		self["url"] = url
		self["metadata"] = copy.deepcopy(metadata) if metadata is not None else {}

	@property
	def ticket_id(self):
		return self["ticket_id"]

	@property
	def issuer(self):
		return self["issuer"]

	@classmethod
	def from_dict(cls, value, **kwargs):
		return cls(value, **kwargs)

	@classmethod
	def from_any(cls, value, **kwargs):
		if isinstance(value, cls):
			return value
		return cls(value, **kwargs)

	def is_expired(self, now=None):
		if not self.get("expires_at"):
			return False
		try:
			expires = datetime.datetime.fromisoformat(
				str(self["expires_at"]).replace("Z", "+00:00")
			)
		except Exception:
			return False
		if expires.tzinfo is None:
			expires = expires.replace(tzinfo=datetime.timezone.utc)
		if now is None:
			now = datetime.datetime.now(datetime.timezone.utc)
		return now > expires

	def __str__(self):
		return self.ticket_id

	def __eq__(self, other):
		if isinstance(other, str):
			return self.ticket_id == str(other)
		return dict.__eq__(self, other)

	def __ne__(self, other):
		return not self.__eq__(other)


def _ticket_from_any(value):
	if value is None:
		return None
	if isinstance(value, ApprovalTicket):
		return value
	if isinstance(value, str):
		return ApprovalTicket(value)
	if isinstance(value, dict):
		return ApprovalTicket(value)
	if hasattr(value, "ticket_id"):
		return ApprovalTicket(str(value.ticket_id))
	return ApprovalTicket(str(value))


class EvidenceRange(_AttrDict):
	"""One approved virtual-address range.

	``end`` is exclusive, matching minidump memory descriptors.  ``access`` is
	``raw`` or ``page_summary``.
	"""

	_aliases = {
		"start_address": "start",
		"original_start": "start",
		"original_address": "start",
		"va": "start",
		"address": "start",
		"begin": "start",
		"end_address": "end",
		"original_end": "end",
		"stop": "end",
		"length": "size",
		"mode": "access",
		"permission": "access",
		"ticket_id": "ticket",
		"approval": "ticket",
	}

	def __init__(
		self,
		start=None,
		end=None,
		access=None,
		ticket=None,
		page_size=None,
		label=None,
		size=None,
		length=None,
		mode=None,
		**kwargs
	):
		if isinstance(start, str) and end is None and _looks_like_range_string(start):
			text = start.strip()
			pieces = text.split(":")
			bounds = pieces[0].split("-", 1)
			start = bounds[0].strip()
			end = bounds[1].strip()
			if len(pieces) > 1 and access is None:
				access = pieces[1].strip()
			if len(pieces) > 2 and ticket is None:
				ticket = pieces[2].strip()
		if isinstance(start, EvidenceRange):
			other = start
			start = other.start
			end = other.end
			access = other.access
			ticket = other.ticket_id
			page_size = other.page_size
			label = other.label
		elif isinstance(start, dict):
			source = start
			range_value = source.get("range")
			if isinstance(range_value, (tuple, list)) and len(range_value) >= 2:
				start, end = range_value[0], range_value[1]
			else:
				start = source.get(
					"start",
					source.get(
						"start_address",
						source.get(
							"address",
							source.get(
								"original_address",
								source.get(
									"original_start",
									source.get("va", source.get("begin")),
								),
							),
						),
					),
				)
				end = source.get(
					"end", source.get("end_address", source.get("original_end"))
				)
			size = source.get(
				"size", source.get("length", source.get("original_size", size))
			)
			access = source.get(
				"access",
				source.get(
					"mode",
					source.get(
						"visibility",
						source.get(
							"permission", source.get("kind", access)
						),
					),
				),
			)
			ticket = source.get(
				"ticket",
				source.get(
					"ticket_id",
					source.get(
						"approval",
						source.get(
							"work_order", source.get("number", ticket)
						),
					),
				),
			)
			page_size = source.get("page_size", page_size)
			label = source.get("label", label)
		elif isinstance(start, (tuple, list)):
			items = list(start)
			if items:
				start = items[0]
			if len(items) > 1 and end is None:
				end = items[1]
			if len(items) > 2 and access is None:
				access = items[2]
			if len(items) > 3 and ticket is None:
				ticket = items[3]
			if len(items) > 4 and page_size is None:
				page_size = items[4]
		if start is None:
			start = kwargs.get(
				"start_address",
				kwargs.get("original_address", kwargs.get("va", kwargs.get("address"))),
			)
		if end is None:
			end = kwargs.get("end_address", kwargs.get("original_end"))
		if size is None:
			size = kwargs.get("length", length)
		if mode is None:
			mode = kwargs.get(
				"permission", kwargs.get("mode", kwargs.get("kind"))
			)
		if access is None:
			access = mode
		if ticket is None:
			ticket = kwargs.get(
				"ticket",
				kwargs.get("ticket_id", kwargs.get("approval")),
			)
		if page_size is None:
			page_size = kwargs.get("page_size")
		if label is None:
			label = kwargs.get("label")

		start = _as_int(start, "range start")
		if end is not None:
			end = _as_int(end, "range end")
		if end is None:
			if size is None:
				raise EvidencePolicyError("range requires either end or size")
			end = start + _as_int(size, "range size")
		if size is None:
			size = end - start
		if start < 0 or end <= start:
			raise EvidencePolicyError("invalid range 0x%x-0x%x" % (start, end))

		# A three-argument call such as (start, end, "IR-123") is common.
		if access is not None and ticket is None:
			try:
				normalized = _normalize_access(access)
			except EvidencePolicyError:
				ticket = access
				normalized = RAW
			access = normalized
		else:
			access = _normalize_access(access)

		approval = _ticket_from_any(ticket)
		if page_size is not None:
			page_size = _as_int(page_size, "page size")
			if page_size <= 0:
				raise EvidencePolicyError("page size must be positive")

		_A = _AttrDict.__init__
		_A(self)
		self["start"] = start
		self["end"] = end
		self["size"] = end - start
		self["access"] = access
		self["mode"] = access
		self["ticket"] = _TicketId(approval.ticket_id) if approval else None
		self["approval_ticket"] = approval.to_dict() if approval else None
		self["page_size"] = page_size
		self["label"] = label
		self._approval = approval

	@property
	def start(self):
		return self["start"]

	@property
	def end(self):
		return self["end"]

	@property
	def size(self):
		return self["size"]

	@property
	def access(self):
		return self["access"]

	@property
	def mode(self):
		return self["access"]

	@property
	def ticket(self):
		return self["ticket"]

	@property
	def ticket_id(self):
		return self["ticket"]

	@property
	def page_size(self):
		return self["page_size"]

	@property
	def label(self):
		return self["label"]

	@property
	def approval_ticket(self):
		return self._approval

	@classmethod
	def from_dict(cls, value, **kwargs):
		return cls(value, **kwargs)

	@classmethod
	def from_any(cls, value, **kwargs):
		if isinstance(value, cls):
			return value
		return cls(value, **kwargs)

	def contains(self, address):
		return self.start <= address < self.end

	def intersects(self, start, end):
		return self.start < end and start < self.end

	def intersection(self, start, end):
		left = max(self.start, start)
		right = min(self.end, end)
		if left >= right:
			return None
		return left, right

	def __str__(self):
		return "0x%x-0x%x %s ticket=%s" % (
			self.start,
			self.end,
			self.access,
			self.ticket,
		)


def _looks_like_range_sequence(value):
	if isinstance(value, (EvidenceRange, dict)):
		return False
	if isinstance(value, (tuple, list)):
		return not (
			len(value) in (2, 3, 4, 5)
			and isinstance(value[0], int)
			and isinstance(value[1], int)
		)
	return False


class EvidencePolicy(_AttrDict):
	"""The approved ranges and ticket that govern an evidence view."""

	_aliases = {
		"authorized_ranges": "ranges",
		"allowed_ranges": "ranges",
		"approved_ranges": "ranges",
		"segments": "ranges",
	}

	def __init__(
		self,
		ranges=None,
		ticket=None,
		page_size=DEFAULT_PAGE_SIZE,
		name=None,
		metadata=None,
		require_ticket=True,
		**kwargs
	):
		# Accept a work-order wrapper such as
		# {"ticket": "IR-1", "policy": [ranges]}.
		if isinstance(ranges, dict) and "policy" in ranges and not any(
			key in ranges
			for key in (
				"ranges",
				"authorized_ranges",
				"allowed_ranges",
				"addresses",
				"segments",
				"approved_ranges",
			)
		):
			outer = ranges
			ranges = outer.get("policy")
			if ticket is None:
				ticket = outer.get(
					"ticket",
					outer.get(
						"approval_ticket",
						outer.get(
							"ticket_id",
							outer.get(
								"work_order",
								outer.get("approval", outer.get("ticket_number")),
							),
						),
					),
				)

		# Accept EvidencePolicy("IR-1", [ranges]) as well as the usual
		# EvidencePolicy([ranges], ticket="IR-1").
		if (
			isinstance(ranges, (ApprovalTicket, dict))
			and "ranges" not in ranges
			and "authorized_ranges" not in ranges
			and "allowed_ranges" not in ranges
			and "addresses" not in ranges
			and "original_addresses" not in ranges
			and "segments" not in ranges
			and "approved_ranges" not in ranges
			and not (
				isinstance(ranges, dict)
				and any(
					key in ranges
					for key in (
						"range",
						"start",
						"start_address",
						"address",
						"original_address",
						"va",
						"begin",
						"end",
						"size",
						"length",
					)
				)
			)
		):
			ranges, ticket = ticket, ranges
		elif isinstance(ranges, str) and _looks_like_range_string(ranges):
			ranges = [ranges]
		elif isinstance(ranges, str) and (
			ticket is None
			or isinstance(ticket, (list, tuple, EvidencePolicy))
			or (isinstance(ticket, dict) and "ranges" in ticket)
		):
			ranges, ticket = ticket, ranges

		if isinstance(ranges, EvidencePolicy):
			source = ranges
			ranges = [item.to_dict() for item in source.ranges]
			if ticket is None:
				ticket = source.ticket
			if page_size == DEFAULT_PAGE_SIZE:
				page_size = source.page_size
			if name is None:
				name = source.get("name")
			if metadata is None:
				metadata = source.get("metadata")
		elif isinstance(ranges, dict) and any(
			key in ranges
			for key in (
				"ranges",
				"authorized_ranges",
				"allowed_ranges",
				"addresses",
				"original_addresses",
				"segments",
				"approved_ranges",
			)
		):
			source = ranges
			ranges = source.get(
				"ranges",
				source.get(
					"authorized_ranges",
					source.get(
							"allowed_ranges",
							source.get(
									"addresses",
									source.get(
										"original_addresses",
										source.get(
											"segments",
											source.get("approved_ranges"),
										),
									),
								),
						),
				),
			)
			if ticket is None:
				ticket = source.get(
				"ticket",
				source.get(
					"approval_ticket",
					source.get("ticket_id", source.get("work_order")),
				),
			)
			page_size = source.get("page_size", page_size)
			name = source.get("name", name)
			metadata = source.get("metadata", metadata)
		elif isinstance(ranges, dict):
			ranges = [ranges]
		if ranges is None:
			ranges = kwargs.get(
				"authorized_ranges",
				kwargs.get(
					"ranges",
					kwargs.get(
						"segments",
						kwargs.get("allowed_ranges", kwargs.get("approved_ranges")),
					),
				),
			)
		if ticket is None:
			ticket = kwargs.get(
				"approval_ticket",
				kwargs.get("ticket_id", kwargs.get("work_order")),
			)
		if ranges is None:
			raise EvidencePolicyError("at least one approved range is required")
		if isinstance(ranges, (EvidenceRange, dict)):
			ranges = [ranges]
		elif isinstance(ranges, (tuple, list)) and len(ranges) in (2, 3, 4, 5):
			if all(
				not isinstance(item, (list, tuple, dict, EvidenceRange))
				for item in ranges
			) and not any(_looks_like_range_string(item) for item in ranges):
				ranges = [ranges]

		default_ticket = _ticket_from_any(ticket)
		try:
			page_size = _as_int(page_size, "page size")
		except EvidencePolicyError:
			raise
		if page_size <= 0:
			raise EvidencePolicyError("page size must be positive")

		parsed = []
		for index, item in enumerate(list(ranges)):
			try:
				parsed.append(
					EvidenceRange(
						item,
						ticket=default_ticket if isinstance(item, (str, tuple, list)) else None,
						page_size=page_size,
					)
					if not isinstance(item, EvidenceRange)
					else EvidenceRange(
						item,
						ticket=item.ticket_id or (
							default_ticket.ticket_id if default_ticket else None
						),
						page_size=item.page_size or page_size,
					)
				)
			except EvidencePolicyError:
				raise
			except Exception as exc:
				raise EvidencePolicyError(
					"invalid approved range at index %d: %s" % (index, exc)
				)

		if not parsed:
			raise EvidencePolicyError("at least one approved range is required")
		for item in parsed:
			if item.ticket is None and default_ticket is not None:
				item["ticket"] = _TicketId(default_ticket.ticket_id)
				item["approval_ticket"] = default_ticket.to_dict()
				item._approval = default_ticket
		if default_ticket is None:
			tickets = [item.ticket for item in parsed if item.ticket]
			if tickets:
				for item in parsed:
					if item.approval_ticket is not None:
						default_ticket = item.approval_ticket
						break
				if default_ticket is None:
					default_ticket = _ticket_from_any(tickets[0])
		if require_ticket:
			missing = [idx for idx, item in enumerate(parsed) if not item.ticket]
			if missing:
				raise EvidencePolicyError(
					"approved ranges %s have no approval ticket" % missing
				)
			if default_ticket is None:
				raise EvidencePolicyError("an approval ticket is required")

		ordered = sorted(parsed, key=lambda item: item.start)
		for left, right in zip(ordered, ordered[1:]):
			if right.start < left.end:
				raise EvidencePolicyError(
					"approved ranges overlap: %s and %s" % (left, right)
				)

		_A = _AttrDict.__init__
		_A(self)
		self["ranges"] = ordered
		self["ticket"] = default_ticket.ticket_id if default_ticket else None
		self["ticket_id"] = default_ticket.ticket_id if default_ticket else None
		self["approval_ticket"] = (
			default_ticket.to_dict() if default_ticket else None
		)
		self["page_size"] = page_size
		self["name"] = name
		self["metadata"] = copy.deepcopy(metadata) if metadata is not None else {}
		self._approval = default_ticket

	@property
	def ranges(self):
		return self["ranges"]

	@property
	def authorized_ranges(self):
		return self["ranges"]

	@property
	def allowed_ranges(self):
		return self["ranges"]

	@property
	def ticket(self):
		return self._approval

	@property
	def ticket_id(self):
		return self._approval.ticket_id if self._approval else None

	@property
	def page_size(self):
		return self["page_size"]

	def range_at(self, address):
		for index, item in enumerate(self.ranges):
			if item.contains(address):
				return index, item
		return None, None

	def get_range(self, address):
		index, item = self.range_at(address)
		return item

	range_for = get_range

	def contains(self, address):
		return self.get_range(address) is not None

	def is_authorized(self, address, size=1):
		return self.authorization(address, size)["fully_covered"]

	def next_range(self, address):
		for index, item in enumerate(self.ranges):
			if item.start >= address:
				return index, item
		return None, None

	def authorization(self, address, size=1):
		matches = []
		end = address + size
		for index, item in enumerate(self.ranges):
			if item.intersects(address, end):
				left, right = item.intersection(address, end)
				matches.append(
					{
						"index": index,
						"start": left,
						"end": right,
						"size": right - left,
						"access": item.access,
						"ticket": item.ticket,
						"range": item.to_dict(),
					}
				)
		return {
			"address": address,
			"size": size,
			"allowed": bool(matches),
			"fully_covered": bool(matches)
			and matches[0]["start"] == address
			and matches[-1]["end"] == end,
			"ranges": matches,
		}

	def to_dict(self):
		payload = dict(self)
		payload["ranges"] = [item.to_dict() for item in self.ranges]
		payload["ticket_id"] = self.ticket_id
		return copy.deepcopy(payload)

	@classmethod
	def from_dict(cls, value, **kwargs):
		if isinstance(value, EvidencePolicy):
			return value
		return cls(value, **kwargs)

	@classmethod
	def from_ranges(cls, ranges, ticket=None, page_size=DEFAULT_PAGE_SIZE, **kwargs):
		return cls(
			ranges,
			ticket=ticket,
			page_size=page_size,
			**kwargs
		)

	@classmethod
	def from_work_order(cls, work_order, page_size=DEFAULT_PAGE_SIZE, **kwargs):
		return cls(work_order, page_size=page_size, **kwargs)

	@classmethod
	def from_any(cls, value, ticket=None, page_size=DEFAULT_PAGE_SIZE, **kwargs):
		if isinstance(value, EvidencePolicy):
			if ticket is not None:
				return cls(
					[item.to_dict() for item in value.ranges],
					ticket=ticket,
					page_size=value.page_size,
				)
			return value
		if isinstance(value, dict) and "policy" in value and not (
			"ranges" in value or "authorized_ranges" in value
		):
			nested = value.get("policy")
			return cls(
				nested,
				ticket=ticket or value.get("ticket"),
				page_size=page_size,
				**kwargs
			)
		if isinstance(value, dict) and (
			"ranges" in value or "authorized_ranges" in value
		):
			return cls(value, ticket=ticket, page_size=page_size, **kwargs)
		if value is None:
			raise EvidencePolicyError("evidence policy is required")
		return cls(value, ticket=ticket, page_size=page_size, **kwargs)


class EvidencePageSummary(_AttrDict):
	"""A page-level summary.  It intentionally contains no page bytes."""

	_aliases = {
		"address": "start",
		"page_address": "start",
		"page_start": "start",
		"page_end": "end",
		"length": "size",
		"digest": "sha256",
		"hash": "sha256",
		"redacted": "raw_withheld",
	}

	def __init__(self, value=None, **kwargs):
		_A = _AttrDict.__init__
		_A(self)
		if value:
			self.update(copy.deepcopy(dict(value)))
		self.update(copy.deepcopy(kwargs))
		self["raw_withheld"] = True
		self["data"] = None
		self["raw"] = None
		self["content"] = None

	@property
	def raw(self):
		return None

	@property
	def content(self):
		return None

	def to_dict(self):
		payload = copy.deepcopy(dict(self))
		for key in ("data", "raw", "content"):
			payload.pop(key, None)
		return payload


class EvidenceReceiptEntry(_AttrDict):
	"""One range entry in an evidence receipt."""

	_aliases = {
		"start_address": "original_address",
		"original_start": "original_address",
		"end_address": "original_end",
		"length": "original_size",
		"mode": "access",
	}


class EvidenceReceipt(_AttrDict):
	"""A serialisable receipt describing provenance and each redaction."""

	_aliases = {
		"entries": "ranges",
		"redactions": "ranges",
		"ticket_number": "ticket_id",
	}

	def __call__(self):
		return self

	def to_dict(self):
		return copy.deepcopy(dict(self))


class EvidenceReadResult(bytes):
	"""Result returned by evidence reads.

	The object is a ``bytes`` instance, so a wholly raw read can be compared
	directly with expected bytes.  For page-summary reads it is empty and the
	summary is available from ``.summary``; ``.data`` is ``None`` in that case,
	making it hard to mistake a summary for raw content.
	"""

	def __new__(
		cls,
		content=b"",
		mode=RAW,
		address=None,
		size=None,
		covered_end=None,
		summary=None,
		truncated=False,
		denied=False,
		suppressed=False,
		descriptor_suppressed_size=0,
		receipt=None,
		explanations=None,
		**kwargs
	):
		obj = bytes.__new__(cls, content or b"")
		obj._mode = mode
		obj._address = address
		obj._size = size
		obj._covered_end = covered_end
		obj._summary = list(summary or [])
		obj._truncated = bool(truncated)
		obj._denied = bool(denied)
		obj._suppressed = bool(suppressed)
		obj._descriptor_suppressed_size = int(descriptor_suppressed_size or 0)
		obj._receipt = receipt
		obj._explanations = list(explanations or [])
		for key, value in kwargs.items():
			setattr(obj, key, value)
		return obj

	@property
	def data(self):
		if self._mode in (RAW, "mixed"):
			return bytes(self)
		return None

	@property
	def content(self):
		return self.data

	@property
	def bytes(self):
		return bytes(self)

	@property
	def summary(self):
		return self._summary

	@property
	def pages(self):
		return self._summary

	@property
	def mode(self):
		return self._mode

	@property
	def status(self):
		if isinstance(self._receipt, dict):
			return self._receipt.get("status") or self._mode
		return self._mode

	@property
	def address(self):
		return self._address

	@property
	def requested_address(self):
		return self._address

	@property
	def start(self):
		return self._address

	@property
	def requested_end(self):
		return None if self._address is None or self._size is None else self._address + self._size

	@property
	def end(self):
		return self.requested_end

	@property
	def size(self):
		return self._size

	@property
	def requested_size(self):
		return self._size

	@property
	def covered_end(self):
		return self._covered_end

	@property
	def returned_size(self):
		return len(self)

	@property
	def suppressed_size(self):
		return sum(page.get("size", 0) for page in self._summary)

	@property
	def truncated(self):
		return self._truncated

	@property
	def is_truncated(self):
		return self._truncated

	@property
	def denied(self):
		return self._denied

	@property
	def is_denied(self):
		return self._denied

	@property
	def suppressed(self):
		return self._suppressed

	@property
	def is_suppressed(self):
		return self._suppressed

	@property
	def is_mixed(self):
		return self._mode == "mixed"

	@property
	def descriptor_suppressed_size(self):
		return self._descriptor_suppressed_size

	@property
	def descriptor_suppressed(self):
		return bool(self._descriptor_suppressed_size)

	@property
	def receipt(self):
		return self._receipt

	@property
	def receipt_status(self):
		if isinstance(self._receipt, dict):
			return self._receipt.get("status")
		return None

	@property
	def disposition(self):
		return self.status

	@property
	def read_receipt(self):
		return self._receipt

	@property
	def explanations(self):
		return self._explanations

	@property
	def explanation(self):
		return " ".join(self._explanations)

	@property
	def raw(self):
		return self.data

	@property
	def is_summary(self):
		return self.mode == PAGE_SUMMARY

	def __bool__(self):
		return not self._denied

	__nonzero__ = __bool__

	def __getitem__(self, key):
		if isinstance(key, str):
			fields = {
				"data": self.data,
				"raw": self.data,
				"content": self.data,
				"bytes": self.bytes,
				"is_summary": self.is_summary,
				"is_mixed": self.is_mixed,
				"is_truncated": self.is_truncated,
				"is_denied": self.is_denied,
				"is_suppressed": self.is_suppressed,
				"summary": self.summary,
				"pages": self.pages,
				"mode": self.mode,
				"status": self.status,
				"address": self.address,
				"start": self.start,
				"end": self.end,
				"size": self.size,
				"truncated": self.truncated,
				"denied": self.denied,
				"suppressed": self.suppressed,
				"suppressed_size": self.suppressed_size,
				"returned_size": self.returned_size,
				"descriptor_suppressed": self.descriptor_suppressed,
				"descriptor_suppressed_size": self.descriptor_suppressed_size,
				"receipt": self.receipt,
				"receipt_status": self.receipt_status,
				"disposition": self.disposition,
				"explanations": self.explanations,
				"explanation": self.explanation,
			}
			if key in fields:
				return fields[key]
			raise KeyError(key)
		return bytes.__getitem__(self, key)

	def get(self, key, default=None):
		try:
			return self[key]
		except (KeyError, TypeError):
			return default

	def to_bytes(self):
		return bytes(self)

	def to_json(self, indent=None, include_data=False):
		return json.dumps(
			self.to_dict(include_data=include_data),
			indent=indent,
			sort_keys=True,
		)

	def to_dict(self, include_data=False):
		payload = {
			"mode": self.mode,
			"status": self.status,
			"disposition": self.disposition,
			"requested_address": self._address,
			"requested_size": self._size,
			"returned_size": len(self),
			"covered_end": self._covered_end,
			"truncated": self._truncated,
			"denied": self._denied,
			"suppressed": self._suppressed,
			"suppressed_size": self.suppressed_size,
			"descriptor_suppressed": self.descriptor_suppressed,
			"descriptor_suppressed_size": self.descriptor_suppressed_size,
			"explanations": list(self._explanations),
			"summary": [item.to_dict() for item in self._summary],
			"receipt": (
				self._receipt.to_dict()
				if isinstance(self._receipt, EvidenceReceipt)
				else self._receipt
			),
		}
		if include_data and self.data is not None:
			payload["data_b64"] = base64.b64encode(self.data).decode("ascii")
		return payload


class EvidenceVerification(_AttrDict):
	def __init__(self, **kwargs):
		_A = _AttrDict.__init__
		_A(self)
		self.update(kwargs)
		self.setdefault("ok", False)
		self.setdefault("verified", self["ok"])
		self.setdefault("mismatches", [])
		self.setdefault("range_checks", [])

	@property
	def ok(self):
		return bool(self["ok"])

	def __bool__(self):
		return self.ok

	__nonzero__ = __bool__

	def raise_if_failed(self):
		if not self.ok:
			raise EvidenceVerificationError(
				"original evidence verification failed: %s"
				% "; ".join(str(item) for item in self.get("mismatches", []))
			)
		return True


class _MemorySource(object):
	def __init__(
		self,
		start,
		end,
		file_rva,
		stream,
		stream_type=None,
		stream_rva=None,
		stream_size=None,
		descriptor_index=None,
		origin="memory_descriptor",
		thread_id=None,
		thread_index=None,
		priority=10,
	):
		self.start = start
		self.end = end
		self.file_rva = file_rva
		self.stream = stream
		self.stream_type = stream_type
		self.stream_rva = stream_rva
		self.stream_size = stream_size
		self.descriptor_index = descriptor_index
		self.origin = origin
		self.thread_id = thread_id
		self.thread_index = thread_index
		self.priority = priority

	def contains(self, start, end):
		return self.start <= start and end <= self.end

	def mapping(self, module=None, memory_info=None):
		payload = {
			"stream": self.stream,
			"stream_name": self.stream,
			"stream_type": self.stream_type,
			"stream_type_name": self.stream,
			"stream_rva": self.stream_rva,
			"stream_size": self.stream_size,
			"descriptor_index": self.descriptor_index,
			"index": self.descriptor_index,
			"origin": self.origin,
			"virtual_address": self.start,
			"original_address": self.start,
			"start": self.start,
			"end": self.end,
			"size": self.end - self.start,
			"file_rva": self.file_rva,
			"file_offset": self.file_rva,
			"offset": self.file_rva,
			"rva": self.file_rva,
			"start_file_address": self.file_rva,
			"memory_descriptor_index": self.descriptor_index,
			"descriptor": self.descriptor_index,
			"virtual_start": self.start,
			"virtual_end": self.end,
			"original_end": self.end,
			"thread_id": self.thread_id,
			"thread_index": self.thread_index,
			"module": None,
			"module_name": None,
			"module_base": None,
			"module_offset": None,
			"memory_info": None,
		}
		if module:
			payload["module"] = copy.deepcopy(module)
			payload["module_name"] = module.get("name")
			payload["module_base"] = module.get("baseaddress")
			payload["module_offset"] = (
				self.start - module["baseaddress"] if module.get("baseaddress") is not None else None
			)
		if memory_info:
			payload["memory_info"] = copy.deepcopy(memory_info)
		return _AttrDict(payload)


class _RawInterval(object):
	def __init__(self, start, end, data, mapping_sources, entry_index=None):
		self.start = start
		self.end = end
		self.data = data
		self.mapping_sources = list(mapping_sources or [])
		self.entry_index = entry_index

	@property
	def size(self):
		return self.end - self.start

	def contains(self, address):
		return self.start <= address < self.end

	def slice(self, start, end):
		left = max(start, self.start)
		right = min(end, self.end)
		if left >= right:
			return b""
		return self.data[left - self.start:right - self.start]

	def to_dict(self):
		return {
			"start": self.start,
			"end": self.end,
			"size": self.size,
			"sha256": _sha256(self.data),
			"entry_index": self.entry_index,
			"mapping_sources": copy.deepcopy(self.mapping_sources),
		}


class EvidenceMemorySegment(object):
	"""A policy-shaped memory segment exposed by an evidence view."""

	def __init__(self, view, item, source=None):
		self._view = view
		self._range = item
		self.start_address = item.start
		self.end_address = item.end
		self.start = item.start
		self.end = item.end
		self.start_virtual_address = item.start
		self.end_virtual_address = item.end
		self.size = item.size
		self.access = item.access
		self.mode = item.access
		self.authorized = True
		self.redacted = item.access == PAGE_SUMMARY
		self.raw_exported = item.access == RAW
		self.ticket = item.ticket
		self.start_file_address = (
			source.file_rva if source is not None else None
		)
		self.file_rva = self.start_file_address
		self.rva = self.start_file_address
		self.mapping_source = (
			source.mapping() if source is not None else None
		)
		self.mapping = self.mapping_source
		self.provenance = copy.deepcopy(self.mapping_source)

	def inrange(self, address):
		return self.start_address <= address < self.end_address

	def remaining_len(self, address):
		if not self.inrange(address):
			return None
		return self.end_address - address

	def read(self, virtual_address=None, size=None, file_handler=None):
		# Support both read(address, size) and the legacy
		# read(file_handle, segment_relative_start, segment_relative_end).
		if (
			size is not None
			and file_handler is not None
			and not isinstance(virtual_address, int)
		):
			start = _as_int(size, "read start")
			end = _as_int(file_handler, "read end")
			return self._view.read(self.start_address + start, end - start)
		if virtual_address is None:
			virtual_address = self.start_address
		if size is None:
			size = self.end_address - _as_int(virtual_address, "read address")
		return self._view.read(_as_int(virtual_address, "read address"), size)

	def read_bytes(self, virtual_address=None, size=None):
		if virtual_address is None:
			virtual_address = self.start_address
		if size is None:
			size = self.end_address - _as_int(virtual_address, "read address")
		return self._view.read_bytes(virtual_address, size)

	def find(self, pattern, file_handler=None, chunksize=None):
		result = self.search(
			pattern,
			file_handler=file_handler,
			find_first=True,
			chunksize=chunksize,
		)
		if isinstance(result, list):
			return result[0] if result else -1
		return result

	def search(self, pattern, file_handler=None, find_first=False, chunksize=None):
		if isinstance(file_handler, bool) and find_first is False:
			find_first = file_handler
		return self._view.search(
			pattern,
			start=self.start_address,
			end=self.end_address,
			find_first=find_first,
		)

	@staticmethod
	def get_header():
		return ["VA Start", "RVA", "Size", "Access", "Ticket"]

	def to_row(self):
		return [
			hex(self.start_address),
			hex(self.start_file_address) if self.start_file_address is not None else None,
			hex(self.size),
			self.access,
			self.ticket,
		]

	def __str__(self):
		return "VA Start: 0x%x, Size: 0x%x, Access: %s, Ticket: %s" % (
			self.start_address,
			self.size,
			self.access,
			self.ticket,
		)


class EvidenceThread(_AttrDict):
	"""Thread metadata and restricted stack access for an evidence view."""

	_aliases = {
		"Id": "thread_id",
		"tid": "thread_id",
		"stack_start": "stack_address",
		"stack_start_address": "stack_address",
		"stack_end": "stack_end_address",
		"stack_rsp": "rsp",
		"rsp_address": "rsp",
		"context_rsp": "rsp",
		"context_rip": "rip",
		"rip_address": "rip",
	}

	def __init__(self, value=None, view=None, **kwargs):
		_A = _AttrDict.__init__
		_A(self)
		if value:
			self.update(copy.deepcopy(dict(value)))
		self.update(copy.deepcopy(kwargs))
		self._view = view
		self.setdefault("rsp", None)
		self.setdefault("rip", None)
		self.setdefault("stack_address", None)
		self.setdefault("stack_end_address", None)
		self.setdefault("stack_size", None)
		self.setdefault("Rsp", self.get("rsp"))
		self.setdefault("RIP", self.get("rip"))

	def _resolve_address(self, offset=0, address=None):
		if address is not None:
			return address
		if self.stack_address is None:
			raise EvidenceAccessDenied(
				"thread %s has no stack mapping in this dump" % self.thread_id
			)
		return self.stack_address + offset

	def read(self, offset=0, size=None, address=None):
		if self._view is None:
			raise EvidenceError("detached thread metadata cannot read memory")
		target = self._resolve_address(offset=offset, address=address)
		if size is None:
			if self.stack_end is None:
				raise EvidenceAccessDenied("read size is required")
			size = self.stack_end - target
		return self._view.read(target, size)

	def read_bytes(self, offset=0, size=None, address=None):
		if self._view is None:
			raise EvidenceError("detached thread metadata cannot read memory")
		target = self._resolve_address(offset=offset, address=address)
		if size is None:
			if self.stack_end is None:
				raise EvidenceAccessDenied("read size is required")
			size = self.stack_end - target
		return self._view.read_bytes(target, size)

	def read_stack(self, offset=0, size=None, address=None):
		return self.read(offset=offset, size=size, address=address)

	def read_at_rsp(self, size):
		if self.rsp is None:
			raise EvidenceAccessDenied("thread has no RSP in this dump")
		return self._view.read(self.rsp, size)

	@property
	def context(self):
		return self

	@property
	def registers(self):
		return {"Rsp": self.rsp, "Rip": self.rip}

	@property
	def stack_reader(self):
		return self.stack

	@property
	def stack(self):
		if self._view is None or self.stack_address is None:
			return None
		for segment in self._view.memory_segments:
			if segment.start_address <= self.stack_address < segment.end_address:
				return segment
		return None


class EvidenceReader(object):
	"""Memory reader whose every access is governed by an evidence policy."""

	def __init__(self, view):
		self.view = view
		self.reader = view
		self.filename = view.source.get("filename") if view.source else None
		self.file_handle = None
		self.modules = view.modules
		self.unloaded_modules = []
		self.sysinfo = view.sysinfo
		self.is_fulldump = view.is_fulldump
		self.sizeof_ptr = view.pointer_size
		self.size_of_ptr = view.pointer_size
		self.unpack_ptr = "<Q" if self.sizeof_ptr == 8 else "<L"
		self.sizeof_long = 4
		self.unpack_long = "<L"

	@property
	def memory_segments(self):
		return self.view.memory_segments

	def get_handler(self):
		return None

	def get_memory(self):
		return self.view.memory_segments

	def get_buffered_reader(self, segment_chunk_size=None):
		return EvidenceBufferedReader(self, segment_chunk_size=segment_chunk_size)

	def read(self, address, size=None):
		return self.view.read(address, size)

	def read_at(self, address, size):
		return self.view.read(address, size)

	def read_bytes(self, address, size=None):
		return self.view.read_bytes(address, size)

	def read_exact(self, address, size):
		return self.view.read_exact(address, size)

	def read_int(self, address):
		return int.from_bytes(
			self.read_bytes(address, self.sizeof_ptr),
			byteorder="little",
			signed=True,
		)

	def read_uint(self, address):
		return int.from_bytes(
			self.read_bytes(address, self.sizeof_ptr),
			byteorder="little",
			signed=False,
		)

	def find(self, pattern, start=None, end=None, **kwargs):
		return self.view.find(
			pattern, start=start, end=end, **kwargs
		)

	def search(self, pattern, find_first=False, start=None, end=None,
			chunksize=None, **kwargs):
		return self.view.search(
			pattern,
			start=start,
			end=end,
			find_first=find_first,
			**kwargs
		)

	def authorization(self, address, size=1):
		return self.view.authorization(address, size)

	def get_evidence_view(self):
		return self.view

	def get_evidence_reader(self):
		return self

	def get_module_by_name(self, module_name):
		needle = str(module_name).lower()
		for module in self.modules:
			name = str((module or {}).get("name") or "").lower()
			if needle in name:
				return module
		return None

	def get_unloaded_by_name(self, module_name):
		return None

	def find_in_module(self, module_name, pattern, find_first=True,
			reverse_order=False, chunksize=None):
		result = self.search_module(
			module_name,
			pattern,
			find_first=find_first,
			reverse_order=reverse_order,
			chunksize=chunksize,
		)
		if isinstance(result, list):
			return result[0] if result else -1
		return result

	def search_module(self, module_name, pattern, find_first=False,
			reverse_order=False, chunksize=None):
		module = self.get_module_by_name(module_name)
		if module is None:
			raise EvidencePolicyError("could not find module %r" % module_name)
		start = module.get("baseaddress")
		end = module.get("endaddress")
		if end is None and start is not None and module.get("size"):
			end = start + module["size"]
		return self.view.search(
			pattern, start=start, end=end, find_first=find_first
		)


class EvidenceBufferedReader(object):
	"""Cursor-oriented wrapper around :class:`EvidenceReader`."""

	def __init__(self, reader, segment_chunk_size=None):
		if isinstance(reader, EvidenceView):
			reader = reader.get_reader()
		self.reader = reader
		self.view = reader.view
		self.segment_chunk_size = segment_chunk_size
		self.current_position = None

	def get_reader(self):
		return self.reader

	def get_evidence_view(self):
		return self.view

	def get_evidence_reader(self):
		return self.reader

	def get_handler(self):
		return self.reader.get_handler()

	def get_memory(self):
		return self.view.memory_segments

	def _current_range(self, address=None):
		if address is None:
			address = self.current_position
		if address is None:
			return None
		_, item = self.view.policy.range_at(address)
		return item

	@property
	def current_segment(self):
		item = self._current_range()
		if item is None:
			return None
		for segment in self.view.memory_segments:
			if segment.start_address == item.start:
				return segment
		return None

	def move(self, address):
		self.current_position = _as_int(address, "address")
		return self.current_position

	def seek(self, offset, whence=0):
		if self.current_position is None:
			raise EvidenceError("move() must be called before seek()")
		offset = _as_int(offset, "offset")
		item = self._current_range()
		if whence == 0:
			target = (item.start if item else self.current_position) + offset
		elif whence == 1:
			target = self.current_position + offset
		elif whence == 2:
			target = (item.end if item else self.current_position) - offset
		else:
			raise EvidencePolicyError("seek whence must be 0, 1 or 2")
		self.current_position = target
		return target

	def tell(self):
		return self.current_position

	def align(self, alignment=None):
		if self.current_position is None:
			raise EvidenceError("move() must be called before align()")
		if alignment is None:
			alignment = self.reader.sizeof_ptr
		offset = self.current_position % alignment
		if offset:
			self.current_position += alignment - offset
		return self.current_position

	def read(self, size=-1):
		if self.current_position is None:
			raise EvidenceError("move() must be called before read()")
		item = self._current_range()
		if size == -1:
			if item is None:
				size = 0
			else:
				size = item.end - self.current_position
		if size < 0:
			raise EvidencePolicyError("read size must be -1 or non-negative")
		result = self.view.read(self.current_position, size)
		self.current_position = (
			result.covered_end
			if result.covered_end is not None
			else self.current_position + len(result)
		)
		return result

	def peek(self, size):
		if self.current_position is None:
			raise EvidenceError("move() must be called before peek()")
		return self.view.read(self.current_position, size)

	def read_bytes(self, size=-1):
		result = self.read(size)
		if result.data is None or result.truncated:
			raise EvidenceAccessDenied(
				"read violates the evidence policy: %s"
				% (result.explanation or result.status),
				address=result.address,
				size=result.size,
				result=result,
			)
		return bytes(result)

	def read_exact(self, size):
		return self.read_bytes(size)

	def read_int(self):
		data = self.read(self.reader.sizeof_ptr)
		if data.data is None or data.truncated or len(data) != self.reader.sizeof_ptr:
			raise EvidenceAccessDenied(
				"integer read violates the evidence policy: %s"
				% (data.explanation or data.status),
				address=self.current_position - len(data),
				size=self.reader.sizeof_ptr,
				result=data,
			)
		return int.from_bytes(data, byteorder="little", signed=True)

	def read_uint(self):
		data = self.read(self.reader.sizeof_ptr)
		if data.data is None or data.truncated or len(data) != self.reader.sizeof_ptr:
			raise EvidenceAccessDenied(
				"integer read violates the evidence policy: %s"
				% (data.explanation or data.status),
				address=self.current_position - len(data),
				size=self.reader.sizeof_ptr,
				result=data,
			)
		return int.from_bytes(data, byteorder="little", signed=False)

	def get_ptr(self, address):
		return self.reader.read_uint(address)

	def get_ptr_with_offset(self, address):
		if self.reader.sizeof_ptr == 8:
			value = int.from_bytes(
				self.view.read_bytes(address, 4),
				byteorder="little",
				signed=True,
			)
			return address + 4 + value
		return self.reader.read_uint(address)

	def find(self, pattern):
		if self.current_position is None:
			raise EvidenceError("move() must be called before find()")
		item = self._current_range()
		end = item.end if item else None
		return self.view.find(pattern, start=self.current_position, end=end)

	def find_all(self, pattern):
		return self.view.search(pattern, start=self.current_position, find_first=False)

	def find_global(self, pattern):
		return self.view.find(pattern)

	def find_all_global(self, pattern):
		return self.view.search(pattern, find_first=False)


class EvidenceView(object):
	"""A restricted, handoff-ready view of a minidump's approved memory."""

	def __init__(
		self,
		source=None,
		ranges=None,
		ticket=None,
		policy=None,
		page_size=DEFAULT_PAGE_SIZE,
		authorization=None,
		access_policy=None,
		require_ticket=True,
		compute_source_digest=True,
		include_threads=True,
		**kwargs
	):
		self._init_empty()
		if hasattr(source, "__fspath__"):
			source = os.fspath(source)
		if isinstance(source, EvidenceView):
			self._copy_from(source)
			return
		if isinstance(source, EvidenceBundle):
			self._copy_from(source)
			return
		if isinstance(source, (bytes, bytearray)):
			if bytes(source[:4]) == b"MDMP":
				source = self._parse_minidump_bytes(bytes(source))
			else:
				self._load_manifest(self._decode_manifest(source))
				return
		if isinstance(source, str):
			if source.lstrip().startswith("{"):
				self._load_manifest(self._decode_manifest(source))
				return
			if os.path.isfile(source):
				with open(source, "rb") as handle:
					magic = handle.read(4)
				if magic != b"MDMP":
					self._load_manifest(self._decode_manifest_file(source))
					return
				source = self._parse_minidump_path(source)
			else:
				raise EvidenceError("source path does not exist: %s" % source)
		if isinstance(source, dict) and source.get("schema") == EVIDENCE_SCHEMA:
			self._load_manifest(source)
			return

		if policy is None:
			policy = authorization if authorization is not None else access_policy
		if ticket is None:
			ticket = kwargs.get(
				"approval_ticket",
				kwargs.get(
					"work_order",
					kwargs.get(
						"ticket_id",
						kwargs.get("approval", kwargs.get("ticket_number")),
					),
				),
			)
		if policy is None:
			policy = kwargs.get(
				"evidence_policy",
				kwargs.get(
					"authorized_ranges",
					kwargs.get(
						"allowed_ranges",
						kwargs.get(
							"approved_ranges", kwargs.get("segments")
						),
					),
				),
			)
		if isinstance(ranges, EvidencePolicy):
			if policy is not None:
				raise EvidencePolicyError("policy specified more than once")
			policy = ranges
			ranges = None
		if policy is None:
			policy = ranges
		if policy is None:
			raise EvidencePolicyError("an evidence policy is required")
		policy = EvidencePolicy.from_any(
			policy,
			ticket=ticket,
			page_size=page_size,
			require_ticket=require_ticket,
		)
		self._build_view(
			source,
			policy,
			page_size=page_size,
			compute_source_digest=compute_source_digest,
			include_threads=include_threads,
		)

	@staticmethod
	def _parse_minidump_path(path):
		from minidump.minidumpfile import MinidumpFile

		return MinidumpFile.parse(path)

	@staticmethod
	def _parse_minidump_bytes(data):
		from minidump.minidumpfile import MinidumpFile

		return MinidumpFile.parse_bytes(data)

	@staticmethod
	def _decode_manifest(data):
		if isinstance(data, (bytes, bytearray)):
			data = bytes(data).decode("utf-8")
		return json.loads(data)

	@staticmethod
	def _decode_manifest_file(path):
		with open(path, "r", encoding="utf-8") as handle:
			return json.load(handle)

	def _init_empty(self):
		self._policy = None
		self._page_size = DEFAULT_PAGE_SIZE
		self._source_meta = {}
		self._entries = []
		self._raw_intervals = []
		self._summary_pages = {}
		self._receipt = EvidenceReceipt()
		self._manifest = {}
		self._integrity = None
		self._threads = []
		self._pointer_size = 8
		self._is_fulldump = True
		self._modules = []
		self._sysinfo = None
		self._detached = False
		self._io_lock = threading.RLock()
		self._memory_segment_cache = None
		self._accepted = False
		self._custody = []

	def _copy_from(self, other):
		self._policy = EvidencePolicy.from_dict(other.policy.to_dict())
		self._page_size = other.page_size
		self._source_meta = copy.deepcopy(other._source_meta)
		self._entries = copy.deepcopy(other._entries)
		self._raw_intervals = [
			_RawInterval(
				item.start,
				item.end,
				bytes(item.data),
				copy.deepcopy(item.mapping_sources),
				item.entry_index,
			)
			for item in other._raw_intervals
		]
		self._summary_pages = copy.deepcopy(other._summary_pages)
		self._receipt = EvidenceReceipt(other._receipt.to_dict())
		self._manifest = copy.deepcopy(other._manifest)
		self._integrity = copy.deepcopy(other._integrity)
		self._threads = [EvidenceThread(item.to_dict(), view=self) for item in other._threads]
		self._pointer_size = other._pointer_size
		self._is_fulldump = other._is_fulldump
		self._modules = copy.deepcopy(other._modules)
		self._sysinfo = copy.deepcopy(other._sysinfo)
		self._detached = other._detached
		self._accepted = other._accepted
		self._custody = copy.deepcopy(other._custody)
		self._minidump = getattr(other, "_minidump", None)

	@property
	def policy(self):
		return self._policy

	@property
	def authorization_policy(self):
		return self._policy

	@property
	def evidence_policy(self):
		return self._policy

	@property
	def access_policy(self):
		return self._policy

	@property
	def ranges(self):
		return self._policy.ranges

	@property
	def authorized_ranges(self):
		return self._policy.ranges

	@property
	def evidence_ranges(self):
		return self._policy.ranges

	@property
	def redacted(self):
		return bool(self.page_summary_ranges)

	@property
	def has_redactions(self):
		return self.redacted

	@property
	def redactions(self):
		return self.page_summary_ranges

	@property
	def redaction_entries(self):
		return [
			EvidenceReceiptEntry(entry)
			for entry in copy.deepcopy(self._entries)
			if entry.get("access") == PAGE_SUMMARY
		]

	@property
	def raw_entries(self):
		return [
			EvidenceReceiptEntry(entry)
			for entry in copy.deepcopy(self._entries)
			if entry.get("access") == RAW
		]

	@property
	def page_summary_ranges(self):
		return [
			item for item in self._policy.ranges
			if item.access == PAGE_SUMMARY
		]

	@property
	def raw_ranges(self):
		return [
			item for item in self._policy.ranges if item.access == RAW
		]

	@property
	def exported_ranges(self):
		return self.raw_ranges

	@property
	def summary_ranges(self):
		return self.page_summary_ranges

	@property
	def ticket(self):
		return self._policy.ticket

	@property
	def approval_ticket(self):
		return self._policy.ticket

	@property
	def ticket_id(self):
		return self._policy.ticket_id

	@property
	def range_count(self):
		return len(self.ranges)

	@property
	def page_size(self):
		return self._page_size

	@property
	def pointer_size(self):
		return self._pointer_size

	@property
	def is_fulldump(self):
		return self._is_fulldump

	@property
	def source(self):
		return _CallableDict(copy.deepcopy(self._source_meta))

	@property
	def source_sha256(self):
		return self._source_meta.get("sha256")

	@property
	def source_size(self):
		return self._source_meta.get("size")

	@property
	def source_path(self):
		return self._source_meta.get("filename")

	@property
	def source_filename(self):
		return self._source_meta.get("filename")

	@property
	def receipt(self):
		return self._receipt

	@property
	def get_receipt(self):
		return self._receipt

	@property
	def manifest(self):
		return _CallableDict(self.to_dict())

	def get_manifest(self, include_integrity=True):
		return self.to_dict(include_integrity=include_integrity)

	def get_policy(self):
		return self.policy

	def get_ranges(self):
		return self.ranges

	def get_entries(self):
		return self.entries

	def get_address_map(self):
		return self.address_map

	def get_threads(self):
		return self.threads

	def get_ticket(self):
		return self.ticket

	@property
	def entries(self):
		return [
			EvidenceReceiptEntry(item)
			for item in copy.deepcopy(self._entries)
		]

	@property
	def address_map(self):
		return [
			_AttrDict(item)
			for item in copy.deepcopy(self._manifest.get("raw_layout", []))
		]

	@property
	def authorized_size(self):
		return sum(item.size for item in self.ranges)

	@property
	def exported_size(self):
		return sum(interval.size for interval in self._raw_intervals)

	@property
	def suppressed_size(self):
		return sum(
			entry.get("suppressed_size", 0) for entry in self._entries
		)

	@property
	def descriptor_suppressed_size(self):
		return sum(
			entry.get("descriptor_suppressed_size", 0)
			for entry in self._entries
		)

	@property
	def provenance(self):
		return [
			_AttrDict(item)
			for item in copy.deepcopy(self._manifest.get("mapping_sources", []))
		]

	@property
	def mapping_sources(self):
		return self.provenance

	@property
	def modules(self):
		return copy.deepcopy(self._modules)

	@property
	def sysinfo(self):
		return copy.deepcopy(self._sysinfo)

	@property
	def threads(self):
		return list(self._threads)

	@property
	def thread_contexts(self):
		return list(self._threads)

	@property
	def custody(self):
		return copy.deepcopy(self._custody)

	@property
	def accepted(self):
		return bool(self._accepted)

	@property
	def accepted_by(self):
		return self._manifest.get("accepted_by")

	@property
	def accepted_at(self):
		return self._manifest.get("accepted_at")

	@property
	def source_verified(self):
		return bool(self._manifest.get("source_verified", False))

	@property
	def acceptance_chain(self):
		return self.custody

	@property
	def handoffs(self):
		return self.custody

	@property
	def custody_chain(self):
		return self.custody

	@property
	def integrity(self):
		return copy.deepcopy(self.to_dict().get("integrity", {}))

	@property
	def digest(self):
		return self.to_dict()["integrity"]["digest"]

	def __len__(self):
		return len(self.ranges)

	def __iter__(self):
		return iter(self.ranges)

	def __getitem__(self, key):
		if isinstance(key, int):
			return self.ranges[key]
		if key == "manifest":
			return self.manifest
		if key == "integrity":
			return self.integrity
		if key == "digest":
			return self.digest
		if key == "accepted":
			return self.accepted
		if key == "accepted_by":
			return self.accepted_by
		if key == "accepted_at":
			return self.accepted_at
		if key == "source_verified":
			return self.source_verified
		if key in ("custody", "acceptance_chain", "handoffs"):
			return self.custody
		manifest = self.to_dict(include_integrity=False)
		if key in manifest:
			return manifest[key]
		raise KeyError(key)

	def get(self, key, default=None):
		try:
			return self[key]
		except (KeyError, IndexError, TypeError):
			return default

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, traceback):
		self.close()
		return False

	def __str__(self):
		lines = [
			"EvidenceView ticket=%s source_sha256=%s"
			% (self.policy.ticket_id, self.source_sha256)
		]
		for item in self.ranges:
			lines.append(str(item))
		return "\n".join(lines)

	def __repr__(self):
		return "<EvidenceView ranges=%d ticket=%s>" % (
			len(self.ranges),
			self.policy.ticket_id,
		)

	# ------------------------------------------------------------------
	# Construction
	# ------------------------------------------------------------------

	def _build_view(self, source, policy, page_size, compute_source_digest, include_threads):
		mf = self._coerce_minidump(source)
		self._minidump = mf
		self._policy = policy
		self._page_size = page_size
		self._pointer_size = self._detect_pointer_size(mf)
		self._is_fulldump = bool(
			getattr(
				mf,
				"is_fulldump",
				getattr(mf, "memory_segments_64", None) is not None,
			)
		)
		self._modules = self._snapshot_modules(mf)
		self._sysinfo = self._snapshot_sysinfo(mf)
		handle = getattr(mf, "file_handle", None)
		if handle is None:
			raise EvidenceError("minidump source has no file handle")

		source_size = self._handle_size(handle)
		source_digest = (
			self._handle_digest(handle) if compute_source_digest else None
		)
		filename = getattr(mf, "filename", None)
		if hasattr(filename, "__fspath__"):
			filename = os.fspath(filename)
		self._source_meta = {
			"filename": filename,
			"basename": os.path.basename(filename) if filename else None,
			"size": source_size,
			"file_size": source_size,
			"sha256": source_digest,
			"digest": source_digest,
			"path": filename,
			"minidump_signature": "MDMP",
			"pointer_size": self._pointer_size,
			"computed_digest": bool(compute_source_digest),
		}

		sources = self._collect_sources(mf)
		self._entries = []
		self._raw_intervals = []
		self._summary_pages = {}
		raw_layout = []
		raw_offset = 0

		for index, item in enumerate(self.ranges):
			entry = self._build_entry(index, item, sources, handle)
			self._entries.append(entry)
			if item.access == RAW:
				for chunk in entry["raw_chunks"]:
					data = base64.b64decode(chunk["data_b64"])
					chunk["exported_offset"] = raw_offset
					raw_offset += len(data)
					self._raw_intervals.append(
						_RawInterval(
							chunk["start"],
							chunk["end"],
							data,
							chunk["mapping_sources"],
							index,
						)
					)
					raw_layout.append(
						{
							"entry_index": index,
							"original_address": chunk["start"],
							"original_end": chunk["end"],
							"original_size": chunk["size"],
							"exported_offset": chunk["exported_offset"],
							"exported_size": chunk["size"],
							"sha256": chunk["sha256"],
							"stream": (chunk["mapping_source"] or {}).get("stream"),
							"file_rva": (chunk["mapping_source"] or {}).get("file_rva"),
							"descriptor_index": (
								(chunk["mapping_source"] or {}).get("descriptor_index")
							),
							"mapping_source": copy.deepcopy(chunk["mapping_source"]),
						}
					)
			else:
				self._summary_pages[index] = [
					EvidencePageSummary(item) for item in entry["pages"]
				]
			entry["exported_offset"] = (
				entry["raw_chunks"][0]["exported_offset"]
				if entry.get("raw_chunks")
				else None
			)
			entry["bundle_offset"] = entry["exported_offset"]

		self._raw_intervals.sort(key=lambda item: item.start)
		self._threads = (
			self._snapshot_threads(mf) if include_threads else []
		)
		self._receipt = EvidenceReceipt(
			{
				"schema": EVIDENCE_SCHEMA,
				"schema_version": 1,
				"kind": "evidence_handoff",
				"accepted": False,
				"accepted_by": None,
				"accepted_at": None,
				"source_verified": False,
				"custody": [],
				"created_at": _now_iso(),
				"ticket": self.policy.ticket_id,
				"ticket_id": self.policy.ticket_id,
				"approval": self.policy.ticket_id,
				"policy": self.policy.to_dict(),
				"approval_ticket": (
					self.ticket.to_dict() if self.ticket else None
				),
				"source": copy.deepcopy(self._source_meta),
				"source_sha256": self._source_meta.get("sha256"),
				"source_size": self._source_meta.get("size"),
				"range_count": len(self._entries),
				"ranges": [self._receipt_entry(entry) for entry in self._entries],
				"redactions": [
					self._receipt_entry(entry)
					for entry in self._entries
					if entry.get("access") == PAGE_SUMMARY
				],
				"redacted": any(
					entry.get("access") == PAGE_SUMMARY
					for entry in self._entries
				),
				"has_redactions": any(
					entry.get("access") == PAGE_SUMMARY
					for entry in self._entries
				),
				"exported_size": sum(
					entry.get("exported_size", 0) for entry in self._entries
				),
				"suppressed_size": sum(
					entry.get("suppressed_size", 0) for entry in self._entries
				),
				"truncated": any(entry.get("truncated") for entry in self._entries),
				"truncated_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("truncated")
				],
				"descriptor_suppressed_size": sum(
					entry.get("descriptor_suppressed_size", 0)
					for entry in self._entries
				),
				"descriptor_suppressed_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("descriptor_suppressed_size")
				],
				"raw_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("access") == RAW
				],
				"exported_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("access") == RAW
				],
				"summary_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("access") == PAGE_SUMMARY
				],
				"suppressed_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("access") == PAGE_SUMMARY
				],
				"redacted_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("access") == PAGE_SUMMARY
				],
				"unmapped_ranges": [
					entry["index"]
					for entry in self._entries
					if entry.get("unmapped")
				],
				"range_explanations": [
					{
						"index": entry["index"],
						"start": entry["start"],
						"end": entry["end"],
						"explanations": list(entry.get("explanations", [])),
					}
					for entry in self._entries
					if entry.get("explanations")
				],
				"mapping_sources": self._collect_mapping_sources(self._entries),
				"explanations": [
					explanation
					for entry in self._entries
					for explanation in entry.get("explanations", [])
				],
			}
		)
		self._manifest = {
			"schema": EVIDENCE_SCHEMA,
			"schema_version": 1,
			"created_at": self._receipt["created_at"],
			"ticket": self.policy.ticket_id,
			"ticket_id": self.policy.ticket_id,
			"approval": self.policy.ticket_id,
			"approval_ticket": (
				self.ticket.to_dict() if self.ticket else None
			),
			"policy": self.policy.to_dict(),
			"ranges": [
				item.to_dict() for item in self.policy.ranges
			],
			"source": copy.deepcopy(self._source_meta),
			"source_sha256": self._source_meta.get("sha256"),
			"source_size": self._source_meta.get("size"),
			"pointer_size": self._pointer_size,
			"is_fulldump": self._is_fulldump,
			"range_count": len(self._entries),
			"redacted": any(
				entry.get("access") == PAGE_SUMMARY for entry in self._entries
			),
			"has_redactions": any(
				entry.get("access") == PAGE_SUMMARY for entry in self._entries
			),
			"exported_size": sum(
				entry.get("exported_size", 0) for entry in self._entries
			),
			"suppressed_size": sum(
				entry.get("suppressed_size", 0) for entry in self._entries
			),
			"descriptor_suppressed_size": sum(
				entry.get("descriptor_suppressed_size", 0)
				for entry in self._entries
			),
			"summary_ranges": [
				entry["index"]
				for entry in self._entries
				if entry.get("access") == PAGE_SUMMARY
			],
			"redactions": [
				item.to_dict() for item in self.page_summary_ranges
			],
			"suppressed_ranges": [
				entry["index"]
				for entry in self._entries
				if entry.get("access") == PAGE_SUMMARY
			],
			"truncated_ranges": [
				entry["index"]
				for entry in self._entries
				if entry.get("truncated")
			],
			"unmapped_ranges": [
				entry["index"]
				for entry in self._entries
				if entry.get("unmapped")
			],
			"sysinfo": copy.deepcopy(self._sysinfo),
			"modules": copy.deepcopy(self._modules),
			"entries": copy.deepcopy(self._entries),
			"raw_layout": raw_layout,
			"address_map": copy.deepcopy(raw_layout),
			"mapping_sources": self._collect_mapping_sources(self._entries),
			"provenance": self._collect_mapping_sources(self._entries),
			"receipt": self._receipt.to_dict(),
			"threads": [item.to_dict() for item in self._threads],
			"custody": [],
		}
		self._integrity = {
			"algorithm": "sha256",
			"digest": _sha256(_canonical_json(copy.deepcopy(self._manifest))),
		}
		self._detached = False

	def _coerce_minidump(self, source):
		if hasattr(source, "memory_segments") and hasattr(source, "file_handle"):
			return source
		if hasattr(source, "read") and hasattr(source, "seek"):
			from minidump.minidumpfile import MinidumpFile

			return MinidumpFile.parse_external(source, getattr(source, "name", ""))
		if hasattr(source, "reader") and hasattr(source.reader, "file_handle"):
			return source.reader
		raise EvidenceError(
			"source must be a minidump path, bytes, file handle, "
			"MinidumpFile or MinidumpFileReader"
		)

	def _detect_pointer_size(self, mf):
		sysinfo = getattr(mf, "sysinfo", None)
		arch = getattr(sysinfo, "ProcessorArchitecture", None)
		try:
			if int(getattr(arch, "value", arch)) in (9, 12):
				return 8
			if int(getattr(arch, "value", arch)) in (0, 5):
				return 4
		except Exception:
			pass
		return getattr(mf, "sizeof_ptr", 8) or 8

	def _snapshot_sysinfo(self, mf):
		sysinfo = getattr(mf, "sysinfo", None)
		if sysinfo is None:
			return None
		payload = {}
		for key in (
			"ProcessorArchitecture",
			"ProcessorLevel",
			"ProcessorRevision",
			"NumberOfProcessors",
			"ProductType",
			"MajorVersion",
			"MinorVersion",
			"BuildNumber",
			"PlatformId",
			"SuiteMask",
			"OperatingSystem",
		):
			if hasattr(sysinfo, key):
				value = getattr(sysinfo, key)
				payload[key] = (
					getattr(value, "value", value)
					if not isinstance(value, (str, int, float, bool, type(None)))
					else value
				)
		return _AttrDict(payload)

	def _snapshot_modules(self, mf):
		modules = getattr(mf, "modules", None)
		if modules is None:
			return []
		result = []
		for module in getattr(modules, "modules", modules):
			result.append(
				_AttrDict(
					{
						"name": getattr(module, "name", None),
					"baseaddress": getattr(module, "baseaddress", None),
					"endaddress": getattr(module, "endaddress", None),
					"size": getattr(module, "size", None),
						"timestamp": getattr(module, "timestamp", None),
					}
				)
			)
		return result

	def _find_directory(self, mf, stream_type):
		for directory in getattr(mf, "directories", []) or []:
			if getattr(directory.StreamType, "value", directory.StreamType) == stream_type:
				return directory
		return None

	def _collect_sources(self, mf):
		sources = []
		memory64 = getattr(mf, "memory_segments_64", None)
		memory32 = getattr(mf, "memory_segments", None)
		memory64_segments = getattr(memory64, "memory_segments", memory64)
		memory32_segments = getattr(memory32, "memory_segments", memory32)
		if memory64 is not None:
			directory = self._find_directory(mf, 9)
			stream_rva = directory.Location.Rva if directory else None
			stream_size = directory.Location.DataSize if directory else None
			for index, segment in enumerate(memory64_segments or []):
				sources.append(
					_MemorySource(
						segment.start_virtual_address,
						segment.end_virtual_address,
						segment.start_file_address,
						"Memory64ListStream",
						9,
						stream_rva,
						stream_size,
						index,
						priority=0,
					)
				)
		elif memory32_segments is not None:
			full_dump = bool(getattr(mf, "is_fulldump", False))
			stream_type = 9 if full_dump else 5
			stream_name = (
				"Memory64ListStream" if full_dump else "MemoryListStream"
			)
			directory = self._find_directory(mf, stream_type)
			stream_rva = directory.Location.Rva if directory else None
			stream_size = directory.Location.DataSize if directory else None
			for index, segment in enumerate(memory32_segments):
				sources.append(
					_MemorySource(
						segment.start_virtual_address,
						segment.end_virtual_address,
						segment.start_file_address,
						stream_name,
						stream_type,
						stream_rva,
						stream_size,
						index,
						priority=1,
					)
				)
		if memory32_segments is not None and memory64 is not None:
			# A MinidumpFile can technically carry both streams.  Include the
			# legacy stream as secondary provenance.
			directory = self._find_directory(mf, 5)
			for index, segment in enumerate(memory32_segments):
				sources.append(
					_MemorySource(
						segment.start_virtual_address,
						segment.end_virtual_address,
						segment.start_file_address,
						"MemoryListStream",
						5,
						directory.Location.Rva if directory else None,
						directory.Location.DataSize if directory else None,
						index,
						priority=2,
					)
				)

		seen = set()
		unique = []
		for item in sorted(
			sources,
			key=lambda s: (s.start, s.priority, s.stream, s.descriptor_index or 0),
		):
			key = (item.start, item.end, item.file_rva)
			if key in seen:
				continue
			seen.add(key)
			unique.append(item)
		sources = unique

		sources.extend(self._thread_sources(mf, "threads", "ThreadListStream", 3, 5))
		sources.extend(
			self._thread_sources(mf, "threads_ex", "ThreadExListStream", 8, 6)
		)
		return sorted(
			sources,
			key=lambda s: (s.start, s.end, s.priority, s.stream, s.descriptor_index or 0),
		)

	def _thread_sources(self, mf, attribute, stream, stream_type, priority):
		thread_list = getattr(mf, attribute, None)
		if thread_list is None:
			return []
		directory = self._find_directory(mf, stream_type)
		result = []
		for index, thread in enumerate(getattr(thread_list, "threads", []) or []):
			for label in ("Stack", "BackingStore"):
				descriptor = getattr(thread, label, None)
				if descriptor is None:
					continue
				start = getattr(descriptor, "StartOfMemoryRange", None)
				size = getattr(descriptor, "DataSize", None)
				rva = getattr(descriptor, "Rva", None)
				if start is None or not size or rva is None:
					continue
				result.append(
					_MemorySource(
						start,
						start + size,
						rva,
						stream,
						stream_type,
						directory.Location.Rva if directory else None,
						directory.Location.DataSize if directory else None,
						index,
						origin="thread_%s" % label.lower(),
						thread_id=getattr(thread, "ThreadId", None),
						thread_index=index,
						priority=priority,
					)
				)
		return result

	def _coverage_pieces(self, start, end, sources=None):
		if sources is None:
			sources = getattr(self, "_active_sources", [])
		points = {start, end}
		relevant = []
		for source in sources:
			if source.start < end and start < source.end:
				left = max(source.start, start)
				right = min(source.end, end)
				points.add(left)
				points.add(right)
				relevant.append(source)
		ordered = sorted(points)
		result = []
		for left, right in zip(ordered, ordered[1:]):
			coverings = [
				source
				for source in relevant
				if source.start <= left and right <= source.end
			]
			primary = min(
				coverings,
				key=lambda item: (
					item.priority,
					item.stream,
					item.descriptor_index or 0,
				),
			) if coverings else None
			result.append(
				{
					"start": left,
					"end": right,
					"primary": primary,
					"coverings": coverings,
				}
			)
		return result

	def _read_source(self, handle, source, start, end):
		if source is None or start >= end:
			return b""
		offset = source.file_rva + (start - source.start)
		data = self._read_handle(handle, offset, end - start)
		return data or b""

	def _module_for(self, address):
		for module in self._modules:
			base = module.get("baseaddress")
			module_end = module.get("endaddress")
			if base is None:
				continue
			if module_end is None and module.get("size") is not None:
				module_end = base + module["size"]
			if module_end is not None and base <= address < module_end:
				return module
		return None

	def _memory_info_for(self, address):
		memory_info = getattr(self, "_memory_info", None)
		if not memory_info:
			return None
		for entry in memory_info:
			base = getattr(entry, "BaseAddress", None)
			size = getattr(entry, "RegionSize", None)
			if base is not None and size is not None and base <= address < base + size:
				payload = {}
				for key in (
					"BaseAddress",
					"AllocationBase",
					"AllocationProtect",
					"RegionSize",
					"State",
					"Protect",
					"Type",
				):
					if hasattr(entry, key):
						value = getattr(entry, key)
						payload[key] = getattr(value, "value", value)
				return payload
		return None

	def _mappings_for_piece(self, piece):
		mappings = []
		for source in piece["coverings"]:
			mappings.append(
				source.mapping(
					module=self._module_for(piece["start"]),
					memory_info=self._memory_info_for(piece["start"]),
				)
			)
		return mappings

	def _build_entry(self, index, item, sources, handle):
		self._active_sources = sources
		self._memory_info = getattr(
			getattr(getattr(self, "_minidump", None), "memory_info", None),
			"entries",
			None,
		)
		coverage = self._coverage_pieces(item.start, item.end, sources=sources)
		covered = sum(
			piece["end"] - piece["start"]
			for piece in coverage
			if piece["primary"] is not None
		)
		entry = {
			"index": index,
			"range": item.to_dict(),
			"original_address": item.start,
			"original_end": item.end,
			"original_size": item.size,
			"address": item.start,
			"start_address": item.start,
			"end_address": item.end,
			"length": item.size,
			"start": item.start,
			"end": item.end,
			"size": item.size,
			"access": item.access,
			"mode": item.access,
			"disclosure": item.access,
			"redaction": (
				PAGE_SUMMARY if item.access == PAGE_SUMMARY else None
			),
			"redacted": item.access == PAGE_SUMMARY,
			"raw_exported": item.access == RAW,
			"ticket": item.ticket,
			"approval": item.ticket,
			"approval_ticket": (
				item.approval_ticket.to_dict() if item.approval_ticket else None
			),
			"label": item.label,
			"page_size": item.page_size or self._page_size,
			"authorized": True,
			"explanations": [],
			"raw_chunks": [],
			"pages": [],
			"page_count": 0,
			"unmapped": covered == 0,
		}
		if item.access == RAW:
			entry["status"] = "raw" if covered == item.size else "truncated"
			entry["exported_size"] = covered
			entry["suppressed_size"] = item.size - covered
			entry["sha256"] = None
			digest = hashlib.sha256()
			for piece in coverage:
				source = piece["primary"]
				if source is None:
					entry["explanations"].append(
						"Approved raw range 0x%x-0x%x has a descriptor gap at "
						"0x%x-0x%x; those bytes are withheld."
						% (item.start, item.end, piece["start"], piece["end"])
					)
					continue
				data = self._read_source(
					handle, source, piece["start"], piece["end"]
				)
				actual_end = piece["start"] + len(data)
				if actual_end < piece["end"]:
					entry["explanations"].append(
						"Memory descriptor at RVA 0x%x supplied only %d of %d "
						"approved bytes starting at 0x%x; the short tail is "
						"descriptor-suppressed."
						% (
							source.file_rva,
							len(data),
							piece["end"] - piece["start"],
							piece["start"],
						)
					)
				if not data:
					continue
				mappings = self._mappings_for_piece(piece)
				chunk = {
					"original_address": piece["start"],
					"original_end": actual_end,
					"start": piece["start"],
					"end": actual_end,
					"size": len(data),
					"data_b64": base64.b64encode(data).decode("ascii"),
					"sha256": _sha256(data),
					"stream": mappings[0].get("stream") if mappings else None,
					"file_rva": mappings[0].get("file_rva") if mappings else None,
					"descriptor_index": (
						mappings[0].get("descriptor_index") if mappings else None
					),
					"mapping_source": copy.deepcopy(mappings[0]) if mappings else None,
					"mapping_sources": mappings,
				}
				entry["raw_chunks"].append(chunk)
				digest.update(data)
			entry["exported_size"] = sum(
				chunk["size"] for chunk in entry["raw_chunks"]
			)
			entry["suppressed_size"] = item.size - entry["exported_size"]
			entry["descriptor_suppressed_size"] = entry["suppressed_size"]
			if entry["raw_chunks"]:
				entry["sha256"] = digest.hexdigest()
			if entry["suppressed_size"]:
				entry["status"] = "truncated"
				entry["explanations"].append(
					"Approved raw range 0x%x-0x%x exported %d of %d bytes; "
					"%d bytes were descriptor-suppressed and are not present "
					"in the handoff."
					% (
						item.start,
						item.end,
						entry["exported_size"],
						item.size,
						entry["suppressed_size"],
					)
				)
			if len(entry["raw_chunks"]) > 1:
				entry["explanations"].append(
					"Approved raw range 0x%x-0x%x spans %d minidump memory "
					"descriptors; every chunk retains its original virtual "
					"address and file RVA."
					% (item.start, item.end, len(entry["raw_chunks"]))
				)
		else:
			pages = self._build_pages(item, sources, handle)
			entry["pages"] = [page.to_dict() for page in pages]
			entry["page_count"] = len(pages)
			entry["exported_size"] = 0
			entry["suppressed_size"] = item.size
			entry["descriptor_suppressed_size"] = item.size - sum(
				page.get("covered_size", 0) for page in pages
			)
			entry["sha256"] = None
			entry["status"] = (
				"page_summary"
				if all(page.get("complete", False) for page in pages)
				else "page_summary_truncated"
			)
			entry["explanations"].append(
				"Approved range 0x%x-0x%x is page-summary only under ticket "
				"%s; raw bytes are withheld and only %d page summaries are "
				"exported."
				% (item.start, item.end, item.ticket, len(pages))
			)
			incomplete = sum(
				1 for page in pages if not page.get("complete", False)
			)
			if incomplete:
				entry["explanations"].append(
					"%d page summaries are incomplete because the minidump "
					"memory descriptors do not cover their full approved "
					"span; those bytes are descriptor-suppressed."
					% incomplete
				)
		entry["raw_chunk_count"] = len(entry.get("raw_chunks", []))
		entry["exported_address"] = (
			item.start if item.access == RAW and entry.get("raw_chunks") else None
		)
		entry["mapping_sources"] = self._collect_entry_mappings(entry)
		entry["mapping_source"] = (
			copy.deepcopy(entry["mapping_sources"][0])
			if entry["mapping_sources"]
			else None
		)
		entry["mapping"] = copy.deepcopy(entry["mapping_source"])
		entry["provenance"] = copy.deepcopy(entry["mapping_sources"])
		primary_mapping = entry["mapping_source"] or {}
		entry["stream"] = primary_mapping.get("stream")
		entry["stream_rva"] = primary_mapping.get("stream_rva")
		entry["stream_size"] = primary_mapping.get("stream_size")
		entry["stream_type"] = primary_mapping.get("stream_type")
		entry["stream_type_name"] = primary_mapping.get("stream_type_name")
		entry["file_rva"] = primary_mapping.get("file_rva")
		entry["rva"] = primary_mapping.get("rva")
		entry["start_file_address"] = primary_mapping.get(
			"start_file_address"
		)
		entry["descriptor_index"] = primary_mapping.get("descriptor_index")
		entry["module_name"] = primary_mapping.get("module_name")
		entry["module_base"] = primary_mapping.get("module_base")
		entry["module_offset"] = primary_mapping.get("module_offset")
		entry["memory_info"] = primary_mapping.get("memory_info")
		entry["thread_id"] = primary_mapping.get("thread_id")
		entry["thread_index"] = primary_mapping.get("thread_index")
		entry["origin"] = primary_mapping.get("origin")
		entry["explanation"] = " ".join(entry["explanations"])
		entry["truncated"] = entry["status"] in (
			"truncated",
			"page_summary_truncated",
			"unmapped",
		)
		return entry

	def _collect_entry_mappings(self, entry):
		found = []
		for chunk in entry.get("raw_chunks", []):
			for mapping in chunk.get("mapping_sources", []):
				if mapping not in found:
					found.append(copy.deepcopy(mapping))
		for page in entry.get("pages", []):
			for mapping in page.get("mapping_sources", []):
				if mapping not in found:
					found.append(copy.deepcopy(mapping))
		return found

	def _collect_mapping_sources(self, entries):
		found = []
		for entry in entries:
			for mapping in self._collect_entry_mappings(entry):
				if mapping not in found:
					found.append(copy.deepcopy(mapping))
		return found

	def _build_pages(self, item, sources, handle):
		page_size = item.page_size or self._page_size
		first = item.start - (item.start % page_size)
		pages = []
		page_index = 0
		while first < item.end:
			page_start = max(first, item.start)
			page_end = min(first + page_size, item.end)
			coverage = self._coverage_pieces(
				page_start, page_end, sources=sources
			)
			digest = hashlib.sha256()
			covered = 0
			mappings = []
			segments = []
			complete = True
			for piece in coverage:
				source = piece["primary"]
				if source is None:
					complete = False
					continue
				data = self._read_source(
					handle, source, piece["start"], piece["end"]
				)
				actual_end = piece["start"] + len(data)
				if actual_end < piece["end"]:
					complete = False
				if not data:
					continue
				digest.update(data)
				covered += len(data)
				piece_mappings = self._mappings_for_piece(piece)
				for mapping in piece_mappings:
					if mapping not in mappings:
						mappings.append(copy.deepcopy(mapping))
				segments.append(
					{
						"start": piece["start"],
						"end": actual_end,
						"size": len(data),
						"sha256": _sha256(data),
						"stream": (
							piece_mappings[0].get("stream") if piece_mappings else None
						),
						"file_rva": (
							piece_mappings[0].get("file_rva") if piece_mappings else None
						),
						"descriptor_index": (
							piece_mappings[0].get("descriptor_index")
							if piece_mappings
							else None
						),
						"mapping_source": (
							copy.deepcopy(piece_mappings[0])
							if piece_mappings
							else None
						),
					}
				)
			page = EvidencePageSummary(
				{
					"page_index": page_index,
					"page_start": first,
					"page_end": first + page_size,
					"start": page_start,
					"end": page_end,
					"size": page_end - page_start,
					"page_size": page_size,
					"covered_size": covered,
					"complete": complete and covered == (page_end - page_start),
					"sha256": digest.hexdigest() if covered else None,
					"segments": segments,
					"mapping_source": (
						copy.deepcopy(mappings[0]) if mappings else None
					),
					"mapping_sources": mappings,
					"ticket": item.ticket,
					"access": PAGE_SUMMARY,
					"redacted": True,
				}
			)
			pages.append(page)
			first += page_size
			page_index += 1
		return pages

	def _snapshot_threads(self, mf):
		result = []
		for attribute in ("threads", "threads_ex"):
			thread_list = getattr(mf, attribute, None)
			if thread_list is None:
				continue
			for index, thread in enumerate(getattr(thread_list, "threads", []) or []):
				stack = getattr(thread, "Stack", None)
				stack_start = getattr(stack, "StartOfMemoryRange", None)
				stack_size = getattr(stack, "DataSize", None)
				context = getattr(thread, "ContextObject", None)
				rsp = getattr(context, "Rsp", getattr(context, "Esp", None))
				rip = getattr(context, "Rip", getattr(context, "Eip", None))
				context_location = getattr(thread, "ThreadContext", None)
				payload = {
					"thread_id": getattr(thread, "ThreadId", None),
					"thread_index": index,
					"teb": getattr(thread, "Teb", None),
					"stack_address": stack_start,
					"stack_end_address": (
						stack_start + stack_size
						if stack_start is not None and stack_size is not None
						else None
					),
					"stack_size": stack_size,
					"stack_file_rva": getattr(stack, "Rva", None),
					"context_rva": getattr(context_location, "Rva", None),
					"context_size": getattr(context_location, "DataSize", None),
					"rsp": rsp,
					"rip": rip,
					"Rsp": rsp,
					"RIP": rip,
					"stream": (
						"ThreadListStream"
						if attribute == "threads"
						else "ThreadExListStream"
					),
				}
				result.append(EvidenceThread(payload, view=self))
		return result

	def _receipt_entry(self, entry):
		payload = copy.deepcopy(entry)
		chunks = payload.pop("raw_chunks", [])
		payload["raw_chunks"] = [
			{
				key: copy.deepcopy(chunk[key])
				for key in chunk
				if key != "data_b64"
			}
			for chunk in chunks
		]
		payload["exported_size"] = sum(chunk["size"] for chunk in chunks)
		payload["pages"] = copy.deepcopy(payload.get("pages", []))
		payload["redacted"] = entry["access"] == PAGE_SUMMARY
		payload["raw_exported"] = entry["access"] == RAW
		return EvidenceReceiptEntry(payload)

	# ------------------------------------------------------------------
	# Handles, digests and source verification
	# ------------------------------------------------------------------

	def _read_handle(self, handle, offset, size):
		with self._io_lock:
			position = None
			try:
				position = handle.tell()
			except Exception:
				pass
			try:
				handle.seek(offset, 0)
				return handle.read(size)
			finally:
				if position is not None:
					try:
						handle.seek(position, 0)
					except Exception:
						pass

	def _handle_size(self, handle):
		with self._io_lock:
			position = None
			try:
				position = handle.tell()
			except Exception:
				pass
			try:
				handle.seek(0, 2)
				return handle.tell()
			finally:
				if position is not None:
					try:
						handle.seek(position, 0)
					except Exception:
						pass

	def _handle_digest(self, handle):
		with self._io_lock:
			position = None
			try:
				position = handle.tell()
			except Exception:
				pass
			try:
				handle.seek(0, 0)
				digest = hashlib.sha256()
				while True:
					chunk = handle.read(1024 * 1024)
					if not chunk:
						break
					digest.update(chunk)
				return digest.hexdigest()
			finally:
				if position is not None:
					try:
						handle.seek(position, 0)
					except Exception:
						pass

	# ------------------------------------------------------------------
	# Restricted reads
	# ------------------------------------------------------------------

	def _policy_range_at(self, address):
		return self.policy.range_at(address)

	def _next_range(self, address):
		return self.policy.next_range(address)

	def _raw_interval_at(self, address):
		for interval in self._raw_intervals:
			if interval.start <= address < interval.end:
				return interval
		return None

	def _read_raw(self, start, end):
		data = bytearray()
		cursor = start
		pieces = []
		while cursor < end:
			interval = self._raw_interval_at(cursor)
			if interval is None:
				break
			chunk_end = min(end, interval.end)
			chunk = interval.slice(cursor, chunk_end)
			if not chunk:
				break
			data.extend(chunk)
			pieces.append(
				{
					"start": cursor,
					"end": cursor + len(chunk),
					"size": len(chunk),
					"sha256": _sha256(chunk),
					"entry_index": interval.entry_index,
					"mapping_source": (
						copy.deepcopy(interval.mapping_sources[0])
						if interval.mapping_sources
						else None
					),
					"mapping_sources": copy.deepcopy(interval.mapping_sources),
				}
			)
			cursor += len(chunk)
			if cursor < chunk_end:
				break
		return bytes(data), pieces, cursor

	def _summary_for(self, entry_index, start, end):
		result = []
		for page in self._summary_pages.get(entry_index, []):
			if page["start"] < end and start < page["end"]:
				item = EvidencePageSummary(page.to_dict())
				item["requested_start"] = start
				item["requested_end"] = end
				item["clipped"] = not (
					page["start"] >= start and page["end"] <= end
				)
				result.append(item)
		return result

	def _resolve_read(self, address, size):
		requested_end = address + size
		raw = bytearray()
		summaries = []
		explanations = []
		read_ranges = []
		unauthorized = []
		cursor = address
		raw_end = address
		summary_end = address
		summary_size = 0
		descriptor_suppressed_size = 0

		while cursor < requested_end:
			index, item = self._policy_range_at(cursor)
			if item is None:
				next_index, next_item = self._next_range(cursor)
				gap_end = (
					min(next_item.start, requested_end)
					if next_item is not None
					else requested_end
				)
				unauthorized.append(
					{
						"original_address": cursor,
						"original_end": gap_end,
						"start": cursor,
						"end": gap_end,
						"size": gap_end - cursor,
						"reason": "outside_approved_ranges",
					}
				)
				if gap_end > cursor:
					explanations.append(
						"Requested span 0x%x-0x%x is outside every approved "
						"range; %d bytes from 0x%x were withheld."
						% (
							address,
							requested_end,
							gap_end - cursor,
							cursor,
						)
					)
				break

			limit = min(requested_end, item.end)
			if item.access == PAGE_SUMMARY:
				pages = self._summary_for(index, cursor, limit)
				summaries.extend(pages)
				summary_size += limit - cursor
				page_descriptor_missing = sum(
					page.get("size", 0) - page.get("covered_size", 0)
					for page in pages
				)
				descriptor_suppressed_size += page_descriptor_missing
				if page_descriptor_missing:
					explanations.append(
						"%d bytes in page summaries 0x%x-0x%x are "
						"descriptor-suppressed because minidump memory "
						"descriptors do not cover them."
						% (page_descriptor_missing, cursor, limit)
					)
				summary_end = limit
				read_ranges.append(
					{
						"index": index,
						"original_address": cursor,
						"original_end": limit,
						"start": cursor,
						"end": limit,
						"size": limit - cursor,
						"access": PAGE_SUMMARY,
						"ticket": item.ticket,
						"status": "page_summary",
						"sha256": None,
						"complete": all(
							page.get("complete", False) for page in pages
						),
						"descriptor_suppressed_size": page_descriptor_missing,
						"pages": [page.to_dict() for page in pages],
						"mapping_sources": self._collect_page_mappings(pages),
						"mapping_source": (
							self._collect_page_mappings(pages)[0]
							if self._collect_page_mappings(pages)
							else None
						),
					}
				)
				if not raw:
					explanations.append(
						"Range 0x%x-0x%x is approved for page summaries only; "
						"%d requested bytes were described by %d page "
						"summaries and no raw bytes were returned."
						% (
							cursor,
							limit,
							limit - cursor,
							len(pages),
						)
					)
				else:
					explanations.append(
						"Read returned the raw prefix 0x%x-0x%x and stopped "
						"at 0x%x, where the approved range becomes "
						"page-summary only; the remaining %d bytes are "
						"described by page summaries instead of raw data."
						% (
							address,
							cursor,
							cursor,
							requested_end - cursor,
						)
					)
				cursor = limit
				if cursor >= requested_end:
					break
				_next_index, next_item = self._policy_range_at(cursor)
				if next_item is not None and next_item.access == RAW:
					explanations.append(
						"Read stopped at 0x%x after the page-summary span; "
						"%d remaining bytes belong to a raw range but are not "
						"returned after a summary-only span."
						% (cursor, requested_end - cursor)
					)
					break
				continue

			data, pieces, available_end = self._read_raw(cursor, limit)
			raw_descriptor_missing = max(0, limit - available_end)
			descriptor_suppressed_size += raw_descriptor_missing
			if data:
				raw.extend(data)
				raw_end = available_end
				read_ranges.append(
					{
						"index": index,
						"original_address": cursor,
						"original_end": available_end,
						"start": cursor,
						"end": available_end,
						"size": available_end - cursor,
						"access": RAW,
						"ticket": item.ticket,
						"status": "raw",
						"sha256": _sha256(data) if data else None,
						"descriptor_suppressed_size": raw_descriptor_missing,
						"chunks": pieces,
						"mapping_sources": self._collect_chunk_mappings(pieces),
						"mapping_source": (
							self._collect_chunk_mappings(pieces)[0]
							if self._collect_chunk_mappings(pieces)
							else None
						),
					}
				)
			if available_end < limit:
				unauthorized.append(
					{
						"original_address": available_end,
						"original_end": limit,
						"start": available_end,
						"end": limit,
						"size": limit - available_end,
						"reason": "descriptor_coverage_ends",
						"ticket": item.ticket,
					}
				)
				explanations.append(
					"Read stopped at 0x%x because minidump memory descriptors "
					"cover only up to 0x%x of the approved range ending at "
					"0x%x; %d descriptor-suppressed bytes were withheld."
					% (
						available_end,
						available_end,
						limit,
						limit - available_end,
					)
				)
				cursor = available_end
				break
			cursor = limit
			raw_end = limit
			if cursor >= requested_end:
				break

		if raw and summaries:
			mode = "mixed"
		elif raw:
			mode = RAW
		elif summaries:
			mode = PAGE_SUMMARY
		else:
			mode = "denied"

		covered_end = max(raw_end, summary_end)
		if mode == PAGE_SUMMARY:
			truncated = summary_end < requested_end
		else:
			truncated = covered_end < requested_end or bool(summaries)
		denied = not raw and not summaries
		suppressed = bool(summaries)
		if mode == "page_summary" and covered_end >= requested_end and not raw:
			truncated = False
		if descriptor_suppressed_size:
			truncated = True

		if mode == RAW and not explanations:
			explanations = [
				"Read 0x%x-0x%x is fully covered by approved raw range(s)."
				% (address, requested_end)
			]
		if mode == "denied" and not explanations:
			explanations.append(
				"Requested span 0x%x-0x%x is not covered by any approved "
				"range." % (address, requested_end)
			)

		receipt_status = mode
		if truncated and mode == RAW:
			receipt_status = "truncated"
		elif truncated and mode == PAGE_SUMMARY:
			receipt_status = "page_summary_truncated"
		receipt = EvidenceReceipt(
			{
				"kind": "read",
				"requested_address": address,
				"requested_size": size,
				"returned_address": address if raw else None,
				"returned_size": len(raw),
				"covered_end": covered_end,
				"status": receipt_status,
				"mode": mode,
				"truncated": truncated,
				"suppressed": suppressed,
				"descriptor_suppressed": bool(descriptor_suppressed_size),
				"descriptor_suppressed_size": descriptor_suppressed_size,
				"denied": denied,
				"ticket": self.policy.ticket_id,
				"ticket_id": self.policy.ticket_id,
				"approval": self.policy.ticket_id,
				"ranges": read_ranges,
				"mapping_sources": [
					mapping
					for item in read_ranges
					for mapping in item.get("mapping_sources", [])
				],
				"raw_ranges": [
					{
						"start": item["start"],
						"end": item["end"],
						"access": item["access"],
						"ticket": item.get("ticket"),
						"mapping_source": item.get("mapping_source"),
					}
					for item in read_ranges
					if item.get("access") == RAW
				],
				"suppressed_ranges": [
					{
						"start": item["start"],
						"end": item["end"],
						"access": item["access"],
						"ticket": item.get("ticket"),
						"mapping_source": item.get("mapping_source"),
					}
					for item in read_ranges
					if item.get("access") == PAGE_SUMMARY
				],
				"redacted_ranges": [
					{
						"start": item["start"],
						"end": item["end"],
						"access": item["access"],
						"ticket": item.get("ticket"),
						"mapping_source": item.get("mapping_source"),
					}
					for item in read_ranges
					if item.get("access") == PAGE_SUMMARY
				],
				"truncated_ranges": list(unauthorized),
				"range_explanations": [
					{
						"index": item.get("index"),
						"start": item.get("start"),
						"end": item.get("end"),
						"status": item.get("status"),
					}
					for item in read_ranges
				],
				"descriptor_suppressed_ranges": [
					{
						"start": item["start"],
						"end": item["end"],
						"size": item.get("descriptor_suppressed_size", 0),
					}
					for item in read_ranges
					if item.get("descriptor_suppressed_size")
				],
				"source": copy.deepcopy(self._source_meta),
				"source_sha256": self._source_meta.get("sha256"),
				"source_size": self._source_meta.get("size"),
				"policy": self.policy.to_dict(),
				"unauthorized_ranges": unauthorized,
				"explanations": list(explanations),
				"explanation": " ".join(explanations),
			}
		)
		return EvidenceReadResult(
			bytes(raw),
			mode=mode,
			address=address,
			size=size,
			covered_end=covered_end,
			summary=summaries,
			truncated=truncated,
			denied=denied,
			suppressed=suppressed,
			descriptor_suppressed_size=descriptor_suppressed_size,
			receipt=receipt,
			explanations=explanations,
		)

	@staticmethod
	def _collect_page_mappings(pages):
		result = []
		for page in pages:
			for mapping in page.get("mapping_sources", []):
				if mapping not in result:
					result.append(copy.deepcopy(mapping))
		return result

	@staticmethod
	def _collect_chunk_mappings(chunks):
		result = []
		for chunk in chunks:
			for mapping in chunk.get("mapping_sources", []):
				if mapping not in result:
					result.append(copy.deepcopy(mapping))
		return result

	def read(self, address, size=None, strict=False, truncate=True):
		address = _as_int(address, "read address")
		if size is None:
			index, item = self._policy_range_at(address)
			size = item.end - address if item is not None else 0
		else:
			size = _as_int(size, "read size")
		if size == -1:
			index, item = self._policy_range_at(address)
			size = item.end - address if item is not None else 0
		if size < 0:
			raise EvidencePolicyError("read size must be non-negative or -1")
		if size == 0:
			index, item = self._policy_range_at(address)
			allowed = item is not None
			mode = item.access if allowed else "denied"
			suppressed = False
			explanations = [
				"Zero-length read at 0x%x." % address
			]
			receipt = EvidenceReceipt(
				{
					"kind": "read",
					"requested_address": address,
					"requested_size": 0,
					"returned_address": address if allowed else None,
					"returned_size": 0,
					"covered_end": address,
					"status": mode,
					"mode": mode,
					"truncated": False,
					"suppressed": suppressed,
					"descriptor_suppressed": False,
					"descriptor_suppressed_size": 0,
					"denied": not allowed,
					"ticket": self.policy.ticket_id,
					"ticket_id": self.policy.ticket_id,
					"approval": self.policy.ticket_id,
					"ranges": [],
					"unauthorized_ranges": [],
					"explanations": explanations,
					"explanation": " ".join(explanations),
				}
			)
			return EvidenceReadResult(
				b"",
				mode=mode,
				address=address,
				size=0,
				covered_end=address,
				summary=[],
				truncated=False,
				denied=not allowed,
				suppressed=suppressed,
				receipt=receipt,
				explanations=explanations,
			)
		result = self._resolve_read(address, size)
		if (strict or not truncate) and (
			result.denied or result.truncated or result.suppressed
		):
			raise EvidenceAccessDenied(
				"read 0x%x+0x%x violates the evidence policy: %s"
				% (address, size, result.explanation or result.status),
				address=address,
				size=size,
				result=result,
			)
		return result

	def read_at(self, address, size):
		return self.read(address, size)

	def read_exact(self, address, size):
		return self.read(address, size, strict=True)

	def read_bytes(self, address, size=None):
		return self.read(address, size, strict=True)

	def try_read(self, address, size=None):
		return self.read(address, size)

	def summarize(self, address, size):
		result = self.read(address, size, strict=False)
		return result.summary

	def range_at(self, address):
		return self.policy.get_range(address)

	def contains(self, address):
		return self.range_at(address) is not None

	inrange = contains

	def authorization(self, address, size=1):
		return self.policy.authorization(address, size)

	def is_authorized(self, address, size=1):
		return self.authorization(address, size)["fully_covered"]

	is_allowed = is_authorized
	authorized = is_authorized
	allowed = is_authorized

	def page_summaries(self, address, size):
		return self.summarize(address, size)

	def explain(self, address, size=1):
		return self.read(address, size).explanations

	def remaining(self, address):
		index, item = self._policy_range_at(address)
		if item is None:
			return 0
		return item.end - address

	# ------------------------------------------------------------------
	# Readers, segments and threads
	# ------------------------------------------------------------------

	@property
	def memory_segments(self):
		if self._memory_segment_cache is None:
			self._memory_segment_cache = []
			for index, item in enumerate(self.ranges):
				mappings = []
				for raw in self._raw_intervals:
					if raw.entry_index == index:
						mappings.extend(raw.mapping_sources)
						if mappings:
							break
				if not mappings:
					for page in self._summary_pages.get(index, []):
						mappings.extend(page.get("mapping_sources", []))
						if mappings:
							break
				source = None
				if mappings:
					mapping = mappings[0]
					mapping_start = mapping.get("start", item.start)
					file_rva = mapping.get("file_rva")
					if file_rva is not None:
						file_rva += item.start - mapping_start
					source = _MemorySource(
						item.start,
						item.end,
						file_rva,
						mapping.get("stream"),
						mapping.get("stream_type"),
						mapping.get("stream_rva"),
						mapping.get("stream_size"),
						mapping.get("descriptor_index"),
					)
				self._memory_segment_cache.append(
					EvidenceMemorySegment(self, item, source=source)
				)
		return list(self._memory_segment_cache)

	@property
	def memory(self):
		return self.memory_segments

	def get_memory(self):
		return self.memory_segments

	def get_handler(self):
		return None

	def get_file_handle(self):
		return None

	def close(self):
		return None

	@property
	def reader(self):
		return self.get_reader()

	@property
	def buffered_reader(self):
		return self.get_buffered_reader()

	def get_module_by_name(self, module_name):
		return self.get_reader().get_module_by_name(module_name)

	def search_module(self, module_name, pattern, find_first=False,
			reverse_order=False, chunksize=None):
		return self.get_reader().search_module(
			module_name,
			pattern,
			find_first=find_first,
			reverse_order=reverse_order,
			chunksize=chunksize,
		)

	def get_reader(self):
		return EvidenceReader(self)

	def get_evidence_view(self):
		return self

	def get_evidence_reader(self):
		return self.get_reader()

	def get_buffered_reader(self, segment_chunk_size=None):
		return EvidenceBufferedReader(self.get_reader(), segment_chunk_size)

	def restricted_reader(self):
		return self.get_reader()

	authorized_reader = restricted_reader

	def get_thread(self, thread_id):
		if hasattr(thread_id, "thread_id"):
			thread_id = thread_id.thread_id
		for thread in self._threads:
			if thread.thread_id == thread_id:
				return thread
			if str(thread.thread_id) == str(thread_id):
				return thread
		return None

	def thread(self, thread_id):
		return self.get_thread(thread_id)

	def thread_context(self, thread_id):
		return self.get_thread(thread_id)

	def get_thread_context(self, thread_id):
		return self.get_thread(thread_id)

	def read_thread_context(self, thread_id, offset=0, size=None, address=None):
		return self.read_thread_stack(
			thread_id, offset=offset, size=size, address=address
		)

	def read_thread_stack(self, thread_id, offset=0, size=None, address=None):
		thread = self.get_thread(thread_id)
		if thread is None:
			raise EvidenceAccessDenied("unknown thread id %r" % (thread_id,))
		return thread.read(offset=offset, size=size, address=address)

	def read_thread(self, thread_id, offset=0, size=None, address=None):
		return self.read_thread_stack(thread_id, offset=offset, size=size, address=address)

	def thread_stack(self, thread_id, offset=0, size=None, address=None):
		return self.read_thread_stack(
			thread_id, offset=offset, size=size, address=address
		)

	# ------------------------------------------------------------------
	# Search
	# ------------------------------------------------------------------

	def _iter_raw_runs(self, start=None, end=None):
		intervals = self._raw_intervals
		if start is not None:
			intervals = [item for item in intervals if item.end > start]
		if end is not None:
			intervals = [item for item in intervals if item.start < end]
		run_start = None
		run_end = None
		run_data = None
		for item in sorted(intervals, key=lambda value: value.start):
			left = max(item.start, start) if start is not None else item.start
			right = min(item.end, end) if end is not None else item.end
			if left >= right:
				continue
			data = item.slice(left, right)
			if run_data is None:
				run_start = left
				run_end = right
				run_data = bytearray(data)
			elif left == run_end:
				run_data.extend(data)
				run_end = right
			else:
				yield run_start, bytes(run_data)
				run_start = left
				run_end = right
				run_data = bytearray(data)
		if run_data is not None:
			yield run_start, bytes(run_data)

	def search(self, pattern, start=None, end=None, find_first=False, **kwargs):
		pattern = bytes(pattern)
		if not pattern:
			return [] if not find_first else -1
		found = []
		for run_start, data in self._iter_raw_runs(start=start, end=end):
			offset = 0
			while True:
				marker = data.find(pattern, offset)
				if marker < 0:
					break
				found.append(run_start + marker)
				if find_first:
					return found[:1]
				offset = marker + 1
		return found

	def find(self, pattern, start=None, end=None, **kwargs):
		result = self.search(
			pattern, start=start, end=end, find_first=True, **kwargs
		)
		if isinstance(result, list):
			return result[0] if result else -1
		return result if result is not None else -1

	def find_all(self, pattern, start=None, end=None):
		return self.search(pattern, start=start, end=end, find_first=False)

	# ------------------------------------------------------------------
	# Serialisation, acceptance and re-handoff
	# ------------------------------------------------------------------

	def to_dict(self, include_integrity=True):
		payload = copy.deepcopy(self._manifest)
		payload.pop("integrity", None)
		if include_integrity:
			payload["integrity"] = {
				"algorithm": "sha256",
				"digest": _sha256(_canonical_json(payload)),
			}
		return payload

	def to_json(self, indent=None):
		if indent is None:
			return _canonical_json(self.to_dict()).decode("utf-8")
		return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

	def to_bytes(self):
		return _canonical_json(self.to_dict())

	serialize = to_bytes

	def to_bundle(self):
		return EvidenceBundle.from_dict(self.to_dict(include_integrity=False))

	@classmethod
	def from_bytes(cls, data):
		return EvidenceBundle.from_bytes(data)

	@classmethod
	def from_dict(cls, manifest):
		return EvidenceBundle.from_dict(manifest)

	@classmethod
	def open(cls, path):
		return EvidenceBundle.open(path)

	def export_bundle(self, target=None):
		return self.export(target=target)

	def export(self, target=None):
		data = self.to_bytes()
		if target is None:
			return data
		if hasattr(target, "write"):
			target.write(data)
		else:
			with open(target, "wb") as handle:
				handle.write(data)
		return data

	def accept(
		self,
		actor="external-recipient",
		note=None,
		at=None,
		verifier=None,
		original=None,
		custodian=None,
	):
		self.verify_integrity()
		source_verified = False
		verification_source = original if original is not None else custodian
		if verification_source is not None:
			self.verify_original(verification_source, strict=True)
			source_verified = True
		if verifier is not None:
			outcome = verifier(self) if callable(verifier) else bool(verifier)
			if outcome is False:
				raise EvidenceVerificationError(
					"handoff verifier rejected the evidence view"
				)
		manifest = self.to_dict(include_integrity=False)
		manifest["accepted"] = True
		manifest["accepted_by"] = actor
		manifest["accepted_at"] = at or _now_iso()
		manifest["source_verified"] = source_verified
		manifest.setdefault("custody", []).append(
			{
				"action": "accepted",
				"actor": actor,
				"at": at or _now_iso(),
				"note": note,
				"previous_digest": self.digest,
				"bundle_sha256": self.digest,
				"digest": self.digest,
				"source_verified": source_verified,
			}
		)
		receipt_payload = manifest.setdefault("receipt", {})
		receipt_payload.update(
			{
				"accepted": True,
				"accepted_by": actor,
				"accepted_at": manifest["accepted_at"],
				"source_verified": source_verified,
				"custody": copy.deepcopy(manifest["custody"]),
			}
		)
		return EvidenceBundle.from_dict(manifest)

	def handoff(self, to_actor, from_actor=None, note=None, at=None):
		self.verify_integrity()
		manifest = self.to_dict(include_integrity=False)
		manifest.setdefault("custody", []).append(
			{
				"action": "handoff",
				"from": from_actor,
				"to": to_actor,
				"at": at or _now_iso(),
				"note": note,
				"previous_digest": self.digest,
				"bundle_sha256": self.digest,
				"digest": self.digest,
			}
		)
		receipt_payload = manifest.setdefault("receipt", {})
		receipt_payload["custody"] = copy.deepcopy(manifest["custody"])
		return EvidenceBundle.from_dict(manifest)

	def rehandoff(self, to_actor, from_actor=None, note=None, at=None):
		return self.handoff(
			to_actor,
			from_actor=from_actor,
			note=note,
			at=at,
		)

	def verify_integrity(self):
		payload = copy.deepcopy(self.to_dict(include_integrity=False))
		expected = (
			self._integrity.get("digest") if self._integrity else None
		)
		actual = _sha256(_canonical_json(payload))
		if expected is not None and expected != actual:
			raise EvidenceIntegrityError(
				"evidence bundle digest mismatch (expected %s, got %s)"
				% (expected, actual)
			)
		return True

	def _load_manifest(self, manifest):
		if not isinstance(manifest, dict):
			raise EvidenceIntegrityError("evidence bundle must be a JSON object")
		if manifest.get("schema") != EVIDENCE_SCHEMA:
			raise EvidenceIntegrityError(
				"unsupported evidence schema %r" % manifest.get("schema")
			)
		payload = copy.deepcopy(manifest)
		integrity = payload.pop("integrity", None)
		if integrity:
			if integrity.get("algorithm", "sha256") != "sha256":
				raise EvidenceIntegrityError(
					"unsupported integrity algorithm %r"
					% integrity.get("algorithm")
				)
			digest = _sha256(_canonical_json(payload))
			if digest != integrity.get("digest"):
				raise EvidenceIntegrityError(
					"evidence bundle digest mismatch (expected %s, got %s)"
					% (integrity.get("digest"), digest)
				)
		self._manifest = payload
		self._integrity = copy.deepcopy(integrity)
		if self._integrity is None:
			self._integrity = {
				"algorithm": "sha256",
				"digest": _sha256(_canonical_json(copy.deepcopy(payload))),
			}
		self._policy = EvidencePolicy.from_dict(payload["policy"])
		self._page_size = self._policy.page_size
		self._source_meta = copy.deepcopy(payload.get("source", {}))
		self._pointer_size = payload.get("pointer_size", 8)
		self._is_fulldump = bool(payload.get("is_fulldump", True))
		self._sysinfo = copy.deepcopy(payload.get("sysinfo"))
		self._modules = copy.deepcopy(payload.get("modules", []))
		self._entries = copy.deepcopy(payload.get("entries", []))
		self._receipt = EvidenceReceipt(copy.deepcopy(payload.get("receipt", {})))
		for key in (
			"accepted",
			"accepted_by",
			"accepted_at",
			"source_verified",
			"custody",
		):
			if key in payload:
				self._receipt[key] = copy.deepcopy(payload[key])
		self._threads = [
			EvidenceThread(item, view=self)
			for item in payload.get("threads", [])
		]
		self._accepted = bool(payload.get("accepted", False))
		self._custody = copy.deepcopy(payload.get("custody", []))
		self._detached = True
		self._raw_intervals = []
		self._summary_pages = {}
		self._memory_segment_cache = None
		for index, entry in enumerate(self._entries):
			item = self.ranges[index]
			for chunk in entry.get("raw_chunks", []):
				data = base64.b64decode(chunk.get("data_b64", ""))
				if item.access != RAW:
					raise EvidenceIntegrityError(
						"page-summary entry %d contains raw bytes" % index
					)
				if chunk.get("size") is not None and chunk["size"] != len(data):
					raise EvidenceIntegrityError(
						"raw chunk size mismatch in entry %d" % index
					)
				if entry.get("sha256") and not self._chunks_match(
					entry["raw_chunks"], entry["sha256"]
				):
					raise EvidenceIntegrityError(
						"raw entry digest mismatch in entry %d" % index
					)
				if not (item.start <= chunk["start"] < chunk["end"] <= item.end):
					raise EvidenceIntegrityError(
						"raw chunk outside approved range in entry %d" % index
					)
				self._raw_intervals.append(
					_RawInterval(
						chunk["start"],
						chunk["end"],
						data,
						(chunk.get("mapping_sources") or ([chunk["mapping_source"]] if chunk.get("mapping_source") else [])),
						index,
					)
				)
			if item.access == PAGE_SUMMARY:
				if entry.get("raw_chunks"):
					raise EvidenceIntegrityError(
						"page-summary entry %d contains raw chunks" % index
					)
				for page in entry.get("pages", []):
					if "data" in page or "data_b64" in page:
						raise EvidenceIntegrityError(
							"page summary %d/%d contains raw content"
							% (index, page.get("page_index"))
						)
				self._summary_pages[index] = [
					EvidencePageSummary(page) for page in entry.get("pages", [])
				]
		self._raw_intervals.sort(key=lambda value: value.start)

	@staticmethod
	def _chunks_match(chunks, expected=None):
		digest = hashlib.sha256()
		for chunk in chunks:
			data = base64.b64decode(chunk.get("data_b64", ""))
			if chunk.get("sha256") and chunk["sha256"] != _sha256(data):
				return False
			digest.update(data)
		return expected is None or digest.hexdigest() == expected

	# ------------------------------------------------------------------
	# Original-source verification
	# ------------------------------------------------------------------

	def _open_verification_source(self, source):
		close = False
		if source is None:
			source = self._source_meta.get("filename")
		if source is None:
			original = getattr(self, "_minidump", None)
			source = getattr(original, "file_handle", None)
		if source is None:
			raise EvidenceVerificationError(
				"the custodian's original source is required for verification"
			)
		if isinstance(source, (bytes, bytearray)):
			return io.BytesIO(bytes(source)), True
		if hasattr(source, "__fspath__"):
			source = os.fspath(source)
		if isinstance(source, str):
			return open(source, "rb"), True
		if hasattr(source, "file_handle"):
			return source.file_handle, False
		if hasattr(source, "reader") and hasattr(source.reader, "file_handle"):
			return source.reader.file_handle, False
		if hasattr(source, "read") and hasattr(source, "seek"):
			return source, False
		raise EvidenceVerificationError("unsupported verification source %r" % (source,))

	def verify_original(
		self,
		source=None,
		strict=False,
		byte_by_byte=True,
	):
		"""Verify the custodian's original dump byte-for-byte.

		The complete source digest is checked, then every exported raw chunk and
		every page-summary digest is re-read from the original file offsets.  A
		single changed byte therefore produces a mismatch.
		"""

		handle, close = self._open_verification_source(source)
		mismatches = []
		range_checks = []
		evidence_bytes_checked = 0
		try:
			actual_size = self._handle_size_plain(handle)
			actual_digest = self._handle_digest_plain(handle)
			expected_digest = self._source_meta.get("sha256")
			expected_size = self._source_meta.get("size")
			if expected_size is not None and actual_size != expected_size:
				mismatches.append(
					{
						"kind": "source_size",
						"expected": expected_size,
						"actual": actual_size,
					}
				)
			if expected_digest is not None and actual_digest != expected_digest:
				mismatches.append(
					{
						"kind": "source_sha256",
						"expected": expected_digest,
						"actual": actual_digest,
					}
				)
			for index, entry in enumerate(self._entries):
				item = self.ranges[index]
				if item.access == RAW:
					chunked = hashlib.sha256()
					entry_ok = True
					entry_checked = 0
					for chunk in entry.get("raw_chunks", []):
						mapping = chunk.get("mapping_source") or (
						(chunk.get("mapping_sources") or [{}])[0]
					)
						file_rva = mapping.get("file_rva")
						if file_rva is None:
							entry_ok = False
							mismatches.append(
								{
									"kind": "missing_file_rva",
									"entry_index": index,
									"start": chunk["start"],
								}
							)
							continue
						expected = base64.b64decode(chunk.get("data_b64", ""))
						offset = file_rva + (chunk["start"] - mapping.get("start", chunk["start"]))
						actual = self._read_handle_plain(handle, offset, len(expected))
						if byte_by_byte:
							same = actual == expected
						else:
							same = _sha256(actual) == chunk.get("sha256")
						if not same:
							entry_ok = False
							mismatches.append(
								{
									"kind": "raw_chunk",
									"entry_index": index,
									"start": chunk["start"],
									"end": chunk["end"],
									"file_rva": offset,
								}
							)
						chunked.update(actual)
						entry_checked += len(actual)
					if entry.get("sha256") and chunked.hexdigest() != entry["sha256"]:
						entry_ok = False
						mismatches.append(
							{
								"kind": "raw_entry_sha256",
								"entry_index": index,
							}
						)
					evidence_bytes_checked += entry_checked
					range_checks.append(
						{
							"entry_index": index,
							"start": item.start,
							"end": item.end,
							"access": RAW,
							"checked_bytes": entry_checked,
							"ok": entry_ok,
						}
					)
				else:
					page_ok = True
					page_checked = 0
					for page in entry.get("pages", []):
						digest = hashlib.sha256()
						for segment in page.get("segments", []):
							mapping = segment.get("mapping_source") or (
								(segment.get("mapping_sources") or [{}])[0]
							)
							file_rva = mapping.get("file_rva")
							if file_rva is None:
								page_ok = False
								continue
							offset = file_rva + (
								segment["start"] - mapping.get("start", segment["start"])
							)
							actual = self._read_handle_plain(
								handle, offset, segment["size"]
							)
							if len(actual) != segment["size"]:
								page_ok = False
							digest.update(actual)
							page_checked += len(actual)
						if page.get("sha256") and digest.hexdigest() != page["sha256"]:
							page_ok = False
							mismatches.append(
								{
									"kind": "page_summary_sha256",
									"entry_index": index,
									"page_index": page.get("page_index"),
								}
							)
					evidence_bytes_checked += page_checked
					range_checks.append(
						{
							"entry_index": index,
							"start": item.start,
							"end": item.end,
							"access": PAGE_SUMMARY,
							"checked_bytes": page_checked,
							"ok": page_ok,
						}
					)
		finally:
			if close:
				handle.close()

		ok = not mismatches
		result = EvidenceVerification(
			ok=ok,
			verified=ok,
			source_size=actual_size,
			expected_size=expected_size,
			source_sha256=actual_digest,
			expected_sha256=expected_digest,
			checked_bytes=actual_size,
			evidence_bytes_checked=evidence_bytes_checked,
			byte_by_byte=bool(byte_by_byte),
			range_checks=range_checks,
			mismatches=mismatches,
			ticket_id=self.policy.ticket_id,
		)
		if strict and not ok:
			result.raise_if_failed()
		return result

	def verify_source(self, source=None, strict=False):
		return self.verify_original(source=source, strict=strict)

	def verify_custodian(self, source=None, strict=False):
		return self.verify_original(source=source, strict=strict)

	def verify_original_bytes(self, source=None, strict=False):
		return self.verify_original(source=source, strict=strict, byte_by_byte=True)

	@staticmethod
	def _handle_size_plain(handle):
		position = None
		try:
			position = handle.tell()
		except Exception:
			pass
		try:
			handle.seek(0, 2)
			return handle.tell()
		finally:
			if position is not None:
				handle.seek(position, 0)

	@staticmethod
	def _handle_digest_plain(handle):
		position = None
		try:
			position = handle.tell()
		except Exception:
			pass
		try:
			handle.seek(0, 0)
			digest = hashlib.sha256()
			while True:
				chunk = handle.read(1024 * 1024)
				if not chunk:
					break
				digest.update(chunk)
			return digest.hexdigest()
		finally:
			if position is not None:
				handle.seek(position, 0)

	@staticmethod
	def _read_handle_plain(handle, offset, size):
		position = None
		try:
			position = handle.tell()
		except Exception:
			pass
		try:
			handle.seek(offset, 0)
			return handle.read(size)
		finally:
			if position is not None:
				handle.seek(position, 0)


class EvidenceBundle(EvidenceView):
	"""A detached, serialised evidence view suitable for re-handoff."""

	@classmethod
	def from_dict(cls, manifest):
		if isinstance(manifest, EvidenceView):
			manifest = manifest.to_dict(include_integrity=False)
		obj = cls.__new__(cls)
		obj._init_empty()
		obj._load_manifest(manifest)
		return obj

	@classmethod
	def from_bytes(cls, data):
		if isinstance(data, str) and os.path.isfile(data):
			return cls.open(data)
		if isinstance(data, str):
			manifest = json.loads(data)
		else:
			manifest = json.loads(bytes(data).decode("utf-8"))
		return cls.from_dict(manifest)

	@classmethod
	def open(cls, path):
		with open(path, "rb") as handle:
			return cls.from_bytes(handle.read())

	def to_dict(self, include_integrity=True):
		payload = copy.deepcopy(self._manifest)
		payload.pop("integrity", None)
		if include_integrity:
			payload["integrity"] = {
				"algorithm": "sha256",
				"digest": _sha256(_canonical_json(payload)),
			}
		return payload


# Backwards/forwards-friendly public aliases.
RestrictedEvidenceView = EvidenceView
RestrictedEvidenceReader = EvidenceReader
RestrictedEvidenceRange = EvidenceRange
EvidenceAuthorization = EvidencePolicy
EvidenceAccessPolicy = EvidencePolicy
EvidenceTicket = ApprovalTicket
Approval = ApprovalTicket
EvidenceScope = EvidencePolicy
RestrictedEvidenceBundle = EvidenceBundle
EvidenceHandoff = EvidenceBundle
EvidenceHandoffBundle = EvidenceBundle


def build_evidence_view(
	source,
	ranges=None,
	ticket=None,
	policy=None,
	page_size=DEFAULT_PAGE_SIZE,
	**kwargs
):
	"""Build a restricted :class:`EvidenceView` from a minidump."""

	return EvidenceView(
		source,
		ranges=ranges,
		ticket=ticket,
		policy=policy,
		page_size=page_size,
		**kwargs
	)


def create_evidence_view(source, ranges=None, ticket=None, policy=None, **kwargs):
	return build_evidence_view(
		source,
		ranges=ranges,
		ticket=ticket,
		policy=policy,
		**kwargs
	)


def make_evidence_view(source, ranges=None, ticket=None, policy=None, **kwargs):
	return build_evidence_view(
		source,
		ranges=ranges,
		ticket=ticket,
		policy=policy,
		**kwargs
	)


def open_evidence_view(source):
	"""Open an exported evidence bundle (bytes, JSON text or path)."""

	if isinstance(source, EvidenceView):
		return source
	if isinstance(source, str):
		if source.lstrip().startswith("{"):
			return EvidenceBundle.from_bytes(source)
		return EvidenceBundle.open(source)
	if hasattr(source, "read") and not isinstance(source, (bytes, bytearray)):
		return EvidenceBundle.from_bytes(source.read())
	return EvidenceBundle.from_bytes(source)


def load_evidence_bundle(source):
	return open_evidence_view(source)


def verify_evidence_source(view, source=None, strict=False):
	if not isinstance(view, EvidenceView):
		view = open_evidence_view(view)
	return view.verify_original(source=source, strict=strict)


__all__ = [
	"EVIDENCE_SCHEMA",
	"RAW",
	"PAGE_SUMMARY",
	"DEFAULT_PAGE_SIZE",
	"EvidenceError",
	"EvidenceException",
	"EvidencePolicyError",
	"EvidenceIntegrityError",
	"EvidenceVerificationError",
	"EvidenceAccessDenied",
	"ApprovalTicket",
	"EvidenceTicket",
	"Approval",
	"EvidenceRange",
	"RestrictedEvidenceRange",
	"EvidencePolicy",
	"EvidenceAuthorization",
	"EvidenceAccessPolicy",
	"EvidenceScope",
	"EvidencePageSummary",
	"EvidenceReceiptEntry",
	"EvidenceReceipt",
	"EvidenceReadResult",
	"EvidenceVerification",
	"EvidenceMemorySegment",
	"EvidenceThread",
	"EvidenceReader",
	"RestrictedEvidenceReader",
	"EvidenceBufferedReader",
	"EvidenceView",
	"RestrictedEvidenceView",
	"EvidenceBundle",
	"RestrictedEvidenceBundle",
	"EvidenceHandoff",
	"EvidenceHandoffBundle",
	"build_evidence_view",
	"create_evidence_view",
	"make_evidence_view",
	"open_evidence_view",
	"load_evidence_bundle",
	"verify_evidence_source",
]
