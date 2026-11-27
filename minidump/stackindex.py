#!/usr/bin/env python3
#
# Stack fragment cross-check without exchanging stack bytes.
#
# Two investigators may only exchange *coordinates* of stack fragments that
# were explicitly approved.  This module turns a parsed minidump into a small
# byte-free index, records where every piece of attribution evidence came from,
# and reconciles two such indexes.
#
import json
import ntpath


class StackCoordinate:
	"""Byte-free identity of a captured stack fragment.

	The identity of a call site is the pair (thread id, instruction pointer).
	Stack ranges are descriptive evidence, not part of the identity, because two
	collections of the same call site commonly capture different boundaries.
	"""

	def __init__(self, thread_id, call_site):
		self.thread_id = int(thread_id)
		self.call_site = int(call_site)

	@staticmethod
	def from_dict(data):
		raw_call_site = data['call_site']
		call_site = int(raw_call_site, 0) if isinstance(raw_call_site, str) else int(raw_call_site)
		return StackCoordinate(int(data['thread_id']), call_site)

	def key(self):
		return (self.thread_id, self.call_site)

	def to_dict(self):
		return {
			'thread_id': self.thread_id,
			'call_site': '0x%x' % self.call_site,
		}

	def __eq__(self, other):
		return isinstance(other, StackCoordinate) and self.key() == other.key()

	def __hash__(self):
		return hash(self.key())

	def __str__(self):
		return 'thread=0x%x call_site=0x%x' % (self.thread_id, self.call_site)


class Evidence:
	"""Pointer to the minidump stream/field backing an index entry.

	Only metadata is stored; no stack content is ever read into the index.
	"""

	def __init__(self, source, stream, field, detail=None):
		self.source = source
		self.stream = stream
		self.field = field
		self.detail = detail

	def to_dict(self):
		out = {
			'source': self.source,
			'stream': self.stream,
			'field': self.field,
		}
		if self.detail is not None:
			out['detail'] = self.detail
		return out


class ModuleAttribution:
	"""Image that contains the call site, with version evidence."""

	def __init__(self, name, base_address, size, timestamp, version, evidence):
		self.name = name
		self.base_address = base_address
		self.size = size
		self.timestamp = timestamp
		self.version = version
		self.evidence = evidence

	def to_dict(self):
		return {
			'name': self.name,
			'base_address': '0x%x' % self.base_address,
			'size': '0x%x' % self.size,
			'timestamp': '0x%x' % self.timestamp,
			'version': self.version,
			'evidence': self.evidence.to_dict(),
		}


class StackIndexEntry:
	"""One approved stack fragment, described without any stack bytes."""

	def __init__(self, coordinate, stack_start, stack_end, thread_evidence,
			context_evidence, range_evidence, module=None):
		self.coordinate = coordinate
		self.stack_start = stack_start
		self.stack_end = stack_end
		self.thread_evidence = thread_evidence
		self.context_evidence = context_evidence
		self.range_evidence = range_evidence
		self.module = module

	def to_dict(self):
		out = {
			'coordinate': self.coordinate.to_dict(),
			'stack_range': {
				'start': '0x%x' % self.stack_start,
				'end': '0x%x' % self.stack_end,
			},
			'evidence': {
				'thread': self.thread_evidence.to_dict(),
				'call_site': self.context_evidence.to_dict(),
				'stack_range': self.range_evidence.to_dict(),
			},
		}
		if self.module is not None:
			out['module'] = self.module.to_dict()
		return out


class IntersectionEntry:
	"""A coordinate present in both indexes.

	The mismatch list keeps an intersection even when the collections differ;
	the differences are reported instead of silently dropping the match.
	"""

	def __init__(self, coordinate, left, right, mismatches):
		self.coordinate = coordinate
		self.left = left
		self.right = right
		self.mismatches = mismatches

	def to_dict(self):
		return {
			'coordinate': self.coordinate.to_dict(),
			'mismatches': list(self.mismatches),
			'left': self.left.to_dict(),
			'right': self.right.to_dict(),
		}


class ReconciliationResult:
	def __init__(self, source_left, source_right, intersection, unverified_left,
			unverified_right, suppressed):
		self.source_left = source_left
		self.source_right = source_right
		self.intersection = intersection
		self.unverified_left = unverified_left
		self.unverified_right = unverified_right
		self.suppressed = suppressed

	def to_dict(self):
		return {
			'sources': {
				'left': self.source_left,
				'right': self.source_right,
			},
			'intersection': [entry.to_dict() for entry in self.intersection],
			'unverified': {
				'left': [entry.to_dict() for entry in self.unverified_left],
				'right': [entry.to_dict() for entry in self.unverified_right],
			},
			'suppressed_without_permission': [coord.to_dict() for coord in self.suppressed],
		}

	def to_json(self, indent=2):
		return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


def _module_basename(name):
	return ntpath.basename(name).lower()


def _format_version(version_info):
	if version_info is None:
		return None
	try:
		return '%d.%d.%d.%d' % (
			(version_info.dwFileVersionMS >> 16) & 0xffff,
			version_info.dwFileVersionMS & 0xffff,
			(version_info.dwFileVersionLS >> 16) & 0xffff,
			version_info.dwFileVersionLS & 0xffff,
		)
	except AttributeError:
		return None


def _find_module(minidump_file, address):
	if minidump_file.modules is None:
		return None
	for module in minidump_file.modules.modules:
		if module.inrange(address):
			return module
	return None


def load_allowed_coordinates(handle_or_path):
	"""Load the shared permission list.

	Expected JSON shape::

	    {"allowed": [{"thread_id": 1234, "call_site": "0x7ff8..."}, ...]}

	A bare list of coordinate objects is accepted as well.
	"""
	if hasattr(handle_or_path, 'read'):
		payload = json.load(handle_or_path)
	else:
		with open(handle_or_path, 'r', encoding='utf-8') as handle:
			payload = json.load(handle)
	rows = payload['allowed'] if isinstance(payload, dict) else payload
	allowed = set()
	for row in rows:
		allowed.add(StackCoordinate.from_dict(row).key())
	return allowed


def build_stack_index(minidump_file, allowed_coordinates, source_label=None):
	"""Build a byte-free index of approved stack fragments in a dump."""
	if minidump_file.threads is None:
		return [], []

	label = source_label or (minidump_file.filename or 'minidump')
	entries = []
	suppressed = []

	for thread in minidump_file.threads.threads:
		stack = thread.Stack
		if stack is None:
			continue
		stack_start = stack.StartOfMemoryRange
		stack_end = stack_start + stack.DataSize

		call_site = None
		context = getattr(thread, 'ContextObject', None)
		if context is not None and hasattr(context, 'Rip'):
			call_site = context.Rip
		elif context is not None and hasattr(context, 'Eip'):
			call_site = context.Eip
		if call_site is None:
			continue

		coordinate = StackCoordinate(thread.ThreadId, call_site)
		if coordinate.key() not in allowed_coordinates:
			suppressed.append(coordinate)
			continue

		thread_evidence = Evidence(
			label, 'ThreadListStream', 'MINIDUMP_THREAD.ThreadId',
			'thread 0x%x' % thread.ThreadId,
		)
		context_evidence = Evidence(
			label, 'ThreadListStream',
			'MINIDUMP_THREAD.ThreadContext (instruction pointer)',
			'0x%x' % call_site,
		)
		range_evidence = Evidence(
			label, 'ThreadListStream', 'MINIDUMP_THREAD.Stack',
			'va 0x%x-0x%x, file rva 0x%x' % (
				stack_start, stack_end, stack.Rva),
		)

		module = None
		owner = _find_module(minidump_file, call_site)
		if owner is not None:
			module = ModuleAttribution(
				owner.name,
				owner.baseaddress,
				owner.size,
				owner.timestamp,
				_format_version(owner.versioninfo),
				Evidence(
					label, 'ModuleListStream',
					'MINIDUMP_MODULE range/version',
					'call site 0x%x inside image' % call_site,
				),
			)

		entries.append(StackIndexEntry(
			coordinate, stack_start, stack_end,
			thread_evidence, context_evidence, range_evidence, module,
		))

	entries.sort(key=lambda entry: entry.coordinate.key())
	suppressed.sort(key=lambda coordinate: coordinate.key())
	return entries, suppressed


def _compare_entries(left, right):
	mismatches = []

	if left.stack_start != right.stack_start or left.stack_end != right.stack_end:
		mismatches.append('collection_boundary')

	left_module = left.module
	right_module = right.module
	if left_module is None or right_module is None:
		if left_module is not None or right_module is not None:
			mismatches.append('module_attribution')
		return mismatches

	if _module_basename(left_module.name) != _module_basename(right_module.name):
		mismatches.append('module_attribution')
		return mismatches

	if left_module.timestamp != right_module.timestamp or \
			left_module.version != right_module.version:
		mismatches.append('sample_version')

	return mismatches


def reconcile(left_file, right_file, allowed_coordinates,
		left_label=None, right_label=None):
	"""Reconcile two parsed dumps against one shared permission list.

	Returns the independent intersection, with explicit boundary/version
	mismatches, and the unverified fragments on each side.  Coordinates missing
	from the permission list never enter either output and are reported as
	suppressed instead.
	"""
	left_entries, left_suppressed = build_stack_index(
		left_file, allowed_coordinates, left_label)
	right_entries, right_suppressed = build_stack_index(
		right_file, allowed_coordinates, right_label)

	left_by_key = {entry.coordinate.key(): entry for entry in left_entries}
	right_by_key = {entry.coordinate.key(): entry for entry in right_entries}

	intersection = []
	for key in sorted(set(left_by_key) & set(right_by_key)):
		left_entry = left_by_key[key]
		right_entry = right_by_key[key]
		intersection.append(IntersectionEntry(
			left_entry.coordinate, left_entry, right_entry,
			_compare_entries(left_entry, right_entry),
		))

	unverified_left = [left_by_key[key] for key in sorted(set(left_by_key) - set(right_by_key))]
	unverified_right = [right_by_key[key] for key in sorted(set(right_by_key) - set(left_by_key))]

	suppressed_keys = sorted(set(
		coord.key() for coord in left_suppressed + right_suppressed
	))
	suppressed = [StackCoordinate(*key) for key in suppressed_keys]

	return ReconciliationResult(
		left_label or left_file.filename or 'left',
		right_label or right_file.filename or 'right',
		intersection, unverified_left, unverified_right, suppressed,
	)
