#!/usr/bin/env python3
#
# Forensic address attribution.
#
# Joins the exception stream with both the loaded module table and the
# unloaded module list. Every address is resolved against the *raw* table
# entries (base/size taken straight from the minidump), so the relative
# position of an address inside a module is always backed by the original
# numbers rather than by a name lookup.
#
from enum import Enum
from typing import List, Optional


class AttributionVerdict(Enum):
	# An exception record exists and its address is covered by a loaded
	# module. The loaded module is the owner at crash time.
	LOADED_MATCH = 'loaded_match'
	# An exception record exists, but its address only falls inside modules
	# that have since been unloaded. This is a historical attribution only.
	UNLOADED_ONLY = 'unloaded_only'
	# An exception record exists, yet no loaded or unloaded module covers
	# the address. It cannot be attributed to any recorded module.
	UNATTRIBUTED = 'unattributed'
	# No exception stream / exception record is present in the dump, so
	# there is no faulting address to attribute.
	NO_EXCEPTION = 'no_exception'


class EvidenceKind(Enum):
	LOADED_MODULE = 'loaded_module'
	UNLOADED_MODULE = 'unloaded_module'


class ModuleEvidence:
	"""
	A single raw table row that covers the queried address.

	One evidence object is created per table row, so two rows that share the
	same module name are kept separate and never merged into one evidence
	item.
	"""

	def __init__(self, kind, module, address, boundary):
		self.kind = kind
		self.name = module.name
		self.baseaddress = module.baseaddress
		self.size = module.size
		self.endaddress = module.endaddress
		self.address = address
		# Distance from the module base, recomputed from the raw values.
		self.offset = address - module.baseaddress
		# Bytes between the address and the first byte past the module.
		# 0 means the address sits exactly on the module's end boundary.
		self.distance_to_end = module.endaddress - address
		# How the address relates to the raw [base, end) interval.
		self.boundary = boundary
		self.timestamp = module.timestamp
		self.checksum = module.checksum

	@property
	def is_loaded(self):
		return self.kind == EvidenceKind.LOADED_MODULE

	@property
	def is_unloaded(self):
		return self.kind == EvidenceKind.UNLOADED_MODULE

	@property
	def at_tail(self):
		return self.boundary == BoundaryRelation.AT_TAIL

	def to_dict(self):
		return {
			'kind': self.kind.value,
			'name': self.name,
			'baseaddress': self.baseaddress,
			'size': self.size,
			'endaddress': self.endaddress,
			'address': self.address,
			'offset': self.offset,
			'distance_to_end': self.distance_to_end,
			'boundary': self.boundary.value,
			'at_tail': self.at_tail,
			'timestamp': self.timestamp,
			'checksum': self.checksum,
		}

	def __str__(self):
		state = 'loaded' if self.is_loaded else 'unloaded'
		return (
			'%s module %s [0x%x-0x%x) covers 0x%x '
			'(base+0x%x, %s)'
		) % (
			state, self.name, self.baseaddress, self.endaddress,
			self.address, self.offset, self.boundary.value,
		)


class BoundaryRelation(Enum):
	# address is a normal byte strictly inside [base, end)
	INSIDE = 'inside'
	# address == endaddress: the first byte *after* the raw range. It is
	# kept as evidence of the module that ends immediately before it, but
	# the boundary condition is recorded explicitly instead of pretending
	# the byte belongs to the module image.
	AT_TAIL = 'at_tail'


class AddressAttribution:
	"""
	Attribution result for one exception record (or one queried address).
	"""

	def __init__(self, address, thread_id=None, exception_code=None):
		self.address = address
		self.thread_id = thread_id
		self.exception_code = exception_code
		self.verdict = None  # type: Optional[AttributionVerdict]
		self.loaded_evidence = []  # type: List[ModuleEvidence]
		self.unloaded_evidence = []  # type: List[ModuleEvidence]
		self.reasons = []  # type: List[str]
		self.confidence = 0.0

	@property
	def all_evidence(self):
		return self.loaded_evidence + self.unloaded_evidence

	@property
	def has_overlap(self):
		"""True when more than one raw table row covers the same address."""
		return len(self.all_evidence) > 1

	@property
	def owner(self):
		"""
		The module that owns the address at crash time.

		Loaded modules always win over historical unloaded coverage. When
		several loaded rows overlap, every one of them stays in
		``loaded_evidence`` and the first raw match is reported as owner so
		that the overlap remains visible instead of being silently merged.
		"""
		if self.loaded_evidence:
			return self.loaded_evidence[0]
		return None

	def to_dict(self):
		return {
			'address': self.address,
			'thread_id': self.thread_id,
			'exception_code': self.exception_code.value
			if self.exception_code is not None else None,
			'verdict': self.verdict.value if self.verdict is not None else None,
			'confidence': self.confidence,
			'has_overlap': self.has_overlap,
			'owner': self.owner.to_dict() if self.owner else None,
			'loaded_evidence': [e.to_dict() for e in self.loaded_evidence],
			'unloaded_evidence': [e.to_dict() for e in self.unloaded_evidence],
			'reasons': list(self.reasons),
		}

	def __str__(self):
		lines = [
			'Address 0x%x thread=%s code=%s' % (
				self.address,
				'0x%x' % self.thread_id if self.thread_id is not None else 'n/a',
				self.exception_code.name if self.exception_code is not None else 'n/a',
			),
			'Verdict: %s (confidence %.2f)' % (
				self.verdict.value if self.verdict else 'n/a', self.confidence),
		]
		for evidence in self.loaded_evidence:
			lines.append('  ' + str(evidence))
		for evidence in self.unloaded_evidence:
			lines.append('  ' + str(evidence))
		for reason in self.reasons:
			lines.append('  - ' + reason)
		return '\n'.join(lines)


class ForensicAttributor:
	"""
	Resolves faulting addresses using the module tables and exception stream
	of a parsed :class:`MinidumpFile`.
	"""

	# Confidence weights. A live loaded range is the strongest statement the
	# dump can make; an unloaded range is only historical context.
	_LOADED_WEIGHT = 0.7
	_UNLOADED_WEIGHT = 0.3
	# Extra confidence when the exception record names a live thread.
	_THREAD_WEIGHT = 0.1

	def __init__(self, minidump_file):
		self.minidump = minidump_file
		self.loaded_modules = self._loaded_modules()
		self.unloaded_modules = self._unloaded_modules()

	def _loaded_modules(self):
		if self.minidump.modules is None:
			return []
		return list(self.minidump.modules.modules)

	def _unloaded_modules(self):
		if self.minidump.unloaded_modules is None:
			return []
		return list(self.minidump.unloaded_modules.modules)

	def _thread_exists(self, thread_id):
		if thread_id is None:
			return False
		if self.minidump.threads is not None:
			for thread in self.minidump.threads.threads:
				if thread.ThreadId == thread_id:
					return True
		if self.minidump.threads_ex is not None:
			for thread in self.minidump.threads_ex.threads:
				if thread.ThreadId == thread_id:
					return True
		return False

	@staticmethod
	def _relation(module, address):
		"""
		Classify the address against the raw half-open [base, end) range.

		Returns None when the address is unrelated to the row.
		"""
		if module.baseaddress <= address < module.endaddress:
			return BoundaryRelation.INSIDE
		if address == module.endaddress:
			return BoundaryRelation.AT_TAIL
		return None

	def attribute_address(self, address, thread_id=None, exception_code=None):
		# type: (int, Optional[int], object) -> AddressAttribution
		"""
		Resolve a single address against both module tables.

		Each matching table row becomes its own :class:`ModuleEvidence`,
		including rows that merely share a name with another row.
		"""
		result = AddressAttribution(address, thread_id, exception_code)

		for module in self.loaded_modules:
			relation = self._relation(module, address)
			if relation is not None:
				result.loaded_evidence.append(
					ModuleEvidence(
						EvidenceKind.LOADED_MODULE, module, address, relation))
		for module in self.unloaded_modules:
			relation = self._relation(module, address)
			if relation is not None:
				result.unloaded_evidence.append(
					ModuleEvidence(
						EvidenceKind.UNLOADED_MODULE, module, address, relation))

		self._finalize(result, thread_id)
		return result

	def attribute_exceptions(self):
		# type: () -> List[AddressAttribution]
		"""
		Attribute every exception record found in the exception stream.

		Returns an empty list when the dump carries no exception stream.
		Callers that need the explicit "no exception thread" statement should
		use :meth:`explain_no_exception`.
		"""
		if self.minidump.exception is None:
			return []

		results = []
		for record in self.minidump.exception.exception_records:
			address = record.ExceptionRecord.ExceptionAddress
			results.append(self.attribute_address(
				address,
				thread_id=record.ThreadId,
				exception_code=record.ExceptionRecord.ExceptionCode,
			))
		return results

	def explain_no_exception(self):
		# type: () -> AddressAttribution
		"""
		Explicit result for dumps without an exception stream/record.

		The module tables may still cover addresses, but without a faulting
		thread there is nothing to attribute, so the verdict is always
		``NO_EXCEPTION`` with zero confidence.
		"""
		result = AddressAttribution(address=None)
		result.verdict = AttributionVerdict.NO_EXCEPTION
		result.confidence = 0.0
		result.reasons.append(
			'no exception stream present in the dump; no faulting thread or '
			'address can be attributed')
		return result

	def _finalize(self, result, thread_id):
		live_thread = self._thread_exists(thread_id)
		loaded = result.loaded_evidence
		unloaded = result.unloaded_evidence

		if loaded:
			result.verdict = AttributionVerdict.LOADED_MATCH
			owner = result.owner
			result.reasons.append(
				'address 0x%x maps to loaded module %s raw range '
				'[0x%x, 0x%x), offset 0x%x' % (
					result.address, owner.name, owner.baseaddress,
					owner.endaddress, owner.offset))
			if owner.at_tail:
				result.reasons.append(
					'address equals the raw endaddress 0x%x of %s; it is '
					'the first byte past the image and is attributed with '
					'an explicit at-tail boundary condition'
					% (owner.endaddress, owner.name))
			confidence = self._LOADED_WEIGHT
			if len(loaded) > 1:
				result.reasons.append(
					'%d loaded table rows overlap at this address; each row '
					'is reported as separate evidence and none is merged'
					% len(loaded))
			if unloaded:
				result.reasons.append(
					'%d unloaded row(s) historically covered the same page; '
					'kept as historical evidence, the loaded module remains '
					'the crash-time owner' % len(unloaded))
			if thread_id is None:
				result.reasons.append(
					'address was queried without an exception thread id')
			elif live_thread:
				confidence += self._THREAD_WEIGHT
				result.reasons.append(
					'exception thread 0x%x exists in the thread list'
					% thread_id)
			else:
				result.reasons.append(
					'exception thread 0x%x is not present in any thread '
					'list' % thread_id)
			result.confidence = min(confidence, 1.0)
			return

		if unloaded:
			result.verdict = AttributionVerdict.UNLOADED_ONLY
			first = unloaded[0]
			result.reasons.append(
				'no loaded module covers 0x%x; only %d unloaded row(s) '
				'historically map it, first match %s [0x%x, 0x%x)' % (
					result.address, len(unloaded), first.name,
					first.baseaddress, first.endaddress))
			if len(unloaded) > 1:
				result.reasons.append(
					'%d unloaded rows overlap; reported individually and '
					'never merged even when names are identical'
					% len(unloaded))
			# Unloaded evidence alone can never reach the confidence of a
			# live module, no matter how many rows overlap.
			result.confidence = self._UNLOADED_WEIGHT
			return

		result.verdict = AttributionVerdict.UNATTRIBUTED
		result.confidence = 0.0
		result.reasons.append(
			'address 0x%x matches neither the loaded module table nor the '
			'unloaded module list' % result.address)


def attribute_minidump(minidump_file):
	# type: (object) -> List[AddressAttribution]
	"""
	Convenience entry point: attribute all exception records of a dump.
	"""
	return ForensicAttributor(minidump_file).attribute_exceptions()
