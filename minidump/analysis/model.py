#!/usr/bin/env python3
#
# Read-only minidump investigation model.
#
# Every object in this module only carries metadata about the dump
# (stream types, RVAs, sizes, virtual addresses, status flags). It never
# stores nor renders the raw bytes of the dumped process' memory.
#

import enum


class StreamRole(enum.Enum):
	"""Classification of a stream relative to an investigation path."""

	# The stream (or an accepted substitute) is indispensable: without any
	# carrier for the capability, the corresponding evidence cannot be
	# established at all.
	REQUIRED = 'required'

	# The stream contributes evidence, but another present stream can carry
	# the same capability, or the investigation can proceed in a degraded
	# (partial) mode without it.
	SUBSTITUTABLE = 'substitutable'

	# The stream only adds human readable context; its absence never blocks
	# the technical reconstruction.
	EXPLANATORY = 'explanatory'

	# The stream is irrelevant for the requested investigation path.
	IRRELEVANT = 'irrelevant'


class ReferenceStatus(enum.Enum):
	"""Liveness of the backing data referenced by a directory entry."""

	# Directory entry present and every location it points at resolves
	# inside the file with the declared amount of bytes.
	RESOLVED = 'resolved'

	# Directory entry present, but the data it references is missing or
	# truncated (the referenced RVA/size does not fit the file).
	DANGLING = 'dangling'

	# The directory entry itself is absent.
	ABSENT = 'absent'


class Capability(enum.Enum):
	"""Abstract investigation capabilities, decoupled from concrete streams."""

	EXCEPTION_FACTS = 'exception_facts'
	THREAD_ENUMERATION = 'thread_enumeration'
	THREAD_CONTEXT = 'thread_context'
	STACK_MEMORY = 'stack_memory'
	MODULE_RESOLUTION = 'module_resolution'
	SYSTEM_ENVIRONMENT = 'system_environment'
	PROCESS_METADATA = 'process_metadata'
	HANDLE_INVENTORY = 'handle_inventory'
	COMMENT = 'comment'


class InvestigationStage(enum.Enum):
	"""Ordered evidence stages used by the built-in investigation paths."""

	DIRECTORY = 'directory'
	EXCEPTION = 'exception'
	THREAD = 'thread'
	CONTEXT = 'context'
	STACK = 'stack'
	MODULE = 'module'
	SYSTEM = 'system'
	METADATA = 'metadata'


class InvestigationPath:
	"""
	A caller supplied investigation path.

	A path is an ordered list of evidence stages. The analyzer walks the
	stage list and, for every stream present in the dump, reverse-looks-up
	which stages the stream participates in and whether it is required,
	substitutable or merely explanatory for those stages.
	"""

	# Full crash post-mortem: exception -> faulting thread -> register
	# context -> stack memory, with modules/system info as supporting
	# evidence.
	CRASH_RECONSTRUCTION = (
		InvestigationStage.DIRECTORY,
		InvestigationStage.EXCEPTION,
		InvestigationStage.THREAD,
		InvestigationStage.CONTEXT,
		InvestigationStage.STACK,
		InvestigationStage.MODULE,
		InvestigationStage.SYSTEM,
	)

	# Degraded path used when no exception stream survived compression:
	# enumerate threads and reconstruct their contexts/stacks only.
	THREAD_ONLY_RECONSTRUCTION = (
		InvestigationStage.DIRECTORY,
		InvestigationStage.THREAD,
		InvestigationStage.CONTEXT,
		InvestigationStage.STACK,
		InvestigationStage.SYSTEM,
	)

	def __init__(self, name, stages):
		self.name = name
		self.stages = tuple(stages)

	@classmethod
	def from_string(cls, value):
		"""
		Resolve a caller supplied path specification.

		Accepted forms:
		  * 'crash' / 'full'            -> CRASH_RECONSTRUCTION
		  * 'threads' / 'thread-only'   -> THREAD_ONLY_RECONSTRUCTION
		  * comma separated stage names -> custom ordered path
		"""
		text = value.strip().lower()
		if text in ('crash', 'full', 'crash-reconstruction'):
			return cls('crash-reconstruction', cls.CRASH_RECONSTRUCTION)
		if text in ('threads', 'thread-only', 'thread-only-reconstruction'):
			return cls('thread-only-reconstruction', cls.THREAD_ONLY_RECONSTRUCTION)

		requested = []
		for raw in text.replace(';', ',').split(','):
			name = raw.strip().upper()
			if not name:
				continue
			try:
				requested.append(InvestigationStage[name])
			except KeyError:
				raise ValueError('unknown investigation stage %r' % raw)
		if not requested:
			raise ValueError('empty investigation path %r' % value)
		return cls('custom:' + text, requested)

	def contains(self, stage):
		return stage in self.stages

	def __str__(self):
		return '%s[%s]' % (self.name, ' -> '.join(s.value for s in self.stages))


class EvidenceReference:
	"""
	A single reverse-looked-up reference from a stream toward data the
	investigation path needs (thread context, stack memory, ...).

	Only location metadata is kept: no referenced bytes are ever read or
	attached to this object.
	"""

	def __init__(self, kind, owner, rva, declared_size, status,
			virtual_address=None, detail=None):
		self.kind = kind
		self.owner = owner
		self.rva = rva
		self.declared_size = declared_size
		self.status = status
		self.virtual_address = virtual_address
		self.detail = detail

	def to_dict(self):
		return {
			'kind': self.kind,
			'owner': self.owner,
			'rva': None if self.rva is None else hex(self.rva),
			'declared_size': self.declared_size,
			'virtual_address': (
				None if self.virtual_address is None else hex(self.virtual_address)
			),
			'status': self.status.value,
			'detail': self.detail,
		}

	def __str__(self):
		va = '' if self.virtual_address is None else ' va=%s' % hex(self.virtual_address)
		rva = 'rva=%s' % ('<none>' if self.rva is None else hex(self.rva))
		return '%s %s size=%s%s [%s]%s' % (
			self.kind, self.owner, self.declared_size, va,
			self.status.value,
			'' if not self.detail else ' ' + self.detail,
		)


class StreamAssessment:
	"""Per-stream verdict for the requested investigation path."""

	def __init__(self, stream_type, present, role, status, capabilities,
			references, notes=None):
		self.stream_type = stream_type
		self.present = present
		self.role = role
		self.status = status
		self.capabilities = tuple(capabilities)
		self.references = list(references)
		self.notes = list(notes or [])

	def to_dict(self):
		return {
			'stream': self.stream_type.name,
			'present': self.present,
			'role': self.role.value,
			'reference_status': self.status.value,
			'capabilities': [cap.value for cap in self.capabilities],
			'references': [ref.to_dict() for ref in self.references],
			'notes': self.notes,
		}

	def __str__(self):
		head = '%-26s present=%-5s role=%-13s refs=%s' % (
			self.stream_type.name, self.present, self.role.value, self.status.value,
		)
		lines = [head]
		for ref in self.references:
			lines.append('    - ' + str(ref))
		for note in self.notes:
			lines.append('    * ' + note)
		return '\n'.join(lines)


class InvestigationReport:
	"""
	Aggregate, serializable result of a read-only investigation.

	The report deliberately exposes only metadata and human readable
	classifications. It contains no raw process memory content.
	"""

	def __init__(self, source, file_size, path, assessments,
			capability_coverage, verdict, partial, blocking_reasons,
			dangling_references):
		self.source = source
		self.file_size = file_size
		self.path = path
		self.assessments = list(assessments)
		self.capability_coverage = dict(capability_coverage)
		self.verdict = verdict
		self.partial = partial
		self.blocking_reasons = list(blocking_reasons)
		self.dangling_references = list(dangling_references)

	def to_dict(self):
		return {
			'source': self.source,
			'file_size': self.file_size,
			'investigation_path': str(self.path),
			'verdict': self.verdict,
			'partial': self.partial,
			'blocking_reasons': self.blocking_reasons,
			'capability_coverage': {
				cap.value: state.value if hasattr(state, 'value') else state
				for cap, state in self.capability_coverage.items()
			},
			'dangling_references': [ref.to_dict() for ref in self.dangling_references],
			'streams': [item.to_dict() for item in self.assessments],
		}

	def __str__(self):
		lines = [
			'== Read-only minidump investigation ==',
			'source: %s' % self.source,
			'file size: %d bytes' % self.file_size,
			'investigation path: %s' % self.path,
			'verdict: %s (partial=%s)' % (self.verdict, self.partial),
		]
		if self.blocking_reasons:
			lines.append('blocking reasons:')
			for reason in self.blocking_reasons:
				lines.append('  - ' + reason)
		if self.dangling_references:
			lines.append('dangling references (entry present, data missing):')
			for ref in self.dangling_references:
				lines.append('  - ' + str(ref))
		lines.append('capability coverage:')
		for cap, state in sorted(self.capability_coverage.items(),
				key=lambda item: item[0].value):
			state_value = state.value if hasattr(state, 'value') else str(state)
			lines.append('  - %-20s %s' % (cap.value, state_value))
		lines.append('stream assessments:')
		for assessment in self.assessments:
			lines.append('  ' + str(assessment).replace('\n', '\n  '))
		return '\n'.join(lines)
