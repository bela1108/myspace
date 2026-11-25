#!/usr/bin/env python3
#
# Read-only impact analyzer for minidump files.
#
# The analyzer answers a single operational question: for a caller supplied
# investigation path, which streams are required, which ones have an
# accepted substitute, and which ones only carry explanatory context?
#
# It works strictly read-only: it never opens a stream for content
# extraction and it never reads the bytes referenced by location
# descriptors. Only directory metadata (RVA/size/virtual addresses) is
# inspected, which also makes dangling references detectable.
#

from minidump.analysis.model import (
	StreamRole,
	ReferenceStatus,
	Capability,
	InvestigationStage,
	InvestigationPath,
	EvidenceReference,
	StreamAssessment,
	InvestigationReport,
)
from minidump.constants import MINIDUMP_STREAM_TYPE


class ReadOnlyAnalysisError(Exception):
	pass


class _CapabilityState:
	RESOLVED = 'resolved'
	DEGRADED = 'degraded'
	DANGLING = 'dangling'
	ABSENT = 'absent'


# Static knowledge table: which investigation stages each stream feeds.
# The effective role (required / substitutable / explanatory) is derived
# from this table together with the stream that actually carries the
# capability in the current dump.
STREAM_STAGE_CAPABILITIES = {
	MINIDUMP_STREAM_TYPE.ExceptionStream: (
		(InvestigationStage.EXCEPTION, Capability.EXCEPTION_FACTS),
	),
	MINIDUMP_STREAM_TYPE.ThreadListStream: (
		(InvestigationStage.THREAD, Capability.THREAD_ENUMERATION),
		(InvestigationStage.CONTEXT, Capability.THREAD_CONTEXT),
		(InvestigationStage.STACK, Capability.STACK_MEMORY),
	),
	MINIDUMP_STREAM_TYPE.ThreadExListStream: (
		(InvestigationStage.THREAD, Capability.THREAD_ENUMERATION),
		(InvestigationStage.CONTEXT, Capability.THREAD_CONTEXT),
		(InvestigationStage.STACK, Capability.STACK_MEMORY),
	),
	MINIDUMP_STREAM_TYPE.MemoryListStream: (
		(InvestigationStage.STACK, Capability.STACK_MEMORY),
	),
	MINIDUMP_STREAM_TYPE.Memory64ListStream: (
		(InvestigationStage.STACK, Capability.STACK_MEMORY),
	),
	MINIDUMP_STREAM_TYPE.ModuleListStream: (
		(InvestigationStage.MODULE, Capability.MODULE_RESOLUTION),
	),
	MINIDUMP_STREAM_TYPE.UnloadedModuleListStream: (
		(InvestigationStage.MODULE, Capability.MODULE_RESOLUTION),
	),
	MINIDUMP_STREAM_TYPE.SystemInfoStream: (
		(InvestigationStage.SYSTEM, Capability.SYSTEM_ENVIRONMENT),
	),
	MINIDUMP_STREAM_TYPE.MiscInfoStream: (
		(InvestigationStage.METADATA, Capability.PROCESS_METADATA),
	),
	MINIDUMP_STREAM_TYPE.MemoryInfoListStream: (
		(InvestigationStage.METADATA, Capability.PROCESS_METADATA),
	),
	MINIDUMP_STREAM_TYPE.ThreadInfoListStream: (
		(InvestigationStage.METADATA, Capability.PROCESS_METADATA),
	),
	MINIDUMP_STREAM_TYPE.HandleDataStream: (
		(InvestigationStage.METADATA, Capability.HANDLE_INVENTORY),
	),
	MINIDUMP_STREAM_TYPE.CommentStreamA: (
		(InvestigationStage.METADATA, Capability.COMMENT),
	),
	MINIDUMP_STREAM_TYPE.CommentStreamW: (
		(InvestigationStage.METADATA, Capability.COMMENT),
	),
}

# Capabilities whose absence still allows a technically meaningful,
# albeit partial, reconstruction.
SUBSTITUTABLE_CAPABILITIES = frozenset({
	Capability.STACK_MEMORY,
	Capability.MODULE_RESOLUTION,
})

# Capabilities that only enrich the narrative and never block a stage.
EXPLANATORY_CAPABILITIES = frozenset({
	Capability.PROCESS_METADATA,
	Capability.HANDLE_INVENTORY,
	Capability.COMMENT,
	Capability.SYSTEM_ENVIRONMENT,
})


class MinidumpImpactAnalyzer:
	"""
	Read-only impact analyzer.

	Given a parsed :class:`MinidumpFile` and a caller supplied
	:class:`InvestigationPath`, it reverse-looks-up the directory entries,
	threads, exception records and stack memory references and classifies
	every stream as required, substitutable or explanatory for that path.

	The analyzer never calls the memory reader and never returns raw bytes:
	all checks are performed on location descriptors (RVA/size) against the
	file size, which is exactly what allows dangling references to be
	reported without touching the referenced content.
	"""

	def __init__(self, minidump_file):
		self.mf = minidump_file
		self.file_size = self._measure_file_size()
		self._present_types = frozenset(
			entry.StreamType for entry in minidump_file.directories
		)

	def _measure_file_size(self):
		handle = self.mf.file_handle
		position = handle.tell()
		handle.seek(0, 2)
		size = handle.tell()
		handle.seek(position, 0)
		return size

	def _location_is_resolved(self, location):
		if location is None:
			return False
		if location.Rva is None or location.DataSize is None:
			return False
		return location.Rva + location.DataSize <= self.file_size

	def _reference_for_location(self, kind, owner, location,
			virtual_address=None, detail=None):
		if location is None:
			return EvidenceReference(
				kind, owner, None, None, ReferenceStatus.ABSENT,
				virtual_address=virtual_address, detail=detail,
			)
		status = (
			ReferenceStatus.RESOLVED
			if self._location_is_resolved(location)
			else ReferenceStatus.DANGLING
		)
		return EvidenceReference(
			kind, owner, location.Rva, location.DataSize, status,
			virtual_address=virtual_address, detail=detail,
		)

	def analyze(self, path):
		if isinstance(path, str):
			path = InvestigationPath.from_string(path)
		self.path = path
		assessments = []
		for stream_type, entries in STREAM_STAGE_CAPABILITIES.items():
			assessment = self._assess_stream(stream_type, entries, path)
			if assessment is not None:
				assessments.append(assessment)

		coverage = self._build_capability_coverage(assessments, path)
		dangling = []
		for assessment in assessments:
			dangling.extend(
				ref for ref in assessment.references
				if ref.status == ReferenceStatus.DANGLING
			)
		blocking, verdict, partial = self._build_verdict(
			path, coverage, dangling,
		)
		return InvestigationReport(
			source=self.mf.filename or '<buffer>',
			file_size=self.file_size,
			path=path,
			assessments=assessments,
			capability_coverage=coverage,
			verdict=verdict,
			partial=partial,
			blocking_reasons=blocking,
			dangling_references=dangling,
		)

	def _assess_stream(self, stream_type, stage_capabilities, path):
		relevant = [(stage, cap) for stage, cap in stage_capabilities
			if path.contains(stage)]
		if not relevant:
			return None
		capabilities = tuple(dict.fromkeys(cap for _, cap in relevant))
		present = stream_type in self._present_types
		references = []
		notes = []
		if present:
			references = [self._directory_reference(stream_type)]
			references.extend(self._collect_references(stream_type))
			status = self._aggregate_status(references)
		else:
			status = ReferenceStatus.ABSENT
		role = self._derive_role(stream_type, capabilities, present, references)
		if not present:
			notes.append('directory entry absent from this trimmed dump')
		elif role == StreamRole.SUBSTITUTABLE:
			notes.append('evidence also available through another stream or degraded path')
		return StreamAssessment(
			stream_type=stream_type, present=present, role=role,
			status=status, capabilities=capabilities,
			references=references, notes=notes,
		)

	def _derive_role(self, stream_type, capabilities, present, references):
		if all(cap in EXPLANATORY_CAPABILITIES for cap in capabilities):
			return StreamRole.EXPLANATORY
		if all(cap in SUBSTITUTABLE_CAPABILITIES for cap in capabilities):
			return StreamRole.SUBSTITUTABLE
		# Streams that share a hard capability with a sibling stream are
		# substitutable carriers: ThreadList vs ThreadEx, MemoryList vs
		# Memory64List, ModuleList vs UnloadedModuleList.
		if self._has_sibling_carrier(stream_type, capabilities):
			return StreamRole.SUBSTITUTABLE
		return StreamRole.REQUIRED

	def _has_sibling_carrier(self, stream_type, capabilities):
		siblings = {
			MINIDUMP_STREAM_TYPE.ThreadListStream:
				MINIDUMP_STREAM_TYPE.ThreadExListStream,
			MINIDUMP_STREAM_TYPE.ThreadExListStream:
				MINIDUMP_STREAM_TYPE.ThreadListStream,
			MINIDUMP_STREAM_TYPE.MemoryListStream:
				MINIDUMP_STREAM_TYPE.Memory64ListStream,
			MINIDUMP_STREAM_TYPE.Memory64ListStream:
				MINIDUMP_STREAM_TYPE.MemoryListStream,
			MINIDUMP_STREAM_TYPE.ModuleListStream:
				MINIDUMP_STREAM_TYPE.UnloadedModuleListStream,
			MINIDUMP_STREAM_TYPE.UnloadedModuleListStream:
				MINIDUMP_STREAM_TYPE.ModuleListStream,
		}
		sibling = siblings.get(stream_type)
		return sibling is not None and sibling in self._present_types

	def _aggregate_status(self, references):
		if not references:
			return ReferenceStatus.RESOLVED
		if any(ref.status == ReferenceStatus.DANGLING for ref in references):
			return ReferenceStatus.DANGLING
		if all(ref.status == ReferenceStatus.ABSENT for ref in references):
			return ReferenceStatus.ABSENT
		return ReferenceStatus.RESOLVED


	def _directory_location(self, stream_type):
		for entry in self.mf.directories:
			if entry.StreamType == stream_type:
				return entry.Location
		return None

	def _directory_reference(self, stream_type):
		# The directory entry is itself a reference toward the stream body.
		# Validating it independently of the (possibly failed) high level
		# parser is what reveals an entry that survived compression while
		# the backing data did not.
		return self._reference_for_location(
			'directory-entry', stream_type.name,
			self._directory_location(stream_type),
			detail='stream directory location descriptor',
		)

	def _collect_references(self, stream_type):
		mf = self.mf
		if stream_type == MINIDUMP_STREAM_TYPE.ExceptionStream and mf.exception:
			return self._exception_references()
		if stream_type == MINIDUMP_STREAM_TYPE.ThreadListStream and mf.threads:
			return self._thread_references(mf.threads.threads, owner='thread')
		if stream_type == MINIDUMP_STREAM_TYPE.ThreadExListStream and mf.threads_ex:
			return self._thread_references(mf.threads_ex.threads, owner='thread-ex')
		if stream_type == MINIDUMP_STREAM_TYPE.MemoryListStream and mf.memory_segments:
			return self._memory_list_references(mf.memory_segments.memory_segments)
		if stream_type == MINIDUMP_STREAM_TYPE.Memory64ListStream and mf.memory_segments_64:
			return self._memory_list_references(mf.memory_segments_64.memory_segments)
		return []

	def _exception_references(self):
		refs = []
		for index, record in enumerate(self.mf.exception.exception_records):
			owner = 'exception[%d].thread-%d' % (index, record.ThreadId)
			refs.append(self._reference_for_location(
				'exception-context', owner, record.ThreadContext,
				detail='faulting thread register context',
			))
		return refs

	def _thread_references(self, threads, owner):
		refs = []
		for thread in threads:
			label = '%s[%d]' % (owner, thread.ThreadId)
			refs.append(self._reference_for_location(
				'thread-context', label, thread.ThreadContext,
				detail='register context',
			))
			stack_location = getattr(thread.Stack, 'MemoryLocation', None)
			refs.append(self._reference_for_location(
				'thread-stack', label, stack_location,
				virtual_address=thread.Stack.StartOfMemoryRange,
				detail='inline stack range descriptor',
			))
		return refs

	def _memory_list_references(self, segments):
		refs = []
		for index, segment in enumerate(segments):
			location = type('Location', (), {
				'Rva': segment.start_file_address,
				'DataSize': segment.size,
			})()
			refs.append(self._reference_for_location(
				'memory-range', 'memory[%d]' % index, location,
				virtual_address=segment.start_virtual_address,
				detail='process virtual memory range',
			))
		return refs

	def _build_capability_coverage(self, assessments, path):
		wanted = set()
		for entries in STREAM_STAGE_CAPABILITIES.values():
			for stage, cap in entries:
				if path.contains(stage):
					wanted.add(cap)
		carriers = {cap: [] for cap in wanted}
		for assessment in assessments:
			for cap in assessment.capabilities:
				if cap in carriers:
					carriers[cap].append(assessment)
		coverage = {}
		for cap in sorted(wanted, key=lambda item: item.value):
			coverage[cap] = self._coverage_state(carriers.get(cap, []))
		return coverage

	def _coverage_state(self, carriers):
		if not carriers:
			return _CapabilityState.ABSENT
		healthy = [item for item in carriers
			if item.present and item.status != ReferenceStatus.DANGLING]
		dangling = [item for item in carriers
			if item.present and item.status == ReferenceStatus.DANGLING]
		if healthy:
			return _CapabilityState.RESOLVED
		if dangling:
			return _CapabilityState.DANGLING
		return _CapabilityState.ABSENT

	def _build_verdict(self, path, coverage, dangling):
		blocking = []
		partial = False
		for cap, state in coverage.items():
			if state == _CapabilityState.RESOLVED:
				continue
			if cap in EXPLANATORY_CAPABILITIES:
				partial = True
				continue
			if cap in SUBSTITUTABLE_CAPABILITIES:
				partial = True
				blocking.append(
					'%s only partially available (%s)' % (cap.value, state)
				)
				continue
			if state == _CapabilityState.DANGLING:
				blocking.append(
					'%s directory entry present but referenced data is missing'
					% cap.value
				)
			else:
				blocking.append('%s has no surviving stream' % cap.value)
		if not blocking:
			verdict = 'full reconstruction possible'
		elif self._hard_blocked(coverage):
			verdict = 'reconstruction blocked'
		else:
			verdict = 'partial reconstruction possible'
		return blocking, verdict, partial

	def _hard_blocked(self, coverage):
		for cap, state in coverage.items():
			if cap in EXPLANATORY_CAPABILITIES or cap in SUBSTITUTABLE_CAPABILITIES:
				continue
			if state != _CapabilityState.RESOLVED:
				return True
		return False
