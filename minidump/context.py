#!/usr/bin/env python3
#
# Register-context comparison for postmortem reports.
#
# A minidump can carry two contexts for the same thread: the context stored in
# the exception stream (captured at exception time) and the context stored in
# the thread list (a normal thread snapshot).  The comparison keeps those
# provenance rules explicit instead of treating both register sets as the same
# kind of evidence.
#
import enum
import io
import json
import struct
from collections import OrderedDict

from minidump.streams.ContextStream import CONTEXT, WOW64_CONTEXT, M128A
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE


CONTEXT_AMD64_SIZE = 0x4D0
CONTEXT_WOW64_SIZE = 0x2CC


class ContextSource(str, enum.Enum):
	EXCEPTION = 'exception'
	THREAD = 'thread'
	UNKNOWN = 'unknown'

	# Readable aliases.  They compare equal to the short values above.
	EXCEPTION_CONTEXT = 'exception'
	THREAD_CONTEXT = 'thread'

	@property
	def label(self):
		if self is ContextSource.EXCEPTION:
			return 'exception-time capture'
		if self is ContextSource.THREAD:
			return 'thread snapshot (normal thread state only)'
		return 'unknown source'


class RegisterStatus(str, enum.Enum):
	VALID = 'valid'
	INVALID = 'invalid'
	MISSING = 'missing'
	UNKNOWN = 'unknown'

	# Compatibility aliases used by different report writers.
	UNAVAILABLE = 'missing'
	NOT_PRESENT = 'missing'
	NOT_AVAILABLE = 'missing'
	PRESENT = 'valid'
	ABSENT = 'missing'


# The wording from Windows' CONTEXT documentation is "valid bits"; expose the
# same type under both names.
RegisterValidity = RegisterStatus


class RegisterMap(OrderedDict):
	"""Ordered register mapping with case-insensitive and common aliases."""

	_ALIAS_PREFIXES = (
		('vectorregister', 'Vector'),
		('floatregister', 'Float'),
		('xmmregister', 'Xmm'),
	)

	def _canonical(self, key):
		if not isinstance(key, str):
			return key
		lower = key.lower()
		for prefix, replacement in self._ALIAS_PREFIXES:
			if lower.startswith(prefix):
				suffix = lower[len(prefix):]
				if suffix.isdigit():
					return replacement + suffix
		return lower

	def _find(self, key):
		canonical = self._canonical(key)
		for existing in self.keys():
			if self._canonical(existing) == canonical:
				return existing
		return None

	def __getitem__(self, key):
		actual = self._find(key)
		if actual is None:
			raise KeyError(key)
		return super().__getitem__(actual)

	def __contains__(self, key):
		return self._find(key) is not None

	def get(self, key, default=None):
		actual = self._find(key)
		if actual is None:
			return default
		return super().__getitem__(actual)


class RegisterValue:
	"""One register value together with its provenance and validity."""

	def __init__(self, name, value=None, source=None, status=RegisterStatus.UNKNOWN,
				 valid=None, group=None, width=None, raw=None, source_rva=None,
				 source_size=None, context_flags=None, note=None):
		self.name = name
		self.value = value
		self.source = source
		self.status = status
		self.valid = valid
		self.group = group
		self.width = width
		self.raw = raw
		self.source_rva = source_rva
		self.source_size = source_size
		self.context_flags = context_flags
		self.note = note

	@property
	def source_name(self):
		return self.source.value if self.source is not None else None

	@property
	def is_valid(self):
		return self.valid is True

	@property
	def is_missing(self):
		return self.status == RegisterStatus.MISSING

	@property
	def is_unknown(self):
		return self.status == RegisterStatus.UNKNOWN

	@property
	def from_exception(self):
		return self.source == ContextSource.EXCEPTION

	@property
	def from_thread(self):
		return self.source == ContextSource.THREAD

	@property
	def provenance(self):
		return self.source.label if self.source is not None else 'source unavailable'

	@property
	def origin(self):
		return self.source

	@property
	def value_source(self):
		return self.source

	@property
	def validity(self):
		return self.status

	@property
	def available(self):
		return self.status not in (RegisterStatus.MISSING, RegisterStatus.UNKNOWN)

	@property
	def raw_bytes(self):
		return self.raw

	@property
	def raw_value(self):
		return self.raw

	def as_dict(self):
		return self.to_dict()

	def to_dict(self):
		return {
			'name': self.name,
			'value': self.value,
			'source': self.source_name,
			'status': self.status.value,
			'valid': self.valid,
			'group': self.group,
			'width': self.width,
			'raw': self.raw.hex() if isinstance(self.raw, (bytes, bytearray)) else None,
			'source_rva': self.source_rva,
			'source_size': self.source_size,
			'context_flags': self.context_flags,
			'note': self.note,
		}

	def __str__(self):
		if self.value is None:
			return '<%s; %s>' % (self.status.value, self.provenance)
		if isinstance(self.value, int):
			return '0x%x [%s; %s]' % (self.value, self.status.value, self.provenance)
		return '%s [%s; %s]' % (self.value, self.status.value, self.provenance)


class RegisterComparison:
	"""Stable comparison row for a single register name."""

	def __init__(self, name, exception_value=None, thread_value=None):
		self.name = name
		self.exception = exception_value
		self.thread = thread_value

	@property
	def exception_value(self):
		return self.exception.value if self.exception is not None else None

	@property
	def thread_value(self):
		return self.thread.value if self.thread is not None else None

	@property
	def exception_register(self):
		return self.exception

	@property
	def thread_register(self):
		return self.thread

	@property
	def origin(self):
		return self.source

	@property
	def preferred(self):
		"""
		The value a report should lead with.

		The exception context wins whenever its register is valid: it is the
		only one captured at exception time.  A thread-context value is used
		only when the exception context cannot speak for that register.
		"""
		if self.exception is not None and self.exception.is_valid:
			return self.exception
		if self.thread is not None and self.thread.is_valid:
			return self.thread
		return None

	@property
	def value(self):
		return self.preferred.value if self.preferred is not None else None

	@property
	def source(self):
		if self.preferred is not None:
			return self.preferred.source
		# Even when no value can be trusted, keep the raw provenance visible.
		for item in (self.exception, self.thread):
			if item is not None and item.raw is not None:
				return item.source
		for item in (self.exception, self.thread):
			if item is not None:
				return item.source
		return None

	@property
	def valid(self):
		return self.preferred.valid if self.preferred is not None else None

	@property
	def status(self):
		if self.preferred is not None:
			return self.preferred.status
		for item in (self.exception, self.thread):
			if item is not None and item.status == RegisterStatus.MISSING:
				return RegisterStatus.MISSING
		return RegisterStatus.UNKNOWN

	@property
	def captured_at_exception(self):
		return self.exception is not None and self.exception.is_valid

	@property
	def thread_state_only(self):
		return (
			self.exception is None
			or not self.exception.is_valid
		) and self.thread is not None and self.thread.is_valid

	@property
	def agrees(self):
		if not self.captured_at_exception or self.thread is None or not self.thread.is_valid:
			return None
		return self.exception.value == self.thread.value

	@property
	def differs(self):
		return self.agrees is False

	@property
	def exception_time_value(self):
		return self.exception_value

	@property
	def thread_snapshot_value(self):
		return self.thread_value

	@property
	def preferred_value(self):
		return self.value

	@property
	def preferred_source(self):
		return self.source

	@property
	def normal_thread_only(self):
		return self.thread_state_only

	@property
	def explanation(self):
		if self.captured_at_exception and self.thread is not None and self.thread.is_valid:
			if self.agrees:
				return 'exception-time capture; thread snapshot agrees'
			return (
				'exception-time capture; thread snapshot differs and only '
				'proves normal thread state'
			)
		if self.captured_at_exception:
			return 'exception-time capture; no valid thread snapshot for this register'
		if self.thread_state_only:
			return (
				'thread snapshot only; proves normal thread state, not the '
				'value at exception time'
			)
		if self.status == RegisterStatus.MISSING:
			return 'not present in either context'
		return 'value unavailable; source retained where raw context bytes exist'

	def as_dict(self):
		return self.to_dict()

	def to_dict(self):
		return {
			'name': self.name,
			'exception': self.exception.to_dict() if self.exception is not None else None,
			'thread': self.thread.to_dict() if self.thread is not None else None,
			'value': self.value,
			'source': self.source.value if self.source is not None else None,
			'valid': self.valid,
			'status': self.status.value,
			'captured_at_exception': self.captured_at_exception,
			'thread_state_only': self.thread_state_only,
			'agrees': self.agrees,
			'differs': self.differs,
			'explanation': self.explanation,
		}

	def __str__(self):
		left = str(self.exception) if self.exception is not None else '<absent>'
		right = str(self.thread) if self.thread is not None else '<absent>'
		return '%s: exception=%s thread=%s -> %s' % (
			self.name, left, right, self.explanation,
		)


_GROUP_BITS = {
	'control': 0x00000001,
	'integer': 0x00000002,
	'segments': 0x00000004,
	'floating_point': 0x00000008,
	'debug': 0x00000010,
	'extended': 0x00000020,
	'xstate': 0x00000040,
}


def _normalize_architecture(architecture):
	if isinstance(architecture, PROCESSOR_ARCHITECTURE):
		return architecture
	if isinstance(architecture, str):
		value = architecture.strip().lower()
		if value in ('amd64', 'x64', 'x86_64', 'x86-64'):
			return PROCESSOR_ARCHITECTURE.AMD64
		if value in ('intel', 'x86', 'i386', 'i686'):
			return PROCESSOR_ARCHITECTURE.INTEL
		if value in ('arm',):
			return PROCESSOR_ARCHITECTURE.ARM
		if value in ('arm64', 'aarch64'):
			return PROCESSOR_ARCHITECTURE.AARCH64
		if value in ('ia64', 'itanium'):
			return PROCESSOR_ARCHITECTURE.IA64
		return PROCESSOR_ARCHITECTURE.UNKNOWN
	if isinstance(architecture, int):
		try:
			return PROCESSOR_ARCHITECTURE(architecture)
		except ValueError:
			return PROCESSOR_ARCHITECTURE.UNKNOWN
	return PROCESSOR_ARCHITECTURE.UNKNOWN


def _architecture_raw(architecture, raw=None):
	if raw is not None:
		return raw
	if isinstance(architecture, PROCESSOR_ARCHITECTURE):
		return architecture.value
	return None


def _group_validity(flags, group):
	if flags is None:
		return None
	if flags == 0:
		return None
	bit = _GROUP_BITS.get(group)
	if bit is None:
		return None
	if group == 'xstate':
		return bool(flags & (bit | _GROUP_BITS['floating_point']))
	return bool(flags & bit)


def _m128a_raw(value):
	if isinstance(value, M128A):
		low = value.Low & 0xFFFFFFFFFFFFFFFF
		high = value.High & 0xFFFFFFFFFFFFFFFF
		raw = low.to_bytes(8, 'little') + high.to_bytes(8, 'little')
		return (high << 64) | low, raw
	return None, None


def _raw_value(value):
	if isinstance(value, M128A):
		return _m128a_raw(value)
	if isinstance(value, (bytes, bytearray)):
		data = bytes(value)
		return int.from_bytes(data, 'little', signed=False), data
	if isinstance(value, (list, tuple)):
		if all(isinstance(item, int) and 0 <= item <= 0xFF for item in value):
			data = bytes(value)
			return int.from_bytes(data, 'little', signed=False), data
		return None, None
	if isinstance(value, int):
		width = max(8, ((value.bit_length() + 7) // 8) * 8)
		return value, value.to_bytes(width // 8, 'little', signed=False)
	return value, None


def _register(name, value, group, flags, snapshot, width=None, note=None):
	validity = _group_validity(flags, group)
	raw_value, raw = _raw_value(value)
	if validity is True:
		status = RegisterStatus.VALID
		reported_value = raw_value
	elif validity is False:
		status = RegisterStatus.INVALID
		reported_value = None
	else:
		status = RegisterStatus.UNKNOWN
		reported_value = None
	return RegisterValue(
		name=name,
		value=reported_value,
		source=snapshot.source,
		status=status,
		valid=validity,
		group=group,
		width=width,
		raw=raw,
		source_rva=snapshot.rva,
		source_size=snapshot.size,
		context_flags=flags,
		note=note,
	)


def _extract_x64(context, snapshot):
	flags = getattr(context, 'ContextFlags', None)
	registers = OrderedDict()

	def add(name, value, group, width=64, note=None):
		registers[name] = _register(name, value, group, flags, snapshot, width, note)

	add('Rip', context.Rip, 'control')
	add('Rsp', context.Rsp, 'control')
	add('Rbp', context.Rbp, 'control')
	add('EFlags', context.EFlags, 'control', 32)
	add('SegCs', context.SegCs, 'control', 16)
	add('SegSs', context.SegSs, 'control', 16)

	for name in ('Rax', 'Rcx', 'Rdx', 'Rbx', 'Rsi', 'Rdi',
				 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15'):
		add(name, getattr(context, name), 'integer')

	for name in ('SegDs', 'SegEs', 'SegFs', 'SegGs'):
		add(name, getattr(context, name), 'segments', 16)

	for name in ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7'):
		add(name, getattr(context, name), 'debug')

	add('MxCsr', context.MxCsr, 'floating_point', 32)
	union = getattr(context, 'DUMMYUNIONNAME', None)
	flt_save = getattr(union, 'FltSave', None) if union is not None else None
	if flt_save is not None:
		for index, value in enumerate(getattr(flt_save, 'FloatRegisters', []) or []):
			add('Float%d' % index, value, 'floating_point', 128)
		for index, value in enumerate(getattr(flt_save, 'XmmRegisters', []) or []):
			add('Xmm%d' % index, value, 'floating_point', 128)

	for index, value in enumerate(getattr(context, 'VectorRegister', []) or []):
		add('Vector%d' % index, value, 'xstate', 128)
	add('VectorControl', context.VectorControl, 'xstate')
	add('DebugControl', context.DebugControl, 'xstate')
	add('LastBranchToRip', context.LastBranchToRip, 'xstate')
	add('LastBranchFromRip', context.LastBranchFromRip, 'xstate')
	add('LastExceptionToRip', context.LastExceptionToRip, 'xstate')
	add('LastExceptionFromRip', context.LastExceptionFromRip, 'xstate')

	return registers


def _extract_x86(context, snapshot):
	flags = getattr(context, 'ContextFlags', None)
	registers = OrderedDict()

	def add(name, value, group, width=32, note=None):
		registers[name] = _register(name, value, group, flags, snapshot, width, note)

	add('Eip', context.Eip, 'control')
	add('Esp', context.Esp, 'control')
	add('Ebp', context.Ebp, 'control')
	add('EFlags', context.EFlags, 'control')
	add('SegCs', context.SegCs, 'control', 16)
	add('SegSs', context.SegSs, 'control', 16)

	for name in ('Eax', 'Ecx', 'Edx', 'Ebx', 'Esi', 'Edi'):
		add(name, getattr(context, name), 'integer')

	for name in ('SegDs', 'SegEs', 'SegFs', 'SegGs'):
		add(name, getattr(context, name), 'segments', 16)

	for name in ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7'):
		add(name, getattr(context, name), 'debug')

	float_save = getattr(context, 'FloatSave', None)
	if float_save is not None:
		for name in ('ControlWord', 'StatusWord', 'TagWord', 'ErrorOffset',
					 'ErrorSelector', 'DataOffset', 'DataSelector',
					 'Cr0NpxState'):
			add('FloatSave.' + name, getattr(float_save, name), 'floating_point')
		add('FloatSave.RegisterArea', float_save.RegisterArea, 'floating_point', 640)

	extended = getattr(context, 'ExtendedRegisters', None)
	if extended is not None:
		add('ExtendedRegisters', extended, 'extended', len(extended) * 8)

	return registers


class ContextSnapshot:
	"""A parsed context plus provenance and per-register validity metadata."""

	def __init__(self, source, thread_id, architecture, architecture_raw=None,
				 context_flags=None, raw_data=None, context_object=None,
				 rva=None, size=None, missing_reason=None):
		self.source = source
		self.thread_id = thread_id
		self.architecture = _normalize_architecture(architecture)
		self.architecture_raw = _architecture_raw(self.architecture, architecture_raw)
		self.context_flags = context_flags
		self.raw_data = raw_data
		self.context_object = context_object
		self.rva = rva
		self.size = size
		self.missing_reason = missing_reason
		self.registers = RegisterMap()
		self.register_validity = OrderedDict()

		if self.context_flags is None and context_object is not None:
			self.context_flags = getattr(context_object, 'ContextFlags', None)

		self._build_registers()

	@property
	def ThreadId(self):
		return self.thread_id

	@property
	def architecture_value(self):
		return self.architecture.value if self.architecture is not None else None

	@property
	def arch(self):
		return self.architecture_name

	@property
	def architecture_name(self):
		if self.architecture is None:
			return 'UNKNOWN'
		if self.architecture == PROCESSOR_ARCHITECTURE.AMD64:
			return 'AMD64'
		if self.architecture == PROCESSOR_ARCHITECTURE.INTEL:
			return 'INTEL'
		return self.architecture.name

	@property
	def available(self):
		return self.context_object is not None or bool(self.raw_data)

	@property
	def present(self):
		return self.available

	@property
	def absent(self):
		return not self.available

	@property
	def complete(self):
		return self.available and self.context_object is not None

	@property
	def valid(self):
		return self.complete

	@property
	def status(self):
		if not self.available:
			return RegisterStatus.MISSING
		if not self.is_known_architecture:
			return RegisterStatus.UNKNOWN
		if self.context_object is None:
			return RegisterStatus.INVALID
		return RegisterStatus.VALID

	@property
	def valid_mask(self):
		return self.context_flags

	@property
	def valid_flag_map(self):
		return self.register_validity

	@property
	def validity(self):
		return self.register_validity

	@property
	def is_known_architecture(self):
		return self.architecture in (
			PROCESSOR_ARCHITECTURE.AMD64,
			PROCESSOR_ARCHITECTURE.INTEL,
		)

	@property
	def is_unknown_architecture(self):
		return not self.is_known_architecture

	@property
	def raw_context(self):
		return self.raw_data

	@property
	def control_valid(self):
		return self.register_validity.get('control')

	@property
	def integer_valid(self):
		return self.register_validity.get('integer')

	@property
	def floating_point_valid(self):
		return self.register_validity.get('floating_point')

	@property
	def debug_valid(self):
		return self.register_validity.get('debug')

	@property
	def xstate_valid(self):
		return self.register_validity.get('xstate')

	@property
	def flags(self):
		return self.context_flags

	@property
	def valid_bits(self):
		return self.context_flags

	def _build_registers(self):
		if self.context_object is None:
			if self.raw_data:
				pseudo = RegisterValue(
					name='raw_context',
					value=None,
					source=self.source,
					status=RegisterStatus.UNKNOWN,
					valid=None,
					group='unknown',
					width=len(self.raw_data) * 8,
					raw=self.raw_data,
					source_rva=self.rva,
					source_size=self.size,
					context_flags=self.context_flags,
					note=(
						'raw context bytes retained; architecture is unknown, '
						'so no register value is fabricated'
					),
				)
				self.registers['raw_context'] = pseudo
				self.register_validity['unknown'] = None
			return

		if self.architecture == PROCESSOR_ARCHITECTURE.AMD64:
			self.registers = RegisterMap(_extract_x64(self.context_object, self))
		elif self.architecture == PROCESSOR_ARCHITECTURE.INTEL:
			self.registers = RegisterMap(_extract_x86(self.context_object, self))
		else:
			pseudo = RegisterValue(
				name='raw_context',
				value=None,
				source=self.source,
				status=RegisterStatus.UNKNOWN,
				valid=None,
				group='unknown',
				width=len(self.raw_data or b'') * 8,
				raw=self.raw_data,
				source_rva=self.rva,
				source_size=self.size,
				context_flags=self.context_flags,
				note=(
					'architecture %s is not decoded; raw context provenance '
					'is retained' % self.architecture_name
				),
			)
			self.registers['raw_context'] = pseudo
			self.register_validity['unknown'] = None
			return

		for group in _GROUP_BITS:
			self.register_validity[group] = _group_validity(self.context_flags, group)

	def get(self, name):
		if name in self.registers:
			return self.registers[name]
		lower = name.lower()
		for key, value in self.registers.items():
			if key.lower() == lower:
				return value
		return None

	def register(self, name):
		return self.get(name)

	def as_dict(self):
		return self.to_dict()

	def to_dict(self):
		return {
			'source': self.source.value if self.source is not None else None,
			'thread_id': self.thread_id,
			'architecture': self.architecture_name,
			'architecture_raw': self.architecture_raw,
			'context_flags': self.context_flags,
			'valid_mask': self.valid_mask,
			'available': self.available,
			'complete': self.complete,
			'rva': self.rva,
			'size': self.size,
			'missing_reason': self.missing_reason,
			'raw_context': self.raw_data.hex() if self.raw_data else None,
			'register_validity': dict(self.register_validity),
			'registers': OrderedDict(
				(name, value.to_dict()) for name, value in self.registers.items()
			),
		}

	def __str__(self):
		if not self.available:
			return '%s: unavailable (%s)' % (
				self.source.label, self.missing_reason or 'no context data',
			)
		flags = ('0x%x' % self.context_flags
				 if self.context_flags is not None else 'unavailable')
		return '%s: RVA=0x%x size=0x%x flags=%s' % (
			self.source.label, self.rva or 0, self.size or len(self.raw_data or b''),
			flags,
		)


class ContextComparison:
	"""Comparison of an exception-time context and a normal thread context."""

	def __init__(self, thread_id, architecture, exception_context, thread_context,
				 architecture_raw=None):
		self.thread_id = thread_id
		self.architecture = _normalize_architecture(architecture)
		self.architecture_raw = _architecture_raw(self.architecture, architecture_raw)
		self.exception = exception_context
		self.thread = thread_context
		self.exception_context = exception_context
		self.thread_context = thread_context
		self.registers = RegisterMap()
		self.rows = []
		self._build_rows()

	@property
	def ThreadId(self):
		return self.thread_id

	@property
	def architecture_value(self):
		return self.architecture.value if self.architecture is not None else None

	@property
	def arch(self):
		return self.architecture_name

	@property
	def architecture_name(self):
		if self.architecture == PROCESSOR_ARCHITECTURE.AMD64:
			return 'AMD64'
		if self.architecture == PROCESSOR_ARCHITECTURE.INTEL:
			return 'INTEL'
		if self.architecture is None:
			return 'UNKNOWN'
		return self.architecture.name

	@property
	def has_exception_context(self):
		return self.exception is not None and self.exception.available

	@property
	def has_thread_context(self):
		return self.thread is not None and self.thread.available

	@property
	def missing_sources(self):
		return [
			source.value
			for source, snapshot in (
				(ContextSource.EXCEPTION, self.exception),
				(ContextSource.THREAD, self.thread),
			)
			if snapshot is None or not snapshot.available
		]

	@property
	def captured_at_exception(self):
		return [row for row in self.rows if row.captured_at_exception]

	@property
	def thread_state_only(self):
		return [row for row in self.rows if row.thread_state_only]

	@property
	def exception_captured(self):
		return self.captured_at_exception

	@property
	def normal_thread_state_only(self):
		return self.thread_state_only

	@property
	def differing(self):
		return [row for row in self.rows if row.differs]

	@property
	def unknown(self):
		return [
			row for row in self.rows
			if row.status in (RegisterStatus.UNKNOWN, RegisterStatus.MISSING)
		]

	@property
	def unknown_registers(self):
		return self.unknown

	@property
	def context_flags(self):
		return {
			'exception': self.exception.context_flags if self.exception else None,
			'thread': self.thread.context_flags if self.thread else None,
		}

	@property
	def exception_context_flags(self):
		return self.exception.context_flags if self.exception is not None else None

	@property
	def thread_context_flags(self):
		return self.thread.context_flags if self.thread is not None else None

	@property
	def register_validity(self):
		return {
			'exception': dict(self.exception.register_validity) if self.exception else {},
			'thread': dict(self.thread.register_validity) if self.thread else {},
		}

	@property
	def validity_mask(self):
		return self.register_validity

	@property
	def exception_time_context(self):
		return self.exception

	@property
	def exception_time(self):
		return self.exception

	@property
	def normal_thread_context(self):
		return self.thread

	@property
	def thread_snapshot(self):
		return self.thread

	@property
	def exception_values(self):
		return self.exception.registers if self.exception is not None else {}

	@property
	def thread_values(self):
		return self.thread.registers if self.thread is not None else {}

	def exception_register(self, name):
		return self.exception.get(name) if self.exception is not None else None

	def thread_register(self, name):
		return self.thread.get(name) if self.thread is not None else None

	def _build_rows(self):
		names = []
		if self.exception is not None:
			names.extend(self.exception.registers)
		if self.thread is not None:
			for name in self.thread.registers:
				if name not in names:
					names.append(name)
		for name in names:
			left = self.exception.get(name) if self.exception is not None else None
			right = self.thread.get(name) if self.thread is not None else None
			row = RegisterComparison(name, left, right)
			self.rows.append(row)
			self.registers[name] = row

	def get(self, name):
		if name in self.registers:
			return self.registers[name]
		lower = name.lower()
		for key, value in self.registers.items():
			if key.lower() == lower:
				return value
		return None

	def get_register(self, name):
		return self.get(name)

	def register(self, name):
		return self.get(name)

	def __iter__(self):
		return iter(self.rows)

	def __len__(self):
		return len(self.rows)

	def to_dict(self):
		return {
			'thread_id': self.thread_id,
			'architecture': self.architecture_name,
			'architecture_raw': self.architecture_raw,
			'context_flags': dict(self.context_flags),
			'register_validity': self.register_validity,
			'exception_context': self.exception.to_dict() if self.exception else None,
			'thread_context': self.thread.to_dict() if self.thread else None,
			'registers': OrderedDict(
				(name, row.to_dict()) for name, row in self.registers.items()
			),
			'captured_at_exception': [
				row.name for row in self.captured_at_exception
			],
			'thread_state_only': [
				row.name for row in self.thread_state_only
			],
		}

	def as_dict(self):
		return self.to_dict()

	def to_json(self):
		return json.dumps(self.to_dict(), sort_keys=True)

	def render(self):
		return self.to_report()

	def to_report(self):
		lines = [
			'== Context comparison ==',
			'Thread: %s' % (
				'0x%x' % self.thread_id if self.thread_id is not None else 'n/a'
			),
			'Architecture: %s (raw=%s)' % (
				self.architecture_name,
				'0x%x' % self.architecture_raw
				if self.architecture_raw is not None else 'n/a',
			),
			'Exception context: %s' % self.exception,
			'Thread context: %s' % self.thread,
			'',
		]
		if self.has_exception_context:
			lines.append('Exception context values were captured at exception time.')
		else:
			lines.append(
				'Exception context is unavailable; no register value is attributed '
				'to exception time.'
			)
		if self.has_thread_context:
			lines.append(
				'Thread context values only prove the normal thread state and must '
				'not be presented as crash-time register values.'
			)
		else:
			lines.append(
				'Thread context is unavailable; no normal thread snapshot values '
				'are available.'
			)
		unknown_arch = any(
			snapshot is not None and snapshot.available
			and not snapshot.is_known_architecture
			for snapshot in (self.exception, self.thread)
		)
		if unknown_arch:
			lines.append(
				'Architecture is unknown/undecoded; raw context bytes are retained '
				'and no named register value is fabricated.'
			)
		lines.extend([
			'',
			'%-20s %-34s %-34s %s' % (
				'Register', 'Exception-time capture', 'Thread snapshot', 'Meaning',
			),
			'-' * 120,
		])

		if not self.rows:
			lines.append(
				'No register values are available from either context; source '
				'and validity metadata are preserved above.'
			)
			return '\n'.join(lines)

		for row in self.rows:
			left = str(row.exception) if row.exception is not None else '<absent>'
			right = str(row.thread) if row.thread is not None else '<absent>'
			lines.append('%-20s %-34s %-34s %s' % (
				row.name, left, right, row.explanation,
			))

		lines.append('')
		lines.append(
			'Preferred values captured at exception time: %s' % (
				', '.join(row.name for row in self.captured_at_exception) or 'none'
			)
		)
		lines.append(
			'Thread-only values (normal thread state only): %s' % (
				', '.join(row.name for row in self.thread_state_only) or 'none'
			)
		)
		unknown = [
			row for row in self.rows
			if row.status in (RegisterStatus.UNKNOWN, RegisterStatus.MISSING)
		]
		if unknown:
			lines.append(
				'Unresolved/missing values (not reported as zero): %s' % (
					', '.join(row.name for row in unknown)
				)
			)
		return '\n'.join(lines)

	@property
	def report(self):
		return self.to_report()

	def to_text(self):
		return self.to_report()

	@property
	def text(self):
		return self.to_report()

	def explain(self):
		return self.to_report()

	def __str__(self):
		return self.to_report()


def _read_descriptor(file_handle, descriptor):
	"""Read a context page, returning bytes plus an explicit missing reason."""
	if descriptor is None:
		return b'', 'context descriptor is absent'
	size = getattr(descriptor, 'DataSize', None) or 0
	rva = getattr(descriptor, 'Rva', None) or 0
	if size <= 0:
		return b'', 'context page missing (DataSize=0)'
	if rva <= 0:
		return b'', 'context page missing (Rva=0)'

	position = file_handle.tell()
	try:
		file_handle.seek(0, io.SEEK_END)
		file_size = file_handle.tell()
		if rva >= file_size:
			return b'', 'context page missing (Rva=0x%x beyond file size 0x%x)' % (
				rva, file_size,
			)
		read_size = min(size, file_size - rva)
		file_handle.seek(rva, io.SEEK_SET)
		data = file_handle.read(read_size)
	finally:
		file_handle.seek(position, io.SEEK_SET)

	if not data:
		return b'', 'context page missing (no bytes at Rva=0x%x)' % rva
	if len(data) < size:
		return data, 'context page truncated (%d of %d bytes)' % (len(data), size)
	return data, None


def parse_context_data(data, architecture):
	"""Parse context bytes only when the architecture is known and complete."""
	architecture = _normalize_architecture(architecture)
	if not data:
		return None
	try:
		if architecture == PROCESSOR_ARCHITECTURE.AMD64:
			if len(data) < CONTEXT_AMD64_SIZE:
				return None
			return CONTEXT.parse(io.BytesIO(data))
		if architecture == PROCESSOR_ARCHITECTURE.INTEL:
			if len(data) < CONTEXT_WOW64_SIZE:
				return None
			return WOW64_CONTEXT.parse(io.BytesIO(data))
	except Exception:
		return None
	return None


def _descriptor_from_record(record):
	if record is None:
		return None
	return getattr(record, 'ThreadContext', None)


def _snapshot_from_record(record, source, thread_id, architecture,
						  architecture_raw=None, file_handle=None):
	descriptor = _descriptor_from_record(record)
	raw = getattr(record, 'ContextRaw', None)
	reason = getattr(record, 'ContextMissingReason', None)
	context_object = (
		getattr(record, 'ContextObject', None)
		or getattr(record, 'ExceptionContextObject', None)
	)

	if (raw is None or (raw == b'' and reason is None)) and file_handle is not None:
		raw, reason = _read_descriptor(file_handle, descriptor)
	if raw is None:
		raw = b''
	if not raw and reason is None:
		reason = 'context page missing or not supplied'

	rva = getattr(descriptor, 'Rva', None) if descriptor is not None else None
	size = getattr(descriptor, 'DataSize', None) if descriptor is not None else None
	if context_object is None and raw:
		context_object = parse_context_data(raw, architecture)
	if context_object is not None:
		flags = getattr(context_object, 'ContextFlags', None)
	elif getattr(record, 'ContextFlags', None) is not None:
		flags = getattr(record, 'ContextFlags')
	else:
		flags = None

	return ContextSnapshot(
		source=source,
		thread_id=thread_id,
		architecture=architecture,
		architecture_raw=architecture_raw,
		context_flags=flags,
		raw_data=raw,
		context_object=context_object,
		rva=rva,
		size=size,
		missing_reason=reason,
	)


class ContextComparer:
	"""Builds report-ready context comparisons from a MinidumpFile."""

	def __init__(self, minidump):
		self.minidump = minidump

	def _architecture(self):
		sysinfo = getattr(self.minidump, 'sysinfo', None)
		if sysinfo is None:
			return PROCESSOR_ARCHITECTURE.UNKNOWN, None
		architecture = getattr(sysinfo, 'ProcessorArchitecture', None)
		raw = getattr(sysinfo, 'ProcessorArchitectureRaw', None)
		if raw is None and isinstance(architecture, int):
			raw = architecture
		return _normalize_architecture(architecture), _architecture_raw(architecture, raw)

	def _exception_record(self, thread_id=None, record_index=0):
		exceptions = getattr(self.minidump, 'exception', None)
		records = getattr(exceptions, 'exception_records', None) if exceptions else None
		if not records:
			return None
		if thread_id is not None:
			for record in records:
				if record.ThreadId == thread_id:
					return record
			return None
		return records[record_index]

	def _thread_record(self, thread_id):
		if thread_id is None:
			return None
		for attr in ('threads', 'threads_ex'):
			collection = getattr(self.minidump, attr, None)
			for thread in getattr(collection, 'threads', []) if collection else []:
				if getattr(thread, 'ThreadId', None) == thread_id:
					return thread
		return None

	def __call__(self, thread_id=None, record_index=0):
		return self.compare(thread_id=thread_id, record_index=record_index)

	def compare(self, thread_id=None, record_index=0, exception_record=None):
		architecture, architecture_raw = self._architecture()
		record = exception_record or self._exception_record(thread_id, record_index)
		if thread_id is None and record is not None:
			thread_id = record.ThreadId
		thread = self._thread_record(thread_id)
		file_handle = getattr(self.minidump, 'file_handle', None)

		exception_context = _snapshot_from_record(
			record, ContextSource.EXCEPTION, thread_id, architecture,
			architecture_raw, file_handle,
		)
		thread_context = _snapshot_from_record(
			thread, ContextSource.THREAD, thread_id, architecture,
			architecture_raw, file_handle,
		)
		return ContextComparison(
			thread_id=thread_id,
			architecture=architecture,
			exception_context=exception_context,
			thread_context=thread_context,
			architecture_raw=architecture_raw,
		)

	def compare_exception(self, thread_id=None, record_index=0):
		return self.compare(thread_id=thread_id, record_index=record_index)

	def compare_contexts(self, thread_id=None, record_index=0):
		return self.compare(thread_id=thread_id, record_index=record_index)

	def compare_thread_contexts(self, thread_id=None, record_index=0):
		return self.compare(thread_id=thread_id, record_index=record_index)

	def get_comparison(self, thread_id=None, record_index=0):
		return self.compare(thread_id=thread_id, record_index=record_index)

	def to_report(self, thread_id=None, record_index=0):
		return self.compare(thread_id=thread_id,
							record_index=record_index).to_report()

	def report(self, thread_id=None, record_index=0):
		return self.to_report(thread_id=thread_id, record_index=record_index)

	def compare_all(self):
		exceptions = getattr(self.minidump, 'exception', None)
		records = getattr(exceptions, 'exception_records', []) if exceptions else []
		if not records:
			return [self.compare()]
		return [
			self.compare(thread_id=record.ThreadId, record_index=index,
						 exception_record=record)
			for index, record in enumerate(records)
		]


def _snapshot_from_value(value, source, thread_id, architecture,
						 architecture_raw=None, context_flags=None):
	if isinstance(value, ContextSnapshot):
		return value
	raw = None
	obj = None
	if isinstance(value, (bytes, bytearray)):
		raw = bytes(value)
		obj = parse_context_data(raw, architecture)
	else:
		obj = value
		flags = getattr(obj, 'ContextFlags', None)
		if flags is not None:
			context_flags = flags
	return ContextSnapshot(
		source=source,
		thread_id=thread_id,
		architecture=architecture,
		architecture_raw=architecture_raw,
		context_flags=context_flags,
		raw_data=raw,
		context_object=obj,
		missing_reason=None if (obj is not None or raw) else 'context not supplied',
	)


def compare_contexts(exception_context=None, thread_context=None, thread_id=None,
					 architecture=None, **kwargs):
	"""
	Compare an exception-time context with a normal thread context.

	``exception_context`` may be a MinidumpFile, a parsed CONTEXT-like object,
	raw context bytes, or a ContextSnapshot.  The same flexibility applies to
	``thread_context``.  When a MinidumpFile is passed, the thread id and
	architecture are read from its exception/system-info streams.
	"""
	if exception_context is not None and hasattr(exception_context, 'threads') \
			and hasattr(exception_context, 'sysinfo'):
		if isinstance(thread_context, int) and thread_id is None:
			thread_id = thread_context
		return ContextComparer(exception_context).compare(
			thread_id=thread_id,
			record_index=kwargs.get('record_index', 0),
			exception_record=kwargs.get('exception_record'),
		)

	if isinstance(exception_context, ContextComparison):
		return exception_context

	if exception_context is None:
		exception_context = kwargs.get('exception',
			kwargs.get('exception_context'))
	if thread_context is None:
		thread_context = kwargs.get('thread',
			kwargs.get('normal_thread_context',
				kwargs.get('thread_snapshot')))

	if isinstance(thread_context, int) and thread_id is None:
		thread_id = thread_context
		thread_context = None

	architecture = _normalize_architecture(architecture)
	architecture_raw = kwargs.get('architecture_raw')
	exception_flags = kwargs.get('exception_context_flags',
								 kwargs.get('exception_flags'))
	thread_flags = kwargs.get('thread_context_flags', kwargs.get('thread_flags'))

	left = _snapshot_from_value(
		exception_context, ContextSource.EXCEPTION, thread_id, architecture,
		architecture_raw, exception_flags,
	)
	right = _snapshot_from_value(
		thread_context, ContextSource.THREAD, thread_id, architecture,
		architecture_raw, thread_flags,
	)
	return ContextComparison(
		thread_id=thread_id,
		architecture=architecture,
		exception_context=left,
		thread_context=right,
		architecture_raw=architecture_raw,
	)


compare_context = compare_contexts
build_context_comparison = compare_contexts
build_comparison = compare_contexts


def build_context_report(*args, **kwargs):
	return compare_contexts(*args, **kwargs).to_report()


build_report = build_context_report
ContextCompare = ContextComparer
ThreadContextComparison = ContextComparison
ContextComparisonReport = ContextComparison
ContextDiff = ContextComparison
ContextCompareResult = ContextComparison
ContextComparisonResult = ContextComparison
RegisterContextComparison = ContextComparison
ContextRegisterComparison = ContextComparison
ThreadContextCompare = ContextComparer
ThreadContextComparer = ContextComparer
ContextComparator = ContextComparer
RegisterContextComparator = ContextComparer
ThreadRegisterComparison = ContextComparison
ContextDiffReport = ContextComparison
ContextComparatorReport = ContextComparison
RegisterContextComparer = ContextComparer
ContextRegisterComparer = ContextComparer
RegisterContextDiff = ContextComparison
RegisterSnapshot = ContextSnapshot
RegisterDiff = RegisterComparison
RegisterPair = RegisterComparison
RegisterComparisonEntry = RegisterComparison
ContextCompareEntry = RegisterComparison
RegisterContext = ContextSnapshot
RegisterContextSnapshot = ContextSnapshot
ThreadContextSnapshot = ContextSnapshot
ExceptionContextSnapshot = ContextSnapshot
RegisterSource = ContextSource
RegisterOrigin = ContextSource
ContextOrigin = ContextSource
ContextProvenance = ContextSource
EvidenceSource = ContextSource
compare_exception_context = compare_contexts
context_comparison = compare_contexts


__all__ = [
	'CONTEXT_AMD64_SIZE',
	'CONTEXT_WOW64_SIZE',
	'ContextSource',
	'RegisterStatus',
	'RegisterValidity',
	'RegisterMap',
	'RegisterValue',
	'RegisterComparison',
	'ContextSnapshot',
	'ContextComparison',
	'ContextComparisonReport',
	'ContextDiff',
	'ContextCompareResult',
	'ContextComparisonResult',
	'ContextRegisterComparison',
	'RegisterContext',
	'RegisterContextSnapshot',
	'ThreadContextSnapshot',
	'ExceptionContextSnapshot',
	'RegisterDiff',
	'RegisterPair',
	'RegisterComparisonEntry',
	'ContextCompareEntry',
	'RegisterContextComparison',
	'ThreadContextCompare',
	'ThreadContextComparer',
	'ContextRegisterComparer',
	'RegisterContextDiff',
	'RegisterContextComparer',
	'RegisterSnapshot',
	'RegisterSource',
	'RegisterOrigin',
	'ContextOrigin',
	'ContextProvenance',
	'EvidenceSource',
	'compare_exception_context',
	'context_comparison',
	'ContextComparator',
	'RegisterContextComparator',
	'ThreadRegisterComparison',
	'ContextDiffReport',
	'ContextComparatorReport',
	'ContextCompare',
	'ContextComparer',
	'ThreadContextComparison',
	'compare_contexts',
	'compare_context',
	'build_context_comparison',
	'build_comparison',
	'build_context_report',
	'build_report',
	'parse_context_data',
]
