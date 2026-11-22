#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io

# The ProcessVmCountersStream carries a VM_COUNTERS_EX (or VM_COUNTERS_EX2)
# structure as used by NtQueryInformationProcess(ProcessVmCounters).
# The stream itself has no header, so the layout is inferred from the
# stream size and the pointer size of the dumped process.
#
# VM_COUNTERS_EX  (winternl.h):
#   SIZE_T PeakVirtualSize;
#   SIZE_T VirtualSize;
#   ULONG  PageFaultCount;
#   SIZE_T PeakWorkingSetSize;
#   SIZE_T WorkingSetSize;
#   SIZE_T QuotaPeakPagedPoolUsage;
#   SIZE_T QuotaPagedPoolUsage;
#   SIZE_T QuotaPeakNonPagedPoolUsage;
#   SIZE_T QuotaNonPagedPoolUsage;
#   SIZE_T PagefileUsage;
#   SIZE_T PeakPagefileUsage;
#   SIZE_T PrivateUsage;
# VM_COUNTERS_EX2 appends:
#   SIZE_T PrivateWorkingSetSize;
#   SIZE_T SharedCommitUsage;

VM_COUNTER_FIELDS_EX = [
	'PeakVirtualSize',
	'VirtualSize',
	'PageFaultCount',
	'PeakWorkingSetSize',
	'WorkingSetSize',
	'QuotaPeakPagedPoolUsage',
	'QuotaPagedPoolUsage',
	'QuotaPeakNonPagedPoolUsage',
	'QuotaNonPagedPoolUsage',
	'PagefileUsage',
	'PeakPagefileUsage',
	'PrivateUsage',
]

VM_COUNTER_FIELDS_EX2 = VM_COUNTER_FIELDS_EX + [
	'PrivateWorkingSetSize',
	'SharedCommitUsage',
]

# stream size -> (pointer size, field list)
_KNOWN_LAYOUTS = {
	48: (4, VM_COUNTER_FIELDS_EX),
	56: (4, VM_COUNTER_FIELDS_EX2),
	96: (8, VM_COUNTER_FIELDS_EX),
	112: (8, VM_COUNTER_FIELDS_EX2),
}


class MinidumpProcessVmCounters:
	def __init__(self):
		self.counters = {}       # field name -> int
		self.pointer_size = None # 4 or 8 when the layout was recognized
		self.is_recognized = False
		self.raw_data = None     # kept when the layout is not recognized

	@staticmethod
	def parse(dir, buff):
		t = MinidumpProcessVmCounters()
		buff.seek(dir.Location.Rva)
		data = buff.read(dir.Location.DataSize)
		t._parse_data(data)
		return t

	@staticmethod
	async def aparse(dir, buff):
		t = MinidumpProcessVmCounters()
		await buff.seek(dir.Location.Rva)
		data = await buff.read(dir.Location.DataSize)
		t._parse_data(data)
		return t

	def _parse_data(self, data):
		layout = _KNOWN_LAYOUTS.get(len(data))
		if layout is None:
			self.raw_data = data
			return
		pointer_size, fields = layout
		self.pointer_size = pointer_size
		chunk = io.BytesIO(data)
		for field in fields:
			if field == 'PageFaultCount':
				value = int.from_bytes(chunk.read(4), byteorder='little', signed=False)
				if pointer_size == 8:
					chunk.read(4)  # alignment padding
			else:
				value = int.from_bytes(chunk.read(pointer_size), byteorder='little', signed=False)
			self.counters[field] = value
		self.is_recognized = True

	def __getattr__(self, name):
		if name in VM_COUNTER_FIELDS_EX2:
			return self.counters.get(name)
		raise AttributeError(name)

	def __str__(self):
		t = '== MinidumpProcessVmCounters ==\n'
		if not self.is_recognized:
			size = len(self.raw_data) if self.raw_data is not None else 0
			t += 'Unrecognized layout, %d raw bytes kept\n' % size
			return t
		for field, value in self.counters.items():
			t += '%s: %s\n' % (field, value)
		return t
