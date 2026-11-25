#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# Read-only comparison of minidump files that share a process ID.
#
# A lightweight dump and a full dump may reuse the same process ID while
# the process itself was restarted in between the two captures. This
# module correlates the thread stream and the ProcessVmCounters stream
# of such dumps using the caller-supplied collection window and
# generation number, and reports which entries were intended to be
# collected, which are actually present and which can not be verified
# against the caller's intent.
#
# Entries are keyed by (generation, kind, entry id) and are never merged
# on the entry id alone, so same-numbered threads that belong to
# different process generations are never joined into a single entry.
#
# The comparison is strictly read-only: dump files are only opened for
# reading and no state is written back.

import enum

from minidump.minidumpfile import MinidumpFile
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.common_structs import construct_table


class EntryKind(enum.Enum):
	THREAD = 'thread'
	COUNTERS = 'counters'


class CollectionIntent:
	"""
	Caller-supplied collection parameters.

	process_id:   expected process ID shared by the dumps (optional)
	generation:   expected process generation number, matched against the
	              dumped process' ProcessCreateTime (optional)
	window_start: start of the caller's collection window, epoch seconds (optional)
	window_end:   end of the caller's collection window, epoch seconds (optional)
	"""
	def __init__(self, process_id=None, generation=None, window_start=None, window_end=None):
		self.process_id = process_id
		self.generation = generation
		self.window_start = window_start
		self.window_end = window_end

	def mismatches(self, facts):
		"""
		Returns the list of reasons why the given dump facts can not be
		verified against this intent. An empty list means the dump matches
		the caller's collection window and generation.
		"""
		reasons = []
		if self.process_id is not None:
			if facts.process_id is None:
				reasons.append('process-id-unknown')
			elif facts.process_id != self.process_id:
				reasons.append('process-id-mismatch')
		if self.generation is not None:
			if facts.generation is None:
				reasons.append('generation-unknown')
			elif facts.generation != self.generation:
				reasons.append('generation-mismatch')
		if self.window_start is not None or self.window_end is not None:
			if not facts.captured_at:
				reasons.append('capture-time-unknown')
			else:
				if self.window_start is not None and facts.captured_at < self.window_start:
					reasons.append('before-window')
				if self.window_end is not None and facts.captured_at > self.window_end:
					reasons.append('after-window')
		return reasons


class StreamEntry:
	"""
	A single thread or counter-stream entry found in a dump, tagged with
	the process generation it belongs to.
	"""
	def __init__(self, source, generation, kind, entry_id, detail=''):
		self.source = source
		self.generation = generation
		self.kind = kind
		self.entry_id = entry_id
		self.detail = detail

	def key(self):
		# The generation is always part of the key: entries with the same
		# id (e.g. a reused thread id) from different process generations
		# must stay separate and are never joined into one entry.
		return (self.generation, self.kind, self.entry_id)

	@staticmethod
	def get_header():
		return ['Source', 'Generation', 'Kind', 'Id', 'Detail']

	def to_row(self):
		if self.kind == EntryKind.THREAD and self.entry_id is not None:
			entry_id = hex(self.entry_id)
		else:
			entry_id = str(self.entry_id)
		generation = str(self.generation) if self.generation is not None else 'unknown'
		return [str(self.source), generation, self.kind.value, entry_id, self.detail]

	def to_dict(self):
		return {
			'source': self.source,
			'generation': self.generation,
			'kind': self.kind.value,
			'id': self.entry_id,
			'detail': self.detail,
		}


class DumpFacts:
	"""
	Read-only facts extracted from a single dump file.
	"""
	def __init__(self):
		self.filename = None
		self.process_id = None
		self.generation = None   # ProcessCreateTime of the dumped process
		self.captured_at = None  # dump capture time (header TimeDateStamp)
		self.entries = []

	@staticmethod
	def extract(filename):
		mf = MinidumpFile.parse(filename)
		try:
			facts = DumpFacts()
			facts.filename = filename
			if mf.header is not None:
				facts.captured_at = mf.header.TimeDateStamp
			if mf.misc_info is not None:
				facts.process_id = mf.misc_info.ProcessId
				facts.generation = mf.misc_info.ProcessCreateTime
			threads = mf.threads if mf.threads is not None else mf.threads_ex
			if threads is not None:
				for thread in threads.threads:
					facts.entries.append(StreamEntry(filename, facts.generation, EntryKind.THREAD, thread.ThreadId))
			for directory in mf.directories:
				if directory.StreamType == MINIDUMP_STREAM_TYPE.ProcessVmCountersStream:
					detail = 'size=%d rva=0x%x' % (directory.Location.DataSize, directory.Location.Rva)
					facts.entries.append(StreamEntry(filename, facts.generation, EntryKind.COUNTERS, 'ProcessVmCounters', detail))
			return facts
		finally:
			if mf.file_handle is not None:
				mf.file_handle.close()


class ComparisonReport:
	"""
	Result of a read-only dump comparison.

	intended:     entries from dumps matching the caller's collection
	              window and generation (intent collection)
	present:      every entry actually found in the compared dumps
	unverifiable: entries that can not be checked against the caller's
	              intent, as (entry, reasons) pairs
	"""
	def __init__(self, intent):
		self.intent = intent
		self.dumps = []
		self.intended = []
		self.present = []
		self.unverifiable = []

	def to_dict(self):
		return {
			'intent': {
				'process_id': self.intent.process_id,
				'generation': self.intent.generation,
				'window_start': self.intent.window_start,
				'window_end': self.intent.window_end,
			},
			'intended': [entry.to_dict() for entry in self.intended],
			'present': [entry.to_dict() for entry in self.present],
			'unverifiable': [
				{'entry': entry.to_dict(), 'reasons': reasons}
				for entry, reasons in self.unverifiable
			],
		}

	@staticmethod
	def __section(title, header, rows):
		t = '== %s (%d) ==\n' % (title, len(rows))
		if rows:
			t += construct_table([header] + rows)
		else:
			t += '(none)\n'
		return t

	def __str__(self):
		t = '== Compared dumps ==\n'
		for facts, reasons in self.dumps:
			status = 'matches intent' if not reasons else 'unverifiable: %s' % ', '.join(reasons)
			t += '%s: pid=%s generation=%s captured_at=%s -> %s\n' % (
				facts.filename,
				facts.process_id,
				facts.generation if facts.generation is not None else 'unknown',
				facts.captured_at if facts.captured_at is not None else 'unknown',
				status,
			)
		t += '\n'
		t += self.__section('Intended (intent collection)', StreamEntry.get_header(), [entry.to_row() for entry in self.intended])
		t += '\n'
		t += self.__section('Present (actually existing)', StreamEntry.get_header(), [entry.to_row() for entry in self.present])
		t += '\n'
		header = StreamEntry.get_header() + ['Reasons']
		rows = [entry.to_row() + [', '.join(reasons)] for entry, reasons in self.unverifiable]
		t += self.__section('Unverifiable (can not be rechecked)', header, rows)
		return t


def compare_dumps(intent, filenames):
	"""
	Read-only comparison of two or more dump files that share a process
	ID (e.g. a lightweight dump and a full dump taken across a process
	restart). The caller's collection window and generation number decide
	which entries count as intended; everything found is reported as
	present, and anything that can not be verified against the intent is
	reported as unverifiable. Entries are never merged on their id alone.
	"""
	report = ComparisonReport(intent)
	for filename in filenames:
		facts = DumpFacts.extract(filename)
		reasons = intent.mismatches(facts)
		report.dumps.append((facts, reasons))
		for entry in facts.entries:
			report.present.append(entry)
			if reasons:
				report.unverifiable.append((entry, reasons))
			else:
				report.intended.append(entry)
	return report
