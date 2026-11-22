#!/usr/bin/env python3
#
# Read-only cross-dump comparison entry point.
#
# Incident response sometimes leaves several minidumps of the same process
# number (PID) behind, even though the process itself was restarted between
# captures. The dump format does not record which process *generation* a
# capture belongs to, so this module relies on caller-supplied metadata
# (capture time window + process generation number, recorded elsewhere at
# capture time) to join the thread table and the VM counters table of each
# dump and to confront what was meant to be captured with what actually
# ended up in the files.
#
# Everything here is strictly read-only: dump files are only ever opened
# in binary read mode and no stream is modified.
#
# Identity rule: a thread id only identifies a thread within one process
# generation. Identical thread ids showing up under different generation
# numbers are reported as collisions and are NEVER stitched together into
# a single timeline.

import enum
import json
import logging
from datetime import datetime, timezone

from minidump.minidumpfile import MinidumpFile

logger = logging.getLogger(__name__)


class CaptureIntent(enum.Enum):
	THREADS = 'threads'
	VM_COUNTERS = 'vm_counters'


def _parse_timestamp(value):
	"""
	Accepts epoch seconds (int/float) or an ISO 8601 string.
	Naive ISO timestamps are treated as UTC. Returns epoch seconds.
	"""
	if isinstance(value, (int, float)):
		return int(value)
	if isinstance(value, str):
		text = value.strip()
		if text.endswith('Z'):
			text = text[:-1] + '+00:00'
		try:
			dt = datetime.fromisoformat(text)
		except ValueError:
			return int(float(text))
		if dt.tzinfo is None:
			dt = dt.replace(tzinfo=timezone.utc)
		return int(dt.timestamp())
	raise ValueError('Unsupported timestamp value: %r' % (value,))


class CaptureContext:
	"""
	Caller-recorded metadata for one captured dump: which file, which
	process generation it belongs to, the capture time window and what
	the capture was supposed to collect (capture intent).
	"""
	def __init__(self, label, path, generation, window_start, window_end, intent):
		self.label = label
		self.path = path
		self.generation = int(generation)
		self.window_start = _parse_timestamp(window_start)
		self.window_end = _parse_timestamp(window_end)
		if self.window_end < self.window_start:
			raise ValueError('Capture window end is before window start for %s' % label)
		self.intent = frozenset(self._normalize_intent(intent))

	@staticmethod
	def _normalize_intent(intent):
		for item in intent:
			if isinstance(item, CaptureIntent):
				yield item
			else:
				yield CaptureIntent(str(item))

	@staticmethod
	def from_dict(entry):
		window = entry.get('window')
		if isinstance(window, dict):
			window_start = window.get('start')
			window_end = window.get('end')
		elif isinstance(window, (list, tuple)) and len(window) == 2:
			window_start, window_end = window
		else:
			raise ValueError('Capture entry %r needs a window of {start, end} or [start, end]' % (entry.get('label'),))
		return CaptureContext(
			label = entry.get('label') or entry['path'],
			path = entry['path'],
			generation = entry['generation'],
			window_start = window_start,
			window_end = window_end,
			intent = entry.get('intent', []),
		)

	@staticmethod
	def load_manifest(manifest_path):
		import os
		with open(manifest_path, 'r') as f:
			manifest = json.load(f)
		base = os.path.dirname(os.path.abspath(manifest_path))
		contexts = []
		for entry in manifest.get('captures', []):
			entry = dict(entry)
			if not os.path.isabs(entry['path']):
				entry['path'] = os.path.join(base, entry['path'])
			contexts.append(CaptureContext.from_dict(entry))
		return contexts


class CapturedDump:
	"""
	Read-only view of one dump file, joined with its CaptureContext.
	"""
	def __init__(self, context):
		self.context = context
		self.pid = None
		self.capture_time = None
		self.thread_ids = []
		self.threads_present = False
		self.counters_present = False
		self.counters_recognized = False
		self.counters = None

	@staticmethod
	def load(context):
		dump = CapturedDump(context)
		mf = MinidumpFile.parse(context.path)  # opens the file read-only
		try:
			dump.capture_time = mf.header.TimeDateStamp
			if mf.misc_info is not None:
				dump.pid = mf.misc_info.ProcessId
			if mf.threads is not None:
				dump.threads_present = True
				dump.thread_ids = [t.ThreadId for t in mf.threads.threads]
			if mf.vm_counters is not None:
				dump.counters_present = True
				dump.counters_recognized = mf.vm_counters.is_recognized
				dump.counters = mf.vm_counters
		finally:
			if mf.file_handle is not None:
				mf.file_handle.close()
		return dump


class ReportItem:
	def __init__(self, capture, intent, detail):
		self.capture = capture
		self.intent = intent  # CaptureIntent or None for capture-level findings
		self.detail = detail

	def to_dict(self):
		return {
			'capture': self.capture,
			'intent': self.intent.value if self.intent is not None else None,
			'detail': self.detail,
		}

	def __str__(self):
		intent = self.intent.value if self.intent is not None else 'capture'
		return '[%s] (%s) %s' % (self.capture, intent, self.detail)


class ComparisonReport:
	def __init__(self):
		self.intended = []   # ReportItem: what the capture was supposed to collect
		self.captured = []   # ReportItem: what actually made it into the dump
		self.missed = []     # ReportItem: intended but not captured
		self.uncertain = []  # ReportItem: present but cannot be re-verified
		self.notes = []      # informational observations (e.g. PID reuse)
		# generation -> {'pids': set, 'captures': [label], 'thread_ids': set,
		#                'counters': {label: counters}}
		# This is the ONLY join scope: threads and counters are connected
		# within one generation, never across generations.
		self.generations = {}

	def to_dict(self):
		return {
			'intended': [i.to_dict() for i in self.intended],
			'captured': [i.to_dict() for i in self.captured],
			'missed': [i.to_dict() for i in self.missed],
			'uncertain': [i.to_dict() for i in self.uncertain],
			'notes': list(self.notes),
			'generations': {
				str(gen): {
					'pids': sorted(data['pids']) if data['pids'] else [],
					'captures': list(data['captures']),
					'thread_ids': sorted(data['thread_ids']),
					'counters': sorted(data['counters'].keys()),
				}
				for gen, data in sorted(self.generations.items())
			},
		}

	@staticmethod
	def _filter(items, intents):
		if intents is None:
			return items
		return [i for i in items if i.intent is None or i.intent in intents]

	def to_text(self, sections=None, intents=None):
		all_sections = ['intended', 'captured', 'missed', 'uncertain']
		if sections is None:
			sections = all_sections
		lines = []
		for section in sections:
			items = self._filter(getattr(self, section), intents)
			lines.append('== %s ==' % section.upper())
			if not items:
				lines.append('  (none)')
			for item in items:
				lines.append('  %s' % item)
		if self.notes:
			lines.append('== NOTES ==')
			for note in self.notes:
				lines.append('  %s' % note)
		return '\n'.join(lines)


def _format_tid(tid):
	return '0x%x' % tid


def compare_captures(contexts):
	"""
	Compares the dumps described by the given CaptureContext objects.
	Returns a ComparisonReport. Never modifies the dump files.
	"""
	report = ComparisonReport()
	dumps = []
	for context in contexts:
		dump = CapturedDump.load(context)
		dumps.append(dump)
		gen = report.generations.setdefault(dump.context.generation, {
			'pids': set(), 'captures': [], 'thread_ids': set(), 'counters': {},
		})
		gen['captures'].append(dump.context.label)
		if dump.pid is not None:
			gen['pids'].add(dump.pid)

	for dump in dumps:
		ctx = dump.context
		gen = report.generations[ctx.generation]

		if dump.capture_time is not None and not (ctx.window_start <= dump.capture_time <= ctx.window_end):
			report.uncertain.append(ReportItem(ctx.label, None,
				'dump timestamp %d falls outside the caller-recorded capture window [%d, %d]; '
				'cannot re-verify when this capture was taken'
				% (dump.capture_time, ctx.window_start, ctx.window_end)))

		for intent in sorted(ctx.intent, key=lambda i: i.value):
			report.intended.append(ReportItem(ctx.label, intent, 'capture was meant to collect %s' % intent.value))
			if intent == CaptureIntent.THREADS:
				if dump.threads_present and dump.thread_ids:
					gen['thread_ids'].update(dump.thread_ids)
					report.captured.append(ReportItem(ctx.label, intent,
						'%d thread(s): %s' % (len(dump.thread_ids), ', '.join(_format_tid(t) for t in dump.thread_ids))))
				else:
					report.missed.append(ReportItem(ctx.label, intent,
						'no thread list stream found in the dump'))
			elif intent == CaptureIntent.VM_COUNTERS:
				if dump.counters_present and dump.counters_recognized:
					gen['counters'][ctx.label] = dump.counters
					report.captured.append(ReportItem(ctx.label, intent,
						'VM counters captured (%d values)' % len(dump.counters.counters)))
				elif dump.counters_present:
					report.uncertain.append(ReportItem(ctx.label, intent,
						'VM counters stream present but layout not recognized; '
						'counter values can only be treated as not re-verified'))
				else:
					report.missed.append(ReportItem(ctx.label, intent,
						'no VM counters stream found in the dump'))

	# Identity checks across captures. Generations are caller-supplied, so a
	# shared PID across generations means the PID was reused (process was
	# restarted); a PID change within one generation contradicts the metadata.
	gen_groups = {}
	for dump in dumps:
		gen_groups.setdefault(dump.context.generation, []).append(dump)

	for generation, members in sorted(gen_groups.items()):
		pids = {m.pid for m in members if m.pid is not None}
		if len(pids) > 1:
			for m in members:
				report.uncertain.append(ReportItem(m.context.label, None,
					'process id %s conflicts with other captures of generation %d (%s); '
					'generation metadata cannot be re-verified'
					% (m.pid, generation, ', '.join(sorted(str(p) for p in pids)))))

	pid_to_gens = {}
	for dump in dumps:
		if dump.pid is not None:
			pid_to_gens.setdefault(dump.pid, set()).add(dump.context.generation)
	for pid, gens in sorted(pid_to_gens.items()):
		if len(gens) > 1:
			report.notes.append(
				'process id %d appears in generations %s: same process number, '
				'different process generations (restart between captures)'
				% (pid, ', '.join(str(g) for g in sorted(gens))))

	# Thread identity: identical thread ids in different generations must not
	# be stitched into one timeline. Report them as collisions instead.
	tid_to_gens = {}
	for dump in dumps:
		for tid in dump.thread_ids:
			tid_to_gens.setdefault(tid, {}).setdefault(dump.context.generation, []).append(dump.context.label)
	for tid, gens in sorted(tid_to_gens.items()):
		if len(gens) > 1:
			where = ', '.join(
				'generation %d (%s)' % (g, ', '.join(labels))
				for g, labels in sorted(gens.items())
			)
			for g, labels in sorted(gens.items()):
				for label in labels:
					report.uncertain.append(ReportItem(label, CaptureIntent.THREADS,
						'thread id %s also appears in %s; identical thread ids across '
						'generations are kept as separate threads and cannot be '
						're-verified as one timeline' % (_format_tid(tid), where)))

	return report


def run():
	import argparse

	parser = argparse.ArgumentParser(
		description='Read-only comparison of minidump captures using caller-recorded '
					'capture windows and process generation numbers')
	parser.add_argument('manifest', help='JSON manifest listing the captures '
		'(path, generation, capture window, capture intent per dump)')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--intent', action='append', choices=[i.value for i in CaptureIntent],
		help='Only show items for this capture intent (repeatable)')
	parser.add_argument('--section', action='append',
		choices=['intended', 'captured', 'missed', 'uncertain'],
		help='Only show these report sections (repeatable, default: all)')
	parser.add_argument('--json', action='store_true', help='Emit the report as JSON')
	parser.add_argument('--strict', action='store_true',
		help='Exit with status 1 when missed or uncertain items exist')

	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.WARNING)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.INFO)
	else:
		logging.basicConfig(level=logging.DEBUG)

	contexts = CaptureContext.load_manifest(args.manifest)
	report = compare_captures(contexts)

	intents = [CaptureIntent(i) for i in args.intent] if args.intent else None
	if args.json:
		print(json.dumps(report.to_dict(), indent=2))
	else:
		print(report.to_text(sections=args.section, intents=intents))

	if args.strict and (report.missed or report.uncertain):
		return 1
	return 0


if __name__ == '__main__':
	import sys
	sys.exit(run())
