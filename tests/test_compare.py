#!/usr/bin/env python3
#
# Regression tests for the read-only comparison entry point and for the
# "same PID, different process generation" fixture scenario.
#
# Written in unittest style so they run with both `python -m unittest`
# and pytest.

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_builder

from minidump.minidumpfile import MinidumpFile
from minidump.compare import (
	CaptureContext,
	CaptureIntent,
	compare_captures,
)


class CompareTestBase(unittest.TestCase):
	def setUp(self):
		self._tmp = tempfile.TemporaryDirectory()
		self.addCleanup(self._tmp.cleanup)
		self.tmpdir = self._tmp.name

	def _write(self, name, data):
		path = os.path.join(self.tmpdir, name)
		with open(path, 'wb') as f:
			f.write(data)
		return path

	def _scenario_contexts(self):
		light_path = self._write('light.dmp', fixture_builder.build_light_snapshot())
		full_path = self._write('full.dmp', fixture_builder.build_full_snapshot())
		return [
			CaptureContext(
				label='light-snapshot', path=light_path,
				generation=fixture_builder.LIGHT_GENERATION,
				window_start=fixture_builder.LIGHT_WINDOW[0],
				window_end=fixture_builder.LIGHT_WINDOW[1],
				intent=['threads', 'vm_counters'],
			),
			CaptureContext(
				label='full-snapshot', path=full_path,
				generation=fixture_builder.FULL_GENERATION,
				window_start=fixture_builder.FULL_WINDOW[0],
				window_end=fixture_builder.FULL_WINDOW[1],
				intent=['threads', 'vm_counters'],
			),
		]


class TestFixtures(CompareTestBase):
	def test_fixture_dumps_are_format_valid(self):
		light = MinidumpFile.parse_bytes(fixture_builder.build_light_snapshot())
		self.assertEqual(light.misc_info.ProcessId, fixture_builder.SCENARIO_PID)
		self.assertEqual([t.ThreadId for t in light.threads.threads], [0x100, 0x104])
		self.assertIsNone(light.vm_counters)

		full = MinidumpFile.parse_bytes(fixture_builder.build_full_snapshot())
		self.assertEqual(full.misc_info.ProcessId, fixture_builder.SCENARIO_PID)
		self.assertEqual([t.ThreadId for t in full.threads.threads], [0x104, 0x108])
		self.assertIsNotNone(full.vm_counters)
		self.assertTrue(full.vm_counters.is_recognized)
		self.assertEqual(full.vm_counters.counters['PageFaultCount'], 1234)
		self.assertEqual(full.vm_counters.counters['PrivateUsage'], 0x18000)


class TestComparison(CompareTestBase):
	def test_intended_captured_missed(self):
		report = compare_captures(self._scenario_contexts())

		# everything both captures were meant to collect
		self.assertEqual(len(report.intended), 4)

		captured = {(i.capture, i.intent) for i in report.captured}
		self.assertIn(('light-snapshot', CaptureIntent.THREADS), captured)
		self.assertIn(('full-snapshot', CaptureIntent.THREADS), captured)
		self.assertIn(('full-snapshot', CaptureIntent.VM_COUNTERS), captured)

		# the light snapshot was meant to collect VM counters but has none
		missed = [(i.capture, i.intent) for i in report.missed]
		self.assertEqual(missed, [('light-snapshot', CaptureIntent.VM_COUNTERS)])

	def test_same_tid_across_generations_is_not_stitched(self):
		report = compare_captures(self._scenario_contexts())

		# the shared thread id 0x104 is reported as a collision for both captures
		collisions = [i for i in report.uncertain if i.intent == CaptureIntent.THREADS]
		self.assertEqual(len(collisions), 2)
		self.assertEqual({i.capture for i in collisions}, {'light-snapshot', 'full-snapshot'})
		self.assertTrue(all('0x104' in i.detail for i in collisions))

		# generations stay separate: no merged timeline for 0x104
		self.assertEqual(report.generations[1]['thread_ids'], {0x100, 0x104})
		self.assertEqual(report.generations[2]['thread_ids'], {0x104, 0x108})

		# PID reuse across generations is noted
		self.assertTrue(any('4242' in note for note in report.notes))

	def test_same_tid_within_one_generation_may_join(self):
		contexts = self._scenario_contexts()
		for ctx in contexts:
			ctx.generation = 7  # caller says: same process generation
		report = compare_captures(contexts)

		self.assertEqual([i for i in report.uncertain if i.intent == CaptureIntent.THREADS], [])
		self.assertEqual(report.generations[7]['thread_ids'], {0x100, 0x104, 0x108})

	def test_capture_window_violation_is_uncertain(self):
		contexts = self._scenario_contexts()
		contexts[0].window_start = fixture_builder.LIGHT_TIMESTAMP + 10
		contexts[0].window_end = fixture_builder.LIGHT_TIMESTAMP + 20
		report = compare_captures(contexts)

		window_items = [i for i in report.uncertain if i.intent is None]
		self.assertEqual(len(window_items), 1)
		self.assertEqual(window_items[0].capture, 'light-snapshot')
		self.assertIn('capture window', window_items[0].detail)

	def test_unrecognized_counters_layout_is_uncertain(self):
		bad_counters = fixture_builder.build_minidump(
			[
				(fixture_builder.STREAM_THREAD_LIST, fixture_builder.build_thread_list([0x200])),
				(fixture_builder.STREAM_MISC_INFO, fixture_builder.build_misc_info(4242)),
				(fixture_builder.STREAM_PROCESS_VM_COUNTERS, b'\x01' * 40),  # unknown layout
			],
			timestamp=fixture_builder.FULL_TIMESTAMP,
			flags=0,
		)
		path = self._write('bad_counters.dmp', bad_counters)
		ctx = CaptureContext(
			label='odd-counters', path=path, generation=3,
			window_start=fixture_builder.FULL_WINDOW[0],
			window_end=fixture_builder.FULL_WINDOW[1],
			intent=['vm_counters'],
		)
		report = compare_captures([ctx])

		self.assertEqual(report.missed, [])
		self.assertEqual(len(report.uncertain), 1)
		self.assertEqual(report.uncertain[0].intent, CaptureIntent.VM_COUNTERS)
		self.assertIn('layout not recognized', report.uncertain[0].detail)

	def test_intent_filter_for_on_duty_view(self):
		report = compare_captures(self._scenario_contexts())

		text = report.to_text(sections=['missed', 'uncertain'],
			intents=[CaptureIntent.VM_COUNTERS])
		self.assertIn('== MISSED ==', text)
		self.assertIn('no VM counters stream', text)
		# thread collisions are filtered out when only vm_counters is requested
		self.assertNotIn('0x104', text)

		text = report.to_text(sections=['uncertain'], intents=[CaptureIntent.THREADS])
		self.assertIn('0x104', text)


class TestCli(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.manifest = os.path.join(fixture_builder.FIXTURE_DIR, 'manifest.json')
		if not os.path.exists(cls.manifest):
			fixture_builder.main()

	def _run_cli(self, *args):
		env = dict(os.environ)
		repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		env['PYTHONPATH'] = repo_root + os.pathsep + env.get('PYTHONPATH', '')
		return subprocess.run(
			[sys.executable, '-m', 'minidump.compare', self.manifest, *args],
			capture_output=True, text=True, env=env,
		)

	def test_cli_strict_mode(self):
		proc = self._run_cli('--strict')
		# missed + uncertain items exist in this scenario, so strict mode fails
		self.assertEqual(proc.returncode, 1)
		self.assertIn('== MISSED ==', proc.stdout)
		self.assertIn('== UNCERTAIN ==', proc.stdout)

	def test_cli_intent_and_section_filter_json(self):
		proc = self._run_cli('--intent', 'vm_counters', '--section', 'missed', '--json')
		self.assertEqual(proc.returncode, 0)
		report = json.loads(proc.stdout)
		self.assertEqual(len(report['missed']), 1)
		self.assertEqual(report['missed'][0]['intent'], 'vm_counters')


if __name__ == '__main__':
	unittest.main()
