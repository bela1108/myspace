import io
import json
import logging
import unittest

from minidump.minidumpfile import MinidumpFile
from minidump.stackindex import (
	StackCoordinate,
	build_stack_index,
	load_allowed_coordinates,
	reconcile,
)
from tests.synthetic_minidump import SyntheticModule, SyntheticThread, build_minidump


THREAD_SHARED = 0x1100
THREAD_SIDE_A = 0x2200
THREAD_SECRET = 0x3300

CALL_SHARED = 0x70001234
CALL_SIDE_A = 0x70005678
CALL_SECRET = 0x70009ABC

APP_BASE = 0x70000000
APP_SIZE = 0x10000


def _parse(data):
	logging.disable(logging.CRITICAL)
	return MinidumpFile.parse_buff(io.BytesIO(data))


def _app_module(timestamp, version_ms, version_ls):
	return SyntheticModule(
		'C:\\investigation\\app.dll',
		APP_BASE, APP_SIZE, timestamp, version_ms, version_ls,
	)


def _build_dump_a():
	threads = [
		SyntheticThread(
			THREAD_SHARED, 0x10000, 0x1000, CALL_SHARED,
			b'AAA-secret-stack-bytes' + b'\x00' * (0x1000 - 24),
		),
		SyntheticThread(
			THREAD_SIDE_A, 0x20000, 0x800, CALL_SIDE_A,
			b'AAA-side-a-bytes' + b'\x00' * (0x800 - 16),
		),
		SyntheticThread(
			THREAD_SECRET, 0x40000, 0x400, CALL_SECRET,
			b'AAA-never-permitted' + b'\x00' * (0x400 - 19),
		),
	]
	modules = [_app_module(0x1000, (1 << 16) | 2, (3 << 16) | 4)]
	return _parse(build_minidump(threads, modules))


def _build_dump_b():
	threads = [
		SyntheticThread(
			THREAD_SHARED, 0x10080, 0xC00, CALL_SHARED,
			b'BBB-different-stack-bytes' + b'\x00' * (0xC00 - 26),
		),
		SyntheticThread(
			THREAD_SECRET, 0x40000, 0x400, CALL_SECRET,
			b'BBB-never-permitted' + b'\x00' * (0x400 - 19),
		),
	]
	modules = [_app_module(0x2000, (1 << 16) | 5, (3 << 16) | 4)]
	return _parse(build_minidump(threads, modules))


def _shared_permissions():
	payload = {
		'allowed': [
			{'thread_id': THREAD_SHARED, 'call_site': hex(CALL_SHARED)},
			{'thread_id': THREAD_SIDE_A, 'call_site': hex(CALL_SIDE_A)},
		]
	}
	return load_allowed_coordinates(io.StringIO(json.dumps(payload)))


class StackIndexTests(unittest.TestCase):
	def setUp(self):
		self.dump_a = _build_dump_a()
		self.dump_b = _build_dump_b()
		self.allowed = _shared_permissions()

	def test_intersection_and_unverified_segments(self):
		result = reconcile(
			self.dump_a, self.dump_b, self.allowed,
			left_label='agency-a', right_label='agency-b',
		)

		self.assertEqual(len(result.intersection), 1)
		shared = result.intersection[0]
		self.assertEqual(
			shared.coordinate.key(), (THREAD_SHARED, CALL_SHARED),
		)
		self.assertIn('collection_boundary', shared.mismatches)
		self.assertIn('sample_version', shared.mismatches)

		self.assertEqual(len(result.unverified_left), 1)
		self.assertEqual(
			result.unverified_left[0].coordinate.key(),
			(THREAD_SIDE_A, CALL_SIDE_A),
		)
		self.assertEqual(result.unverified_right, [])

	def test_evidence_points_to_thread_and_module_streams(self):
		entries, suppressed = build_stack_index(
			self.dump_a, self.allowed, source_label='agency-a',
		)
		entries_by_key = {entry.coordinate.key(): entry for entry in entries}
		entry = entries_by_key[(THREAD_SHARED, CALL_SHARED)]

		self.assertEqual(entry.thread_evidence.stream, 'ThreadListStream')
		self.assertEqual(entry.context_evidence.stream, 'ThreadListStream')
		self.assertEqual(entry.range_evidence.stream, 'ThreadListStream')
		self.assertEqual(entry.module.evidence.stream, 'ModuleListStream')
		self.assertEqual(entry.module.base_address, APP_BASE)
		self.assertEqual(entry.module.version, '1.2.3.4')
		self.assertEqual(
			entry.coordinate,
			StackCoordinate(THREAD_SHARED, CALL_SHARED),
		)

		secret_keys = {coord.key() for coord in suppressed}
		self.assertIn((THREAD_SECRET, CALL_SECRET), secret_keys)

	def test_index_never_carries_stack_bytes(self):
		result = reconcile(self.dump_a, self.dump_b, self.allowed)
		serialized = result.to_json()
		self.assertNotIn('AAA-secret-stack-bytes', serialized)
		self.assertNotIn('BBB-different-stack-bytes', serialized)
		self.assertNotIn('AAA-never-permitted', serialized)
		self.assertNotIn('BBB-never-permitted', serialized)
		self.assertNotIn('stack_data', serialized)

	def test_revoking_permission_removes_coordinate_from_output(self):
		reduced = {
			'allowed': [
				{'thread_id': THREAD_SIDE_A, 'call_site': hex(CALL_SIDE_A)},
			],
		}
		reduced_permissions = load_allowed_coordinates(
			io.StringIO(json.dumps(reduced)),
		)
		result = reconcile(self.dump_a, self.dump_b, reduced_permissions)

		visible = {
			entry.coordinate.key() for entry in result.intersection
		}
		visible.update(
			entry.coordinate.key() for entry in result.unverified_left
		)
		visible.update(
			entry.coordinate.key() for entry in result.unverified_right
		)
		self.assertNotIn((THREAD_SHARED, CALL_SHARED), visible)
		self.assertIn(
			(THREAD_SHARED, CALL_SHARED),
			{coord.key() for coord in result.suppressed},
		)

	def test_unapproved_coordinate_is_never_indexed(self):
		entries, suppressed = build_stack_index(self.dump_a, self.allowed)
		indexed = {entry.coordinate.key() for entry in entries}
		self.assertNotIn((THREAD_SECRET, CALL_SECRET), indexed)
		self.assertEqual(
			{(THREAD_SECRET, CALL_SECRET)},
			{coord.key() for coord in suppressed},
		)


if __name__ == '__main__':
	unittest.main()
