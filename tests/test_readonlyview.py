#!/usr/bin/env python3
#
# Verifies that read-only evidence views over a single shared read handle
# produce the same evidence manifest whether the two forensic readers work
# independently, interleaved, or resume from saved progress.

import hashlib
import io
import struct
import zipfile

import pytest

from minidump.minidumpfile import MinidumpFile
from minidump.readonlyview import SharedReadOnlyHandle, EvidenceView, _merge_intervals


# --- synthetic minidump inside an archive container -------------------------

# virtual address -> data; the last segment declares 6 more bytes than the
# file actually holds, simulating a truncated original (short read / gap).
SEGMENTS = [
	(0x10000, bytes(range(0, 40))),
	(0x20000, bytes(range(100, 160))),
	(0x30000, b'PEB-TEB-region!' * 4),
	(0x40000, hashlib.sha256(b'tail').digest() * 2),
]
TRUNCATED_BY = 6


def build_dump_bytes():
	header_size = 28
	directory_size = 12
	memlist_size = 4 + 16 * len(SEGMENTS)
	data_rva = header_size + directory_size + memlist_size

	blobs = []
	descriptors = []
	rva = data_rva
	for i, (vaddr, data) in enumerate(SEGMENTS):
		declared = len(data) + (TRUNCATED_BY if i == len(SEGMENTS) - 1 else 0)
		descriptors.append((vaddr, declared, rva))
		blobs.append(data)
		rva += len(data)

	dump = struct.pack('<4sHHIIIII', b'MDMP', 1, 1, 1, header_size, 0, 0, 2)
	dump += struct.pack('<III', 5, memlist_size, header_size + directory_size)
	dump += struct.pack('<I', len(descriptors))
	for vaddr, declared, rva in descriptors:
		dump += struct.pack('<QII', vaddr, declared, rva)
	for blob in blobs:
		dump += blob
	return dump


DUMP_BYTES = build_dump_bytes()
DUMP_SIZE = len(DUMP_BYTES)
DUMP_SHA256 = hashlib.sha256(DUMP_BYTES).hexdigest()


class ArchiveContainer:
	"""Archive container that hands out a single read handle for the dump."""
	NAME = 'evidence.dmp'

	def __init__(self, dump_bytes):
		self._buf = io.BytesIO()
		with zipfile.ZipFile(self._buf, 'w', zipfile.ZIP_DEFLATED) as zf:
			zf.writestr(self.NAME, dump_bytes)
		self._buf.seek(0)
		self._zf = zipfile.ZipFile(self._buf)

	def open_handle(self):
		return self._zf.open(self.NAME)


def assign_regions(mf):
	"""Splits the dump's memory segments between the two forensic readers."""
	spans = [
		(seg.start_file_address, seg.start_file_address + seg.size)
		for seg in mf.memory_segments.memory_segments
	]
	return [spans[0], spans[2]], [spans[1], spans[3]]


# --- the three review runs --------------------------------------------------

def run_independent(archive):
	handle = archive.open_handle()
	mf = MinidumpFile.parse_external(handle)
	regions_alpha, regions_beta = assign_regions(mf)
	shared = SharedReadOnlyHandle(handle)
	alpha = EvidenceView(shared, 'alpha', regions_alpha)
	beta = EvidenceView(shared, 'beta', regions_beta)
	alpha.collect(chunk_size=7)
	beta.collect(chunk_size=13)
	return [shared], [alpha, beta]


def run_interleaved(archive):
	handle = archive.open_handle()
	mf = MinidumpFile.parse_external(handle)
	regions_alpha, regions_beta = assign_regions(mf)
	shared = SharedReadOnlyHandle(handle)
	views = [EvidenceView(shared, 'alpha', regions_alpha),
	         EvidenceView(shared, 'beta', regions_beta)]
	exhausted = set()
	turn = 0
	while len(exhausted) < len(views):
		view = views[turn % len(views)]
		turn += 1
		if view.reader_id in exhausted:
			continue
		if view.read(5).exhausted:
			exhausted.add(view.reader_id)
	return [shared], views


def run_resumed(archive):
	handle = archive.open_handle()
	mf = MinidumpFile.parse_external(handle)
	regions_alpha, regions_beta = assign_regions(mf)
	shared = SharedReadOnlyHandle(handle)
	alpha = EvidenceView(shared, 'alpha', regions_alpha)
	beta = EvidenceView(shared, 'beta', regions_beta)

	# first session: both readers only get partway through
	alpha.read(9)
	beta.read(11)
	alpha.read(4)
	state_alpha = alpha.save_progress()
	state_beta = beta.save_progress()

	# the review is paused and later continued on a freshly opened handle
	# of the same archived original
	handle2 = archive.open_handle()
	shared2 = SharedReadOnlyHandle(handle2)
	alpha2 = EvidenceView.resume(shared2, state_alpha, reader_id='alpha')
	beta2 = EvidenceView.resume(shared2, state_beta, reader_id='beta')
	exhausted = set()
	views = [alpha2, beta2]
	turn = 0
	while len(exhausted) < len(views):
		view = views[turn % len(views)]
		turn += 1
		if view.reader_id in exhausted:
			continue
		if view.read(6).exhausted:
			exhausted.add(view.reader_id)
	return [shared, shared2], views


RUNNERS = [run_independent, run_interleaved, run_resumed]


def manifests(views):
	return {view.reader_id: view.manifest() for view in views}


def combined_log(shared_handles):
	"""Provenance records of every session, in the order they happened."""
	return [rec for shared in shared_handles for rec in shared.read_log]


# --- cross-checks -------------------------------------------------------------

def test_all_runs_produce_the_same_evidence_manifest():
	archive = ArchiveContainer(DUMP_BYTES)
	reference = None
	for runner in RUNNERS:
		shared_handles, views = runner(archive)
		manifest = manifests(views)
		if reference is None:
			reference = manifest
		else:
			assert manifest == reference, \
				'%s produced a different evidence list' % runner.__name__


def test_provenance_recomputes_evidence_and_success_ranges():
	archive = ArchiveContainer(DUMP_BYTES)
	for runner in RUNNERS:
		shared_handles, views = runner(archive)
		log = combined_log(shared_handles)
		for view in views:
			audit = view.audit(read_log=log)
			assert audit['provenance_matches']
			assert SharedReadOnlyHandle.coverage_of(log, view.reader_id) == view.evidence
			# success ranges: evidence + gaps exactly partition the regions
			for (rstart, rend) in view.regions:
				covered = sum(
					min(end, rend) - max(start, rstart)
					for start, end in view.evidence
					if start < rend and end > rstart)
				gapped = sum(
					min(end, rend) - max(start, rstart)
					for start, end in view.gaps
					if start < rend and end > rstart)
				assert covered + gapped == rend - rstart
		# the two readers' provenance recombines into all underlying reads
		merged = _merge_intervals(views[0].evidence + views[1].evidence)
		assert SharedReadOnlyHandle.coverage_of(log) == merged


def test_short_read_and_missed_range_are_auditable():
	archive = ArchiveContainer(DUMP_BYTES)
	for runner in RUNNERS:
		shared_handles, views = runner(archive)
		log = combined_log(shared_handles)
		beta = [v for v in views if v.reader_id == 'beta'][0]
		# the truncated tail of the last segment shows up as a short read
		shorts = [r for r in beta.results if r.short]
		assert len(shorts) >= 1
		assert any(r.returned < r.requested for r in shorts)
		# ... and the uncollectable tail is reported as a gap
		assert (DUMP_SIZE, DUMP_SIZE + TRUNCATED_BY) in beta.gaps
		# every short read is backed by an underlying provenance record
		for result in shorts:
			matches = [
				rec for rec in log
				if rec.reader_id == 'beta'
				and rec.offset == result.offset
				and rec.returned == result.returned
			]
			assert len(matches) >= 1


def test_reader_can_only_continue_its_own_review():
	archive = ArchiveContainer(DUMP_BYTES)
	handle = archive.open_handle()
	mf = MinidumpFile.parse_external(handle)
	regions_alpha, regions_beta = assign_regions(mf)
	shared = SharedReadOnlyHandle(handle)
	alpha = EvidenceView(shared, 'alpha', regions_alpha)
	alpha.read(8)
	state = alpha.save_progress()

	with pytest.raises(ValueError):
		EvidenceView.resume(shared, state, reader_id='beta')

	# a reader may not wander into the other reader's region either
	with pytest.raises(ValueError):
		alpha.seek(regions_beta[0][0])


def test_original_stays_untouched():
	archive = ArchiveContainer(DUMP_BYTES)
	for runner in RUNNERS:
		runner(archive)
	handle = archive.open_handle()
	assert hashlib.sha256(handle.read()).hexdigest() == DUMP_SHA256

	shared = SharedReadOnlyHandle(archive.open_handle())
	with pytest.raises(IOError):
		shared.write(b'x')
	with pytest.raises(IOError):
		shared.truncate(0)
