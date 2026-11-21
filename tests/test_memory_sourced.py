import asyncio
import io

import pytest

from minidump.minidumpfile import MinidumpFile
from minidump.aminidumpfile import AMinidumpFile
from minidump.memoryreport import RegionKind

from tests.minidump_fixture import build_minidump, BASE


ORDERS = [(0, 1, 2), (2, 0, 1)]


def _sync_reader(order):
	dump = build_minidump(order)
	return MinidumpFile.parse_buff(io.BytesIO(dump)).get_reader()


class AsyncBuffer:
	def __init__(self, data):
		self._buffer = io.BytesIO(data)

	async def read(self, size=-1):
		return self._buffer.read(size)

	async def seek(self, offset, whence=0):
		return self._buffer.seek(offset, whence)

	def tell(self):
		return self._buffer.tell()


async def _async_reader(order):
	dump = build_minidump(order)
	mf = await AMinidumpFile.parse_external(AsyncBuffer(dump))
	return mf.get_reader()


def _expected_layout():
	return [
		(RegionKind.AGREED, 0x00, 0x04, 1),
		(RegionKind.DISPUTED, 0x04, 0x08, 2),
		# The next two elementary intervals share the same three sources and
		# stay disputed throughout, so they merge into one maximal range.
		(RegionKind.DISPUTED, 0x08, 0x18, 3),
		(RegionKind.AGREED, 0x18, 0x1C, 1),
	]


def test_three_memory_streams_are_collected():
	reader = _sync_reader((0, 1, 2))
	sources = reader.minidump_file.get_memory_sources()
	assert len(sources) == 3
	stream_types = sorted(source.stream_type.name for source in sources)
	assert stream_types == [
		"Memory64ListStream",
		"MemoryListStream",
		"MemoryListStream",
	]
	assert len({source.source_id for source in sources}) == 3


@pytest.mark.parametrize("order", ORDERS)
def test_region_classification_is_order_independent(order):
	report = _sync_reader(order).read_sourced(BASE, 0x1C)
	actual = [
		(region.kind, region.start_address - BASE, region.end_address - BASE, len(region.candidates))
		for region in report.regions
	]
	assert actual == _expected_layout()


@pytest.mark.parametrize("order", ORDERS)
def test_disputed_ranges_only_hold_distinct_candidates(order):
	report = _sync_reader(order).read_sourced(BASE, 0x1C)
	for region in report.disputed_regions:
		assert len(region.candidates) >= 2
		assert len(set(region.candidates)) == len(region.candidates)
		assert all(len(candidate) == region.size for candidate in region.candidates)


def test_disputed_bytes_match_the_three_fixture_sources():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE, 0x1C)
	first_dispute = report.disputed_regions[0]
	assert sorted(first_dispute.candidates) == sorted([
		b"\x14\x15\x16\x17",
		b"\xc0\xc1\xc2\xc3",
	])
	triple = next(region for region in report.regions if region.kind == RegionKind.DISPUTED and len(region.candidates) == 3)
	assert triple.start_address == BASE + 0x08
	assert triple.end_address == BASE + 0x18
	assert b"B" * 16 in triple.candidates


def test_agreed_regions_expose_a_single_value():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE, 0x1C)
	assert report.agreed_regions[0].data == b"\x10\x11\x12\x13"
	assert report.agreed_regions[1].data == bytes((0xC4, 0xC5, 0xC6, 0xC7))


def test_holes_record_missing_evidence():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE - 8, 0x2C)
	assert report.holes[0].start_address == BASE - 8
	assert report.holes[0].end_address == BASE
	assert report.holes[-1].start_address == BASE + 0x1C
	assert report.holes[-1].end_address == BASE + 0x24
	for hole in report.holes:
		assert hole.data is None
		assert hole.candidates == []


def test_adjacent_segments_of_one_source_are_stitched():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE + 0x0C, 0x0C)
	coverage = next(
		item for item in report.source_coverage.values()
		if item.source.stream_type.name == "MemoryListStream"
		and item.parts[0].start_address <= BASE + 0x0C
		and item.parts[-1].end_address >= BASE + 0x18
	)
	assert len(coverage.parts) == 1
	assert coverage.parts[0].start_address == BASE + 0x0C
	assert coverage.parts[0].end_address == BASE + 0x18
	assert coverage.parts[0].data == b"\x1c\x1d\x1e\x1f" + bytes(range(0x30, 0x38))


def test_sources_keep_their_own_bytes():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE, 0x1C)
	for coverage in report.source_coverage.values():
		assert coverage.data == b"".join(part.data for part in coverage.parts)
		for part in coverage.parts:
			assert part.source is coverage.source


def test_directory_swap_produces_identical_report_bytes():
	first = _sync_reader(ORDERS[0]).read_sourced(BASE - 4, 0x28)
	second = _sync_reader(ORDERS[1]).read_sourced(BASE - 4, 0x28)

	def signature(report):
		return [
			(region.kind, region.start_address, region.end_address, tuple(region.candidates))
			for region in report.regions
		]

	assert signature(first) == signature(second)


def test_async_reader_follows_the_same_rules():
	async def scenario():
		reader = await _async_reader((2, 0, 1))
		return await reader.aread_sourced(BASE, 0x1C)

	report = asyncio.run(scenario())
	actual = [
		(region.kind, region.start_address - BASE, region.end_address - BASE, len(region.candidates))
		for region in report.regions
	]
	assert actual == _expected_layout()


def test_async_and_sync_reports_agree():
	async def scenario():
		reader = await _async_reader((0, 1, 2))
		return await reader.aread_sourced(BASE - 8, 0x2C)

	async_report = asyncio.run(scenario())
	sync_report = _sync_reader((0, 1, 2)).read_sourced(BASE - 8, 0x2C)

	assert len(async_report.regions) == len(sync_report.regions)
	for async_region, sync_region in zip(async_report.regions, sync_report.regions):
		assert async_region.kind == sync_region.kind
		assert async_region.start_address == sync_region.start_address
		assert async_region.end_address == sync_region.end_address
		assert async_region.candidates == sync_region.candidates

def test_negative_size_is_rejected():
	reader = _sync_reader((0, 1, 2))
	with pytest.raises(Exception):
		reader.read_sourced(BASE, -1)


def test_zero_length_read_has_no_regions():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE, 0)
	assert report.regions == []
	assert report.start_address == BASE
	assert report.end_address == BASE
	assert report.is_fully_resolved is True
	assert report.has_dispute is False


def test_fully_uncovered_read_is_one_hole():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE + 0x80, 8)
	assert len(report.regions) == 1
	assert report.regions[0].kind == RegionKind.HOLE
	assert report.regions[0].size == 8
	assert report.source_coverage == {}
	assert report.is_fully_resolved is False


def test_resolved_data_fills_holes_and_uses_agreed_bytes():
	report = _sync_reader((0, 1, 2)).read_sourced(BASE - 2, 6)
	resolved = report.resolved_data(hole_fill=b"\x00")
	assert len(resolved) == 6
	assert resolved[:2] == b"\x00\x00"
	assert resolved[2:] == b"\x10\x11\x12\x13"

