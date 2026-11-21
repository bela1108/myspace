#!/usr/bin/env python3
#
# Tests for the forensic address attribution backend.
#
import pytest

from minidump.minidumpfile import MinidumpFile
from minidump.attribution import (
	ForensicAttributor,
	AttributionVerdict,
	BoundaryRelation,
	EvidenceKind,
)
from tests.dumpbuilder import DumpBuilder


def parse(builder):
	return MinidumpFile.parse_bytes(builder.build())


@pytest.fixture
def crash_dump():
	# Two loaded rows share the same image name but occupy different ranges.
	# One unloaded row historically held a page that is now part of a loaded
	# module, and another unloaded row reuses a loaded module name.
	builder = DumpBuilder()
	builder.add_thread(0x100)
	builder.add_thread(0x200)
	builder.add_module(r"C:\app\plugin.dll", 0x10000, 0x3000,
					   timestamp=0xAAAA)
	builder.add_module(r"C:\app\plugin.dll", 0x40000, 0x2000,
					   timestamp=0xBBBB)
	builder.add_module(r"C:\windows\kernel32.dll", 0x50000, 0x4000)
	builder.add_unloaded_module(r"C:\temp\legacy.dll", 0x51000, 0x1000,
								timestamp=0x1111)
	builder.add_unloaded_module(r"C:\app\plugin.dll", 0x60000, 0x2000,
								timestamp=0x2222)
	return parse(builder)

def test_loaded_match_with_live_thread(crash_dump):
	attributor = ForensicAttributor(crash_dump)
	result = attributor.attribute_address(0x10500, thread_id=0x100)
	assert result.verdict == AttributionVerdict.LOADED_MATCH
	assert result.owner.name == r"C:\app\plugin.dll"
	assert result.owner.offset == 0x500
	assert result.owner.boundary == BoundaryRelation.INSIDE
	# Live thread bumps confidence above the base loaded weight.
	assert result.confidence == pytest.approx(0.8)
	assert result.has_overlap is False


def test_same_name_rows_are_not_merged(crash_dump):
	attributor = ForensicAttributor(crash_dump)
	first = attributor.attribute_address(0x10100)
	second = attributor.attribute_address(0x40100)
	# Identical names, distinct raw rows, distinct evidence objects.
	assert first.owner.name == second.owner.name
	assert first.owner.baseaddress != second.owner.baseaddress
	assert first.owner.timestamp != second.owner.timestamp
	assert len(first.loaded_evidence) == 1
	assert len(second.loaded_evidence) == 1


def test_tail_address_kept_with_boundary_evidence(crash_dump):
	# 0x13000 is exactly the raw endaddress of the first plugin.dll row.
	attributor = ForensicAttributor(crash_dump)
	result = attributor.attribute_address(0x13000, thread_id=0x200)
	assert result.verdict == AttributionVerdict.LOADED_MATCH
	owner = result.owner
	assert owner.at_tail is True
	assert owner.boundary == BoundaryRelation.AT_TAIL
	assert owner.distance_to_end == 0
	assert any('endaddress' in reason for reason in result.reasons)


def test_overlap_loaded_and_unloaded_stays_separate(crash_dump):
	# 0x51200 sits inside kernel32.dll and the historical legacy.dll page.
	attributor = ForensicAttributor(crash_dump)
	result = attributor.attribute_address(0x51200, thread_id=0x100)
	assert result.verdict == AttributionVerdict.LOADED_MATCH
	assert result.has_overlap is True
	assert len(result.loaded_evidence) == 1
	assert len(result.unloaded_evidence) == 1
	assert result.owner.kind == EvidenceKind.LOADED_MODULE
	assert result.unloaded_evidence[0].name == r"C:\temp\legacy.dll"
	assert any('historically' in reason for reason in result.reasons)


def test_unloaded_only_is_historical(crash_dump):
	# 0x60100 only matches the unloaded plugin.dll row.
	attributor = ForensicAttributor(crash_dump)
	result = attributor.attribute_address(0x60100)
	assert result.verdict == AttributionVerdict.UNLOADED_ONLY
	assert result.owner is None
	assert len(result.unloaded_evidence) == 1
	assert result.unloaded_evidence[0].is_unloaded
	# Unloaded-only confidence is capped below any live attribution.
	assert result.confidence == pytest.approx(0.3)

def test_unattributed_address(crash_dump):
	attributor = ForensicAttributor(crash_dump)
	result = attributor.attribute_address(0xDEADBEEF)
	assert result.verdict == AttributionVerdict.UNATTRIBUTED
	assert result.all_evidence == []
	assert result.confidence == 0.0


def test_no_exception_dump_gets_explicit_verdict():
	builder = DumpBuilder()
	builder.add_module(r"C:\app\plugin.dll", 0x10000, 0x3000)
	dump = parse(builder)
	attributor = ForensicAttributor(dump)
	assert attributor.attribute_exceptions() == []
	result = attributor.explain_no_exception()
	assert result.verdict == AttributionVerdict.NO_EXCEPTION
	assert result.confidence == 0.0
	assert result.reasons


def test_exception_stream_join_uses_raw_exception_address():
	builder = DumpBuilder()
	builder.add_thread(0x999)
	builder.add_module(r"C:\app\plugin.dll", 0x10000, 0x3000)
	builder.add_exception(0x999, 0x12000)
	dump = parse(builder)
	results = ForensicAttributor(dump).attribute_exceptions()
	assert len(results) == 1
	result = results[0]
	assert result.address == 0x12000
	assert result.thread_id == 0x999
	assert result.verdict == AttributionVerdict.LOADED_MATCH


def test_exception_thread_missing_from_thread_list(crash_dump):
	attributor = ForensicAttributor(crash_dump)
	result = attributor.attribute_address(0x10500, thread_id=0x777)
	assert result.verdict == AttributionVerdict.LOADED_MATCH
	# No live thread: confidence stays at the base loaded weight.
	assert result.confidence == pytest.approx(0.7)
	assert any('not present' in reason for reason in result.reasons)


def test_two_same_name_unloaded_rows_never_merge():
	builder = DumpBuilder()
	builder.add_unloaded_module(r"C:\app\plugin.dll", 0x60000, 0x1000,
								timestamp=0x1000)
	builder.add_unloaded_module(r"C:\app\plugin.dll", 0x60800, 0x1000,
								timestamp=0x2000)
	dump = parse(builder)
	result = ForensicAttributor(dump).attribute_address(0x60900)
	assert result.verdict == AttributionVerdict.UNLOADED_ONLY
	assert len(result.unloaded_evidence) == 2
	assert {evidence.timestamp for evidence in result.unloaded_evidence} == {
		0x1000, 0x2000}
	assert result.has_overlap is True

def _review_dump():
	# Reproduces the on-call confusion: one exception lands exactly on the
	# tail of the currently loaded module, another only hits a page that a
	# since-unloaded module used to occupy.
	builder = DumpBuilder()
	builder.add_thread(0x100)
	builder.add_module(r"C:\app\plugin.dll", 0x10000, 0x3000)
	builder.add_unloaded_module(r"C:\app\plugin.dll", 0x90000, 0x2000,
								timestamp=0x3333)
	builder.add_exception(0x100, 0x13000)
	builder.add_exception(0x100, 0x90100)
	return parse(builder)


def test_review_tail_exception_is_attributed_to_loaded_module():
	dump = _review_dump()
	tail = ForensicAttributor(dump).attribute_exceptions()[0]
	assert tail.address == 0x13000
	assert tail.verdict == AttributionVerdict.LOADED_MATCH
	assert tail.owner.name == r"C:\app\plugin.dll"
	assert tail.owner.at_tail is True
	# The same-named unloaded row lives at a different range and must not
	# be offered as evidence for this address.
	assert tail.unloaded_evidence == []


def test_review_historical_exception_is_not_attributed_to_loaded_module():
	dump = _review_dump()
	historical = ForensicAttributor(dump).attribute_exceptions()[1]
	assert historical.address == 0x90100
	assert historical.verdict == AttributionVerdict.UNLOADED_ONLY
	assert historical.owner is None
	assert len(historical.unloaded_evidence) == 1
	assert historical.unloaded_evidence[0].name == r"C:\app\plugin.dll"
	# Same module name as the loaded row, but evidence stays separate.
	assert historical.loaded_evidence == []


def test_review_cases_are_handled_differently():
	dump = _review_dump()
	tail, historical = ForensicAttributor(dump).attribute_exceptions()
	assert tail.verdict != historical.verdict
	assert tail.confidence > historical.confidence
