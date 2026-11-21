#!/usr/bin/env python3
#
# Human-readable forensic report built on top of ForensicAttributor.
#
from minidump.minidumpfile import MinidumpFile
from minidump.attribution import (
	ForensicAttributor,
	AttributionVerdict,
)


_VERDICT_TITLE = {
	AttributionVerdict.LOADED_MATCH: 'Attributed to a loaded module',
	AttributionVerdict.UNLOADED_ONLY: 'Historical coverage only (unloaded)',
	AttributionVerdict.UNATTRIBUTED: 'No module covers this address',
	AttributionVerdict.NO_EXCEPTION: 'No exception thread in the dump',
}


def _format_evidence(evidence):
	note = 'at-tail boundary' if evidence.at_tail else 		'base+0x%x' % evidence.offset
	return (
		'  - {state}: {name} raw [0x{base:x}, 0x{end:x}) '
		'size 0x{size:x} -> {note}'
	).format(
		state='LOADED  ' if evidence.is_loaded else 'UNLOADED',
		name=evidence.name,
		base=evidence.baseaddress,
		end=evidence.endaddress,
		size=evidence.size,
		note=note,
	)


def build_report(minidump_file):
	attributor = ForensicAttributor(minidump_file)
	results = attributor.attribute_exceptions()

	lines = ['== Forensic address attribution report ==']
	if not results:
		lines.append(_format_result(attributor.explain_no_exception()))
		return '\n'.join(lines)

	for index, result in enumerate(results, start=1):
		lines.append('')
		lines.append('Exception #%d' % index)
		lines.append(_format_result(result))
	return '\n'.join(lines)


def _format_result(result):
	lines = [
		'Address: 0x%x' % result.address if result.address is not None
		else 'Address: n/a',
		'Thread: %s' % (
			'0x%x' % result.thread_id
			if result.thread_id is not None else 'n/a'),
		'Exception: %s' % (
			result.exception_code.name
			if result.exception_code is not None else 'n/a'),
		'Verdict: %s - %s' % (
			result.verdict.value,
			_VERDICT_TITLE[result.verdict]),
		'Confidence: %.2f' % result.confidence,
		'Overlapping candidates: %s' % (
			'yes' if result.has_overlap else 'no'),
	]
	if result.loaded_evidence:
		lines.append('Loaded evidence:')
		lines.extend(_format_evidence(item)
					 for item in result.loaded_evidence)
	if result.unloaded_evidence:
		lines.append('Unloaded (historical) evidence:')
		lines.extend(_format_evidence(item)
					 for item in result.unloaded_evidence)
	lines.append('Reasoning:')
	lines.extend('  * ' + reason for reason in result.reasons)
	return '\n'.join(lines)
