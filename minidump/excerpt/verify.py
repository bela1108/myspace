#!/usr/bin/env python3
#
# Verification of an excerpt against a manifest.
#
# Every byte of the excerpt must fall inside a signed segment record
# and reproduce its hash. Bytes landing in a recorded gap are reported
# as unverifiable (unknown pages were never signed); bytes outside any
# authorized range are reported with their exact span so the caller
# can see precisely which part exceeds the authorization.
from minidump.excerpt.manifest import hash_segment


class VerifyIssue:
	ORIGIN_MISMATCH = 'origin-mismatch'
	UNAUTHORIZED_RANGE = 'unauthorized-range'
	UNKNOWN_PAGES = 'unknown-pages'
	HASH_MISMATCH = 'hash-mismatch'

	def __init__(self, kind, start, end, message):
		self.kind = kind
		self.start = start
		self.end = end
		self.message = message

	def to_dict(self):
		return {
			'kind': self.kind,
			'start': self.start,
			'end': self.end,
			'start_hex': hex(self.start) if self.start is not None else None,
			'end_hex': hex(self.end) if self.end is not None else None,
			'message': self.message,
		}

	def __repr__(self):
		return 'VerifyIssue(%s, %s-%s)' % (
			self.kind,
			hex(self.start) if self.start is not None else None,
			hex(self.end) if self.end is not None else None,
		)


class Verdict:
	def __init__(self):
		self.checked_segments = []
		self.issues = []

	@property
	def ok(self):
		return len(self.issues) == 0

	def to_dict(self):
		return {
			'ok': self.ok,
			'checked_segments': self.checked_segments,
			'issues': [i.to_dict() for i in self.issues],
		}


def verify_excerpt(manifest, excerpt):
	"""
	Verifies every segment of `excerpt` against `manifest`.
	Returns a Verdict; per-range problems are reported as VerifyIssue
	entries with exact virtual addresses.
	"""
	verdict = Verdict()
	if excerpt.origin_digest != manifest.origin_digest:
		verdict.issues.append(VerifyIssue(
			VerifyIssue.ORIGIN_MISMATCH, None, None,
			'Excerpt is pinned to origin %s but manifest covers %s' % (
				excerpt.origin_digest, manifest.origin_digest),
		))
		return verdict

	for seg in excerpt.segments:
		for kind, rec, covered_end in manifest.authorized_coverage(seg.start, seg.end):
			if kind is None:
				verdict.issues.append(VerifyIssue(
					VerifyIssue.UNAUTHORIZED_RANGE, rec, covered_end,
					'Range %s-%s is not covered by any authorized range' % (
						hex(rec), hex(covered_end)),
				))
				continue
			if kind == 'gap':
				verdict.issues.append(VerifyIssue(
					VerifyIssue.UNKNOWN_PAGES, rec.start, covered_end,
					'Range %s-%s crosses unknown pages that were never signed' % (
						hex(rec.start), hex(covered_end)),
				))
				continue
			# signed segment record: hash the matching slice of the excerpt
			slice_start = max(seg.start, rec.start)
			off_lo = slice_start - seg.start
			off_hi = off_lo + (covered_end - slice_start)
			actual = hash_segment(slice_start, seg.data[off_lo:off_hi])
			if slice_start == rec.start and covered_end == rec.end and actual == rec.sha256:
				verdict.checked_segments.append({
					'start': slice_start,
					'end': covered_end,
					'sha256': rec.sha256,
				})
			elif slice_start == rec.start and covered_end == rec.end:
				verdict.issues.append(VerifyIssue(
					VerifyIssue.HASH_MISMATCH, slice_start, covered_end,
					'Content hash mismatch for authorized range %s-%s' % (
						hex(slice_start), hex(covered_end)),
				))
			else:
				# excerpt covers only part of a signed record: verify the
				# partial range against a record for exactly that span
				partial_ok = False
				for cand in manifest.find_segment_records(slice_start, covered_end):
					if cand.start == slice_start and cand.end == covered_end \
							and actual == cand.sha256:
						partial_ok = True
						verdict.checked_segments.append({
							'start': slice_start,
							'end': covered_end,
							'sha256': cand.sha256,
						})
						break
				if not partial_ok:
					verdict.issues.append(VerifyIssue(
						VerifyIssue.HASH_MISMATCH, slice_start, covered_end,
						'No signed record exactly covers %s-%s' % (
							hex(slice_start), hex(covered_end)),
					))
	return verdict
