#!/usr/bin/env python3
#
# Excerpt manifest backend.
#
# Binds caller-authorized memory content of an original dump to the
# original's digest and to virtual address ranges. The manifest only
# ever exposes coverage relations and hashes; actual bytes only ever
# live in excerpts explicitly built for the authorized party.

from minidump.excerpt.image import MemorySegment, MemoryImage
from minidump.excerpt.manifest import (
	SegmentRecord,
	GapRecord,
	ManifestEntry,
	ExcerptManifest,
	build_manifest,
	hash_segment,
)
from minidump.excerpt.excerpt import Excerpt, ExcerptSegment, build_excerpt
from minidump.excerpt.verify import VerifyIssue, Verdict, verify_excerpt

__all__ = [
	'MemorySegment',
	'MemoryImage',
	'SegmentRecord',
	'GapRecord',
	'ManifestEntry',
	'ExcerptManifest',
	'build_manifest',
	'hash_segment',
	'Excerpt',
	'ExcerptSegment',
	'build_excerpt',
	'VerifyIssue',
	'Verdict',
	'verify_excerpt',
]
