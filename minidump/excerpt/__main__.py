#!/usr/bin/env python3
#
# Demo: synthetic dump -> manifest -> local verification endpoint.
#
# Builds a synthetic memory image with a deliberately unmapped page
# inside the authorized region, publishes a manifest (coverage +
# hashes only), then verifies two excerpts over a local HTTP endpoint:
#   A) fully inside the authorized region        -> verifies
#   B) splices in the adjacent, unauthorized page -> rejected, and the
#      verdict names the exact range that exceeds the authorization.

import hashlib
import json
import threading
import urllib.request

from minidump.excerpt.image import MemorySegment, MemoryImage
from minidump.excerpt.manifest import build_manifest
from minidump.excerpt.excerpt import build_excerpt
from minidump.excerpt.server import make_server
from minidump.excerpt.verify import verify_excerpt

PAGE = 0x1000


def build_synthetic_dump():
	"""
	Synthetic 'original dump': a header blob plus three captured pages.
	Page at 0x11000 is deliberately absent (unknown), page at 0x13000
	holds user data that must NOT be shared.
	"""
	pages = {
		0x10000: b'CRASH-CONTEXT:' + bytes(range(256)) * (PAGE // 256 - 1) + bytes(range(240)),
		0x12000: b'MODULE-LIST:' + b'kernel32.dll;ntdll.dll;app.exe;' * (PAGE // 33),
		0x13000: b'USER-PRIVATE:' + b'cookie=secret;token=abc123;' * (PAGE // 27),
	}
	pages = {addr: data[:PAGE].ljust(PAGE, b'.') for addr, data in pages.items()}
	blob = b'SYNDUMP1' + b''.join(
		addr.to_bytes(8, 'little') + data for addr, data in sorted(pages.items())
	)
	image = MemoryImage([MemorySegment(addr, data) for addr, data in pages.items()])
	return blob, image


def post_json(url, payload):
	req = urllib.request.Request(
		url, data=payload.encode('utf-8'),
		headers={'Content-Type': 'application/json'}, method='POST',
	)
	try:
		with urllib.request.urlopen(req) as resp:
			return resp.status, json.loads(resp.read().decode('utf-8'))
	except urllib.error.HTTPError as e:
		return e.code, json.loads(e.read().decode('utf-8'))


def main():
	blob, image = build_synthetic_dump()
	origin_digest = hashlib.sha256(blob).hexdigest()
	print('synthetic dump: %d bytes, origin sha256 %s...' % (len(blob), origin_digest[:16]))

	manifest = build_manifest(
		image, origin_digest,
		[
			(0x10000, 0x13000, 'crash-region'),
			(0x10000, 0x11000, 'crash-context-only', 'entry-0'),
		],
		origin_description='synthetic demo dump',
	)

	entry0 = manifest.entries[0]
	print('\nmanifest entry-0 coverage (unknown page recorded, NOT zero-signed):')
	for seg in entry0.segments:
		print('  signed  %s-%s sha256=%s...' % (hex(seg.start), hex(seg.end), seg.sha256[:16]))
	for gap in entry0.gaps:
		print('  gap     %s-%s (%s, signed=False)' % (hex(gap.start), hex(gap.end), gap.reason))

	print('\ndirectory trace for 0x10000-0x11000 (multiple descriptions, same region):')
	for hit in manifest.trace(0x10000, 0x11000):
		print('  %s (%s) lineage=%s' % (hit['entry'].entry_id, hit['entry'].label, hit['lineage']))

	excerpt_ok = build_excerpt(image, origin_digest, [(0x10000, PAGE)], note='crash context only')
	excerpt_splice = build_excerpt(
		image, origin_digest,
		[(0x10000, PAGE), (0x13000, PAGE)],
		note='crash context + adjacent page spliced in',
	)

	try:
		server = make_server(manifest)
	except OSError as e:
		# sandboxed environments may forbid binding sockets; exercise the
		# same verification logic in-process so the demo still runs.
		print('\nsocket bind unavailable (%s), verifying in-process' % e)
		public_view = manifest.to_public_dict()
		print('public manifest view keys: %s (coverage + hashes only)' % sorted(public_view.keys()))
		for name, excerpt in [('A', excerpt_ok), ('B', excerpt_splice)]:
			verdict = verify_excerpt(manifest, excerpt)
			print_verdict(name, excerpt, verdict.to_dict())
		return

	host, port = server.server_address[:2]
	thread = threading.Thread(target=server.serve_forever, daemon=True)
	thread.start()
	base = 'http://%s:%d' % (host, port)
	print('\nlocal verification endpoint: %s' % base)

	try:
		with urllib.request.urlopen(base + '/manifest') as resp:
			public_view = json.loads(resp.read().decode('utf-8'))
		print('GET /manifest exposes keys: %s (coverage + hashes only)' % sorted(public_view.keys()))

		for name, excerpt in [('A', excerpt_ok), ('B', excerpt_splice)]:
			status, verdict = post_json(base + '/verify', excerpt.to_json())
			print_verdict(name, excerpt, verdict)
	finally:
		server.shutdown()
		server.server_close()


def print_verdict(name, excerpt, verdict):
	print('\nexcerpt %s (%s): ok=%s' % (name, excerpt.note, verdict['ok']))
	for checked in verdict['checked_segments']:
		print('  verified %s-%s' % (hex(checked['start']), hex(checked['end'])))
	for issue in verdict['issues']:
		print('  %s: %s' % (issue['kind'], issue['message']))


if __name__ == '__main__':
	main()
