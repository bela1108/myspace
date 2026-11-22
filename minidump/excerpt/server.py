#!/usr/bin/env python3
#
# Local verification endpoint.
#
# Serves the public manifest view (coverage + hashes only) and verifies
# excerpts posted by a supplier-side tool. The server never sees the
# original dump and never serves memory content.
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from minidump.excerpt.excerpt import Excerpt
from minidump.excerpt.verify import verify_excerpt


def make_handler(manifest):
	class ExcerptVerifyHandler(BaseHTTPRequestHandler):
		server_version = 'MinidumpExcerptVerify/1.0'

		def _send_json(self, code, obj):
			body = json.dumps(obj, indent=2, sort_keys=True).encode('utf-8')
			self.send_response(code)
			self.send_header('Content-Type', 'application/json')
			self.send_header('Content-Length', str(len(body)))
			self.end_headers()
			self.wfile.write(body)

		def do_GET(self):
			if self.path == '/manifest':
				self._send_json(200, manifest.to_public_dict())
			elif self.path == '/health':
				self._send_json(200, {'ok': True})
			else:
				self._send_json(404, {'error': 'unknown endpoint'})

		def do_POST(self):
			if self.path != '/verify':
				self._send_json(404, {'error': 'unknown endpoint'})
				return
			try:
				length = int(self.headers.get('Content-Length', '0'))
				excerpt = Excerpt.from_json(self.rfile.read(length).decode('utf-8'))
			except Exception as e:
				self._send_json(400, {'error': 'invalid excerpt: %s' % e})
				return
			verdict = verify_excerpt(manifest, excerpt)
			self._send_json(200 if verdict.ok else 422, verdict.to_dict())

		def log_message(self, format, *args):
			pass

	return ExcerptVerifyHandler


def make_server(manifest, host='127.0.0.1', port=0):
	"""Returns a ThreadingHTTPServer bound to (host, port); port 0 = ephemeral."""
	return ThreadingHTTPServer((host, port), make_handler(manifest))


def serve(manifest, host='127.0.0.1', port=8765):
	server = make_server(manifest, host, port)
	print('Excerpt verification endpoint listening on http://%s:%d' % server.server_address[:2])
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass
	finally:
		server.server_close()
