"""Standard-library local HTTP interface for slot advisory queries."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Type

from .demo import demo_payload
from .query import run_query


def _json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def create_handler() -> Type[BaseHTTPRequestHandler]:
    class SlotAdvisoryHandler(BaseHTTPRequestHandler):
        server_version = "CpeSlotAdvisory/1.0"

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] in ("/healthz", "/health"):
                self._send_json(200, {"status": "ok"})
                return
            if self.path.split("?", 1)[0] in ("/demo", "/query/demo"):
                self._send_json(200, run_query(demo_payload()))
                return
            self._send_json(404, {"error": "not_found", "endpoints": ["POST /query", "GET /demo", "GET /healthz"]})

        def do_POST(self) -> None:
            if self.path.split("?", 1)[0] != "/query":
                self._send_json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b"{}"
                payload = json.loads(raw.decode("utf-8"))
                self._send_json(200, run_query(payload))
            except Exception as exc:
                self._send_json(400, {"error": type(exc).__name__, "message": str(exc)})

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return SlotAdvisoryHandler


def serve(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), create_handler())
    return server


def main(argv: Optional[list] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Serve the local CPE slot advisory query API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    server = serve(args.host, args.port)
    print("Serving slot advisory query API at http://{}:{}/query".format(args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
