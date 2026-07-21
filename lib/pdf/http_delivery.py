"""Minimal background HTTP delivery for PDF file-format exploits."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple


def start_static_http_server(
    routes: Dict[str, Tuple[bytes, str]],
    *,
    host: str = "0.0.0.0",
    port: int = 8888,
) -> ThreadingHTTPServer:
    """Serve exact path → (body, content_type) maps in a daemon thread.

    ``routes`` keys should include the leading slash (e.g. ``/h``, ``/file.pdf``).
    """

    table = {path.split("?", 1)[0]: (body, ctype) for path, (body, ctype) in routes.items()}
    # Also allow "/" alias to first PDF if present
    if "/" not in table:
        for path, (body, ctype) in table.items():
            if ctype == "application/pdf":
                table["/"] = (body, ctype)
                break

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: A003
            return

        def do_GET(self):  # noqa: N802
            req = (self.path or "/").split("?", 1)[0]
            item = table.get(req)
            if item is None:
                self.send_response(404)
                self.end_headers()
                return
            body, ctype = item
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer((host, int(port)), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def advertise_url(host: str, port: int, path: str) -> str:
    slug = path if path.startswith("/") else f"/{path}"
    if int(port) in (0, 80):
        return f"http://{host}{slug}"
    return f"http://{host}:{int(port)}{slug}"
