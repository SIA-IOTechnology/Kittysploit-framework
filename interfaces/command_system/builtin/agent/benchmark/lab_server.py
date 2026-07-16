#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal in-process HTTP lab for synthetic agent benchmarks."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional


DEFAULT_ROUTES: Dict[str, Dict[str, object]] = {
    "/": {"status": 200, "body": "lab-root"},
    "/login": {"status": 302, "location": "/dashboard", "set_cookie": "session=lab"},
    "/dashboard": {"status": 200, "body": "authenticated"},
    "/rate-limit": {"status": 429, "body": "slow down"},
    "/waf": {"status": 403, "body": "request blocked by waf"},
}


def _make_handler(routes: Dict[str, Dict[str, object]]):
    class _SyntheticLabHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            route = routes.get(self.path, {"status": 404, "body": "missing"})
            latency_ms = int(route.get("latency_ms", 0) or 0)
            if latency_ms > 0:
                time.sleep(min(latency_ms, 250) / 1000.0)
            status = int(route.get("status", 200))
            server_banner = str(route.get("server") or "SyntheticLab/1.0")
            if status in {301, 302, 303, 307, 308}:
                self.send_response(status)
                self.send_header("Location", str(route.get("location", "/")))
                self.send_header("Server", server_banner)
                if route.get("set_cookie"):
                    self.send_header("Set-Cookie", str(route["set_cookie"]))
                self.end_headers()
                return
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", server_banner)
            if route.get("set_cookie"):
                self.send_header("Set-Cookie", str(route["set_cookie"]))
            self.end_headers()
            self.wfile.write(str(route.get("body", "")).encode("utf-8"))

    return _SyntheticLabHandler


class SyntheticHttpLab:
    """Ephemeral HTTP server for CI-friendly agent benchmark runs."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        routes: Optional[Dict[str, Dict[str, object]]] = None,
        mutation: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.routes = dict(routes or DEFAULT_ROUTES)
        self.mutation = dict(mutation or {})
        handler = _make_handler(self.routes)
        self._httpd = HTTPServer((host, port), handler)
        self.port = self._httpd.server_address[1]
        self.base_url = f"http://{host}:{self.port}"
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "SyntheticHttpLab":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        if self._thread:
            self._thread.join(timeout=2)
