#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Lightweight HTTP server for the interactive attack path explorer."""

from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlparse


STATIC_DIR = Path(__file__).resolve().parents[2] / "interfaces" / "graph_explorer" / "static"
DEFAULT_GRAPH_EXPLORER_PORT = 9477


class GraphExplorerServer:
    """Serve the attack path explorer UI and graph JSON API."""

    def __init__(
        self,
        framework: Any,
        *,
        host: str = "127.0.0.1",
        port: int = DEFAULT_GRAPH_EXPLORER_PORT,
        source: str = "both",
        max_steps: int = 50,
        run_id: Optional[str] = None,
    ) -> None:
        self.framework = framework
        self.host = str(host or "127.0.0.1")
        self.port = int(port or DEFAULT_GRAPH_EXPLORER_PORT)
        self.source = str(source or "both")
        self.max_steps = int(max_steps or 50)
        self.run_id = str(run_id or "").strip() or None
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._payload_provider: Callable[[], Dict[str, Any]] = self._default_payload_provider
        self._lock = threading.Lock()
        self._cached_payload: Dict[str, Any] = {}

    def set_payload_provider(self, provider: Callable[[], Dict[str, Any]]) -> None:
        self._payload_provider = provider

    def _default_payload_provider(self) -> Dict[str, Any]:
        from core.graph.data_loader import load_explorer_graph

        graph = load_explorer_graph(
            self.framework,
            source=self.source,
            max_steps=self.max_steps,
            run_id=self.run_id,
        )
        return graph.to_dict()

    def refresh_payload(self) -> Dict[str, Any]:
        with self._lock:
            self._cached_payload = self._payload_provider()
            return dict(self._cached_payload)

    def get_payload(self) -> Dict[str, Any]:
        with self._lock:
            if not self._cached_payload:
                self._cached_payload = self._payload_provider()
            return dict(self._cached_payload)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, *, block: bool = False) -> None:
        if self.is_running():
            return
        self.refresh_payload()
        handler_cls = self._build_handler()
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler_cls)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="graph-explorer",
            daemon=True,
        )
        self._thread.start()
        if block:
            self._thread.join()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        self._httpd = None
        self._thread = None

    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def _build_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                del fmt, args

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                route = parsed.path or "/"
                if route in {"/", "/index.html"}:
                    return server._serve_file(self, STATIC_DIR / "index.html")
                if route.startswith("/static/"):
                    rel = route[len("/static/") :]
                    return server._serve_file(self, STATIC_DIR / rel)
                if route == "/api/graph":
                    params = parse_qs(parsed.query or "")
                    if params.get("refresh", ["0"])[0] in {"1", "true", "yes"}:
                        payload = server.refresh_payload()
                    else:
                        payload = server.get_payload()
                    return server._serve_json(self, payload)
                if route == "/api/health":
                    return server._serve_json(self, {"status": "ok", "url": server.url()})
                self.send_error(404, "Not found")

        return Handler

    @staticmethod
    def _serve_json(handler: BaseHTTPRequestHandler, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        handler.wfile.write(body)

    @staticmethod
    def _serve_file(handler: BaseHTTPRequestHandler, path: Path) -> None:
        try:
            resolved = path.resolve()
            if not str(resolved).startswith(str(STATIC_DIR.resolve())):
                handler.send_error(403, "Forbidden")
                return
            if not resolved.is_file():
                handler.send_error(404, "Not found")
                return
            content = resolved.read_bytes()
            mime, _ = mimetypes.guess_type(str(resolved))
            handler.send_response(200)
            handler.send_header("Content-Type", mime or "application/octet-stream")
            handler.send_header("Content-Length", str(len(content)))
            if resolved.suffix.lower() in {".js", ".css", ".html"}:
                handler.send_header("Cache-Control", "no-store")
            handler.end_headers()
            handler.wfile.write(content)
        except OSError:
            handler.send_error(500, "Could not read file")
