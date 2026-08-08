#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Background HTTP server for download-exec stager delivery."""

from __future__ import annotations

import os
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def log_request(self, code="-", size="-"):
        print(f"[host_stager] {self.client_address[0]} {self.command} {self.path} -> {code}")


class StagerHost:
    """Singleton-ish HTTP file server for second-stage payloads."""

    _instance: Optional["StagerHost"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._directory = ""
        self._host = "0.0.0.0"
        self._port = 8000

    @classmethod
    def get(cls) -> "StagerHost":
        with cls._lock:
            if cls._instance is None:
                cls._instance = StagerHost()
            return cls._instance

    @property
    def running(self) -> bool:
        return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    def start(self, directory: str, host: str = "0.0.0.0", port: int = 8000) -> str:
        directory = str(Path(directory).resolve())
        if not Path(directory).is_dir():
            raise FileNotFoundError(f"Directory not found: {directory}")

        if self.running:
            if self._directory == directory and int(self._port) == int(port):
                return self.base_url()
            self.stop()

        self._directory = directory
        self._host = host
        self._port = int(port)

        handler = lambda *args, **kwargs: _QuietHandler(  # noqa: E731
            *args, directory=directory, **kwargs
        )

        self._httpd = ThreadingHTTPServer((self._host, self._port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url()

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            try:
                self._httpd.server_close()
            except Exception:
                pass
        self._httpd = None
        self._thread = None

    def base_url(self) -> str:
        port = int(self._port or 8000)
        display_host = self._host
        if display_host in ("0.0.0.0", ""):
            display_host = "127.0.0.1"
        if port == 80:
            return f"http://{display_host}"
        return f"http://{display_host}:{port}"

    def status(self) -> dict:
        files = []
        if self._directory and Path(self._directory).is_dir():
            files = sorted(
                p.name
                for p in Path(self._directory).iterdir()
                if p.is_file()
            )[:20]
        return {
            "running": self.running,
            "directory": self._directory,
            "url": self.base_url() if self.running else "",
            "port": self._port,
            "files": files,
        }

    def write_file(self, name: str, content: bytes) -> Path:
        if not self._directory:
            raise RuntimeError("host_stager not started")
        dest = Path(self._directory) / name
        dest.write_bytes(content)
        return dest
