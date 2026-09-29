#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Secure HTTP(S) stager delivery with one-time tokens, TTL and access logs."""

from __future__ import annotations

import json
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse


@dataclass
class StagerArtifact:
    token: str
    path: str
    file_name: str
    content: bytes
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    one_time: bool = True
    allowed_ips: Set[str] = field(default_factory=set)
    consumed: bool = False
    consume_count: int = 0


@dataclass
class StagerAccessLogEntry:
    ts: float
    client_ip: str
    method: str
    path: str
    status: int
    detail: str = ""


class _SecureStagerHandler(BaseHTTPRequestHandler):
    server_version = "KittyStagerHost/2.0"

    def log_message(self, format, *args):
        pass

    @property
    def host(self) -> "StagerHost":
        return self.server.stager_host  # type: ignore[attr-defined]

    def _client_ip(self) -> str:
        return str(self.client_address[0] or "")

    def _log_access(self, status: int, detail: str = "") -> None:
        self.host._append_access_log(
            StagerAccessLogEntry(
                ts=time.time(),
                client_ip=self._client_ip(),
                method=str(self.command or ""),
                path=str(self.path or ""),
                status=int(status),
                detail=str(detail or ""),
            )
        )

    def _reject(self, status: int, detail: str) -> None:
        self.send_response(status)
        self.end_headers()
        self._log_access(status, detail)

    def do_GET(self):
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2 or parts[0] != "dl":
            self._reject(404, "invalid path")
            return

        token = parts[1]
        file_name = parts[2] if len(parts) > 2 else ""
        query = parse_qs(parsed.query or "")
        query_token = (query.get("t") or query.get("token") or [""])[0]

        artifact = self.host._artifacts.get(token)
        if artifact is None:
            self._reject(404, "unknown token")
            return

        if artifact.expires_at and time.time() > artifact.expires_at:
            self._reject(410, "expired")
            return

        if artifact.allowed_ips and self._client_ip() not in artifact.allowed_ips:
            self._reject(403, "ip blocked")
            return

        if query_token and query_token != artifact.token:
            self._reject(403, "bad query token")
            return

        if file_name and file_name != artifact.file_name:
            self._reject(404, "wrong filename")
            return

        if artifact.one_time and artifact.consumed:
            self._reject(410, "already consumed")
            return

        body = artifact.content
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        artifact.consume_count += 1
        if artifact.one_time:
            artifact.consumed = True
        self._log_access(200, f"delivered {len(body)} bytes")


class StagerHost:
    """Singleton HTTP(S) server for one-time stager delivery."""

    _instance: Optional["StagerHost"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._directory = ""
        self._host = "0.0.0.0"
        self._port = 8000
        self._use_ssl = False
        self._artifacts: Dict[str, StagerArtifact] = {}
        self._access_log: List[StagerAccessLogEntry] = []
        self._default_ttl = 3600.0

    @classmethod
    def get(cls) -> "StagerHost":
        with cls._lock:
            if cls._instance is None:
                cls._instance = StagerHost()
            return cls._instance

    @property
    def running(self) -> bool:
        return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    def register_artifact(
        self,
        file_name: str,
        content: bytes,
        *,
        ttl_seconds: Optional[float] = None,
        one_time: bool = True,
        allowed_ips: Optional[Set[str]] = None,
        token: Optional[str] = None,
    ) -> dict:
        """Register a random URL for a build artifact."""
        token = str(token or secrets.token_urlsafe(18)).strip()
        ttl = float(self._default_ttl if ttl_seconds is None else ttl_seconds)
        expires_at = time.time() + ttl if ttl > 0 else 0.0
        path = f"/dl/{token}/{file_name}"
        self._artifacts[token] = StagerArtifact(
            token=token,
            path=path,
            file_name=str(file_name or "stager.bin"),
            content=bytes(content or b""),
            expires_at=expires_at,
            one_time=bool(one_time),
            allowed_ips=set(allowed_ips or []),
        )
        return {
            "token": token,
            "path": path,
            "url": f"{self.base_url()}{path}",
            "expires_at": expires_at,
            "one_time": one_time,
        }

    def _append_access_log(self, entry: StagerAccessLogEntry) -> None:
        self._access_log.append(entry)
        if len(self._access_log) > 500:
            self._access_log = self._access_log[-500:]
        print(
            f"[host_stager] {entry.client_ip} {entry.method} {entry.path} "
            f"-> {entry.status} {entry.detail}".strip()
        )

    def start(
        self,
        directory: str = "",
        host: str = "0.0.0.0",
        port: int = 8000,
        *,
        use_ssl: bool = False,
        certfile: str = "",
        keyfile: str = "",
        default_ttl: float = 3600.0,
    ) -> str:
        directory = str(Path(directory or "output/stagers").resolve())
        Path(directory).mkdir(parents=True, exist_ok=True)

        if self.running:
            if (
                self._directory == directory
                and int(self._port) == int(port)
                and bool(self._use_ssl) == bool(use_ssl)
            ):
                return self.base_url()
            self.stop()

        self._directory = directory
        self._host = host
        self._port = int(port)
        self._use_ssl = bool(use_ssl)
        self._default_ttl = float(default_ttl or 3600.0)

        self._httpd = ThreadingHTTPServer((self._host, self._port), _SecureStagerHandler)
        self._httpd.stager_host = self  # type: ignore[attr-defined]
        if use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if certfile and keyfile:
                ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
            else:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)

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
        scheme = "https" if self._use_ssl else "http"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{display_host}"
        return f"{scheme}://{display_host}:{port}"

    def status(self) -> dict:
        files = []
        if self._directory and Path(self._directory).is_dir():
            files = sorted(p.name for p in Path(self._directory).iterdir() if p.is_file())[:20]
        return {
            "running": self.running,
            "directory": self._directory,
            "url": self.base_url() if self.running else "",
            "port": self._port,
            "use_ssl": self._use_ssl,
            "artifacts": len(self._artifacts),
            "files": files,
            "access_log": [
                {
                    "ts": entry.ts,
                    "client_ip": entry.client_ip,
                    "method": entry.method,
                    "path": entry.path,
                    "status": entry.status,
                    "detail": entry.detail,
                }
                for entry in self._access_log[-20:]
            ],
        }

    def write_file(self, name: str, content: bytes) -> Path:
        if not self._directory:
            raise RuntimeError("host_stager not started")
        dest = Path(self._directory) / name
        dest.write_bytes(content)
        return dest

    def publish_file(
        self,
        name: str,
        content: bytes,
        *,
        ttl_seconds: Optional[float] = None,
        one_time: bool = True,
        allowed_ips: Optional[Set[str]] = None,
    ) -> str:
        """Register secure one-time URL and optionally mirror to serve directory."""
        if not self.running:
            raise RuntimeError("host_stager not started")
        self.write_file(name, content)
        meta = self.register_artifact(
            name,
            content,
            ttl_seconds=ttl_seconds,
            one_time=one_time,
            allowed_ips=allowed_ips,
        )
        return str(meta["url"])

    def export_access_log(self) -> str:
        return json.dumps(self.status()["access_log"], indent=2)
