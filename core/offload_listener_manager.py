#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Manage edge offload listeners that proxy to the teamserver."""

from __future__ import annotations

import threading
import uuid
from typing import Any, Dict, List

from lib.c2.offload_listener import OffloadListenerRegistry, OffloadListenerSpec


class OffloadListenerManager:
    """Register and start lightweight hop proxies on edge nodes."""

    def __init__(self, framework):
        self.framework = framework
        self.registry = OffloadListenerRegistry()
        self._threads: Dict[str, threading.Thread] = {}
        self._servers: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def register(self, bind_host: str, bind_port: int, upstream: str, *, listener_id: str = "", token: str = "") -> str:
        lid = str(listener_id or "").strip() or f"offload-{uuid.uuid4().hex[:8]}"
        spec = OffloadListenerSpec(
            listener_id=lid,
            bind_host=str(bind_host or "0.0.0.0"),
            bind_port=int(bind_port),
            upstream=str(upstream or "").strip(),
            token=str(token or ""),
        )
        with self._lock:
            self.registry.register(spec)
        return lid

    def unregister(self, listener_id: str) -> bool:
        with self._lock:
            self.stop(listener_id)
            return self.registry.unregister(listener_id)

    def list_specs(self) -> List[OffloadListenerSpec]:
        return self.registry.list()

    def start(self, listener_id: str, *, url_prefix: str = "/c2") -> bool:
        spec = next((x for x in self.registry.list() if x.listener_id == listener_id), None)
        if spec is None:
            return False
        if listener_id in self._servers:
            return True

        upstream = spec.upstream.rstrip("/")
        if "://" not in upstream:
            upstream = "http://" + upstream
        parts = upstream.split("://", 1)
        scheme = parts[0]
        hostport = parts[1].split("/", 1)[0]
        if ":" in hostport:
            up_host, up_port_s = hostport.rsplit(":", 1)
            up_port = int(up_port_s)
        else:
            up_host, up_port = hostport, 443 if scheme == "https" else 80

        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import urllib.request

        prefix = "/" + str(url_prefix or "/c2").strip("/")

        class _HopHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _forward(self, method: str):
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length) if length > 0 else None
                target = f"{scheme}://{up_host}:{up_port}{self.path}"
                req = urllib.request.Request(target, data=body, method=method)
                for k, v in self.headers.items():
                    if k.lower() in ("host", "content-length"):
                        continue
                    req.add_header(k, v)
                req.add_header("Host", f"{up_host}:{up_port}")
                if spec.token:
                    req.add_header("X-KS-Offload-Token", spec.token)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                    self.send_response(resp.status)
                    for hk, hv in resp.headers.items():
                        if hk.lower() in ("transfer-encoding", "connection"):
                            continue
                        self.send_header(hk, hv)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

            def do_GET(self):
                if not self.path.startswith(prefix):
                    self.send_response(404)
                    self.end_headers()
                    return
                try:
                    self._forward("GET")
                except Exception:
                    self.send_response(502)
                    self.end_headers()

            def do_POST(self):
                if not self.path.startswith(prefix):
                    self.send_response(404)
                    self.end_headers()
                    return
                try:
                    self._forward("POST")
                except Exception:
                    self.send_response(502)
                    self.end_headers()

        try:
            httpd = ThreadingHTTPServer((spec.bind_host, spec.bind_port), _HopHandler)
        except Exception:
            return False

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        with self._lock:
            self._servers[listener_id] = httpd
            self._threads[listener_id] = thread
        return True

    def stop(self, listener_id: str) -> bool:
        with self._lock:
            httpd = self._servers.pop(listener_id, None)
            self._threads.pop(listener_id, None)
        if httpd is None:
            return False
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
        return True

    def stop_all(self) -> None:
        for spec in list(self.registry.list()):
            self.stop(spec.listener_id)
