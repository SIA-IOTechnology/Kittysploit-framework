#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.websocket.websocket_client import WebsocketTimeoutException, Websocket_client


class Module(Scanner, Websocket_client):
    __info__ = {
        "name": "Peyara Remote Mouse exposure detection",
        "description": (
            "Detects Peyara Remote Mouse <= 1.0.1 exposure by checking TCP 1313, "
            "an Engine.IO OPEN frame, and a Socket.IO namespace connect handshake. "
            "No keyboard injection is performed."
        ),
        "author": ["tmrswrr", "KittySploit Team"],
        "severity": "critical",
        "modules": [
            "exploits/windows/tcp/peyara_remote_mouse_rce",
        ],
        "references": [
            "https://github.com/capture0x/Peyara",
            "https://peyara-remote-mouse.vercel.app/",
        ],
        "tags": [
            "peyara",
            "remote-mouse",
            "socket.io",
            "websocket",
            "windows",
            "rce",
            "scanner",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["peyara", "remote-mouse", "socket.io"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/windows/tcp/peyara_remote_mouse_rce",
                ],
            },
        },
    }

    _AFFECTED_VERSION = "1.0.1"
    _ENGINEIO_OPEN = "0"
    _ENGINEIO_PING = "2"
    _ENGINEIO_PONG = "3"
    _ENGINEIO_CLOSE = "1"
    _SOCKETIO_CONNECT = "40"

    port = OptPort(1313, "Peyara Socket.IO port", True)
    ssl = OptBool(False, "Use WSS", True, advanced=True)
    target_uri = OptString("/", "Base path for the Socket.IO endpoint", required=False)

    def _opt(self, option):
        if hasattr(option, "value"):
            return option.value
        return option

    def _ws_timeout(self) -> float:
        return max(float(self._opt(self.timeout) or 10), 3.0)

    def _socket_io_path(self) -> str:
        base = str(self._opt(self.target_uri) or "/").strip() or "/"
        if not base.startswith("/"):
            base = "/" + base
        base = base.rstrip("/")
        if base:
            return f"{base}/socket.io/?EIO=4&transport=websocket"
        return "/socket.io/?EIO=4&transport=websocket"

    def _recv_text(self) -> str:
        frame = self.ws_recv()
        if frame is None:
            raise WebsocketTimeoutException("WebSocket receive timed out")
        if isinstance(frame, bytes):
            return frame.decode("utf-8", errors="replace")
        return str(frame)

    def _close_session(self) -> None:
        if not self.ws:
            return
        try:
            self.ws_send(self._ENGINEIO_CLOSE)
        except Exception:
            pass
        self.ws_close()

    def _socketio_connect(self) -> bool:
        self.ws_send(self._SOCKETIO_CONNECT)
        for _ in range(3):
            frame = self._recv_text()
            if frame == self._ENGINEIO_PING:
                self.ws_send(self._ENGINEIO_PONG)
            if frame.startswith(self._SOCKETIO_CONNECT):
                return True
        return False

    def _probe_handshake(self) -> tuple:
        try:
            self.ws_close()
            self.ws_connect(path=self._socket_io_path())
            if self.ws:
                self.ws.settimeout(self._ws_timeout())
            frame = self._recv_text()
            if not frame.startswith(self._ENGINEIO_OPEN):
                return False, False, f"Unexpected first frame: {frame[:80]!r}"
            connected = self._socketio_connect()
            if connected:
                return True, True, "Engine.IO OPEN and Socket.IO namespace connect"
            return True, False, "Engine.IO present but Socket.IO connect not acknowledged"
        except Exception as exc:
            return False, False, str(exc)
        finally:
            self._close_session()

    def run(self):
        if not str(self._opt(self.target) or "").strip():
            print_warning("Target host is required")
            return False

        engine_io, socket_io, reason = self._probe_handshake()
        if engine_io and socket_io:
            self.set_info(
                severity="critical",
                reason=(
                    f"{reason} on TCP/{int(self.port)} "
                    f"(Peyara Remote Mouse <= {self._AFFECTED_VERSION} likely)"
                ),
            )
            return True

        if engine_io:
            self.set_info(
                severity="high",
                reason=f"{reason} on TCP/{int(self.port)}",
            )
            return True

        print_error(reason or f"TCP/{int(self.port)} open without Socket.IO handshake")
        return False
