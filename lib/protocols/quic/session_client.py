#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sync bridge between QUIC asyncio protocol and KittySploit shells."""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from lib.protocols.quic.c2_server import C2ServerProtocol, handle_download, handle_upload


class QuicSessionClient:
    """Expose QUIC C2 protocol operations to synchronous shell code."""

    def __init__(self, protocol: C2ServerProtocol, loop: asyncio.AbstractEventLoop):
        self._protocol = protocol
        self._loop = loop
        self._closed = False

    @property
    def protocol(self) -> C2ServerProtocol:
        return self._protocol

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self):
        self._closed = True

    def send_command(self, cmd: str) -> bool:
        return self._protocol.send_command(cmd)

    def get_output(self, *, wait: float = 0.5) -> str:
        if wait > 0:
            time.sleep(wait)
        return self._protocol.get_output()

    def run_shell_command(self, cmd: str, *, wait: float = 0.5) -> str:
        if not self.send_command(cmd):
            return ""
        return self.get_output(wait=wait)

    def upload(self, local_path: str, remote_path: str) -> str:
        future = asyncio.run_coroutine_threadsafe(
            handle_upload(self._protocol, local_path, remote_path),
            self._loop,
        )
        return future.result(timeout=120.0)

    def download(self, remote_path: str, local_path: str) -> str:
        future = asyncio.run_coroutine_threadsafe(
            handle_download(self._protocol, remote_path, local_path),
            self._loop,
        )
        return future.result(timeout=180.0)

    def exec_shellcode(self, hex_payload: str, *, wait: float = 1.0) -> str:
        return self.run_shell_command(f"exec_shellcode {hex_payload.strip()}", wait=wait)

    @classmethod
    def from_session(
        cls,
        framework,
        session_id: str,
    ) -> Optional["QuicSessionClient"]:
        if not framework or not hasattr(framework, "session_manager"):
            return None

        session = framework.session_manager.get_session(session_id)
        if not session or not session.data:
            return None

        listener_id = session.data.get("listener_id")
        if listener_id and hasattr(framework, "active_listeners"):
            listener = framework.active_listeners.get(listener_id)
            if listener and hasattr(listener, "_session_connections"):
                conn = listener._session_connections.get(session_id)
                if isinstance(conn, QuicSessionClient):
                    return conn

        conn = session.data.get("connection")
        if isinstance(conn, QuicSessionClient):
            return conn
        return None
