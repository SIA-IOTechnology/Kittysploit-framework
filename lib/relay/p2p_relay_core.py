#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
P2P relay rendezvous protocol for KittySploit.

Agents and operators connect to a shared relay hub. The hub pairs peers by
token (room id) and bridges their TCP streams — useful when neither side has
a stable public address reachable by the other.
"""

from __future__ import annotations

import socket
import threading
from collections import deque
from typing import Callable, Deque, Dict, Optional, Tuple

PROTOCOL_VERSION = "v1"
PROTOCOL_VERSION_V2 = "v2"
MAGIC = "KSRL"
ROLE_AGENT = "AGENT"
ROLE_OPERATOR = "OPERATOR"


def read_line(sock: socket.socket, timeout: float = 30.0, max_size: int = 512) -> str:
    """Read a single newline-terminated line from *sock*."""
    sock.settimeout(timeout)
    buffer = bytearray()
    while len(buffer) < max_size:
        chunk = sock.recv(1)
        if not chunk:
            break
        if chunk == b"\n":
            break
        buffer.extend(chunk)
    return buffer.decode("utf-8", errors="replace").strip("\r")


def build_handshake(role: str, token: str, version: str = PROTOCOL_VERSION_V2) -> bytes:
    role = role.strip().upper()
    token = token.strip()
    version = (version or PROTOCOL_VERSION_V2).strip()
    if version not in (PROTOCOL_VERSION, PROTOCOL_VERSION_V2):
        raise ValueError(f"Unsupported relay protocol version: {version}")
    if role not in (ROLE_AGENT, ROLE_OPERATOR):
        raise ValueError(f"Invalid relay role: {role}")
    if not token:
        raise ValueError("Relay token cannot be empty")
    return f"{MAGIC}:{version}:{role}:{token}\n".encode("utf-8")


def parse_handshake(line: str) -> Tuple[str, str, str]:
    parts = line.strip().split(":")
    if len(parts) < 4 or parts[0] != MAGIC:
        raise ValueError(f"Invalid relay handshake: {line!r}")
    version = parts[1]
    if version not in (PROTOCOL_VERSION, PROTOCOL_VERSION_V2):
        raise ValueError(f"Unsupported relay protocol version: {version}")
    role = parts[2].upper()
    token = ":".join(parts[3:])
    if role not in (ROLE_AGENT, ROLE_OPERATOR):
        raise ValueError(f"Invalid relay role: {role}")
    if not token:
        raise ValueError("Missing relay token")
    return role, token, version


def send_ack(sock: socket.socket, ok: bool = True, message: str = "") -> None:
    if ok:
        payload = f"{MAGIC}:OK\n"
    else:
        payload = f"{MAGIC}:ERR:{message or 'handshake failed'}\n"
    sock.sendall(payload.encode("utf-8"))


def perform_handshake(
    sock: socket.socket,
    role: str,
    token: str,
    timeout: float = 30.0,
    version: str = PROTOCOL_VERSION_V2,
) -> str:
    """Client-side handshake; raises ValueError on failure. Returns negotiated version."""
    sock.sendall(build_handshake(role, token, version=version))
    line = read_line(sock, timeout=timeout)
    if not line.startswith(f"{MAGIC}:OK"):
        detail = line[len(f"{MAGIC}:ERR:") :] if line.startswith(f"{MAGIC}:ERR:") else line
        raise ValueError(detail or "relay handshake rejected")
    return version


def _enable_tcp_keepalive(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def bridge_sockets(
    sock_a: socket.socket,
    sock_b: socket.socket,
    *,
    on_close: Optional[Callable[[], None]] = None,
) -> None:
    """Bidirectionally forward bytes between two connected sockets."""
    _enable_tcp_keepalive(sock_a)
    _enable_tcp_keepalive(sock_b)
    closed = threading.Event()

    def forward(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            closed.set()
            try:
                dst.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    t1 = threading.Thread(target=forward, args=(sock_a, sock_b), daemon=True)
    t2 = threading.Thread(target=forward, args=(sock_b, sock_a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for sock in (sock_a, sock_b):
        try:
            sock.close()
        except OSError:
            pass
    if on_close:
        try:
            on_close()
        except Exception:
            pass


class RelayHub:
    """TCP rendezvous server that pairs AGENT and OPERATOR peers by token."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = int(port)
        self._server_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._running = False
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._agents: Dict[str, Deque[socket.socket]] = {}
        self._operators: Dict[str, Deque[socket.socket]] = {}
        self.stats = {
            "agents_connected": 0,
            "operators_connected": 0,
            "pairs_bridged": 0,
        }

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(128)
        server.settimeout(1.0)
        self._server_sock = server
        self._running = True
        self._stop_event.clear()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=2.0)
        with self._lock:
            for queue in list(self._agents.values()) + list(self._operators.values()):
                while queue:
                    try:
                        queue.popleft().close()
                    except OSError:
                        pass
            self._agents.clear()
            self._operators.clear()

    def _accept_loop(self) -> None:
        while self._running and self._server_sock is not None:
            try:
                client_sock, _addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    continue
                break
            threading.Thread(
                target=self._handle_client,
                args=(client_sock,),
                daemon=True,
            ).start()

    def _handle_client(self, sock: socket.socket) -> None:
        try:
            line = read_line(sock, timeout=15.0)
            role, token, _version = parse_handshake(line)
            send_ack(sock, ok=True)
            self._enqueue_or_pair(sock, role, token)
        except Exception:
            try:
                send_ack(sock, ok=False, message="invalid handshake")
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _enqueue_or_pair(self, sock: socket.socket, role: str, token: str) -> None:
        with self._lock:
            if role == ROLE_AGENT:
                self.stats["agents_connected"] += 1
                op_queue = self._operators.get(token)
                if op_queue:
                    peer = op_queue.popleft()
                    if not op_queue:
                        self._operators.pop(token, None)
                    threading.Thread(
                        target=self._bridge_pair,
                        args=(sock, peer, token),
                        daemon=True,
                    ).start()
                    return
                self._agents.setdefault(token, deque()).append(sock)
                return

            self.stats["operators_connected"] += 1
            agent_queue = self._agents.get(token)
            if agent_queue:
                peer = agent_queue.popleft()
                if not agent_queue:
                    self._agents.pop(token, None)
                threading.Thread(
                    target=self._bridge_pair,
                    args=(peer, sock, token),
                    daemon=True,
                ).start()
                return
            self._operators.setdefault(token, deque()).append(sock)

    def _bridge_pair(
        self,
        agent_sock: socket.socket,
        operator_sock: socket.socket,
        token: str,
    ) -> None:
        self.stats["pairs_bridged"] += 1
        bridge_sockets(agent_sock, operator_sock)

    def pending_counts(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            tokens = set(self._agents) | set(self._operators)
            return {
                token: {
                    "agents": len(self._agents.get(token, ())),
                    "operators": len(self._operators.get(token, ())),
                }
                for token in sorted(tokens)
            }


def connect_operator(
    relay_host: str,
    relay_port: int,
    token: str,
    timeout: float = 120.0,
    **kwargs,
):
    """Backward-compatible import path — delegates to lib.relay.client."""
    from lib.relay.client import connect_operator as _connect_operator

    return _connect_operator(relay_host, relay_port, token, timeout=timeout, **kwargs)
