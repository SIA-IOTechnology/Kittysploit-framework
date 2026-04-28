#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed llama.cpp RPC server and vulnerable pre-fix builds."""

import socket
import struct

from kittysploit import *
from core.framework.option import OptPort
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


RPC_CMD_HELLO = 14
RPC_CMD_DEVICE_COUNT = 15


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return b""
        data.extend(chunk)
    return bytes(data)


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "llama.cpp RPC b8487 exposure detection",
        "description": (
            "Detects reachable llama.cpp RPC servers and identifies builds that may be "
            "affected by the pre-PR #20908 null-buffer bypass issue."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "cve": "",
        "modules": [],
        "tags": ["scanner", "tcp", "llama.cpp", "rpc", "ai", "exposure"],
    }

    port = OptPort(50052, "Target llama.cpp RPC server port", True)

    def _probe_hello(self, host: str, port: int, timeout: float):
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(bytes([RPC_CMD_HELLO]))
        sock.sendall(struct.pack("<Q", 0))

        raw_len = _recv_exact(sock, 8)
        if len(raw_len) != 8:
            return None, None
        msg_len = struct.unpack("<Q", raw_len)[0]
        if msg_len > 1024:
            return None, None

        payload = _recv_exact(sock, msg_len) if msg_len else b""
        if msg_len and len(payload) != msg_len:
            return None, None

        if len(payload) >= 3:
            version = f"{payload[0]}.{payload[1]}.{payload[2]}"
        else:
            version = "unknown"
        return sock, version

    def _probe_device_count(self, sock: socket.socket):
        try:
            sock.sendall(bytes([RPC_CMD_DEVICE_COUNT]))
            sock.sendall(struct.pack("<Q", 0))
            raw_len = _recv_exact(sock, 8)
            if len(raw_len) != 8:
                return None
            msg_len = struct.unpack("<Q", raw_len)[0]
            if msg_len == 0 or msg_len > 64:
                return None
            payload = _recv_exact(sock, msg_len)
            if len(payload) != msg_len or len(payload) < 4:
                return None
            if len(payload) >= 8:
                return struct.unpack("<Q", payload[:8])[0]
            return struct.unpack("<I", payload[:4])[0]
        except Exception:
            return None

    def run(self):
        host = self._host()
        if not host:
            return False
        port = self._port()
        timeout = self._timeout()

        try:
            sock, version = self._probe_hello(host, port, timeout)
            if not sock:
                return False

            device_count = self._probe_device_count(sock)
            sock.close()
        except Exception:
            return False

        reason = f"llama.cpp RPC endpoint detected on {host}:{port} (version: {version})"
        if device_count is not None:
            reason += f", devices: {device_count}"

        # Conservative posture: exposed pre-fix versions are high risk.
        self.set_info(
            severity="high",
            reason=reason,
            version=version,
            note="If server is pre-PR #20908 (around b8487), prioritize patching and network isolation.",
        )
        return True
