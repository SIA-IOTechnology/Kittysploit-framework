#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NDMP wire helpers (CONFIG_GET_SERVER_INFO probe)."""

from __future__ import annotations

import socket
import struct
from typing import Dict, Optional, Tuple

from core.framework.base_module import BaseModule

NDMP_MSG_CONFIG_GET_SERVER_INFO = 0x0100


class NdmpClient:
    def __init__(self, host: str, port: int = 10000, timeout: float = 10.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)

    @staticmethod
    def build_header(sequence: int, message_type: int) -> bytes:
        return struct.pack("!IIIIII", sequence, 0, 0, 0, message_type, 0)[:16]

    @staticmethod
    def parse_string(data: bytes, offset: int) -> Tuple[str, int]:
        if offset + 4 > len(data):
            return "", offset
        length = struct.unpack("!I", data[offset : offset + 4])[0]
        offset += 4
        if offset + length > len(data):
            return data[offset:].decode("utf-8", errors="replace"), len(data)
        value = data[offset : offset + length].decode("utf-8", errors="replace").rstrip("\x00")
        padded = (length + 3) & ~3
        return value, offset + padded

    @classmethod
    def parse_server_info(cls, data: bytes) -> Dict[str, str]:
        info: Dict[str, str] = {}
        if len(data) < 20:
            return info
        offset = 20
        for field in (
            "vendor_name",
            "product_name",
            "revision_number",
            "os_type",
            "os_version",
            "host_name",
        ):
            if offset >= len(data):
                break
            val, offset = cls.parse_string(data, offset)
            if val:
                info[field] = val
        return info

    def probe_server_info(self) -> Tuple[str, Dict[str, str], bytes]:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            try:
                sock.recv(1024)
            except socket.timeout:
                pass
            sock.sendall(self.build_header(1, NDMP_MSG_CONFIG_GET_SERVER_INFO))
            response = b""
            while len(response) < 8192:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response += chunk
            sock.close()
        except OSError:
            return "unreachable", {}, b""
        info = self.parse_server_info(response)
        if info:
            return "vulnerable", info, response
        if response:
            return "responded", {}, response
        return "connected", {}, b""


class Ndmp(BaseModule):
    def ndmp_host(self) -> str:
        if hasattr(self, "_host"):
            host = self._host()
            if host:
                return host
        raw = str(getattr(self, "target", None) or getattr(self, "rhost", "") or "")
        return raw.split("://")[-1].split("/")[0].split(":")[0]

    def ndmp_port(self) -> int:
        if hasattr(self, "_port"):
            return int(self._port())
        port = getattr(self, "port", 10000)
        if hasattr(port, "value"):
            port = port.value
        return int(port or 10000)

    def ndmp_probe(self, host: Optional[str] = None, port: Optional[int] = None):
        host = host or self.ndmp_host()
        port = port if port is not None else self.ndmp_port()
        return NdmpClient(host, port).probe_server_info()