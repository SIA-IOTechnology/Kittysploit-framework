#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect open SOCKS4/5 proxies (NSE socks-open-proxy)."""

from __future__ import annotations

import socket
import struct
from typing import Dict


def probe_socks_open_proxy(
    host: str,
    port: int = 1080,
    timeout: float = 5.0,
    dest_host: str = "1.1.1.1",
    dest_port: int = 80,
) -> Dict[str, object]:
    """
    Try SOCKS5 no-auth CONNECT then SOCKS4 CONNECT to an external IP.
    Success (granted) => likely open proxy.
    """
    result: Dict[str, object] = {
        "open_proxy": False,
        "socks5": False,
        "socks4": False,
        "error": "",
    }
    # SOCKS5
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")  # VER, NMETHODS, NO AUTH
            resp = sock.recv(2)
            if resp == b"\x05\x00":
                # CONNECT to dest
                try:
                    ip = socket.inet_aton(dest_host)
                    req = b"\x05\x01\x00\x01" + ip + struct.pack("!H", dest_port)
                except OSError:
                    name = dest_host.encode("ascii", errors="ignore")
                    req = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", dest_port)
                sock.sendall(req)
                reply = sock.recv(10)
                if len(reply) >= 2 and reply[0] == 0x05 and reply[1] == 0x00:
                    result["socks5"] = True
                    result["open_proxy"] = True
                    return result
    except Exception as exc:
        result["error"] = str(exc)[:120]

    # SOCKS4
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            ip = socket.inet_aton(dest_host)
            req = b"\x04\x01" + struct.pack("!H", dest_port) + ip + b"kittysploit\x00"
            sock.sendall(req)
            reply = sock.recv(8)
            if len(reply) >= 2 and reply[0] == 0x00 and reply[1] == 0x5A:
                result["socks4"] = True
                result["open_proxy"] = True
                return result
    except Exception as exc:
        if not result["error"]:
            result["error"] = str(exc)[:120]
    return result
