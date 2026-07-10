#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""QNX qconn service identification helpers."""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, Optional


QCONN_DEFAULT_PORT = 8000

_QCONN_SERVICE_RE = re.compile(r"service\s+(\w+)", re.IGNORECASE)


def build_launcher_request(command: str) -> bytes:
    cmd = (command or "/bin/sh -").strip()
    payload = f"service launcher\nstart/flags run {cmd}\n"
    return payload.encode("ascii", errors="replace")


def is_qconn_port_open(host: str, port: int = QCONN_DEFAULT_PORT, timeout: float = 3.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(timeout))
    try:
        sock.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_qconn_service(
    host: str,
    port: int = QCONN_DEFAULT_PORT,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Best-effort qconn fingerprint: TCP open + optional banner after launcher probe.

    Does not spawn a shell — sends an invalid/minimal launcher line and reads any reply.
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": int(port),
        "open": False,
        "qconn": False,
        "banner": "",
        "services": [],
        "error": "",
    }
    if not host:
        result["error"] = "host not set"
        return result

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(timeout))
    try:
        sock.connect((host, int(port)))
        result["open"] = True
        sock.sendall(b"service launcher\nhelp\n")
        chunks: list[bytes] = []
        try:
            while len(b"".join(chunks)) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        banner = b"".join(chunks).decode("utf-8", errors="replace").strip()
        result["banner"] = banner[:500]
        services = sorted({m.group(1).lower() for m in _QCONN_SERVICE_RE.finditer(banner)})
        result["services"] = services
        blob = banner.lower()
        if "launcher" in blob or "qconn" in blob or "neutrino" in blob or services:
            result["qconn"] = True
    except OSError as exc:
        result["error"] = str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result


def launch_qconn_shell(
    host: str,
    port: int = QCONN_DEFAULT_PORT,
    command: str = "/bin/sh -",
    timeout: float = 10.0,
) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(timeout))
    sock.connect((host, int(port)))
    sock.sendall(build_launcher_request(command))
    sock.settimeout(None)
    return sock
