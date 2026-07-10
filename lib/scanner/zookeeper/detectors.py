#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zookeeper four-letter-word probe helpers."""

from __future__ import annotations

import socket
from typing import Dict


def probe_zookeeper(host: str, port: int = 2181, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "version": "", "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(b"srvr")
        data = sock.recv(512)
        if not data:
            result["error"] = "empty_response"
            return result
        text = data.decode("utf-8", errors="replace")
        if "zookeeper version" in text.lower() or "mode:" in text.lower():
            result["detected"] = True
            for line in text.splitlines():
                if "zookeeper version" in line.lower():
                    result["version"] = line.strip()
                    break
            return result
        result["error"] = "unexpected_response"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()


def probe_zookeeper_command(host: str, port: int, command: bytes, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"ok": False, "output": "", "error": ""}
    if len(command) != 4:
        result["error"] = "invalid_four_letter_command"
        return result
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(command)
        data = sock.recv(8192)
        if not data:
            result["error"] = "empty_response"
            return result
        result["ok"] = True
        result["output"] = data.decode("utf-8", errors="replace")
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()


def probe_zookeeper_unauth_info(host: str, port: int = 2181, timeout: float = 5.0) -> Dict[str, object]:
    """Collect srvr/stat/conf output for unauthenticated exposure assessment."""
    result: Dict[str, object] = {"detected": False, "srvr": "", "stat": "", "conf": "", "error": ""}
    base = probe_zookeeper(host, port, timeout)
    if not base.get("detected"):
        result["error"] = base.get("error") or "not_zookeeper"
        return result
    result["detected"] = True
    result["version"] = base.get("version", "")
    for cmd, key in ((b"srvr", "srvr"), (b"stat", "stat"), (b"conf", "conf")):
        info = probe_zookeeper_command(host, port, cmd, timeout)
        if info.get("ok"):
            result[key] = str(info.get("output") or "")[:500]
    return result
