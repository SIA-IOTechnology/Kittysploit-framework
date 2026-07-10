#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight TCP banner readers for scanner modules."""

from __future__ import annotations

import socket
from typing import Optional


def read_tcp_banner(host: str, port: int, timeout: float = 3.0, size: int = 512) -> Optional[str]:
    if not host or not port:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(size)
        if not data:
            return None
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None
    finally:
        sock.close()
