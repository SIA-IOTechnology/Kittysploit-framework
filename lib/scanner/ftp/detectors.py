#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FTP banner detection helpers."""

from __future__ import annotations

import socket
from typing import Dict, Optional


def probe_ftp_banner(host: str, port: int = 21, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "banner": "",
        "product": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(512)
        if not data:
            result["error"] = "empty_banner"
            return result
        banner = data.decode("utf-8", errors="replace").strip()
        result["banner"] = banner
        if not banner.upper().startswith("220"):
            result["error"] = "not_ftp_welcome"
            return result
        result["detected"] = True
        low = banner.lower()
        for product in ("vsftpd", "proftpd", "pure-ftpd", "filezilla", "microsoft ftp"):
            if product in low:
                result["product"] = product
                break
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
