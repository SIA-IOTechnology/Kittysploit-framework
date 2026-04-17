#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MySQL Detectors - Helpers pour détecter et fingerprint des serveurs MySQL
"""

import socket
from typing import Dict, Optional


CLIENT_SSL = 0x0800


def get_handshake(host: str, port: int = 3306, timeout: float = 3.0) -> Optional[bytes]:
    """Récupère le paquet de handshake initial MySQL."""
    if not host or not port:
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        data = sock.recv(4096)
    except Exception:
        return None
    finally:
        sock.close()

    return data if data else None


def fingerprint_mysql(host: str, port: int = 3306, timeout: float = 3.0) -> Dict[str, object]:
    """Fingerprint basique via le handshake MySQL."""
    packet = get_handshake(host=host, port=port, timeout=timeout)
    if not packet or len(packet) < 6:
        return {"success": False}

    if len(packet) < 5:
        return {"success": False}

    payload = packet[4:]
    protocol = payload[0]
    if protocol == 0xFF:
        return {"success": False}

    idx = 1
    version_end = payload.find(b"\x00", idx)
    if version_end == -1:
        return {"success": False}

    version = payload[idx:version_end].decode("utf-8", errors="replace").strip()

    capabilities = 0
    try:
        # protocol + version + NUL + thread_id
        idx = version_end + 1 + 4
        # auth-plugin-data-part-1
        idx += 8
        # filler
        idx += 1
        if len(payload) >= idx + 2:
            cap_lower = int.from_bytes(payload[idx:idx + 2], "little")
            idx += 2
            # charset + status
            idx += 1 + 2
            if len(payload) >= idx + 2:
                cap_upper = int.from_bytes(payload[idx:idx + 2], "little")
                capabilities = (cap_upper << 16) | cap_lower
    except Exception:
        capabilities = 0

    return {
        "success": True,
        "Protocol": str(protocol),
        "Version": version,
        "TLS": "supported" if (capabilities & CLIENT_SSL) else "not-supported",
        "Transport": "tcp",
    }


def detect_mysql(host: str, port: int = 3306, timeout: float = 3.0) -> bool:
    """Détecte MySQL via le handshake initial."""
    info = fingerprint_mysql(host=host, port=port, timeout=timeout)
    return bool(info.get("success"))
