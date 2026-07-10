#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH Detectors - Helpers pour détecter des serveurs SSH
"""

import re
from typing import Optional


def detect_openssh(banner: str) -> Optional[str]:
    """Détecte OpenSSH et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'OpenSSH[_-]([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def detect_dropbear(banner: str) -> Optional[str]:
    """Détecte Dropbear SSH et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'dropbear_([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def probe_ssh_banner(host: str, port: int = 22, timeout: float = 5.0) -> dict:
    """Read SSH banner and classify OpenSSH/Dropbear."""
    import socket

    result = {
        "detected": False,
        "banner": "",
        "product": "",
        "version": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(256)
        if not data:
            result["error"] = "empty_banner"
            return result
        banner = data.decode("utf-8", errors="replace").strip()
        result["banner"] = banner
        if not banner.upper().startswith("SSH-"):
            result["error"] = "not_ssh_protocol"
            return result
        result["detected"] = True
        openssh = detect_openssh(banner)
        if openssh:
            result["product"] = "openssh"
            result["version"] = openssh
            return result
        dropbear = detect_dropbear(banner)
        if dropbear:
            result["product"] = "dropbear"
            result["version"] = dropbear
            return result
        result["product"] = "ssh"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
