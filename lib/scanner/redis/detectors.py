#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Redis Detectors - Helpers pour détecter et énumérer des serveurs Redis
"""

import re
import socket
from typing import Optional, Dict


def get_server_info(host: str, port: int = 6379, timeout: float = 3.0) -> Optional[str]:
    """Envoie INFO à Redis et retourne la réponse brute, ou None."""
    if not host or not port:
        return None

    payload = b"*1\r\n$4\r\nINFO\r\n"
    data = b""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(chunk) < 8192:
                break
    except Exception:
        return None
    finally:
        sock.close()

    if not data:
        return None
    return data.decode("utf-8", errors="replace")


def detect_redis(host: str, port: int = 6379, timeout: float = 3.0) -> bool:
    """Détecte Redis via la commande INFO."""
    response = get_server_info(host=host, port=port, timeout=timeout)
    if not response:
        return False
    if response.startswith("-NOAUTH") or "authentication required" in response.lower():
        return True
    return "redis_version:" in response or response.startswith("$")


def extract_info_field(response: str, pattern: str) -> str:
    """Extrait un champ Redis INFO via regex."""
    if not response:
        return ""
    match = re.search(pattern, response, re.I | re.M)
    return match.group(1).strip() if match else ""


def extract_server_details(response: str) -> Dict[str, str]:
    """Extrait les champs utiles depuis la réponse INFO."""
    if not response:
        return {}

    details = {
        "redis_version": extract_info_field(response, r"redis_version:(\d+\.\d+\.\d+)"),
        "os": extract_info_field(response, r"os:(.*?)\r?\n"),
        "arch_bits": extract_info_field(response, r"arch_bits:(\d+)"),
        "process_id": extract_info_field(response, r"process_id:(\d+)"),
        "used_cpu_sys": extract_info_field(response, r"used_cpu_sys:(\d+\.\d+)"),
        "used_cpu_user": extract_info_field(response, r"used_cpu_user:(\d+\.\d+)"),
        "connected_clients": extract_info_field(response, r"connected_clients:(\d+)"),
        "connected_slaves": extract_info_field(response, r"connected_slaves:(\d+)"),
        "used_memory_human": extract_info_field(response, r"used_memory_human:([^\r\n]+)"),
        "role": extract_info_field(response, r"role:(\w+)"),
    }
    return {key: value for key, value in details.items() if value}
