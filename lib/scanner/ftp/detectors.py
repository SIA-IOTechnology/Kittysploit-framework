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


def _recv_line(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        data = sock.recv(256)
        if not data:
            break
        chunks.append(data)
        if b"\n" in data:
            break
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


def probe_ftp_anonymous(
    host: str,
    port: int = 21,
    timeout: float = 5.0,
    username: str = "anonymous",
    password: str = "anonymous@",
) -> Dict[str, object]:
    """
    Attempt anonymous (or guest) FTP login and optionally LIST.

    Returns keys: detected, anonymous, banner, list_preview, error.
    """
    result: Dict[str, object] = {
        "detected": False,
        "anonymous": False,
        "banner": "",
        "list_preview": "",
        "cwd": "",
        "error": "",
        "username": username,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        banner = _recv_line(sock, timeout)
        result["banner"] = banner
        if not banner.upper().startswith("220"):
            result["error"] = "not_ftp_welcome"
            return result
        result["detected"] = True

        sock.sendall(f"USER {username}\r\n".encode("ascii", errors="ignore"))
        user_resp = _recv_line(sock, timeout)
        # 331 need password, 230 already logged in
        if not (user_resp.startswith("331") or user_resp.startswith("230")):
            result["error"] = f"user_rejected:{user_resp[:80]}"
            return result

        if not user_resp.startswith("230"):
            sock.sendall(f"PASS {password}\r\n".encode("ascii", errors="ignore"))
            pass_resp = _recv_line(sock, timeout)
            if not pass_resp.startswith("230"):
                result["error"] = f"pass_rejected:{pass_resp[:80]}"
                return result

        result["anonymous"] = True

        sock.sendall(b"PWD\r\n")
        pwd_resp = _recv_line(sock, timeout)
        if pwd_resp.startswith("257"):
            result["cwd"] = pwd_resp[4:120].strip()

        # Prefer NLST (names only) over full LIST for lighter evidence
        sock.sendall(b"PASV\r\n")
        pasv_resp = _recv_line(sock, timeout)
        if pasv_resp.startswith("227"):
            import re

            match = re.search(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", pasv_resp)
            if match:
                a, b, c, d, p1, p2 = (int(x) for x in match.groups())
                data_port = p1 * 256 + p2
                data_host = f"{a}.{b}.{c}.{d}"
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    data_sock.settimeout(timeout)
                    data_sock.connect((data_host, data_port))
                    sock.sendall(b"NLST\r\n")
                    list_resp = _recv_line(sock, timeout)
                    if list_resp.startswith(("150", "125")):
                        listing = data_sock.recv(2048).decode("utf-8", errors="replace")
                        result["list_preview"] = listing.strip()[:500]
                        # drain 226
                        _recv_line(sock, timeout)
                finally:
                    data_sock.close()

        try:
            sock.sendall(b"QUIT\r\n")
        except Exception:
            pass
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass
