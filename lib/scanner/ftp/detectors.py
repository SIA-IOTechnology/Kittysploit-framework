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


def _recv_until_complete(sock: socket.socket, timeout: float, *, multiline_code: str = "") -> str:
    """Read FTP reply; for multi-line (e.g. 211-...211 ) keep reading until end marker."""
    sock.settimeout(timeout)
    lines: list[str] = []
    first = _recv_line(sock, timeout)
    if not first:
        return ""
    lines.append(first)
    code = first[:3] if len(first) >= 3 else ""
    # Multi-line replies use "NNN-text" until a final "NNN text"
    if len(first) > 3 and first[3:4] == "-" and code.isdigit():
        end_prefix = f"{code} "
        while True:
            line = _recv_line(sock, timeout)
            if not line:
                break
            lines.append(line)
            if line.startswith(end_prefix) or line == code:
                break
    elif multiline_code and first.startswith(f"{multiline_code}-"):
        while True:
            line = _recv_line(sock, timeout)
            if not line:
                break
            lines.append(line)
            if line.startswith(f"{multiline_code} ") or line == multiline_code:
                break
    return "\n".join(lines)


def _ftp_connect_banner(host: str, port: int, timeout: float) -> tuple:
    """Return (sock, banner, error). Caller must close sock on success."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        banner = _recv_line(sock, timeout)
        if not banner.upper().startswith("220"):
            sock.close()
            return None, banner, "not_ftp_welcome"
        return sock, banner, ""
    except Exception as exc:
        try:
            sock.close()
        except Exception:
            pass
        return None, "", str(exc)


def probe_ftp_syst(host: str, port: int = 21, timeout: float = 5.0) -> Dict[str, object]:
    """Issue SYST after welcome banner (NSE ftp-syst style)."""
    result: Dict[str, object] = {
        "detected": False,
        "banner": "",
        "syst": "",
        "error": "",
    }
    sock, banner, err = _ftp_connect_banner(host, port, timeout)
    if sock is None:
        result["banner"] = banner
        result["error"] = err or "connect_failed"
        return result
    try:
        result["banner"] = banner
        result["detected"] = True
        sock.sendall(b"SYST\r\n")
        resp = _recv_line(sock, timeout)
        if resp.startswith("215"):
            result["syst"] = resp[4:].strip() or resp
        else:
            result["error"] = f"syst_rejected:{resp[:120]}"
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


def probe_ftp_feat(host: str, port: int = 21, timeout: float = 5.0) -> Dict[str, object]:
    """Issue FEAT and parse advertised features."""
    result: Dict[str, object] = {
        "detected": False,
        "banner": "",
        "features": [],
        "raw": "",
        "error": "",
    }
    sock, banner, err = _ftp_connect_banner(host, port, timeout)
    if sock is None:
        result["banner"] = banner
        result["error"] = err or "connect_failed"
        return result
    try:
        result["banner"] = banner
        result["detected"] = True
        sock.sendall(b"FEAT\r\n")
        resp = _recv_until_complete(sock, timeout, multiline_code="211")
        result["raw"] = resp
        if not resp.startswith("211"):
            result["error"] = f"feat_rejected:{resp[:120]}"
            return result
        features: list[str] = []
        for line in resp.splitlines()[1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("211"):
                continue
            # Feature lines are often indented
            features.append(stripped.split()[0].upper() if stripped else "")
        result["features"] = [f for f in features if f]
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
