#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMTP open-relay and capability probes (NSE smtp-open-relay / smtp-commands)."""

from __future__ import annotations

import socket
from typing import Dict, List, Optional


def _smtp_session(host: str, port: int, timeout: float):
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _recv_smtp(sock: socket.socket) -> str:
    chunks: List[str] = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        text = data.decode("latin-1", errors="replace")
        chunks.append(text)
        # Multi-line replies end when "XYZ " (space) appears
        joined = "".join(chunks)
        lines = joined.replace("\r\n", "\n").split("\n")
        lines = [ln for ln in lines if ln]
        if lines and len(lines[-1]) >= 4 and lines[-1][3:4] == " ":
            break
        if len(joined) > 65536:
            break
    return "".join(chunks)


def _send_smtp(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\r\n").encode("ascii", errors="ignore"))


def probe_smtp_commands(host: str, port: int = 25, timeout: float = 5.0) -> Dict[str, object]:
    """EHLO and collect advertised capabilities (NSE smtp-commands)."""
    result: Dict[str, object] = {
        "detected": False,
        "banner": "",
        "capabilities": [],
        "error": "",
    }
    sock: Optional[socket.socket] = None
    try:
        sock = _smtp_session(host, port, timeout)
        banner = _recv_smtp(sock)
        result["banner"] = banner.strip()[:200]
        if not banner.startswith("220"):
            result["error"] = "not_smtp"
            return result
        result["detected"] = True
        _send_smtp(sock, "EHLO kittysploit.local")
        ehlo = _recv_smtp(sock)
        caps: List[str] = []
        for line in ehlo.replace("\r\n", "\n").split("\n"):
            line = line.strip()
            if len(line) >= 4 and line[:3].isdigit():
                caps.append(line[4:].strip())
        result["capabilities"] = [c for c in caps if c][:40]
        _send_smtp(sock, "QUIT")
        try:
            _recv_smtp(sock)
        except Exception:
            pass
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_smtp_open_relay(
    host: str,
    port: int = 25,
    timeout: float = 8.0,
    mail_from: str = "relaytest@example.com",
    rcpt_to: str = "relaytest@example.org",
) -> Dict[str, object]:
    """
    Test third-party relay acceptance (NSE smtp-open-relay).
    Uses external-looking MAIL FROM / RCPT TO; does not send DATA body.
    """
    result: Dict[str, object] = {
        "vulnerable": False,
        "detected": False,
        "mail_from_code": "",
        "rcpt_to_code": "",
        "error": "",
    }
    sock: Optional[socket.socket] = None
    try:
        sock = _smtp_session(host, port, timeout)
        banner = _recv_smtp(sock)
        if not banner.startswith("220"):
            result["error"] = "not_smtp"
            return result
        result["detected"] = True
        _send_smtp(sock, "HELO kittysploit.local")
        _recv_smtp(sock)
        _send_smtp(sock, f"MAIL FROM:<{mail_from}>")
        mail_resp = _recv_smtp(sock)
        result["mail_from_code"] = mail_resp[:3]
        if not mail_resp.startswith("250"):
            result["error"] = f"mail_from_rejected:{mail_resp.strip()[:80]}"
            _send_smtp(sock, "QUIT")
            return result
        _send_smtp(sock, f"RCPT TO:<{rcpt_to}>")
        rcpt_resp = _recv_smtp(sock)
        result["rcpt_to_code"] = rcpt_resp[:3]
        # 250 accepted = likely open relay for external recipient
        if rcpt_resp.startswith("250"):
            result["vulnerable"] = True
        _send_smtp(sock, "RSET")
        try:
            _recv_smtp(sock)
            _send_smtp(sock, "QUIT")
        except Exception:
            pass
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
