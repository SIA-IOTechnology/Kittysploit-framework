#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SIP OPTIONS probe helpers (TCP/UDP)."""

from __future__ import annotations

import random
import socket
from typing import Dict


def _sip_options(host: str, transport: str = "TCP") -> bytes:
    branch = f"z9hG4bK{random.randint(100000, 999999)}"
    tag = f"ks{random.randint(1000, 9999)}"
    call_id = f"{random.randint(100000, 999999)}@kittysploit"
    msg = (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport} 127.0.0.1:5060;branch={branch}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:probe@kittysploit>;tag={tag}\r\n"
        f"To: <sip:{host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:probe@127.0.0.1:5060>\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    return msg.encode("utf-8")


def _parse_sip(data: bytes) -> Dict[str, object]:
    text = data.decode("utf-8", errors="replace")
    first = (text.splitlines() or [""])[0].strip()
    result: Dict[str, object] = {
        "detected": False,
        "status_line": first[:200],
        "server": "",
        "user_agent": "",
        "allow": "",
        "banner": text[:800],
        "error": "",
    }
    if not first.upper().startswith("SIP/2.0"):
        result["error"] = "not_sip"
        return result
    result["detected"] = True
    for line in text.splitlines():
        low = line.lower()
        if low.startswith("server:"):
            result["server"] = line.split(":", 1)[1].strip()[:120]
        elif low.startswith("user-agent:"):
            result["user_agent"] = line.split(":", 1)[1].strip()[:120]
        elif low.startswith("allow:"):
            result["allow"] = line.split(":", 1)[1].strip()[:200]
    return result


def probe_sip_tcp(host: str, port: int = 5060, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "transport": "tcp",
        "status_line": "",
        "server": "",
        "user_agent": "",
        "allow": "",
        "banner": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(_sip_options(host, "TCP"))
        data = sock.recv(4096)
        if not data:
            result["error"] = "empty_response"
            return result
        parsed = _parse_sip(data)
        parsed["transport"] = "tcp"
        return parsed
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_sip_udp(host: str, port: int = 5060, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "transport": "udp",
        "status_line": "",
        "server": "",
        "user_agent": "",
        "allow": "",
        "banner": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_sip_options(host, "UDP"), (host, int(port)))
        data, _addr = sock.recvfrom(4096)
        if not data:
            result["error"] = "empty_response"
            return result
        parsed = _parse_sip(data)
        parsed["transport"] = "udp"
        return parsed
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass
