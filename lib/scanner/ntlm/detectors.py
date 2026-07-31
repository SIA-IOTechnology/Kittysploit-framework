#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse NTLM Type-2 challenges for OS / domain recon (NSE *-ntlm-info)."""

from __future__ import annotations

import base64
import re
import socket
import struct
from typing import Dict, Optional
from urllib.parse import urljoin


def build_ntlm_negotiate() -> bytes:
    """Minimal NTLMSSP Negotiate (Type 1) with Unicode + NTLM + Always Sign."""
    signature = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 1)
    flags = struct.pack("<I", 0xE2088297)  # common desktop negotiate flags
    # Domain / Workstation empty buffers
    empty = struct.pack("<HHI", 0, 0, 0)
    return signature + msg_type + flags + empty + empty


def _read_security_buffer(data: bytes, offset: int) -> bytes:
    if offset + 8 > len(data):
        return b""
    length, _alloc, ptr = struct.unpack_from("<HHI", data, offset)
    if ptr + length > len(data):
        return b""
    return data[ptr : ptr + length]


def _decode_utf16(raw: bytes) -> str:
    try:
        return raw.decode("utf-16-le", errors="ignore").strip("\x00")
    except Exception:
        return ""


# AV_PAIR IDs from MS-NLMP
_AV_IDS = {
    1: "nb_computer",
    2: "nb_domain",
    3: "dns_computer",
    4: "dns_domain",
    5: "dns_tree",
}


def parse_ntlm_challenge(blob: bytes) -> Dict[str, object]:
    """Extract domain / computer / OS hints from an NTLM Type-2 message."""
    info: Dict[str, object] = {
        "ok": False,
        "target_name": "",
        "nb_domain": "",
        "nb_computer": "",
        "dns_domain": "",
        "dns_computer": "",
        "dns_tree": "",
        "os_version": "",
        "flags": 0,
    }
    idx = blob.find(b"NTLMSSP\x00")
    if idx < 0:
        return info
    data = blob[idx:]
    if len(data) < 32:
        return info
    msg_type = struct.unpack_from("<I", data, 8)[0]
    if msg_type != 2:
        return info
    info["ok"] = True
    info["target_name"] = _decode_utf16(_read_security_buffer(data, 12))
    info["flags"] = struct.unpack_from("<I", data, 20)[0]
    target_info = _read_security_buffer(data, 40)
    # Optional version (8 bytes) starts at offset 48 when NEGOTIATE_VERSION set
    if info["flags"] & 0x02000000 and len(data) >= 56:
        major, minor, build = struct.unpack_from("<BBH", data, 48)
        info["os_version"] = f"{major}.{minor}.{build}"
    pos = 0
    while pos + 4 <= len(target_info):
        av_id, av_len = struct.unpack_from("<HH", target_info, pos)
        pos += 4
        if av_id == 0:  # MsvAvEOL
            break
        value = target_info[pos : pos + av_len]
        pos += av_len
        key = _AV_IDS.get(av_id)
        if key:
            info[key] = _decode_utf16(value)
    return info


def probe_http_ntlm_info(
    url: str,
    timeout: float = 8.0,
    verify_ssl: bool = False,
    path: str = "/",
) -> Dict[str, object]:
    """Issue HTTP NTLM Type-1 and parse WWW-Authenticate Type-2."""
    result: Dict[str, object] = {"detected": False, "error": "", "info": {}}
    try:
        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        token = base64.b64encode(build_ntlm_negotiate()).decode("ascii")
        headers = {"Authorization": f"NTLM {token}", "Connection": "close"}
        target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
        resp = requests.get(
            target,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
        )
        auth = resp.headers.get("WWW-Authenticate") or resp.headers.get("www-authenticate") or ""
        match = re.search(r"NTLM\s+([A-Za-z0-9+/=]+)", auth, re.I)
        if not match:
            result["error"] = "no_ntlm_challenge"
            return result
        challenge = base64.b64decode(match.group(1))
        parsed = parse_ntlm_challenge(challenge)
        if not parsed.get("ok"):
            result["error"] = "parse_failed"
            return result
        result["detected"] = True
        result["info"] = parsed
        result["status_code"] = resp.status_code
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result


def probe_smtp_ntlm_info(
    host: str,
    port: int = 25,
    timeout: float = 5.0,
) -> Dict[str, object]:
    """SMTP AUTH NTLM Type-1 → parse Type-2 challenge (NSE smtp-ntlm-info)."""
    result: Dict[str, object] = {"detected": False, "error": "", "info": {}, "banner": ""}
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.settimeout(timeout)

        def _recv() -> str:
            data = sock.recv(4096)
            return data.decode("latin-1", errors="replace")

        def _send(line: str) -> None:
            sock.sendall((line + "\r\n").encode("ascii", errors="ignore"))

        banner = _recv()
        result["banner"] = banner.strip()[:200]
        _send(f"EHLO kittysploit")
        ehlo = _recv()
        if "NTLM" not in ehlo.upper() and "NTLM" not in banner.upper():
            # Still try AUTH NTLM — some servers omit capability ads
            pass
        token = base64.b64encode(build_ntlm_negotiate()).decode("ascii")
        _send(f"AUTH NTLM {token}")
        challenge_line = _recv()
        # 334 <base64>
        parts = challenge_line.strip().split()
        if not parts or not parts[0].startswith("334"):
            result["error"] = f"unexpected_auth_reply:{challenge_line.strip()[:80]}"
            _send("QUIT")
            return result
        b64 = parts[1] if len(parts) > 1 else ""
        if not b64:
            result["error"] = "empty_challenge"
            return result
        parsed = parse_ntlm_challenge(base64.b64decode(b64))
        _send("*")  # cancel auth
        try:
            _recv()
            _send("QUIT")
        except Exception:
            pass
        if not parsed.get("ok"):
            result["error"] = "parse_failed"
            return result
        result["detected"] = True
        result["info"] = parsed
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
