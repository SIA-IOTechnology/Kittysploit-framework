#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP recon helpers (NSE http-bigip-cookie / internal-ip / http-put)."""

from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional
from urllib.parse import urljoin


_PRIVATE_IP_RE = re.compile(
    r"\b(?:"
    r"10(?:\.\d{1,3}){3}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}"
    r"|169\.254(?:\.\d{1,3}){2}"
    r")\b"
)


def decode_bigip_cookie(value: str) -> Optional[str]:
    """
    Decode classic BIGipServer cookie: <host_enc>.<port_enc>.0000
    host_enc is little-endian uint32 of the pool member IP.
    """
    value = (value or "").strip().strip('"')
    parts = value.split(".")
    if len(parts) < 2:
        return None
    try:
        host_enc = int(parts[0])
        port_enc = int(parts[1])
    except ValueError:
        # Newer cookie formats (rd/…, vi/…) — skip
        return None
    if host_enc < 0 or host_enc > 0xFFFFFFFF:
        return None
    ip_bytes = struct.pack("<I", host_enc)
    ip = ".".join(str(b) for b in ip_bytes)
    # port is also endian-swapped 16-bit in classic form
    try:
        port = struct.unpack("<H", struct.pack(">H", port_enc & 0xFFFF))[0]
    except Exception:
        port = port_enc & 0xFFFF
    return f"{ip}:{port}"


def probe_bigip_cookie(headers: Dict[str, str], set_cookie: str = "") -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "cookies": [],
        "decoded": [],
    }
    cookies: List[str] = []
    for key, val in (headers or {}).items():
        if key.lower() == "set-cookie":
            cookies.append(str(val))
    if set_cookie:
        cookies.append(set_cookie)
    found = []
    decoded = []
    for raw in cookies:
        for part in re.split(r",(?=[^ ;]+?=)", raw):
            name = part.split("=", 1)[0].strip()
            if "BIGipServer" in name or name.startswith("BIGip"):
                found.append(part.strip()[:200])
                val = part.split("=", 1)[1].split(";", 1)[0] if "=" in part else ""
                dec = decode_bigip_cookie(val)
                if dec:
                    decoded.append({"cookie": name, "pool_member": dec})
    result["cookies"] = found
    result["decoded"] = decoded
    result["detected"] = bool(found)
    return result


def find_internal_ips(text: str) -> List[str]:
    if not text:
        return []
    seen = set()
    out: List[str] = []
    for m in _PRIVATE_IP_RE.finditer(text):
        ip = m.group(0)
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def probe_http_put(
    url: str,
    path: str = "/kittysploit_put_probe.txt",
    timeout: float = 8.0,
    verify_ssl: bool = False,
    body: bytes = b"kittysploit-put-probe",
) -> Dict[str, object]:
    """Attempt HTTP PUT to detect writable paths (NSE http-put)."""
    result: Dict[str, object] = {
        "writable": False,
        "status_code": 0,
        "error": "",
        "path": path,
    }
    try:
        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
        resp = requests.put(
            target,
            data=body,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
            headers={"Content-Type": "text/plain"},
        )
        result["status_code"] = int(resp.status_code)
        if resp.status_code in (200, 201, 204):
            result["writable"] = True
            # best-effort cleanup
            try:
                requests.delete(target, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            except Exception:
                pass
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
