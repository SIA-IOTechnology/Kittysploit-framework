#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PostgreSQL detection helpers for scanner modules."""

from __future__ import annotations

import socket
import struct
from typing import Dict

# PostgreSQL AuthenticationRequest codes (backend message 'R')
_AUTH_METHODS = {
    0: "trust",
    2: "kerberos",
    3: "cleartext",
    5: "md5",
    7: "gssapi",
    9: "sspi",
    10: "sasl",
    11: "sasl_continue",
    12: "sasl_final",
}


def _startup_packet(user: str = "postgres", database: str = "postgres") -> bytes:
    params = (
        f"user\x00{user}\x00database\x00{database}\x00application_name\x00kittysploit\x00\x00"
    ).encode("utf-8")
    length = 4 + 4 + len(params)
    return struct.pack("!I", length) + struct.pack("!I", 196608) + params


def _parse_auth_method(data: bytes) -> str:
    """Parse AuthenticationRequest type from first backend message."""
    if not data or data[0:1] != b"R" or len(data) < 9:
        return ""
    # 'R' + int32 length + int32 auth type
    auth_type = struct.unpack("!I", data[5:9])[0]
    name = _AUTH_METHODS.get(auth_type, f"unknown_{auth_type}")
    # SASL often means SCRAM-SHA-256; list mechanisms if present
    if auth_type == 10 and len(data) > 9:
        mechs = data[9:].split(b"\x00")
        labels = [m.decode("utf-8", errors="replace") for m in mechs if m]
        if labels:
            return "sasl:" + ",".join(labels)
    return name


def probe_postgresql(
    host: str,
    port: int = 5432,
    timeout: float = 5.0,
    user: str = "postgres",
    database: str = "postgres",
) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "auth_required": False,
        "auth_method": "",
        "version": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(_startup_packet(user=user, database=database))
        data = sock.recv(512)
        if not data:
            result["error"] = "empty_response"
            return result

        msg_type = chr(data[0]) if data else ""
        if msg_type == "R":
            result["detected"] = True
            auth_method = _parse_auth_method(data)
            result["auth_method"] = auth_method
            # Auth type 0 = AuthenticationOk (trust / already authenticated)
            if auth_method == "trust":
                result["auth_required"] = False
            else:
                result["auth_required"] = True
            return result
        if msg_type == "E":
            text = data.decode("utf-8", errors="replace")
            if "postgresql" in text.lower() or "password" in text.lower():
                result["detected"] = True
                result["auth_required"] = True
            result["error"] = text[:200]
            return result
        if msg_type == "N":
            text = data.decode("utf-8", errors="replace")
            if "postgresql" in text.lower():
                result["detected"] = True
            # Notice may be followed by Auth — try another read
            try:
                more = sock.recv(512)
                if more and more[0:1] == b"R":
                    result["detected"] = True
                    auth_method = _parse_auth_method(more)
                    result["auth_method"] = auth_method
                    result["auth_required"] = auth_method != "trust"
            except Exception:
                pass
            return result
        if msg_type == "S":
            result["detected"] = True
            return result
        result["error"] = f"unexpected_message:{msg_type}"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
