#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPMI RMCP probes inspired by NSE ipmi-version / ipmi-cipher-zero."""

from __future__ import annotations

import socket
import struct
from typing import Dict


# Metasploit Rex::Proto::IPMI::Utils.create_ipmi_getchannel_probe
_GET_CHANNEL_AUTH = bytes(
    [
        0x06,
        0x00,
        0xFF,
        0x07,  # RMCP
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x09,
        0x20,
        0x18,
        0xC8,
        0x81,
        0x00,
        0x38,
        0x8E,
        0x04,
        0xB5,
    ]
)


def _cipher_zero_open(console_session_id: bytes = b"\x00\x00\x00\x00") -> bytes:
    """RMCP+ Open Session Request forcing cipher suite 0."""
    head = bytes(
        [
            0x06,
            0x00,
            0xFF,
            0x07,  # RMCP
            0x06,  # Auth type = RMCP+
            0x10,  # PAYLOAD_RMCPPLUSOPEN_REQ
            0x00,
            0x00,
            0x00,
            0x00,  # session id
            0x00,
            0x00,
            0x00,
            0x00,  # sequence
        ]
    )
    if len(console_session_id) != 4:
        console_session_id = b"\x00\x00\x00\x00"
    data = (
        bytes([0x00, 0x00, 0x00, 0x00])
        + console_session_id
        + bytes(
            [
                0x00,
                0x00,
                0x00,
                0x08,  # cipher 0
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x08,  # cipher 0
                0x00,
                0x00,
                0x00,
                0x00,
                0x02,
                0x00,
                0x00,
                0x08,  # no encryption
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )
    )
    return head + struct.pack("<H", len(data)) + data


def probe_ipmi_version(host: str, port: int = 623, timeout: float = 3.0) -> Dict[str, object]:
    """Send Get Channel Authentication Capabilities and fingerprint IPMI."""
    result: Dict[str, object] = {
        "detected": False,
        "ipmi_version": "",
        "auth_types": [],
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_GET_CHANNEL_AUTH, (host, int(port)))
        data, _ = sock.recvfrom(256)
        if len(data) < 20:
            result["error"] = "short_response"
            return result
        # RMCP header + IPMI session + response
        result["detected"] = True
        # Byte after session header often encodes IPMI version / auth support
        # Conservative parse: presence of response = IPMI service
        if len(data) >= 24:
            # Completion code at offset ~20 in many replies; auth support nearby
            auth_byte = data[23] if len(data) > 23 else 0
            auths = []
            mapping = {
                0x01: "none",
                0x02: "md2",
                0x04: "md5",
                0x10: "password",
                0x20: "oem",
            }
            for bit, name in mapping.items():
                if auth_byte & bit:
                    auths.append(name)
            result["auth_types"] = auths
            # IPMI 1.5 vs 2.0: bit in capabilities (byte often 22)
            cap = data[22] if len(data) > 22 else 0
            result["ipmi_version"] = "2.0" if (cap & 0x02) else "1.5"
        else:
            result["ipmi_version"] = "unknown"
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        sock.close()


def probe_ipmi_cipher_zero(host: str, port: int = 623, timeout: float = 3.0) -> Dict[str, object]:
    """
    Probe IPMI 2.0 cipher suite 0 auth bypass (CVE-2013-4782).
    Vulnerable if Open Session Reply error_code == 0.
    """
    result: Dict[str, object] = {
        "vulnerable": False,
        "detected": False,
        "error_code": None,
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_cipher_zero_open(), (host, int(port)))
        data, _ = sock.recvfrom(256)
        if len(data) < 20:
            result["error"] = "short_response"
            return result
        result["detected"] = True
        # RMCP+ Open Session Response: payload type 0x11, error at offset 16 in payload
        # Layout: RMCP(4) + auth(1) + payload_type(1) + session(4) + seq(4) + len(2) + data
        # data[0] = message tag, data[1] = status code
        if len(data) >= 18:
            payload_type = data[5] & 0x3F
            # Some stacks put status at data[17]
            status = data[17] if len(data) > 17 else -1
            result["error_code"] = int(status)
            # PAYLOAD_RMCPPLUSOPEN_REP = 0x11
            if payload_type in (0x11, 0x10) and status == 0:
                result["vulnerable"] = True
            elif status == 0:
                result["vulnerable"] = True
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        sock.close()
