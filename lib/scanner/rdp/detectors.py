#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RDP service detection helpers (NSE rdp-enum-encryption inspired)."""

from __future__ import annotations

import socket
import struct
from typing import Dict, List


_PROTOCOL_FLAGS = {
    0x00000001: "PROTOCOL_SSL",
    0x00000002: "PROTOCOL_HYBRID",
    0x00000004: "PROTOCOL_RDSTLS",
    0x00000008: "PROTOCOL_HYBRID_EX",
}


def _x224_connection_request(requested_protocols: int = 0x0000000B) -> bytes:
    """RDP Negotiation Request (TYPE_RDP_NEG_REQ) inside X.224 Connection Request."""
    # Cookie optional; include negotiation request
    cookie = b"Cookie: mstshash=kittysploit\r\n"
    neg = struct.pack("<BBHI", 0x01, 0x00, 8, requested_protocols)  # type, flags, length, protocols
    # X.224 CR: length indicator + CR CDT + dst-ref + src-ref + class
    x224_payload = bytes([0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + cookie + neg
    x224 = bytes([len(x224_payload)]) + x224_payload
    tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(x224)) + x224
    return tpkt


def probe_rdp(host: str, port: int = 3389, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(_x224_connection_request())
        data = sock.recv(64)
        if len(data) >= 4 and data[0] == 0x03 and data[1] == 0x00:
            result["detected"] = True
            return result
        result["error"] = "unexpected_rdp_banner"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()


def probe_rdp_encryption(host: str, port: int = 3389, timeout: float = 5.0) -> Dict[str, object]:
    """
    Enumerate selected RDP security protocols (NSE rdp-enum-encryption).
    Parses RDP Negotiation Response / Failure after X.224 CC.
    """
    result: Dict[str, object] = {
        "detected": False,
        "selected_protocol": "",
        "selected_flags": [],
        "nla": False,
        "failure_code": None,
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        # Request SSL | HYBRID | HYBRID_EX
        sock.sendall(_x224_connection_request(0x0000000B))
        data = sock.recv(128)
        if len(data) < 11 or data[0] != 0x03:
            result["error"] = "no_rdp_response"
            return result
        result["detected"] = True
        # Find negotiation structure after X.224 CC (0xD0)
        # TPKT(4) + LI(1) + CC… then optional RDP_NEG_*
        idx = data.find(b"\x01\x00\x08\x00")  # TYPE_RDP_NEG_RSP + flags + length 8
        if idx < 0:
            idx = data.find(b"\x02\x00\x08\x00")  # TYPE_RDP_NEG_FAILURE
        if idx < 0 or idx + 8 > len(data):
            result["error"] = "no_negotiation_response"
            return result
        neg_type = data[idx]
        selected = struct.unpack_from("<I", data, idx + 4)[0]
        if neg_type == 0x02:
            result["failure_code"] = selected
            result["error"] = f"negotiation_failure_0x{selected:08x}"
            return result
        flags: List[str] = []
        for bit, name in _PROTOCOL_FLAGS.items():
            if selected & bit:
                flags.append(name)
        if selected == 0:
            flags.append("PROTOCOL_RDP")
        result["selected_protocol"] = hex(selected)
        result["selected_flags"] = flags
        result["nla"] = bool(selected & 0x00000002) or bool(selected & 0x00000008)
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        sock.close()


def probe_rdp_ntlm_info(host: str, port: int = 3389, timeout: float = 8.0) -> Dict[str, object]:
    """
    Best-effort RDP NTLM info via CredSSP after HYBRID negotiation (NSE rdp-ntlm-info).
    Requires NLA; parses NTLMSSP Type-2 from TLS stream.
    """
    result: Dict[str, object] = {"detected": False, "error": "", "info": {}}
    try:
        import ssl

        from lib.scanner.ntlm.detectors import build_ntlm_negotiate, parse_ntlm_challenge
    except Exception as exc:
        result["error"] = str(exc)[:120]
        return result

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        raw.connect((host, int(port)))
        # Request HYBRID only for CredSSP/NLA
        raw.sendall(_x224_connection_request(0x00000002))
        data = raw.recv(128)
        if len(data) < 11 or data[0] != 0x03:
            result["error"] = "no_rdp_response"
            return result
        idx = data.find(b"\x01\x00\x08\x00")
        if idx < 0 or idx + 8 > len(data):
            result["error"] = "nla_not_negotiated"
            return result
        selected = struct.unpack_from("<I", data, idx + 4)[0]
        if not (selected & 0x00000002 or selected & 0x00000008):
            result["error"] = f"hybrid_not_selected_{hex(selected)}"
            return result

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname=host)
        raw = None  # ownership transferred

        ntlm = build_ntlm_negotiate()
        # Minimal ASN.1 CredSSP TSRequest with negoTokens containing NTLM Type1
        # SEQUENCE { version INTEGER, negoTokens [1] NegoData }
        # Keep it simple: send NTLM blob and scrape Type2 from any response bytes
        # Many stacks accept SPNEGO wrapping; also try raw NTLM in TSRequest-like DER

        def _der_len(n: int) -> bytes:
            if n < 0x80:
                return bytes([n])
            if n < 0x100:
                return bytes([0x81, n])
            return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

        def _tlv(tag: int, val: bytes) -> bytes:
            return bytes([tag]) + _der_len(len(val)) + val

        # NegoToken = [0] OCTET STRING of NTLM
        nego_token = _tlv(0xA0, _tlv(0x04, ntlm))
        nego_data = _tlv(0x30, nego_token)  # SEQUENCE OF
        # TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] ... }
        version = _tlv(0xA0, _tlv(0x02, b"\x02"))  # version=2
        nego = _tlv(0xA1, nego_data)
        ts_request = _tlv(0x30, version + nego)
        tls.sendall(ts_request)
        resp = b""
        try:
            while len(resp) < 8192:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"NTLMSSP\x00" in resp:
                    break
        except socket.timeout:
            pass
        if b"NTLMSSP\x00" not in resp:
            result["error"] = "no_ntlm_in_credssp"
            return result
        parsed = parse_ntlm_challenge(resp)
        if not parsed.get("ok"):
            result["error"] = "ntlm_parse_failed"
            return result
        result["detected"] = True
        result["info"] = parsed
        try:
            tls.close()
        except Exception:
            pass
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        try:
            if raw is not None:
                raw.close()
        except Exception:
            pass
