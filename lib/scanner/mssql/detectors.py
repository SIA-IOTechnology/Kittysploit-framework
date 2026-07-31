#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MSSQL detection helpers for scanner modules."""

from __future__ import annotations

import socket
import struct
from typing import Dict, Optional


TDS_PRELOGIN = bytes.fromhex(
    "120100003400000100001f000600012a000102000300042400000400"
)


def _recv_packet(sock: socket.socket, timeout: float) -> Optional[bytes]:
    sock.settimeout(timeout)
    try:
        header = sock.recv(8)
        if len(header) < 8:
            return None
        length = struct.unpack(">H", header[2:4])[0]
        body = header
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        return body
    except Exception:
        return None


def probe_mssql(host: str, port: int = 1433, timeout: float = 5.0) -> Dict[str, object]:
    """Detect MSSQL via TDS prelogin and infer encryption support."""
    result: Dict[str, object] = {
        "success": False,
        "host": host,
        "port": port,
        "detected": False,
        "version_hint": "",
        "encryption": "unknown",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(TDS_PRELOGIN)
        packet = _recv_packet(sock, timeout)
        if not packet or packet[0] != 0x04:
            result["error"] = "No TDS prelogin response"
            return result
        result["success"] = True
        result["detected"] = True
        payload = packet[8:]
        offset = 0
        while offset + 5 <= len(payload):
            token = payload[offset]
            if token == 0xFF:
                break
            rec_len = struct.unpack(">H", payload[offset + 1 : offset + 3])[0]
            value = payload[offset + 3 : offset + 3 + rec_len]
            if token == 0x00 and value:
                result["version_hint"] = value.decode("utf-8", errors="replace").strip("\x00")
            elif token == 0x01 and value:
                enc = value[0] if value else 0
                result["encryption"] = {
                    0: "encryption_off",
                    1: "encryption_on",
                    2: "encryption_not_supported",
                    3: "encryption_required",
                }.get(enc, "unknown")
            offset += 3 + rec_len
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe_mssql_ntlm_info(host: str, port: int = 1433, timeout: float = 8.0) -> Dict[str, object]:
    """
    MSSQL NTLM info via TDS Login7 with SSPI negotiate (NSE ms-sql-ntlm-info).
    Sends prelogin (encryption not required) then LOGIN7 with NTLM Type-1 in SSPI field.
    """
    result: Dict[str, object] = {"detected": False, "error": "", "info": {}}
    try:
        from lib.scanner.ntlm.detectors import build_ntlm_negotiate, parse_ntlm_challenge
    except Exception as exc:
        result["error"] = str(exc)[:120]
        return result

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        # Prelogin requesting encryption OFF (option ENCRYPTION=0)
        prelogin = bytes.fromhex(
            "120100002f00000100001a000600012000010200030004080000ff090000000000000000000000000000"
        )
        sock.sendall(prelogin)
        pre = _recv_packet(sock, timeout)
        if not pre or pre[0] != 0x04:
            result["error"] = "prelogin_failed"
            return result

        ntlm = build_ntlm_negotiate()
        # Build a minimal LOGIN7 packet with SSPI = NTLM Type1
        # LOGIN7 structure is complex; use a compact crafted packet similar to nmap/msf
        # Offsets: header 8 bytes + LOGIN7 fixed + variable strings + SSPI
        hostname = b"KITTYSPLOIT"
        appname = b"KittySploit"
        servername = host.encode("ascii", errors="ignore")[:128]
        # LOGIN7 fixed portion length before variable data = 94 bytes (0x5e) typically
        # We'll craft using known-good approach: put SSPI at end with ibSSPI/cbSSPI

        def _ucs2(s: bytes) -> bytes:
            return b"".join(bytes([c, 0]) for c in s)

        # Simplified LOGIN7: Length, TDSVersion, PacketSize, ClientProgVer, ClientPID,
        # ConnectionID, OptionFlags1/2, TypeFlags, OptionFlags3, ClientTimZone, ClientLCID
        # then offset/length pairs for strings, then SSPI
        fixed = bytearray(94)
        struct.pack_into("<I", fixed, 0, 0)  # Length filled later
        struct.pack_into("<I", fixed, 4, 0x74000004)  # TDS 7.4
        struct.pack_into("<I", fixed, 8, 4096)  # packet size
        struct.pack_into("<I", fixed, 12, 0)
        struct.pack_into("<I", fixed, 16, 1234)  # PID
        struct.pack_into("<I", fixed, 20, 0)
        fixed[24] = 0xE0  # OptionFlags1
        fixed[25] = 0x03  # OptionFlags2 (integrated security / SSPI related bits)
        # Offsets for: ClientName, UserName, Password, AppName, ServerName, Unused, CltIntName,
        # Language, Database, ClientID(6), SSPI, AtchDBFile, ChangePassword
        # Each is USHORT offset + USHORT length (chars for strings, bytes for SSPI)
        # ClientID is 6 bytes inline after Database pair

        var = bytearray()
        pairs = []  # (offset_in_fixed, is_sspi, data)

        def _add_str(offset: int, data: bytes) -> None:
            pairs.append((offset, False, data))

        def _add_sspi(offset: int, data: bytes) -> None:
            pairs.append((offset, True, data))

        # Layout offsets in LOGIN7 for ib*/cch* starting at byte 36
        # 36 ClientName, 40 UserName, 44 Password, 48 AppName, 52 ServerName,
        # 56 Unused, 60 CltIntName, 64 Language, 68 Database, 72 ClientID(6),
        # 78 SSPI, 82 AtchDBFile, 86 ChangePassword, 90 cbSSPILong
        _add_str(36, _ucs2(hostname))
        _add_str(40, b"")  # username
        _add_str(44, b"")  # password
        _add_str(48, _ucs2(appname))
        _add_str(52, _ucs2(servername))
        _add_str(56, b"")
        _add_str(60, _ucs2(b"KittySploit"))
        _add_str(64, b"")
        _add_str(68, b"")
        # ClientID 6 bytes at 72
        fixed[72:78] = b"\x00\x01\x02\x03\x04\x05"
        _add_sspi(78, ntlm)
        _add_str(82, b"")
        _add_str(86, b"")

        cursor = 94
        for off, is_sspi, data in pairs:
            struct.pack_into("<H", fixed, off, cursor)
            if is_sspi:
                struct.pack_into("<H", fixed, off + 2, len(data))
            else:
                # length in unicode chars
                struct.pack_into("<H", fixed, off + 2, len(data) // 2)
            var.extend(data)
            cursor += len(data)

        total_len = 94 + len(var)
        struct.pack_into("<I", fixed, 0, total_len)
        login7 = bytes(fixed) + bytes(var)
        # TDS packet type 0x10 LOGIN7
        pkt = struct.pack(">BBHHBB", 0x10, 0x01, 8 + len(login7), 0x0000, 0x00, 0x00) + login7
        # Fix length field properly
        pkt = struct.pack(">BBH", 0x10, 0x01, 8 + len(login7)) + b"\x00\x00\x00\x00" + login7
        sock.sendall(pkt)

        # Read response — look for NTLMSSP in SSPI token / ERROR / LOGINACK stream
        blob = b""
        for _ in range(5):
            part = _recv_packet(sock, timeout)
            if not part:
                break
            blob += part
            if b"NTLMSSP\x00" in part:
                break
        if b"NTLMSSP\x00" not in blob:
            result["error"] = "no_ntlm_challenge"
            return result
        parsed = parse_ntlm_challenge(blob)
        if not parsed.get("ok"):
            result["error"] = "ntlm_parse_failed"
            return result
        result["detected"] = True
        result["info"] = parsed
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass
