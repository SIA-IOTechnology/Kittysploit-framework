#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TURN / coturn detection via STUN Allocate Request (RFC 5766)."""

from __future__ import annotations

import os
import socket
import struct
from typing import Dict, Iterator, Tuple

STUN_MAGIC = 0x2112A442


def _allocate_request() -> bytes:
    # Allocate Request method=0x003, class=request → type 0x0003
    txid = os.urandom(12)
    header = struct.pack("!HHI", 0x0003, 8, STUN_MAGIC) + txid
    # REQUESTED-TRANSPORT (0x0019): UDP = 17
    attr = struct.pack("!HH", 0x0019, 4) + struct.pack("!BBBB", 17, 0, 0, 0)
    return header + attr


def _iter_attrs(data: bytes) -> Iterator[Tuple[int, bytes]]:
    if len(data) < 20:
        return
    _msg_type, length, magic = struct.unpack("!HHI", data[:8])
    if magic != STUN_MAGIC:
        return
    offset = 20
    end = min(len(data), 20 + length)
    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        value = data[offset : offset + attr_len]
        pad = (4 - (attr_len % 4)) % 4
        offset += attr_len + pad
        yield attr_type, value


def probe_turn(host: str, port: int = 3478, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "coturn": False,
        "software": "",
        "error_code": None,
        "realm": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(_allocate_request(), (host, int(port)))
        data, _addr = sock.recvfrom(4096)
        if len(data) < 20:
            result["error"] = "short_response"
            return result
        msg_type, length, magic = struct.unpack("!HHI", data[:8])
        if magic != STUN_MAGIC:
            result["error"] = "bad_magic"
            return result
        # Allocate Success 0x0103, Allocate Error 0x0113
        if msg_type not in (0x0103, 0x0113):
            # Some servers answer Binding-style; still check SOFTWARE
            pass
        software = ""
        realm = ""
        err_code = None
        for attr_type, value in _iter_attrs(data) or ():
            if attr_type == 0x8022:  # SOFTWARE
                software = value.decode("utf-8", errors="replace").strip("\x00").strip()
            elif attr_type == 0x0014:  # REALM
                realm = value.decode("utf-8", errors="replace").strip("\x00").strip()
            elif attr_type == 0x0009 and len(value) >= 4:  # ERROR-CODE
                err_code = value[2] * 100 + value[3]
        result["software"] = software[:120]
        result["realm"] = realm[:120]
        result["error_code"] = err_code
        is_allocate = msg_type in (0x0103, 0x0113)
        looks_turn = is_allocate or err_code in (401, 438) or bool(realm)
        if not looks_turn and not software:
            result["error"] = f"unexpected_type=0x{msg_type:04x}"
            return result
        # Pure STUN Binding responses without realm/allocate are not TURN
        if msg_type == 0x0101 and not realm and err_code is None:
            result["error"] = "stun_only"
            return result
        if not looks_turn and "turn" not in software.lower() and "coturn" not in software.lower():
            result["error"] = "not_turn"
            return result
        result["detected"] = True
        low = software.lower()
        result["coturn"] = "coturn" in low or "coturn" in realm.lower()
        return result
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
