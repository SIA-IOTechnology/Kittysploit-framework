#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IEC 61850 MMS detection helpers (ISO-on-TCP port 102)."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import List, Optional

# MMS-style COTP CR (differs from typical S7 TSAP pairing)
MMS_COTP_CR = bytes.fromhex("0300001611E00000000100C0010AC1020100C2020100")
# Minimal MMS Initiate Request inside COTP DT
MMS_INITIATE = bytes.fromhex(
    "0300006302f0805f0101003061020101a207060355060502"
    "a038020101a033020100a10e300c06082b0601060501061d020100"
    "a0051b03000000a203020100a216301406082b0601060501061d040100"
    "0201008000"
)
S7_ISO_CR = bytes.fromhex("0300001611E00000000100C0010AC1020100C2020102")
S7_SETUP = bytes.fromhex("0300001902F08032010000040000080000F0000001000101E0")


@dataclass
class Iec61850ProbeResult:
    host: str
    port: int
    detected: bool = False
    cotp_accepted: bool = False
    mms_initiate_ok: bool = False
    s7_conflict: bool = False
    responses: List[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self):
        return {
            "host": self.host,
            "port": self.port,
            "detected": self.detected,
            "cotp_accepted": self.cotp_accepted,
            "mms_initiate_ok": self.mms_initiate_ok,
            "s7_conflict": self.s7_conflict,
            "responses": self.responses,
            "error": self.error,
        }


def _recv(sock: socket.socket, timeout: float, limit: int = 4096) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(limit) or b""
    except socket.timeout:
        return b""


def _looks_like_s7(data: bytes) -> bool:
    return b"\x03\x00" in data and (b"\xf0\x00" in data or b"\x32" in data)


def _looks_like_mms_confirm(data: bytes) -> bool:
    lower = data.lower()
    return b"\xa0" in data and (b"mms" in lower or len(data) > 20 and data[5:7] == b"\x02\xf0")


def _probe_s7_conflict(host: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        sock.sendall(S7_ISO_CR)
        first = _recv(sock, timeout)
        if not first or first[5:6] != b"\xd0":
            return False
        sock.sendall(S7_SETUP)
        second = _recv(sock, timeout)
        return _looks_like_s7(first + second)
    except Exception:
        return False
    finally:
        sock.close()


def probe_iec61850_mms(host: str, port: int = 102, timeout: float = 5.0) -> Iec61850ProbeResult:
    result = Iec61850ProbeResult(host=host, port=int(port))
    if _probe_s7_conflict(host, port, timeout):
        result.s7_conflict = True
        result.error = "Port 102 responds like S7comm — IEC 61850 MMS unlikely"
        return result

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        sock.sendall(MMS_COTP_CR)
        cotp_resp = _recv(sock, timeout)
        if not cotp_resp:
            result.error = "No COTP response"
            return result
        result.responses.append(cotp_resp.hex())
        if len(cotp_resp) >= 6 and cotp_resp[5:6] == b"\xd0":
            result.cotp_accepted = True
        else:
            result.error = "COTP connection rejected"
            return result

        sock.sendall(MMS_INITIATE)
        mms_resp = _recv(sock, timeout)
        if mms_resp:
            result.responses.append(mms_resp.hex())
        if mms_resp and _looks_like_mms_confirm(mms_resp):
            result.mms_initiate_ok = True
            result.detected = True
        elif result.cotp_accepted:
            result.detected = True
            result.error = "COTP accepted with MMS TSAP; MMS initiate response inconclusive"
    except Exception as exc:
        result.error = str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result
