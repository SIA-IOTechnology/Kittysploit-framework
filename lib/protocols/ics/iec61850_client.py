#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IEC 61850 MMS client — ISO-on-TCP (port 102) COTP + Initiate / Identify / GetNameList."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional


# MMS-style COTP CR (TSAP pairing differs from typical S7)
MMS_COTP_CR = bytes.fromhex("0300001611E00000000100C0010AC1020100C2020100")
# Minimal MMS Initiate Request inside COTP DT
MMS_INITIATE = bytes.fromhex(
    "0300006302f0805f0101003061020101a207060355060502"
    "a038020101a033020100a10e300c06082b0601060501061d020100"
    "a0051b03000000a203020100a216301406082b0601060501061d040100"
    "0201008000"
)
# Confirmed Identify Request (invokeID=1)
MMS_IDENTIFY = bytes.fromhex("0300001502f080a00a020101a105a103020100")
# GetNameList — objectClass domain, objectScope vmd-specific (invokeID=2)
MMS_GETNAMELIST_DOMAIN = bytes.fromhex(
    "0300001f02f080a014020102a10fa00da00b020101a006a0040201008000"
)
# GetNameList — namedVariable, vmd-specific (invokeID=3)
MMS_GETNAMELIST_VAR = bytes.fromhex(
    "0300001f02f080a014020103a10fa00da00b020102a006a0040201008000"
)

S7_ISO_CR = bytes.fromhex("0300001611E00000000100C0010AC1020100C2020102")
S7_SETUP = bytes.fromhex("0300001902F08032010000040000080000F0000001000101E0")

IEC61850_PORT = 102


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


@dataclass
class Iec61850IdentifyResult:
    host: str
    port: int
    connected: bool = False
    cotp_accepted: bool = False
    initiate_ok: bool = False
    identify_ok: bool = False
    vendor: str = ""
    model: str = ""
    revision: str = ""
    strings: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    variables: List[str] = field(default_factory=list)
    error: str = ""


def _recv(sock: socket.socket, timeout: float, limit: int = 8192) -> bytes:
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


def _extract_strings(data: bytes, min_len: int = 3) -> List[str]:
    found: List[str] = []
    seen = set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,64}" % min_len, data or b""):
        text = match.group().decode("ascii", errors="ignore").strip()
        if not text or text in seen:
            continue
        # Filter noise
        if text.startswith("http") or all(c in "0123456789abcdefABCDEF" for c in text):
            continue
        seen.add(text)
        found.append(text)
    return found[:48]


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


def probe_iec61850_mms(host: str, port: int = IEC61850_PORT, timeout: float = 5.0) -> Iec61850ProbeResult:
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


class Iec61850Client:
    """Session-oriented IEC 61850 MMS client (ISO-on-TCP)."""

    def __init__(self, host: str, port: int = IEC61850_PORT, timeout: float = 5.0):
        self.host = str(host or "").strip()
        self.port = int(port or IEC61850_PORT)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self.cotp_accepted = False
        self.initiate_ok = False
        self.last_error = ""
        self.last_strings: List[str] = []

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self, *, check_s7: bool = True) -> bool:
        self.close()
        self.last_error = ""
        if not self.host:
            self.last_error = "host required"
            return False
        if check_s7 and _probe_s7_conflict(self.host, self.port, self.timeout):
            self.last_error = "Port responds like S7comm — refusing MMS session"
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            sock.sendall(MMS_COTP_CR)
            cotp = _recv(sock, self.timeout)
            if not cotp or len(cotp) < 6 or cotp[5:6] != b"\xd0":
                self.last_error = "COTP connection rejected"
                sock.close()
                return False
            self.cotp_accepted = True
            sock.sendall(MMS_INITIATE)
            init = _recv(sock, self.timeout)
            self.initiate_ok = bool(init and _looks_like_mms_confirm(init))
            if init:
                self.last_strings = _extract_strings(init)
            self._sock = sock
            return True
        except OSError as exc:
            self.last_error = str(exc)
            try:
                sock.close()
            except Exception:
                pass
            return False

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self.cotp_accepted = False
        self.initiate_ok = False

    def _transact(self, payload: bytes) -> bytes:
        if not self._sock:
            raise RuntimeError("not connected")
        self._sock.sendall(payload)
        return _recv(self._sock, self.timeout)

    def identify(self, *, keep_open: bool = False) -> Iec61850IdentifyResult:
        result = Iec61850IdentifyResult(host=self.host, port=self.port)
        owns = False
        if not self.connected:
            if not self.connect():
                result.error = self.last_error or "connect failed"
                return result
            owns = not keep_open
        result.connected = True
        result.cotp_accepted = self.cotp_accepted
        result.initiate_ok = self.initiate_ok
        try:
            raw = self._transact(MMS_IDENTIFY)
            if not raw:
                result.error = "No Identify response"
                return result
            strings = _extract_strings(raw)
            result.strings = strings
            self.last_strings = list(strings)
            if strings:
                result.vendor = strings[0]
            if len(strings) > 1:
                result.model = strings[1]
            if len(strings) > 2:
                result.revision = strings[2]
            result.identify_ok = True
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            if owns:
                self.close()

    def get_name_list(self, kind: str = "domain") -> List[str]:
        """Best-effort GetNameList; returns printable names from the response."""
        if not self.connected and not self.connect():
            return []
        payload = MMS_GETNAMELIST_DOMAIN if kind == "domain" else MMS_GETNAMELIST_VAR
        try:
            raw = self._transact(payload)
        except OSError:
            return []
        names = _extract_strings(raw, min_len=2)
        filtered = [
            n
            for n in names
            if re.match(r"^[A-Za-z_][\w./-]{1,48}$", n) and " " not in n
        ]
        return filtered[:64] or names[:32]

    def directory(self, *, keep_open: bool = False) -> Iec61850IdentifyResult:
        """Identify + domain/variable name lists."""
        result = self.identify(keep_open=True)
        if not result.connected and result.error:
            if not keep_open:
                self.close()
            return result
        if not self.connected:
            if not self.connect(check_s7=False):
                if not result.error:
                    result.error = self.last_error or "reconnect failed"
                return result
            result.connected = True
            result.cotp_accepted = self.cotp_accepted
            result.initiate_ok = self.initiate_ok
        try:
            result.domains = self.get_name_list("domain")
            result.variables = self.get_name_list("variable")
            if result.domains or result.variables or result.identify_ok:
                result.error = ""
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            if not keep_open:
                self.close()

    def probe(self) -> Iec61850ProbeResult:
        return probe_iec61850_mms(self.host, self.port, self.timeout)


def identify_iec61850(
    host: str,
    port: int = IEC61850_PORT,
    timeout: float = 5.0,
) -> Iec61850IdentifyResult:
    client = Iec61850Client(host, port, timeout)
    try:
        return client.identify()
    finally:
        client.close()


def directory_iec61850(
    host: str,
    port: int = IEC61850_PORT,
    timeout: float = 5.0,
) -> Iec61850IdentifyResult:
    client = Iec61850Client(host, port, timeout)
    try:
        return client.directory()
    finally:
        client.close()
