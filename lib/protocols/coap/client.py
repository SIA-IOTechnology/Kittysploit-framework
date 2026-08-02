#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal CoAP (RFC 7252 / RFC 7641) UDP client — GET/POST/PUT/DELETE/Observe (+ optional DTLS)."""

from __future__ import annotations

import os
import random
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


COAP_PORT = 5683
COAPS_PORT = 5684

# Codes
CODE_GET = 0x01
CODE_POST = 0x02
CODE_PUT = 0x03
CODE_DELETE = 0x04
CODE_EMPTY = 0x00

# Message types
TYPE_CON = 0
TYPE_NON = 1
TYPE_ACK = 2
TYPE_RST = 3

# Common IoT CoAP config/status paths probed by gather modules
DEFAULT_CONFIG_PATHS: Tuple[str, ...] = (
    "config",
    "cfg",
    "configuration",
    "device",
    "device/name",
    "device/info",
    "name",
    "info",
    "version",
    "firmware",
    "status",
    "state",
    "sensor",
    "sensors",
    "temp",
    "temperature",
    "humidity",
    "board",
    "board/name",
    "about",
    "system",
    "sys",
    "time",
)


def _encode_option(number: int, value: bytes, last_number: int) -> Tuple[bytes, int]:
    delta = number - last_number
    length = len(value)
    header = bytearray()

    def _ext(n: int) -> Tuple[int, bytes]:
        if n < 13:
            return n, b""
        if n < 269:
            return 13, bytes([n - 13])
        return 14, struct.pack("!H", n - 269)

    d, d_ext = _ext(delta)
    l, l_ext = _ext(length)
    header.append(((d & 0x0F) << 4) | (l & 0x0F))
    header.extend(d_ext)
    header.extend(l_ext)
    header.extend(value)
    return bytes(header), number


def build_request(
    code: int,
    path: str,
    *,
    payload: bytes = b"",
    observe: Optional[int] = None,
    msg_id: Optional[int] = None,
    token: Optional[bytes] = None,
    confirmable: bool = True,
) -> bytes:
    """Build a CoAP CON/NON request with Uri-Path (+ optional Observe) options."""
    mid = msg_id if msg_id is not None else random.randint(1, 0xFFFF)
    tok = token if token is not None else os.urandom(2)
    msg_type = TYPE_CON if confirmable else TYPE_NON
    ver_t_tkl = ((1 & 0x03) << 6) | ((msg_type & 0x03) << 4) | (len(tok) & 0x0F)
    header = bytes([ver_t_tkl, code & 0xFF]) + struct.pack("!H", mid) + tok

    options = b""
    last = 0
    if observe is not None:
        # Observe option number = 6 (RFC 7641)
        if observe == 0:
            obs_val = b""
        else:
            obs_val = observe.to_bytes((observe.bit_length() + 7) // 8 or 1, "big")
        chunk, last = _encode_option(6, obs_val, last)
        options += chunk

    for segment in [p for p in str(path or "").strip("/").split("/") if p]:
        chunk, last = _encode_option(11, segment.encode("utf-8"), last)
        options += chunk

    packet = header + options
    if payload:
        packet += b"\xff" + payload
    return packet


def build_empty_ack(msg_id: int) -> bytes:
    """Empty ACK for Confirmable notifications (RFC 7252 §4.2)."""
    ver_t_tkl = ((1 & 0x03) << 6) | ((TYPE_ACK & 0x03) << 4) | 0
    return bytes([ver_t_tkl, CODE_EMPTY]) + struct.pack("!H", int(msg_id) & 0xFFFF)


def parse_link_format(body: str) -> List[Dict[str, Any]]:
    """Parse CoRE Link Format (RFC 6690) into ``{path, attrs}`` entries."""
    entries: List[Dict[str, Any]] = []
    for chunk in str(body or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r"<([^>]+)>(.*)$", chunk)
        if not m:
            continue
        path = m.group(1).lstrip("/")
        attrs: Dict[str, str] = {}
        for part in m.group(2).split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                key, val = part.split("=", 1)
                attrs[key.strip()] = val.strip().strip('"')
            else:
                attrs[part] = "true"
        entries.append({"path": path, "attrs": attrs, "obs": "obs" in attrs})
    return entries


@dataclass
class CoapResponse:
    code: int = 0
    msg_id: int = 0
    token: bytes = b""
    payload: bytes = b""
    raw: bytes = b""
    observe: Optional[int] = None
    msg_type: int = TYPE_ACK

    @property
    def code_class(self) -> int:
        return (self.code >> 5) & 0x07

    @property
    def code_detail(self) -> int:
        return self.code & 0x1F

    @property
    def ok(self) -> bool:
        return self.code_class == 2

    @property
    def is_con(self) -> bool:
        return self.msg_type == TYPE_CON

    def text(self) -> str:
        return self.payload.decode("utf-8", errors="replace")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": f"{self.code_class}.{self.code_detail:02d}",
            "msg_id": self.msg_id,
            "observe": self.observe,
            "msg_type": self.msg_type,
            "bytes": len(self.payload),
            "payload": self.text(),
        }


def parse_response(data: bytes) -> Optional[CoapResponse]:
    if not data or len(data) < 4:
        return None
    if (data[0] >> 6) != 1:
        return None
    msg_type = (data[0] >> 4) & 0x03
    tkl = data[0] & 0x0F
    code = data[1]
    msg_id = struct.unpack("!H", data[2:4])[0]
    token = data[4 : 4 + tkl]
    idx = 4 + tkl
    observe = None
    last = 0
    while idx < len(data):
        if data[idx] == 0xFF:
            idx += 1
            break
        opt = data[idx]
        idx += 1
        delta = (opt >> 4) & 0x0F
        length = opt & 0x0F
        if delta == 13:
            delta = data[idx] + 13
            idx += 1
        elif delta == 14:
            delta = struct.unpack("!H", data[idx : idx + 2])[0] + 269
            idx += 2
        if length == 13:
            length = data[idx] + 13
            idx += 1
        elif length == 14:
            length = struct.unpack("!H", data[idx : idx + 2])[0] + 269
            idx += 2
        number = last + delta
        value = data[idx : idx + length]
        idx += length
        last = number
        if number == 6:
            observe = int.from_bytes(value, "big") if value else 0
    payload = data[idx:] if idx <= len(data) else b""
    return CoapResponse(
        code=code,
        msg_id=msg_id,
        token=token,
        payload=payload,
        raw=data,
        observe=observe,
        msg_type=msg_type,
    )


def dtls_support() -> Dict[str, Any]:
    """Report whether this Python/OpenSSL build can attempt CoAPS (DTLS)."""
    proto_names = []
    for name in ("PROTOCOL_DTLSv1_2", "PROTOCOL_DTLSv1", "PROTOCOL_DTLS"):
        if hasattr(ssl, name):
            proto_names.append(name)
    return {
        "available": bool(proto_names),
        "protocols": proto_names,
        "default_port": COAPS_PORT,
        "note": (
            "CoAPS uses DTLS over UDP. Support depends on OpenSSL/Python build; "
            "when unavailable, use plain CoAP or terminate DTLS via a local proxy."
        ),
    }


@dataclass
class CoapClient:
    """Session-oriented CoAP UDP client (optional experimental DTLS / CoAPS)."""

    host: str
    port: int = COAP_PORT
    timeout: float = 5.0
    dtls: bool = False
    _sock: Optional[socket.socket] = field(default=None, repr=False)
    last_well_known: str = ""
    last_error: str = ""
    _observe_token: Optional[bytes] = field(default=None, repr=False)
    _observe_path: str = ""

    @property
    def connected(self) -> bool:
        return self._sock is not None and bool(self.host)

    @property
    def scheme(self) -> str:
        return "coaps" if self.dtls else "coap"

    def _create_plain_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        return sock

    def _wrap_dtls(self, sock: socket.socket) -> socket.socket:
        support = dtls_support()
        if not support["available"]:
            raise RuntimeError(
                "DTLS/CoAPS not available in this Python/OpenSSL build. "
                "Use dtls=false (port 5683) or a DTLS-terminating proxy."
            )
        proto = None
        for name in support["protocols"]:
            proto = getattr(ssl, name, None)
            if proto is not None:
                break
        ctx = ssl.SSLContext(proto)  # type: ignore[arg-type]
        try:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        except Exception:
            pass
        # wrap_socket on datagram is platform-dependent; may raise.
        wrapped = ctx.wrap_socket(sock, server_hostname=self.host)
        wrapped.settimeout(self.timeout)
        return wrapped

    def connect(self) -> bool:
        self.close()
        self.last_error = ""
        if not self.host:
            self.last_error = "empty host"
            return False
        if self.dtls and int(self.port) == COAP_PORT:
            self.port = COAPS_PORT
        try:
            sock = self._create_plain_socket()
            if self.dtls:
                sock = self._wrap_dtls(sock)
                # DTLS handshake typically needs connect()
                try:
                    sock.connect((self.host, int(self.port)))
                except OSError as exc:
                    self.last_error = f"DTLS connect failed: {exc}"
                    try:
                        sock.close()
                    except OSError:
                        pass
                    return False
            self._sock = sock
        except Exception as exc:
            self.last_error = str(exc)
            self._sock = None
            return False

        resp = self.get(".well-known/core")
        if resp and (resp.ok or len(resp.raw) >= 4):
            self.last_well_known = resp.text()
            return True
        # Keep socket for manual ops even if probe empty/timeout
        return True

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._observe_token = None
        self._observe_path = ""

    def _peer(self) -> Tuple[str, int]:
        return (self.host, int(self.port))

    def _send(self, packet: bytes) -> None:
        assert self._sock is not None
        if self.dtls:
            # Connected DTLS socket
            self._sock.send(packet)
        else:
            self._sock.sendto(packet, self._peer())

    def _recv(self, bufsize: int = 4096) -> Optional[bytes]:
        assert self._sock is not None
        try:
            if self.dtls:
                return self._sock.recv(bufsize)
            data, _addr = self._sock.recvfrom(bufsize)
            return data
        except socket.timeout:
            return None
        except OSError as exc:
            self.last_error = str(exc)
            return None

    def _exchange(self, packet: bytes) -> Optional[CoapResponse]:
        if not self._sock:
            if not self.connect():
                return None
        assert self._sock is not None
        try:
            self._send(packet)
            data = self._recv()
            return parse_response(data) if data else None
        except OSError as exc:
            self.last_error = str(exc)
            return None

    def get(self, path: str, *, observe: Optional[int] = None) -> Optional[CoapResponse]:
        return self._exchange(build_request(CODE_GET, path, observe=observe))

    def post(self, path: str, payload: bytes | str = b"") -> Optional[CoapResponse]:
        body = payload.encode("utf-8") if isinstance(payload, str) else payload
        return self._exchange(build_request(CODE_POST, path, payload=body))

    def put(self, path: str, payload: bytes | str = b"") -> Optional[CoapResponse]:
        body = payload.encode("utf-8") if isinstance(payload, str) else payload
        return self._exchange(build_request(CODE_PUT, path, payload=body))

    def delete(self, path: str) -> Optional[CoapResponse]:
        return self._exchange(build_request(CODE_DELETE, path))

    def observe(self, path: str) -> Optional[CoapResponse]:
        """Register Observe (value 0) and return first notification / ACK payload."""
        token = os.urandom(4)
        packet = build_request(CODE_GET, path, observe=0, token=token)
        resp = self._exchange(packet)
        if resp:
            self._observe_token = token
            self._observe_path = path
            if resp.is_con and self._sock:
                try:
                    self._send(build_empty_ack(resp.msg_id))
                except OSError:
                    pass
        return resp

    def observe_stream(
        self,
        path: str,
        *,
        duration: float = 10.0,
        max_notifications: int = 50,
        deregister: bool = True,
    ) -> List[CoapResponse]:
        """
        Register Observe and collect notifications for ``duration`` seconds.

        CON notifications are ACKed (empty ACK). Optional deregister GET without Observe.
        """
        if not self._sock:
            if not self.connect():
                return []
        assert self._sock is not None

        token = os.urandom(4)
        self._observe_token = token
        self._observe_path = path
        notifications: List[CoapResponse] = []

        try:
            self._send(build_request(CODE_GET, path, observe=0, token=token))
        except OSError as exc:
            self.last_error = str(exc)
            return []

        deadline = time.monotonic() + max(0.5, float(duration))
        limit = max(1, int(max_notifications))

        while time.monotonic() < deadline and len(notifications) < limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self._sock.settimeout(min(1.0, remaining))
            except OSError:
                pass
            data = self._recv()
            if not data:
                continue
            resp = parse_response(data)
            if not resp:
                continue
            if resp.token and resp.token != token:
                continue
            if resp.is_con:
                try:
                    self._send(build_empty_ack(resp.msg_id))
                except OSError:
                    pass
            # Skip empty ACKs with no payload and no observe
            if resp.code == CODE_EMPTY and not resp.payload and resp.observe is None:
                continue
            notifications.append(resp)

        if deregister:
            try:
                # RFC 7641: deregistration via GET without Observe, same token
                self._send(build_request(CODE_GET, path, token=token, observe=None))
                self._sock.settimeout(min(1.0, float(self.timeout)))
                self._recv()  # best-effort
            except OSError:
                pass

        try:
            self._sock.settimeout(self.timeout)
        except OSError:
            pass
        return notifications

    def well_known(self) -> str:
        resp = self.get(".well-known/core")
        if resp:
            self.last_well_known = resp.text()
        return self.last_well_known

    def list_resources(self) -> List[Dict[str, Any]]:
        body = self.well_known() or ""
        return parse_link_format(body)
