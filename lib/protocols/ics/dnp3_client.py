#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active DNP3 TCP client — identify, integrity poll, read, and operate probes."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# Application function codes
FC_READ = 0x01
FC_SELECT = 0x03
FC_OPERATE = 0x06
FC_DIRECT_OPERATE = 0x14

# Object groups
GRP_BINARY_INPUT = 0x01
GRP_BINARY_OUTPUT = 0x0A
GRP_ANALOG_INPUT = 0x1E
GRP_DEVICE_ATTR = 0x3C
GRP_CROB = 0x0C

QUAL_ALL = 0x07
QUAL_8BIT_START_STOP = 0x00
QUAL_16BIT_INDEX_COUNT = 0x28


def _crc16(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _build_link_frame(control: int, dest: int, src: int, payload: bytes = b"") -> bytes:
    body = struct.pack("<BBHH", 0x05, 0x64, len(payload) + 5, control)
    body += struct.pack("<HH", dest & 0xFFFF, src & 0xFFFF)
    body += payload
    crc = _crc16(body)
    return body + struct.pack("<H", crc)


def _extract_strings(data: bytes) -> List[str]:
    strings: List[str] = []
    current: List[int] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= 4:
                strings.append(bytes(current).decode("ascii", errors="ignore"))
            current = []
    if len(current) >= 4:
        strings.append(bytes(current).decode("ascii", errors="ignore"))
    return strings


def _response_ok(response: bytes, min_len: int = 12) -> bool:
    if len(response) < min_len:
        return False
    if response[:2] != b"\x05\x64":
        return False
    if len(response) >= 12 and response[10:12] == b"\xc0\x81":
        return False
    return True


@dataclass
class Dnp3ProbeResult:
    host: str
    port: int
    connected: bool = False
    link_alive: bool = False
    master_accepted: bool = False
    unsolicited_enabled: bool = False
    responses: List[str] = field(default_factory=list)
    error: str = ""


@dataclass
class Dnp3IdentifyResult:
    host: str
    port: int
    connected: bool = False
    link_alive: bool = False
    device_attributes: bool = False
    strings: List[str] = field(default_factory=list)
    raw_hex: str = ""
    error: str = ""


@dataclass
class Dnp3IntegrityResult:
    host: str
    port: int
    connected: bool = False
    link_alive: bool = False
    class_results: Dict[str, bool] = field(default_factory=dict)
    points: Dict[str, int] = field(default_factory=dict)
    error: str = ""


@dataclass
class Dnp3ReadResult:
    host: str
    port: int
    group: int
    variation: int
    success: bool = False
    response_len: int = 0
    strings: List[str] = field(default_factory=list)
    raw_hex: str = ""
    error: str = ""


@dataclass
class Dnp3OperateProbeResult:
    host: str
    port: int
    connected: bool = False
    select_accepted: bool = False
    direct_operate_accepted: bool = False
    error: str = ""


class Dnp3Client:
    def __init__(
        self,
        host: str,
        port: int = 20000,
        timeout: float = 5.0,
        src: int = 1024,
        dest: int = 1,
    ):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.src = int(src)
        self.dest = int(dest)
        self._sock: Optional[socket.socket] = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> bool:
        self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError:
            sock.close()
            return False
        self._sock = sock
        return True

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def _send_frame(self, frame: bytes) -> bytes:
        if not self._sock:
            return b""
        payload = struct.pack(">H", len(frame)) + frame
        self._sock.sendall(payload)
        try:
            length_bytes = self._recv_exact(2)
            if not length_bytes:
                return b""
            length = struct.unpack(">H", length_bytes)[0]
            return self._recv_exact(length)
        except socket.timeout:
            return b""

    def _recv_exact(self, size: int) -> bytes:
        if not self._sock:
            return b""
        chunks: List[bytes] = []
        remaining = size
        while remaining > 0:
            part = self._sock.recv(remaining)
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        return b"".join(chunks)

    def _app_request(self, function_code: int, objects: bytes) -> bytes:
        transport = bytes([0xC0])
        app = bytes([function_code]) + objects
        frame = _build_link_frame(0xC4, self.dest, self.src, transport + app)
        return self._send_frame(frame)

    def _read_range(self, group: int, variation: int, start: int, stop: int) -> bytes:
        objects = struct.pack(
            ">BBBBB",
            group & 0xFF,
            variation & 0xFF,
            QUAL_8BIT_START_STOP,
            start & 0xFF,
            stop & 0xFF,
        )
        return self._app_request(FC_READ, objects)

    def _read_all(self, group: int, variation: int) -> bytes:
        objects = struct.pack(">BBB", group & 0xFF, variation & 0xFF, QUAL_ALL)
        return self._app_request(FC_READ, objects)

    def link_status(self) -> bool:
        frame = _build_link_frame(0xC9, self.dest, self.src)
        response = self._send_frame(frame)
        return bool(response and response[:2] == b"\x05\x64")

    def read_device_attributes(self) -> bytes:
        return self._read_all(GRP_DEVICE_ATTR, 0x01)

    def master_read_probe(self) -> bool:
        response = self.read_device_attributes()
        return _response_ok(response, 14)

    def unsolicited_probe(self) -> bool:
        app = bytes([0x03, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06, 0x3C, 0x05, 0x06])
        response = self._app_request(0x03, app)
        if not _response_ok(response, 10):
            return False
        return b"\x81" not in response[10:14]

    def identify(self) -> Dnp3IdentifyResult:
        result = Dnp3IdentifyResult(host=self.host, port=self.port)
        if not self.connect():
            result.error = "connection failed"
            return result
        result.connected = True
        try:
            result.link_alive = self.link_status()
            response = self.read_device_attributes()
            result.device_attributes = _response_ok(response, 14)
            result.raw_hex = response.hex()
            result.strings = _extract_strings(response)
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()

    def integrity_poll(
        self,
        *,
        binary_count: int = 10,
        analog_count: int = 5,
    ) -> Dnp3IntegrityResult:
        result = Dnp3IntegrityResult(host=self.host, port=self.port)
        if not self.connect():
            result.error = "connection failed"
            return result
        result.connected = True
        try:
            result.link_alive = self.link_status()

            checks: List[Tuple[str, bytes]] = [
                ("class0_device_attributes", self.read_device_attributes()),
                ("class1_binary_input", self._read_range(GRP_BINARY_INPUT, 0x01, 0, max(0, binary_count - 1))),
                ("class2_binary_output_status", self._read_range(GRP_BINARY_OUTPUT, 0x02, 0, 0)),
                ("class3_analog_input", self._read_range(GRP_ANALOG_INPUT, 0x01, 0, max(0, analog_count - 1))),
            ]
            for label, response in checks:
                ok = _response_ok(response, 14)
                result.class_results[label] = ok
                if ok:
                    result.points[label] = max(0, len(response) - 12)

            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()

    def read_points(self, group: int, variation: int, start: int, stop: int) -> Dnp3ReadResult:
        result = Dnp3ReadResult(
            host=self.host,
            port=self.port,
            group=int(group),
            variation=int(variation),
        )
        if not self.connect():
            result.error = "connection failed"
            return result
        try:
            response = self._read_range(group, variation, start, stop)
            result.success = _response_ok(response, 14)
            result.response_len = len(response)
            result.raw_hex = response.hex()
            result.strings = _extract_strings(response)
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()

    def _build_crob(self, index: int, control: int = 0x00) -> bytes:
        header = struct.pack("<BBH", GRP_CROB, 0x01, QUAL_16BIT_INDEX_COUNT)
        header += struct.pack("<HH", index & 0xFFFF, 1)
        crob = struct.pack("<BBIIB", control & 0xFF, 1, 0, 0, 0)
        return header + crob

    def probe_operate_accepted(self, index: int = 0) -> Dnp3OperateProbeResult:
        result = Dnp3OperateProbeResult(host=self.host, port=self.port)
        if not self.connect():
            result.error = "connection failed"
            return result
        result.connected = True
        try:
            if not self.link_status():
                result.error = "link status failed"
                return result

            select_resp = self._app_request(FC_SELECT, self._build_crob(index, control=0x00))
            result.select_accepted = _response_ok(select_resp, 16)

            operate_resp = self._app_request(FC_DIRECT_OPERATE, self._build_crob(index, control=0x00))
            result.direct_operate_accepted = _response_ok(operate_resp, 16)
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()

    def probe(self) -> Dnp3ProbeResult:
        result = Dnp3ProbeResult(host=self.host, port=self.port)
        if not self.connect():
            result.error = "connection failed"
            return result
        result.connected = True
        try:
            result.link_alive = self.link_status()
            result.master_accepted = self.master_read_probe()
            result.unsolicited_enabled = self.unsolicited_probe()
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()


def probe_dnp3_master(host: str, port: int = 20000, timeout: float = 5.0) -> Dnp3ProbeResult:
    return Dnp3Client(host, port, timeout).probe()


def probe_dnp3_unsolicited(host: str, port: int = 20000, timeout: float = 5.0) -> Dnp3ProbeResult:
    client = Dnp3Client(host, port, timeout)
    result = Dnp3ProbeResult(host=host, port=port)
    if not client.connect():
        result.error = "connection failed"
        return result
    result.connected = True
    try:
        result.link_alive = client.link_status()
        result.unsolicited_enabled = client.unsolicited_probe()
        return result
    finally:
        client.close()


def identify_dnp3(
    host: str,
    port: int = 20000,
    timeout: float = 5.0,
    src: int = 1024,
    dest: int = 1,
) -> Dnp3IdentifyResult:
    return Dnp3Client(host, port, timeout, src, dest).identify()


def integrity_poll_dnp3(
    host: str,
    port: int = 20000,
    timeout: float = 5.0,
    src: int = 1024,
    dest: int = 1,
    binary_count: int = 10,
    analog_count: int = 5,
) -> Dnp3IntegrityResult:
    return Dnp3Client(host, port, timeout, src, dest).integrity_poll(
        binary_count=binary_count,
        analog_count=analog_count,
    )


def probe_dnp3_operate(
    host: str,
    port: int = 20000,
    timeout: float = 5.0,
    src: int = 1024,
    dest: int = 1,
    index: int = 0,
) -> Dnp3OperateProbeResult:
    return Dnp3Client(host, port, timeout, src, dest).probe_operate_accepted(index)


def read_dnp3_points(
    host: str,
    port: int = 20000,
    timeout: float = 5.0,
    group: int = GRP_BINARY_INPUT,
    variation: int = 1,
    start: int = 0,
    stop: int = 9,
    src: int = 1024,
    dest: int = 1,
) -> Dnp3ReadResult:
    return Dnp3Client(host, port, timeout, src, dest).read_points(group, variation, start, stop)
