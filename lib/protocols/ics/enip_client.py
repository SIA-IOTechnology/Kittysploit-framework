#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""EtherNet/IP List Identity (UDP/44818)."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional


LIST_IDENTITY = bytes.fromhex("6300000000000000000000000000000000000000000000")


@dataclass
class EnipDevice:
    host: str
    port: int
    vendor_id: int = 0
    vendor_name: str = ""
    device_type: int = 0
    product_name: str = ""
    serial_number: int = 0
    product_code: int = 0
    revision: str = ""
    state: int = 0
    raw: bytes = b""


VENDOR_NAMES = {
    0x0001: "Rockwell Automation",
    0x002A: "Siemens",
    0x0055: "Schneider Electric",
    0x004C: "ABB",
}


def _vendor_name(vendor_id: int) -> str:
    return VENDOR_NAMES.get(vendor_id, f"vendor-0x{vendor_id:04X}")


def parse_list_identity_response(data: bytes, source_host: str, source_port: int) -> Optional[EnipDevice]:
    if len(data) < 24:
        return None
    command = struct.unpack_from("<H", data, 0)[0]
    if command != 0x0063:
        return None

    offset = 24
    if len(data) < offset + 2:
        return None
    item_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if item_count < 1:
        return None

    if len(data) < offset + 2:
        return None
    item_type = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if item_type != 0x000C:
        return None
    if len(data) < offset + 2:
        return None
    item_length = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    item = data[offset : offset + item_length]
    if len(item) < 34:
        return None

    vendor_id = struct.unpack_from("<H", item, 4)[0]
    device_type = struct.unpack_from("<H", item, 6)[0]
    product_code = struct.unpack_from("<H", item, 8)[0]
    major = item[12]
    minor = item[13]
    state = item[14]
    serial_number = struct.unpack_from("<I", item, 15)[0]
    name_len = item[19]
    product_name = item[20 : 20 + name_len].decode("latin-1", errors="replace")

    return EnipDevice(
        host=source_host,
        port=source_port,
        vendor_id=vendor_id,
        vendor_name=_vendor_name(vendor_id),
        device_type=device_type,
        product_name=product_name,
        serial_number=serial_number,
        product_code=product_code,
        revision=f"{major}.{minor}",
        state=state,
        raw=data,
    )


def list_identity(
    host: str,
    port: int = 44818,
    timeout: float = 5.0,
    broadcast: bool = False,
) -> List[EnipDevice]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    devices: List[EnipDevice] = []
    try:
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            targets = [("<broadcast>", port)]
        else:
            targets = [(host, port)]

        for target in targets:
            sock.sendto(LIST_IDENTITY, target)
            deadline = timeout
            while deadline > 0:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                device = parse_list_identity_response(data, addr[0], addr[1])
                if device:
                    devices.append(device)
                deadline -= 0.2
    finally:
        sock.close()
    return devices


REGISTER_SESSION = struct.pack("<HHII", 0x0065, 0x0004, 0x00000000, 0x00000000)


@dataclass
class EnipCipScanResult:
    host: str
    port: int
    identity: Optional[EnipDevice] = None
    session_registered: bool = False
    cip_reachable: bool = False
    tags: List[str] = field(default_factory=list)
    error: str = ""


class EnipCipClient:
    def __init__(self, host: str, port: int = 44818, timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._session_handle = 0

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
        self._session_handle = 0

    def register_session(self) -> bool:
        if not self._sock:
            return False
        self._sock.sendall(REGISTER_SESSION)
        response = self._sock.recv(4096)
        if len(response) < 8 or struct.unpack_from("<H", response, 0)[0] != 0x0065:
            return False
        self._session_handle = struct.unpack_from("<I", response, 4)[0]
        return self._session_handle != 0

    def scan_cip(self) -> EnipCipScanResult:
        result = EnipCipScanResult(host=self.host, port=self.port)
        devices = list_identity(self.host, self.port, self.timeout)
        if devices:
            result.identity = devices[0]
        if not self.connect():
            result.error = "tcp connection failed"
            return result
        try:
            result.session_registered = self.register_session()
            result.cip_reachable = result.session_registered
            return result
        except OSError as exc:
            result.error = str(exc)
            return result
        finally:
            self.close()


def scan_enip_cip(host: str, port: int = 44818, timeout: float = 5.0) -> EnipCipScanResult:
    return EnipCipClient(host, port, timeout).scan_cip()


def enumerate_enip_tags(host: str, port: int = 44818, timeout: float = 5.0) -> List[str]:
    """Best-effort tag hints — full CIP tag browse requires pycomm3 on Rockwell targets."""
    result = scan_enip_cip(host, port, timeout)
    tags: List[str] = []
    if result.identity and result.identity.product_name:
        tags.append(result.identity.product_name)
    if result.cip_reachable:
        tags.append("CIP/session-ready")
    return tags
