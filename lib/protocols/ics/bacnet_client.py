#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active BACnet/IP discovery (Who-Is / I-Am)."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import List, Optional

from lib.protocols.ics.bacnet import parse_bacnet


WHO_IS = bytes.fromhex("810a000801ffff00ff")


@dataclass
class BacnetDevice:
    host: str
    port: int
    device_id: Optional[int] = None
    max_apdu: Optional[int] = None
    segmentation: Optional[int] = None
    vendor_id: Optional[int] = None
    raw: bytes = b""


def parse_i_am(payload: bytes, source_host: str, source_port: int) -> Optional[BacnetDevice]:
    parsed = parse_bacnet(payload)
    if not parsed or parsed.get("bvlc_function") != 0x0B:
        return None

    device_id = None
    max_apdu = None
    segmentation = None
    vendor_id = None

    if len(payload) >= 12:
        # Best-effort I-Am APDU parsing after BVLC header.
        apdu_offset = 4
        if len(payload) > apdu_offset + 6 and payload[apdu_offset + 1] == 0x10:
            device_id = int.from_bytes(payload[apdu_offset + 3 : apdu_offset + 7], "big")
            if len(payload) >= apdu_offset + 8:
                max_apdu = payload[apdu_offset + 7]
            if len(payload) >= apdu_offset + 9:
                segmentation = payload[apdu_offset + 8]
            if len(payload) >= apdu_offset + 11:
                vendor_id = int.from_bytes(payload[apdu_offset + 9 : apdu_offset + 11], "big")

    return BacnetDevice(
        host=source_host,
        port=source_port,
        device_id=device_id,
        max_apdu=max_apdu,
        segmentation=segmentation,
        vendor_id=vendor_id,
        raw=payload,
    )


def who_is(
    host: str,
    port: int = 47808,
    timeout: float = 5.0,
    broadcast: bool = False,
) -> List[BacnetDevice]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    devices: List[BacnetDevice] = []
    seen = set()
    try:
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            target = ("<broadcast>", port)
        else:
            target = (host, port)
        sock.sendto(WHO_IS, target)

        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            device = parse_i_am(data, addr[0], addr[1])
            if not device:
                continue
            key = (device.host, device.device_id)
            if key in seen:
                continue
            seen.add(key)
            devices.append(device)
    finally:
        sock.close()
    return devices


def _build_read_property(device_id: int, object_type: int, object_instance: int, property_id: int) -> bytes:
    # BVLC + NPDU + ReadProperty-Request (best-effort unicast).
    invoke_id = 1
    apdu = bytes(
        [
            0x00,
            0x0C,
            invoke_id,
            0x0C,
            (object_type >> 2) & 0xFF,
            ((object_type & 0x03) << 6) | ((object_instance >> 16) & 0x1F),
            (object_instance >> 8) & 0xFF,
            object_instance & 0xFF,
            property_id,
        ]
    )
    npdu = bytes([0x01, 0x00]) + apdu
    bvlc = bytes([0x81, 0x0A, 0x00, len(npdu) + 4]) + npdu
    return bvlc


def read_property(
    host: str,
    device_id: int,
    object_type: int,
    object_instance: int,
    property_id: int,
    port: int = 47808,
    timeout: float = 5.0,
) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        request = _build_read_property(device_id, object_type, object_instance, property_id)
        sock.sendto(request, (host, port))
        data, _addr = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def object_inventory(
    host: str,
    device_id: int,
    port: int = 47808,
    timeout: float = 5.0,
) -> List[dict]:
    # Device object type 8, property object-list = 76.
    raw = read_property(host, device_id, 8, device_id, 76, port, timeout)
    objects: List[dict] = []
    if len(raw) > 12:
        objects.append(
            {
                "device_id": device_id,
                "host": host,
                "raw_hex": raw.hex(),
                "object_count_hint": max(0, len(raw) - 12),
            }
        )
    return objects


def write_property(
    host: str,
    device_id: int,
    object_type: int,
    object_instance: int,
    property_id: int,
    value_bytes: bytes,
    port: int = 47808,
    timeout: float = 5.0,
) -> bytes:
    invoke_id = 2
    opening = bytes(
        [
            0x00,
            0x0F,
            invoke_id,
            0x0F,
            (object_type >> 2) & 0xFF,
            ((object_type & 0x03) << 6) | ((object_instance >> 16) & 0x1F),
            (object_instance >> 8) & 0xFF,
            object_instance & 0xFF,
            property_id,
            0x4E,
            len(value_bytes) & 0xFF,
        ]
    )
    apdu = opening + value_bytes
    npdu = bytes([0x01, 0x00]) + apdu
    bvlc = bytes([0x81, 0x0A, 0x00, len(npdu) + 4]) + npdu
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(bvlc, (host, port))
        data, _addr = sock.recvfrom(4096)
        return data
    finally:
        sock.close()
