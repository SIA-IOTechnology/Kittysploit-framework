#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PROFINET DCP — Layer-2 discovery and IP configuration for PN devices."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence


DCP_ETHERTYPE = 0x8892
DCP_IDENTIFY_REQ = 0xFEFE
DCP_IDENTIFY_RES = 0xFEFF
DCP_SET_REQ = 0xFEFD
DCP_SERVICE_IDENTIFY = 0x05
DCP_SERVICE_SET = 0x04
DCP_OPTION_IP = 0x01
DCP_SUBOPTION_IP_PARAMETER = 0x02

# Identify-all selector (Option 0xFF / Suboption 0xFF)
IDENTIFY_ALL = bytes([0xFF, 0xFF])

PROFINET_BROADCAST_MACS = (
    "01:0e:cf:00:00:00",
    "28:63:36:5a:18:f1",
)

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


@dataclass
class ProfinetDevice:
    mac: str
    name: str = ""
    vendor: str = ""
    device_role: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    gateway: str = ""
    raw: bytes = b""


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw[:6])


def normalize_mac(mac: str) -> str:
    cleaned = str(mac or "").strip().lower().replace("-", ":")
    if not _MAC_RE.match(cleaned):
        raise ValueError(f"invalid MAC address: {mac}")
    return cleaned


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in normalize_mac(mac).split(":"))


def _ipv4_to_bytes(address: str) -> bytes:
    parts = str(address or "").strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"invalid IPv4 address: {address}")
    return bytes(int(part) for part in parts)


def _parse_ip_option(data: bytes, offset: int, length: int) -> tuple[str, str, str]:
    ip = subnet = gateway = ""
    end = min(len(data), offset + length)
    chunk = data[offset:end]
    if len(chunk) >= 12:
        ip = ".".join(str(b) for b in chunk[0:4])
        subnet = ".".join(str(b) for b in chunk[4:8])
        gateway = ".".join(str(b) for b in chunk[8:12])
    return ip, subnet, gateway


def parse_dcp_response(frame: bytes) -> Optional[ProfinetDevice]:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    if ethertype != DCP_ETHERTYPE:
        return None
    if len(frame) < 16:
        return None
    frame_id = struct.unpack_from(">H", frame, 14)[0]
    if frame_id != DCP_IDENTIFY_RES:
        return None

    src_mac = _mac_str(frame[6:12])
    device = ProfinetDevice(mac=src_mac, raw=frame)
    offset = 16
    while offset + 4 <= len(frame):
        service_id = frame[offset]
        service_type = frame[offset + 1]
        option = frame[offset + 2]
        suboption = frame[offset + 3]
        if offset + 6 > len(frame):
            break
        block_length = struct.unpack_from(">H", frame, offset + 4)[0]
        block_start = offset + 6
        block_end = block_start + block_length
        if block_end > len(frame):
            break
        block = frame[block_start:block_end]

        if service_id == DCP_SERVICE_IDENTIFY and service_type == 0x01:
            if option == 0x02 and suboption == 0x02 and block:
                device.name = block.decode("utf-8", errors="replace").strip("\x00 ")
            elif option == 0x01 and suboption == 0x01 and block:
                device.vendor = block.decode("utf-8", errors="replace").strip("\x00 ")
            elif option == 0x01 and suboption == 0x02 and block:
                device.device_role = block.decode("utf-8", errors="replace").strip("\x00 ")
            elif option == 0x01 and suboption == 0x03:
                ip, subnet, gateway = _parse_ip_option(block, 0, len(block))
                device.ip_address = ip
                device.subnet_mask = subnet
                device.gateway = gateway

        offset = block_end
    return device if device.name or device.ip_address else device


def _build_dcp_block(option: int, suboption: int, data: bytes) -> bytes:
    return struct.pack(">BBH", option & 0xFF, suboption & 0xFF, len(data)) + data


def build_identify_request(
    dst_mac: bytes | None = None,
    src_mac: bytes | None = None,
) -> bytes:
    dcp_header = struct.pack(">HBB", DCP_IDENTIFY_REQ, DCP_SERVICE_IDENTIFY, 0x00)
    block = _build_dcp_block(0xFF, 0xFF, IDENTIFY_ALL)
    payload = dcp_header + block
    dst = dst_mac or b"\xff\xff\xff\xff\xff\xff"
    src = src_mac or b"\x00\x00\x00\x00\x00\x00"
    return dst + src + struct.pack(">H", DCP_ETHERTYPE) + payload


def build_set_ip_request(
    dst_mac: bytes,
    src_mac: bytes,
    ip_address: str,
    subnet_mask: str,
    gateway: str,
) -> bytes:
    ip_block = (
        _ipv4_to_bytes(ip_address)
        + _ipv4_to_bytes(subnet_mask)
        + _ipv4_to_bytes(gateway)
    )
    dcp_header = struct.pack(">HBB", DCP_SET_REQ, DCP_SERVICE_SET, 0x00)
    block = _build_dcp_block(DCP_OPTION_IP, DCP_SUBOPTION_IP_PARAMETER, ip_block)
    payload = dcp_header + block
    return dst_mac + src_mac + struct.pack(">H", DCP_ETHERTYPE) + payload


def device_table_rows(devices: Sequence[ProfinetDevice]) -> List[List[str]]:
    rows: List[List[str]] = []
    seen = set()
    for device in devices:
        row = (
            device.name,
            device.vendor or device.device_role,
            device.mac,
            device.ip_address,
            device.subnet_mask,
            device.gateway,
        )
        key = tuple(row)
        if key in seen:
            continue
        seen.add(key)
        rows.append(list(row))
    return rows


def get_interface_mac(interface: str) -> str:
    try:
        from scapy.arch import get_if_hwaddr  # type: ignore
    except ImportError as exc:
        raise RuntimeError("scapy is required for PROFINET DCP — pip install scapy") from exc
    return normalize_mac(get_if_hwaddr(str(interface).strip()))


def _require_scapy():
    try:
        from scapy.all import Ether, sendp, sniff  # type: ignore
        from scapy.config import conf  # type: ignore
    except ImportError as exc:
        raise RuntimeError("scapy is required for PROFINET DCP — pip install scapy") from exc
    return Ether, sendp, sniff, conf


def _collect_dcp_responses(
    interface: str,
    local_mac: str,
    requests: Iterable[bytes],
    timeout: float,
    verbose: int = 0,
) -> List[ProfinetDevice]:
    Ether, sendp, sniff, conf = _require_scapy()
    conf.verb = int(verbose)

    devices: List[ProfinetDevice] = []
    seen = set()

    def _handler(packet) -> None:
        device = parse_dcp_response(bytes(packet))
        if not device:
            return
        key = (device.mac, device.name, device.ip_address)
        if key in seen:
            return
        seen.add(key)
        devices.append(device)

    sniff_filter = f"ether dst host {local_mac}"
    for request in requests:
        sendp(Ether(raw=request), iface=interface, verbose=0)
        sniff(
            iface=interface,
            filter=sniff_filter,
            prn=_handler,
            timeout=float(timeout),
            store=0,
        )
    return devices


def dcp_identify(
    interface: str,
    timeout: float = 3.0,
    count: int = 2,
    verbose: int = 0,
) -> List[ProfinetDevice]:
    local_mac = get_interface_mac(interface)
    src = _mac_bytes(local_mac)
    requests = [
        build_identify_request(_mac_bytes(broadcast_mac), src)
        for broadcast_mac in PROFINET_BROADCAST_MACS
    ]
    for _ in range(max(1, int(count))):
        requests.append(build_identify_request(None, src))

    devices: List[ProfinetDevice] = []
    seen = set()
    for device in _collect_dcp_responses(interface, local_mac, requests, timeout, verbose):
        key = (device.mac, device.name, device.ip_address)
        if key in seen:
            continue
        seen.add(key)
        devices.append(device)
    return devices


def dcp_identify_mac(
    interface: str,
    target_mac: str,
    timeout: float = 3.0,
    verbose: int = 0,
) -> List[ProfinetDevice]:
    local_mac = get_interface_mac(interface)
    request = build_identify_request(_mac_bytes(target_mac), _mac_bytes(local_mac))
    return _collect_dcp_responses(interface, local_mac, [request], timeout, verbose)


def dcp_set_ip(
    interface: str,
    target_mac: str,
    ip_address: str,
    subnet_mask: str,
    gateway: str,
    verbose: int = 0,
) -> None:
    Ether, sendp, _, conf = _require_scapy()
    conf.verb = int(verbose)
    local_mac = get_interface_mac(interface)
    request = build_set_ip_request(
        _mac_bytes(target_mac),
        _mac_bytes(local_mac),
        ip_address,
        subnet_mask,
        gateway,
    )
    sendp(Ether(raw=request), iface=interface, verbose=0)
