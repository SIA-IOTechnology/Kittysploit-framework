#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Matter discovery client — mDNS TXT inventory + UDP/5540 reachability probe."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from lib.protocols.matter.txt import parse_matter_txt
from lib.scanner.mdns.client import MdnsClient, MdnsService


MATTER_UDP_PORT = 5540
MATTER_MDNS_QUERIES: Tuple[str, ...] = (
    "_matterc._udp.local",
    "_matter._tcp.local",
)


@dataclass
class MatterDevice:
    """A Matter node discovered via DNS-SD (+ optional UDP probe)."""

    instance: str = ""
    service_type: str = ""
    host: str = ""
    port: int = 0
    addresses: List[str] = field(default_factory=list)
    commissionable: bool = False
    operational: bool = False
    vendor_id: Optional[int] = None
    product_id: Optional[int] = None
    vendor_name: str = ""
    device_type: Optional[int] = None
    device_type_name: str = ""
    device_name: str = ""
    commissioning_mode: Optional[int] = None
    commissioning_mode_name: str = ""
    discriminator: Optional[int] = None
    pairing_hint: Optional[int] = None
    pairing_instruction: str = ""
    rotating_id: str = ""
    tcp_supported: bool = False
    udp_reachable: Optional[bool] = None
    raw_txt: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance": self.instance,
            "service_type": self.service_type,
            "host": self.host,
            "port": self.port,
            "addresses": list(self.addresses),
            "commissionable": self.commissionable,
            "operational": self.operational,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "vendor_name": self.vendor_name,
            "device_type": self.device_type,
            "device_type_name": self.device_type_name,
            "device_name": self.device_name,
            "commissioning_mode": self.commissioning_mode,
            "commissioning_mode_name": self.commissioning_mode_name,
            "discriminator": self.discriminator,
            "pairing_hint": self.pairing_hint,
            "pairing_instruction": self.pairing_instruction,
            "rotating_id": self.rotating_id,
            "tcp_supported": self.tcp_supported,
            "udp_reachable": self.udp_reachable,
            "raw_txt": dict(self.raw_txt),
        }


@dataclass
class MatterDiscoverResult:
    detected: bool = False
    devices: List[MatterDevice] = field(default_factory=list)
    error: str = ""
    mode: str = "unicast"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "devices": [d.to_dict() for d in self.devices],
            "error": self.error,
            "mode": self.mode,
            "count": len(self.devices),
            "commissionable": sum(1 for d in self.devices if d.commissionable),
            "operational": sum(1 for d in self.devices if d.operational),
        }


def service_from_mdns(svc: MdnsService) -> MatterDevice:
    parsed = parse_matter_txt(svc.txt)
    stype = str(svc.service_type or "").lower()
    commissionable = "_matterc._udp" in stype
    operational = "_matter._tcp" in stype and not commissionable
    # Fallbacks when service_type string is incomplete
    if not commissionable and not operational:
        inst = str(svc.instance or "").lower()
        commissionable = "_matterc._udp" in inst
        operational = "_matter._tcp" in inst
    return MatterDevice(
        instance=svc.instance,
        service_type=svc.service_type,
        host=svc.host,
        port=int(svc.port or (MATTER_UDP_PORT if commissionable else 0)),
        addresses=list(svc.addresses),
        commissionable=commissionable,
        operational=operational,
        vendor_id=parsed.get("vendor_id"),
        product_id=parsed.get("product_id"),
        vendor_name=str(parsed.get("vendor_name") or ""),
        device_type=parsed.get("device_type"),
        device_type_name=str(parsed.get("device_type_name") or ""),
        device_name=str(parsed.get("device_name") or ""),
        commissioning_mode=parsed.get("commissioning_mode"),
        commissioning_mode_name=str(parsed.get("commissioning_mode_name") or ""),
        discriminator=parsed.get("discriminator"),
        pairing_hint=parsed.get("pairing_hint"),
        pairing_instruction=str(parsed.get("pairing_instruction") or ""),
        rotating_id=str(parsed.get("rotating_id") or ""),
        tcp_supported=bool(parsed.get("tcp_supported")),
        raw_txt=dict(parsed.get("raw_txt") or {}),
    )


def probe_matter_udp(host: str, port: int = MATTER_UDP_PORT, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Best-effort UDP probe of Matter operational/commissioning port.

    Sends a short unsecured Matter-shaped datagram and records whether any
    reply arrives. Full PASE/CASE requires crypto and is out of scope.
    """
    host = str(host or "").strip()
    if not host:
        return {"reachable": False, "error": "missing_host", "bytes": 0}
    # Minimal unsecured Matter message header + empty exchange (probe only)
    # flags=0x00, session=0, sec=0, counter=1, then exchange header zeros
    probe = bytes(
        [
            0x00,  # message flags
            0x00,
            0x00,  # session id
            0x00,  # security flags
            0x01,
            0x00,
            0x00,
            0x00,  # message counter
            0x00,  # exchange flags
            0x00,  # protocol opcode
            0x00,
            0x01,  # exchange id
            0x00,
            0x00,  # protocol id (secure channel = 0)
        ]
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(max(0.3, float(timeout)))
        sock.sendto(probe, (host, int(port)))
        try:
            data, addr = sock.recvfrom(2048)
            return {
                "reachable": True,
                "error": "",
                "bytes": len(data),
                "peer": f"{addr[0]}:{addr[1]}",
            }
        except socket.timeout:
            return {"reachable": False, "error": "timeout", "bytes": 0}
    except OSError as exc:
        return {"reachable": False, "error": str(exc), "bytes": 0}
    finally:
        try:
            sock.close()
        except Exception:
            pass


class MatterClient:
    """Session-oriented Matter discovery client (mDNS + UDP probe)."""

    def __init__(
        self,
        host: str = "",
        port: int = MATTER_UDP_PORT,
        timeout: float = 3.0,
        *,
        multicast: bool = False,
    ):
        self.host = str(host or "").strip()
        self.port = int(port or MATTER_UDP_PORT)
        self.timeout = float(timeout or 3.0)
        self.multicast = bool(multicast)
        self.connected = False
        self.last_error = ""
        self.devices: List[MatterDevice] = []
        self.last_result: Optional[MatterDiscoverResult] = None

    def connect(self) -> bool:
        """Discover Matter nodes; succeed if any device found or UDP probe responds."""
        result = self.discover(probe_udp=True)
        self.last_result = result
        self.devices = list(result.devices)
        if result.detected:
            self.connected = True
            self.last_error = ""
            return True
        # Host-only UDP probe when mDNS is quiet
        if self.host:
            udp = probe_matter_udp(self.host, self.port, min(self.timeout, 2.0))
            if udp.get("reachable"):
                self.devices = [
                    MatterDevice(
                        instance=self.host,
                        host=self.host,
                        port=self.port,
                        addresses=[self.host],
                        commissionable=True,
                        udp_reachable=True,
                    )
                ]
                self.connected = True
                self.last_error = ""
                self.last_result = MatterDiscoverResult(
                    detected=True, devices=self.devices, mode="udp"
                )
                return True
            self.last_error = result.error or udp.get("error") or "no_matter_devices"
        else:
            self.last_error = result.error or "no_matter_devices"
        self.connected = False
        return False

    def discover(
        self,
        *,
        probe_udp: bool = False,
        queries: Sequence[str] | None = None,
    ) -> MatterDiscoverResult:
        client = MdnsClient(timeout=self.timeout)
        enum = client.enumerate(
            host=self.host,
            queries=tuple(queries or MATTER_MDNS_QUERIES),
            multicast=self.multicast or not self.host,
            resolve_srv=True,
        )
        devices: List[MatterDevice] = []
        seen = set()
        for svc in enum.services:
            blob = f"{svc.service_type} {svc.instance}".lower()
            if "_matter" not in blob:
                continue
            device = service_from_mdns(svc)
            key = (
                device.instance,
                device.host,
                device.port,
                device.commissionable,
                device.operational,
            )
            if key in seen:
                continue
            seen.add(key)
            if probe_udp:
                targets = list(device.addresses) or ([device.host] if device.host else [])
                if self.host and self.host not in targets:
                    targets.append(self.host)
                for addr in targets:
                    if not addr or addr.endswith(".local"):
                        # Prefer numeric addresses for UDP probe
                        continue
                    udp = probe_matter_udp(
                        addr,
                        int(device.port or self.port or MATTER_UDP_PORT),
                        min(self.timeout, 1.5),
                    )
                    device.udp_reachable = bool(udp.get("reachable"))
                    if device.udp_reachable:
                        break
                if device.udp_reachable is None and targets:
                    # Try .local / hostname last
                    addr = targets[0]
                    udp = probe_matter_udp(
                        addr,
                        int(device.port or self.port or MATTER_UDP_PORT),
                        min(self.timeout, 1.5),
                    )
                    device.udp_reachable = bool(udp.get("reachable"))
            devices.append(device)

        # If typed Matter queries hit names but SRV resolve empty, synthesize stubs
        if not devices and enum.names:
            for name in enum.names:
                low = name.lower()
                if "_matter" not in low:
                    continue
                devices.append(
                    MatterDevice(
                        instance=name,
                        service_type=(
                            "_matterc._udp"
                            if "_matterc" in low
                            else "_matter._tcp"
                        ),
                        host=self.host,
                        port=self.port if "_matterc" in low else 0,
                        addresses=[self.host] if self.host else [],
                        commissionable="_matterc" in low,
                        operational="_matter._tcp" in low and "_matterc" not in low,
                    )
                )

        result = MatterDiscoverResult(
            detected=bool(devices),
            devices=devices,
            error=enum.error if not devices else "",
            mode=enum.mode,
        )
        self.last_result = result
        self.devices = list(devices)
        return result

    def inventory(self) -> Dict[str, Any]:
        if not self.devices and self.last_result is None:
            self.discover(probe_udp=False)
        result = self.last_result or MatterDiscoverResult(devices=self.devices)
        data = result.to_dict()
        data["host"] = self.host
        data["port"] = self.port
        data["timestamp"] = int(time.time())
        return data

    def close(self) -> None:
        self.connected = False


def discover_matter(
    host: str = "",
    timeout: float = 3.0,
    *,
    multicast: bool = False,
    probe_udp: bool = False,
) -> MatterDiscoverResult:
    client = MatterClient(host=host, timeout=timeout, multicast=multicast)
    return client.discover(probe_udp=probe_udp)
