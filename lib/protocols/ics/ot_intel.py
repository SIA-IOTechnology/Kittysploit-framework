#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OT asset intelligence — Purdue levels, vendor hints, workspace enrichment."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS, OT_OUI_HINTS
from lib.protocols.ics.purdue import assign_purdue_level


ICS_SERVICE_PORTS: Dict[int, str] = {
    102: "s7comm",
    111: "sunrpc",
    502: "modbus-tcp",
    2404: "iec104",
    20000: "dnp3",
    44818: "enip",
    47808: "bacnet",
    4840: "opcua",
    8000: "qconn",
}

ICS_PORT_PURDUE_LEVEL: Dict[int, int] = {
    102: 1,
    111: 1,
    502: 1,
    2404: 1,
    20000: 1,
    44818: 1,
    47808: 1,
    8000: 1,
    4840: 2,
}


def normalize_mac_prefix(mac: str) -> str:
    cleaned = str(mac or "").strip().upper().replace("-", ":")
    if len(cleaned) < 8:
        return ""
    return cleaned.replace(":", "")[:6]


def lookup_vendor_from_mac(mac: str) -> str:
    prefix = normalize_mac_prefix(mac)
    if not prefix:
        return ""
    return OT_OUI_HINTS.get(prefix, "")


def purdue_level_for_port(port: int) -> int:
    return int(ICS_PORT_PURDUE_LEVEL.get(int(port), 0))


def purdue_level_for_service(name: str) -> int:
    service = str(name or "").strip().lower()
    for port, label in ICS_SERVICE_PORTS.items():
        if service == label:
            return purdue_level_for_port(port)
    if service in {"scada", "hmi", "wincc", "opcua"}:
        return 2
    if service in {"engineering", "tia", "studio5000"}:
        return 3
    return 0


def infer_device_type(protocols: Iterable[str] | None = None, port: int | None = None) -> str:
    names = {str(item).lower() for item in (protocols or [])}
    if port:
        names.add(ICS_SERVICE_PORTS.get(int(port), ""))
    if names & {"s7comm", "modbus-tcp", "dnp3", "iec104", "enip", "bacnet"}:
        return "PLC/RTU"
    if names & {"opcua", "hmi", "wincc"}:
        return "SCADA/HMI"
    if names & {"qconn"}:
        return "ICS Endpoint"
    if names & {"sunrpc"}:
        return "ICS Endpoint"
    return "Unknown"


def build_ot_asset_record(
    host: str,
    *,
    port: int | None = None,
    protocol: str = "",
    vendor: str = "",
    mac: str = "",
    modbus_units: Iterable[int] | None = None,
    s7_slot: int | None = None,
    protection_level: int | None = None,
    device_type: str = "",
) -> Dict[str, Any]:
    protocols = []
    if protocol:
        protocols.append(str(protocol))
    elif port:
        protocols.append(ICS_SERVICE_PORTS.get(int(port), f"tcp-{port}"))

    resolved_vendor = vendor or lookup_vendor_from_mac(mac)
    device = {
        "ip": host,
        "mac": mac or "",
        "vendor": resolved_vendor or "Unknown",
        "device_type": device_type or infer_device_type(protocols, port),
        "protocols": protocols,
        "roles": set(),
    }
    purdue = assign_purdue_level(device)
    if not purdue and port:
        purdue = purdue_level_for_port(int(port))

    record: Dict[str, Any] = {
        "host": host,
        "port": int(port) if port else None,
        "protocol": protocol or (ICS_SERVICE_PORTS.get(int(port), "") if port else ""),
        "vendor": resolved_vendor,
        "mac": mac or "",
        "device_type": device.get("device_type", "Unknown"),
        "purdue_level": int(purdue or 0),
        "modbus_units": sorted({int(unit) for unit in (modbus_units or [])}),
        "s7_slot": int(s7_slot) if s7_slot is not None else None,
        "protection_level": int(protection_level) if protection_level is not None else None,
    }
    return record


def merge_ot_asset_into_map(assets: Dict[str, Any], record: Dict[str, Any]) -> None:
    host = str(record.get("host") or "").strip()
    if not host:
        return
    current = assets.get(host, {})
    if not isinstance(current, dict):
        current = {}
    merged = dict(current)
    for key, value in record.items():
        if value in (None, "", [], {}):
            continue
        if key == "modbus_units":
            existing = set(merged.get("modbus_units") or [])
            existing.update(value)
            merged["modbus_units"] = sorted(existing)
            continue
        if key == "protocol" and merged.get("protocol") and merged.get("protocol") != value:
            protocols = set(merged.get("protocols") or [])
            if merged.get("protocol"):
                protocols.add(str(merged["protocol"]))
            protocols.add(str(value))
            merged["protocols"] = sorted(protocols)
            continue
        merged[key] = value
    assets[host] = merged
