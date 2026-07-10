#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Classify OT devices from passively observed protocol behavior."""

from __future__ import annotations

import json
from typing import Any

from core.utils.paths import data_resource_exists, read_data_text
from lib.protocols.ics.constants import ICS_TCP_PORTS, OT_OUI_HINTS


def lookup_vendor(mac: str | None, oui_db: dict[str, str] | None = None) -> str:
    if not mac:
        return "Unknown"

    mac_clean = mac.replace("-", "").replace(":", "").upper()
    if len(mac_clean) < 6:
        return "Unknown"

    prefix = mac_clean[:6]
    if prefix in OT_OUI_HINTS:
        return OT_OUI_HINTS[prefix]

    if oui_db:
        return oui_db.get(prefix, "Unknown")

    return "Unknown"


def load_oui_database() -> dict[str, str] | None:
    try:
        if not data_resource_exists("vendors", "oui.json"):
            return None
        return json.loads(read_data_text("vendors", "oui.json"))
    except Exception:
        return None


def infer_device_role(protocol: str, *, to_server: bool, is_write: bool = False) -> str:
    if protocol == "modbus-tcp":
        if to_server and is_write:
            return "modbus-master-write"
        if to_server:
            return "modbus-master"
        return "modbus-slave"

    if protocol == "s7comm":
        return "s7-client" if to_server else "s7-plc"

    if protocol == "dnp3":
        return "dnp3-master" if to_server else "dnp3-outstation"

    if protocol == "bacnet":
        return "bacnet-client" if to_server else "bacnet-device"

    if protocol == "iec104":
        return "iec104-client" if to_server else "iec104-server"

    if protocol in ICS_TCP_PORTS.values():
        return "client" if to_server else "server"

    return "unknown"


def infer_device_type(protocols: set[str], roles: set[str]) -> str:
    proto = set(protocols)
    role = set(roles)

    if "s7comm" in proto and any("s7-plc" in r for r in role):
        return "PLC"
    if "modbus-tcp" in proto and any("modbus-slave" in r for r in role):
        return "PLC/RTU"
    if any("modbus-master" in r for r in role):
        return "SCADA/HMI"
    if "s7comm" in proto and any("s7-client" in r for r in role):
        return "Engineering Workstation"
    if "enip" in proto:
        return "Industrial Controller"
    if "bacnet" in proto:
        return "Building Controller"
    if "dnp3" in proto or "iec104" in proto:
        return "RTU/IED"
    if proto:
        return "ICS Endpoint"
    return "Unknown"


def summarize_device(device: dict[str, Any]) -> str:
    protocols = ", ".join(sorted(device.get("protocols", []))) or "none"
    roles = ", ".join(sorted(device.get("roles", []))) or "none"
    vendor = device.get("vendor", "Unknown")
    device_type = device.get("device_type", "Unknown")
    return (
        f"{device.get('ip', '?')} | type={device_type} | vendor={vendor} | "
        f"protocols=[{protocols}] | roles=[{roles}] | packets={device.get('packet_count', 0)}"
    )
