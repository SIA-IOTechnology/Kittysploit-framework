#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Matter DNS-SD TXT parsers — commissionable + operational discovery keys."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


# Common CSA / manufacturer vendor IDs (subset for operator UX)
MATTER_VENDOR_NAMES: Dict[int, str] = {
    0x100B: "Signify/Philips Hue",
    0x10E1: "Samsung",
    0x1147: "Nanoleaf",
    0x115F: "Google",
    0x1217: "Amazon",
    0x1235: "Eve Systems",
    0x127F: "Nordic Semiconductor",
    0x131B: "Espressif",
    0x1349: "Apple",
    0x1384: "Google Nest",
    0x1399: "Tuya",
    0x1400: "Silicon Labs",
    0xFFF1: "Test Vendor",
    0xFFF2: "Test Vendor 2",
    0xFFF3: "Test Vendor 3",
}

# Common Matter device type IDs
MATTER_DEVICE_TYPES: Dict[int, str] = {
    0x000E: "Aggregator",
    0x000F: "Generic Switch",
    0x0011: "Power Source",
    0x0012: "OTA Requestor",
    0x0013: "Bridged Node",
    0x0016: "Root Node",
    0x0022: "Bridge",
    0x0023: "Temperature Sensor",
    0x0024: "Pressure Sensor",
    0x0025: "Flow Sensor",
    0x0026: "Humidity Sensor",
    0x0027: "On/Off Sensor",
    0x0028: "Smoke CO Alarm",
    0x002B: "Door Lock",
    0x002C: "Door Lock Controller",
    0x002F: "Mode Select",
    0x0100: "On/Off Light",
    0x0101: "Dimmer Switch",
    0x0103: "On/Off Light Switch",
    0x0104: "Dimmer Light Switch",
    0x0106: "Contact Sensor",
    0x0107: "Light Sensor",
    0x0108: "Occupancy Sensor",
    0x010A: "On/Off Plug-in Unit",
    0x010B: "Dimmable Plug-in Unit",
    0x010C: "Pump Controller",
    0x010D: "Extended Color Light",
    0x010F: "Color Temperature Light",
    0x0113: "Window Covering",
    0x0115: "Pump",
    0x0300: "Thermostat",
    0x0301: "Fan",
    0x0302: "Air Quality Sensor",
    0x0305: "HEPA Filter Monitoring",
    0x0306: "Activated Carbon Filter Monitoring",
    0x0307: "Laundry Washer",
    0x0308: "Refrigerator",
}

COMMISSIONING_MODE: Dict[int, str] = {
    0: "not_commissionable",
    1: "standard",
    2: "enhanced",
}


def _int_field(txt: Dict[str, str], key: str) -> Optional[int]:
    raw = str(txt.get(key) or txt.get(key.upper()) or txt.get(key.lower()) or "").strip()
    if not raw:
        return None
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw, 10)
    except ValueError:
        return None


def parse_vendor_product(vp: str) -> Tuple[Optional[int], Optional[int]]:
    """Parse Matter VP TXT (``VID+PID`` or ``VID``)."""
    raw = str(vp or "").strip()
    if not raw:
        return None, None
    if "+" in raw:
        left, right = raw.split("+", 1)
        try:
            return int(left.strip()), int(right.strip())
        except ValueError:
            return None, None
    try:
        return int(raw), None
    except ValueError:
        return None, None


def vendor_name(vendor_id: Optional[int]) -> str:
    if vendor_id is None:
        return ""
    return MATTER_VENDOR_NAMES.get(int(vendor_id), "")


def device_type_name(device_type: Optional[int]) -> str:
    if device_type is None:
        return ""
    return MATTER_DEVICE_TYPES.get(int(device_type), "")


def parse_matter_txt(txt: Dict[str, str] | None) -> Dict[str, Any]:
    """
    Normalize Matter DNS-SD TXT keys into a structured dict.

    Supports commissionable (``_matterc._udp``) and operational (``_matter._tcp``) records.
    """
    data = {str(k): str(v) for k, v in (txt or {}).items()}
    # Case-insensitive access
    folded = {k.lower(): v for k, v in data.items()}

    vendor_id, product_id = parse_vendor_product(folded.get("vp", ""))
    device_type = _int_field(folded, "dt")
    commissioning = _int_field(folded, "cm")
    discriminator = _int_field(folded, "d")
    pairing_hint = _int_field(folded, "ph")

    return {
        "vendor_id": vendor_id,
        "product_id": product_id,
        "vendor_name": vendor_name(vendor_id),
        "device_type": device_type,
        "device_type_name": device_type_name(device_type),
        "device_name": folded.get("dn", ""),
        "commissioning_mode": commissioning,
        "commissioning_mode_name": COMMISSIONING_MODE.get(
            int(commissioning) if commissioning is not None else -1, ""
        ),
        "discriminator": discriminator,
        "pairing_hint": pairing_hint,
        "pairing_instruction": folded.get("pi", ""),
        "rotating_id": folded.get("ri", ""),
        "tcp_supported": folded.get("t", "") in ("1", "true", "True"),
        "session_idle_interval": _int_field(folded, "sii"),
        "session_active_interval": _int_field(folded, "sai"),
        "raw_txt": data,
    }
