#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPS vendor IE parsing (beacon / probe response)."""

from __future__ import annotations

from dataclasses import dataclass, field

from lib.protocols.wlan.ie import VENDOR_IE, iter_information_elements

WPS_OUI = bytes.fromhex("0050f2")
WPS_BEACON_TYPE = 4
_ATTR_MANUFACTURER = 0x1021
_ATTR_MODEL_NAME = 0x1023
_ATTR_MODEL_NUMBER = 0x1024
_ATTR_STATE = 0x1044
_ATTR_UUID_E = 0x1047
_ATTR_SELECTED_REGISTRAR = 0x1041


@dataclass
class WpsAccessPointInfo:
    bssid: str
    ssid: str = ""
    manufacturer: str = ""
    model_name: str = ""
    model_number: str = ""
    wps_state: str = ""
    uuid_e: str = ""
    selected_registrar: bool = False
    locked: bool = False
    raw_attrs: dict[int, str] = field(default_factory=dict)


def _iter_wps_attributes(body: bytes):
    pos = 0
    if len(body) < 4:
        return
    if body[0:3] != WPS_OUI:
        return
    pos = 4
    while pos + 4 <= len(body):
        attr_id = (body[pos] << 8) | body[pos + 1]
        length = (body[pos + 2] << 8) | body[pos + 3]
        pos += 4
        end = pos + length
        if end > len(body):
            break
        value = body[pos:end]
        pos = end
        yield attr_id, value


def _wps_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace").strip()


def parse_wps_ie(body: bytes) -> dict[int, str]:
    """Return attribute id → text for a vendor IE WPS payload."""
    attrs: dict[int, str] = {}
    for attr_id, value in _iter_wps_attributes(body):
        if attr_id in (_ATTR_MANUFACTURER, _ATTR_MODEL_NAME, _ATTR_MODEL_NUMBER):
            attrs[attr_id] = _wps_text(value)
        elif attr_id == _ATTR_STATE and value:
            attrs[attr_id] = {1: "not configured", 2: "configured"}.get(value[0], str(value[0]))
        elif attr_id == _ATTR_UUID_E:
            attrs[attr_id] = value.hex()
        elif attr_id == _ATTR_SELECTED_REGISTRAR:
            attrs[attr_id] = "yes" if value and value[0] == 1 else "no"
    return attrs


def wps_from_ies(ies: bytes, bssid: str, ssid: str = "") -> WpsAccessPointInfo | None:
    info = WpsAccessPointInfo(bssid=bssid, ssid=ssid)
    found = False
    for tag, body, _ in iter_information_elements(ies):
        if tag != VENDOR_IE or len(body) < 4:
            continue
        if body[0:3] != WPS_OUI or body[3] != WPS_BEACON_TYPE:
            continue
        found = True
        attrs = parse_wps_ie(body)
        info.raw_attrs = attrs
        info.manufacturer = attrs.get(_ATTR_MANUFACTURER, "")
        info.model_name = attrs.get(_ATTR_MODEL_NAME, "")
        info.model_number = attrs.get(_ATTR_MODEL_NUMBER, "")
        info.wps_state = attrs.get(_ATTR_STATE, "")
        info.uuid_e = attrs.get(_ATTR_UUID_E, "")
        info.selected_registrar = attrs.get(_ATTR_SELECTED_REGISTRAR, "") == "yes"
    return info if found else None