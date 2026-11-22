#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OWE (Enhanced Open) transition beacon helpers."""

from __future__ import annotations

from dataclasses import dataclass

from lib.protocols.wlan.ie import (
    EXT_OWE_TRANSITION,
    MDIE_IE,
    iter_extension_elements,
    iter_information_elements,
)
from lib.protocols.wlan.mac import mac_to_str
from lib.protocols.wlan.rsn import SecurityInfo


@dataclass
class OweTransitionInfo:
    ssid: str
    bssid: str
    owe_enabled: bool
    transition_bssid: str = ""
    transition_ssid: str = ""
    open_companion: bool = False


def parse_owe_transition_ie(ies: bytes) -> tuple[str, str] | None:
    """Return (companion_bssid, companion_ssid) from OWE transition extension IE."""
    for ext_id, body, _ in iter_extension_elements(ies):
        if ext_id != EXT_OWE_TRANSITION or not body:
            continue
        companion_bssid = ""
        companion_ssid = ""
        if len(body) >= 6:
            companion_bssid = mac_to_str(body[:6])
        if len(body) > 6:
            companion_ssid = body[6:].decode("utf-8", errors="replace").strip()
        return companion_bssid, companion_ssid
    return None


def parse_mobility_domain(ies: bytes) -> int | None:
    for tag, body, _ in iter_information_elements(ies):
        if tag == MDIE_IE and len(body) >= 2:
            return int.from_bytes(body[:2], "little")
    return None


def assess_owe_beacon(ies: bytes, sec: SecurityInfo, bssid: str) -> OweTransitionInfo:
    trans = parse_owe_transition_ie(ies)
    info = OweTransitionInfo(ssid=sec.ssid, bssid=bssid, owe_enabled=sec.owe or bool(trans))
    if trans:
        cb, cs = trans
        info.transition_bssid = cb
        info.transition_ssid = cs
        info.open_companion = sec.cipher == "open" or not sec.akm_labels
    return info