#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.11 deauthentication / disassociation frame builder."""

from __future__ import annotations

from lib.protocols.wlan.mac import is_group_mac, mac_header, str_to_mac

_DEAUTH_ACK_NAV_US = 0x013A

DEAUTH_REASON_LABELS: dict[int, str] = {
    1: "Unspecified",
    2: "Previous authentication no longer valid",
    3: "Station leaving (or deauthenticated)",
    4: "Inactivity",
    5: "AP unable to handle all stations",
    6: "Class 2 frame from nonauthenticated station",
    7: "Class 3 frame from nonassociated station",
    8: "Station leaving (disassociated)",
    15: "4-Way handshake timeout",
    16: "Group key handshake timeout",
    23: "802.1X authentication failed",
}


def deauth_reason_label(code: int) -> str:
    label = DEAUTH_REASON_LABELS.get(code)
    if label:
        return f"{code} ({label})"
    return f"{code} (reserved/unknown)"


def deauth_nav_bytes(dest_mac: str | bytes) -> bytes:
    raw = dest_mac if isinstance(dest_mac, bytes) else str_to_mac(str(dest_mac))
    nav = 0 if is_group_mac(raw) else _DEAUTH_ACK_NAV_US
    return nav.to_bytes(2, "little")


def build_deauth(
    a1: bytes,
    a2: bytes,
    a3: bytes,
    reason: int = 7,
    *,
    disassoc: bool = False,
    duration: bytes | None = None,
) -> bytes:
    subtype = 0x0A if disassoc else 0x0C
    nav = duration if duration is not None else deauth_nav_bytes(a1)
    return mac_header(bytes([subtype << 4, 0x00]), a1, a2, a3, duration=nav) + reason.to_bytes(
        2, "little"
    )


def build_client_deauth(
    bssid: str, client: str, *, broadcast: bool = False, reason: int = 7
) -> list[bytes]:
    """AP -> client and client -> AP deauth frame pair."""
    bssid_b = str_to_mac(bssid)
    client_b = str_to_mac(client if not broadcast else "ff:ff:ff:ff:ff:ff")
    return [
        build_deauth(client_b, bssid_b, bssid_b, reason=reason),
        build_deauth(bssid_b, client_b, bssid_b, reason=reason),
    ]