#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.11 management frame builders (auth, association, probe)."""

from __future__ import annotations

from lib.protocols.wlan.mac import mac_header, str_to_mac


def _mgmt_fc(subtype: int) -> bytes:
    return bytes([(subtype << 4) & 0xF0, 0x00])


def build_open_auth_request(bssid: str, sta: str, seq: int = 1) -> bytes:
    bssid_b = str_to_mac(bssid)
    sta_b = str_to_mac(sta)
    hdr = mac_header(_mgmt_fc(11), bssid_b, sta_b, bssid_b)
    return hdr + (0).to_bytes(2, "little") + seq.to_bytes(2, "little") + (0).to_bytes(2, "little")


def build_association_request(
    bssid: str,
    sta: str,
    ssid: str,
    extra_ies: bytes = b"",
    *,
    capability: int = 0x0431,
    listen_interval: int = 10,
) -> bytes:
    bssid_b = str_to_mac(bssid)
    sta_b = str_to_mac(sta)
    hdr = mac_header(_mgmt_fc(0), bssid_b, sta_b, bssid_b)
    from lib.protocols.wlan.ie import ext_supported_rates_ie, ssid_ie, supported_rates_ie

    body = (
        capability.to_bytes(2, "little")
        + listen_interval.to_bytes(2, "little")
        + ssid_ie(ssid)
        + supported_rates_ie()
        + ext_supported_rates_ie()
        + extra_ies
    )
    return hdr + body


def build_probe_request(sta: str, ssid: str = "", extra_ies: bytes = b"") -> bytes:
    bcast = str_to_mac("ff:ff:ff:ff:ff:ff")
    sta_b = str_to_mac(sta)
    hdr = mac_header(_mgmt_fc(4), bcast, sta_b, bcast)
    from lib.protocols.wlan.ie import ssid_ie, supported_rates_ie

    return hdr + ssid_ie(ssid) + supported_rates_ie() + extra_ies


def build_beacon(
    bssid: str,
    ssid: str,
    channel: int,
    *,
    open_network: bool = True,
    rsn_ie: bytes = b"",
) -> bytes:
    """Construct a management beacon (subtype 8)."""
    bssid_b = str_to_mac(bssid)
    bcast = str_to_mac("ff:ff:ff:ff:ff:ff")
    hdr = mac_header(_mgmt_fc(8), bcast, bssid_b, bssid_b)
    cap = 0x0401 if open_network else 0x0431
    fixed = b"\x00" * 8 + (100).to_bytes(2, "little") + cap.to_bytes(2, "little")
    from lib.protocols.wlan.ie import (
        GENERIC_RSN_PSK_IE,
        ds_param_ie,
        ext_supported_rates_ie,
        ssid_ie,
        supported_rates_ie,
        tim_ie,
    )

    extra = b""
    if not open_network:
        extra = rsn_ie or GENERIC_RSN_PSK_IE
    ies = (
        ssid_ie(ssid)
        + supported_rates_ie()
        + ds_param_ie(channel)
        + tim_ie()
        + ext_supported_rates_ie()
        + extra
    )
    return hdr + fixed + ies