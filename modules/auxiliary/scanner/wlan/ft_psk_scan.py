#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect 802.11r FT-PSK (fast roaming) beacons — not CPU-crackable as classic WPA."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.ft import assess_ft_beacon
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi FT-PSK Scanner",
        "description": (
            "List APs advertising FT-PSK / mobility domain (802.11r). Handshakes "
            "using FT key hierarchy are skipped from .22000 export."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "802.11r", "ft"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    timeout = OptInteger(60, "Scan duration", required=False)
    ft_only = OptBool(True, "Only show FT-capable APs", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        duration = max(10, int(self.timeout or 60))
        seen: set[str] = set()
        print_info(f"FT-PSK survey ({duration}s)")

        def on_frame(raw: bytes, rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw, rssi=rssi)
            if not beacon or beacon.bssid in seen:
                return
            ft = assess_ft_beacon(beacon.ies, beacon.security, beacon.bssid)
            if ft_only and not (ft.ft_psk or ft.ft_8021x):
                return
            seen.add(beacon.bssid)
            md = f"0x{ft.mobility_domain:04x}" if ft.mobility_domain is not None else "?"
            print_success(
                f"FT | {beacon.bssid} | {beacon.ssid or '<hidden>'} | "
                f"md={md} ft_psk={'Y' if ft.ft_psk else 'N'} "
                f"ds={'Y' if ft.rsn_ft_over_ds else 'N'} air={'Y' if ft.rsn_ft_over_air else 'N'}"
            )
            if ft.ft_psk:
                print_warning("  FT-PSK: expect no classic 22000 line from FT exchanges")

        try:
            self.wlan_sniff(on_frame, timeout=float(duration))
        except (PermissionError, OSError) as exc:
            print_error(str(exc))
            return False
        print_info(f"BSSIDs logged: {len(seen)}")
        return True