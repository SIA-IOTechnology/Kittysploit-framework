#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive OWE / OWE-transition beacon survey."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.owe import assess_owe_beacon
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi OWE Scanner",
        "description": (
            "Detect Opportunistic Wireless Encryption (OWE) and transition-mode "
            "companion BSSIDs from beacon IEs."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "owe", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    timeout = OptInteger(60, "Scan duration", required=False)
    owe_only = OptBool(False, "Only print OWE-related BSSIDs", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        duration = max(10, int(self.timeout or 60))
        seen: set[str] = set()
        print_info(f"OWE scan on {self.iface} ({duration}s)")

        def on_frame(raw: bytes, rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw, rssi=rssi)
            if not beacon or beacon.bssid in seen:
                return
            info = assess_owe_beacon(beacon.ies, beacon.security, beacon.bssid)
            if owe_only and not info.owe_enabled:
                return
            seen.add(beacon.bssid)
            if info.owe_enabled:
                print_success(
                    f"OWE | {beacon.bssid} | {beacon.ssid or '<hidden>'} | "
                    f"companion={info.transition_bssid or 'n/a'}"
                )
            elif not owe_only:
                print_status(f"  {beacon.bssid} {beacon.ssid or '<hidden>'} (no OWE)")

        try:
            self.wlan_sniff(on_frame, timeout=float(duration))
        except (PermissionError, OSError) as exc:
            print_error(str(exc))
            return False
        print_info(f"Unique BSSIDs: {len(seen)}")
        return True