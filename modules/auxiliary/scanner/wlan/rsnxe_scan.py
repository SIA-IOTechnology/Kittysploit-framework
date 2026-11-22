#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect RSNXE (WPA3 SAE H2E / WPA3-only) capabilities in beacons."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.rsnxe import parse_rsnxe
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi RSNXE / WPA3 Caps Scanner",
        "description": "Parse RSN Extension IE for SAE hash-to-element and WPA3-only flags.",
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wpa3", "rsnxe"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    timeout = OptInteger(60, "Scan duration", required=False)
    wpa3_only = OptBool(False, "Only APs with RSNXE present", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        duration = max(10, int(self.timeout or 60))
        seen: set[str] = set()

        def on_frame(raw: bytes, rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw, rssi=rssi)
            if not beacon or beacon.bssid in seen:
                return
            rsnxe = parse_rsnxe(beacon.ies)
            if wpa3_only and not rsnxe:
                return
            seen.add(beacon.bssid)
            if rsnxe:
                print_success(
                    f"{beacon.bssid} | {beacon.ssid or '<hidden>'} | "
                    f"h2e={'Y' if rsnxe.sae_h2e else 'N'} "
                    f"wpa3_only={'Y' if rsnxe.wpa3_only else 'N'}"
                )
            elif not wpa3_only:
                print_status(f"{beacon.bssid} (no RSNXE)")

        try:
            self.wlan_sniff(on_frame, timeout=float(duration))
        except (PermissionError, OSError) as exc:
            print_error(str(exc))
            return False
        return True